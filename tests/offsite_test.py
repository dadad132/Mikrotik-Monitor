"""Off-site backups, and secrets sealed at rest.

Router logins and API keys are stored sealed; the key that opens them lives
in its own file, not in the databases. Every night the data, that key and
the hub's WireGuard key are put in one archive, encrypted (age, X25519) to a
public key whose private half never touches the server, and uploaded to
S3-compatible storage. Rebuilding a server from one gives back working
router logins.

Run:  ./.venv/Scripts/python.exe tests/offsite_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.notify.org_email as org_email
from mikromon import cli, offsite, vault, web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, load_config
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DEF = dict(DEFAULT_THRESHOLDS)

print("Sealed at rest")
tmp = tempfile.mkdtemp()
ds = DevicesStore(os.path.join(tmp, "d.db"))
ds.upsert({"name": "R1", "host": "10.10.1.1", "username": "mkm-2",
           "password": "R0uterAdmin!"}, DEF)
blob = ds.db.execute("SELECT config FROM devices").fetchone()[0]
check("a router's login is not readable in the database file",
      "R0uterAdmin!" not in blob and vault.PREFIX in blob)
check("...but reads back, for the monitor and the pages",
      ds.raw("R1")["password"] == "R0uterAdmin!"
      and ds.list_configs(DEF)[0].password == "R0uterAdmin!")
check("the key that opens it is a file of its own, beside the databases",
      os.path.isfile(os.path.join(tmp, "secrets.key")))
ds.close()
raw_db = os.path.join(tmp, "old.db")
import sqlite3  # noqa: E402
c = sqlite3.connect(raw_db)
c.execute("CREATE TABLE devices (name TEXT PRIMARY KEY, config TEXT NOT NULL, "
          "updated REAL NOT NULL, org_id INTEGER NOT NULL DEFAULT 1)")
c.execute("INSERT INTO devices VALUES ('Old', ?, 0, 1)", (json.dumps(
    {"name": "Old", "host": "10.10.9.9", "username": "u",
     "password": "plain-from-before"}),))
c.commit()
c.close()
old = DevicesStore(raw_db)
check("a database from before sealing is sealed the first time it opens, "
      "and keeps working", "plain-from-before" not in old.db.execute(
          "SELECT config FROM devices").fetchone()[0]
      and old.raw("Old")["password"] == "plain-from-before")
old.close()
a = AuthStore(os.path.join(tmp, "a.db"))
a.set_setting("smtp", {"host": "smtp.test", "password": "MailPass9"})
a.set_setting("yoco", {"secret_key": "sk_live_x", "webhook_secret": "w"})
rows = dict(a.db.execute("SELECT key, value FROM platform_settings"))
check("mail, payment and AI keys are sealed too; ordinary settings are not",
      "MailPass9" not in rows["smtp"] and "sk_live_x" not in rows["yoco"]
      and a.get_setting("smtp")["password"] == "MailPass9")
other = tempfile.mkdtemp()
import shutil  # noqa: E402
shutil.copy(os.path.join(tmp, "a.db"), os.path.join(other, "a.db"))
check("a copied database is no use without its key file",
      AuthStore(os.path.join(other, "a.db")).get_setting("smtp") is None)
a.close()

print("\nThe encryption")
ident, rcpt = offsite.generate_identity()
check("a key pair is the standard age one: AGE-SECRET-KEY-1... and age1...",
      ident.startswith("AGE-SECRET-KEY-1") and rcpt.startswith("age1")
      and offsite.recipient_of(ident) == rcpt)
src = os.path.join(tmp, "plain.bin")
data = os.urandom(200_000)
with open(src, "wb") as fh:
    fh.write(data)
offsite.encrypt_file(src, src + ".age", rcpt)
offsite.decrypt_file(src + ".age", src + ".out", ident)
check("encrypt and decrypt round-trip, across chunk boundaries",
      open(src + ".out", "rb").read() == data
      and data[:64] not in open(src + ".age", "rb").read())
try:
    import pyrage
    other_ident = pyrage.x25519.Identity.from_str(ident)
    check("the standard age tool opens our backups (checked with an "
          "independent implementation)", pyrage.decrypt(
              open(src + ".age", "rb").read(), [other_ident]) == data)
except ImportError:
    print("  [skip] pyrage not installed: no independent age check")
wrong, _ = offsite.generate_identity()
try:
    offsite.decrypt_file(src + ".age", src + ".bad", wrong)
    opened = True
except ValueError:
    opened = False
check("...and another key cannot open them", not opened)
check("S3 request signing matches AWS's published example",
      offsite.sign_v4(
          "GET", "examplebucket.s3.amazonaws.com", "/test.txt", "",
          {"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
           "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
                                   "649b934ca495991b7852b855",
           "x-amz-date": "20130524T000000Z"},
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "us-east-1", "AKIAIOSFODNN7EXAMPLE",
          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524T000000Z")
      .endswith("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c60"
                "36bdb41"))

# -------------------------------------------------------------- the nightly job
print("\nThe nightly job")
S3 = {"objects": {}, "deny": False, "bad_sig": 0}
ACCESS, SECRET = "AKIATEST", "s3cr3t-key"


class FakeS3(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        auth_h = self.headers.get("Authorization", "")
        signed = re.search(r"SignedHeaders=([^,]+)", auth_h).group(1).split(";")
        region = re.search(r"Credential=[^/]+/\d+/([^/]+)/", auth_h).group(1)
        want = offsite.sign_v4(
            "PUT", self.headers["Host"], urllib.parse.urlparse(self.path).path,
            "", {h: self.headers[h] for h in signed},
            self.headers["x-amz-content-sha256"], region, ACCESS, SECRET,
            self.headers["x-amz-date"])
        if want != auth_h:
            S3["bad_sig"] += 1
        if S3["deny"]:
            msg = b"<Error><Code>AccessDenied</Code></Error>"
            self.send_response(403)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        S3["objects"][self.path] = body
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


s3 = ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
threading.Thread(target=s3.serve_forever, daemon=True).start()
ENDPOINT = f"http://127.0.0.1:{s3.server_address[1]}"

site = tempfile.mkdtemp()
P = {k: os.path.join(site, v) for k, v in (
    ("auth", "auth.db"), ("devices", "devices.db"), ("metrics", "metrics.db"),
    ("state", "state.json"), ("cfg", "config.yaml"))}
MetricsStore(P["metrics"]).close()
with open(P["state"], "w") as fh:
    json.dump({"devices": {}}, fh)
with open(P["cfg"], "w") as fh:
    fh.write(f"devices_db: {P['devices']}\nauth_db: {P['auth']}\n"
             f"metrics_db: {P['metrics']}\nstate_file: {P['state']}\n")
auth = AuthStore(P["auth"])
auth.signup("boss@platform.test", "secret123", "Platform")
auth.set_setting("smtp", {"host": "smtp.test", "from_addr": "noc@p.test"})
d = DevicesStore(P["devices"])
d.upsert({"name": "Shop", "host": "10.10.5.9", "username": "mkm-2",
          "password": "Shop-Admin-1"}, DEF)
d.close()
cred = tempfile.mkdtemp()
with open(os.path.join(cred, offsite.CREDENTIAL), "w") as fh:
    fh.write("HUBPRIVATEKEY=\n")
auth.set_setting("offsite", {
    "enabled": True, "bucket": "backups", "region": "af-south-1",
    "access_key": ACCESS, "secret_key": SECRET, "endpoint": ENDPOINT,
    "prefix": "easymikrotik", "recipient": rcpt})
check("the storage key is kept sealed as well", SECRET not in dict(
    auth.db.execute("SELECT key, value FROM platform_settings"))["offsite"])
config = load_config(P["cfg"])

mails = []
saved_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: mails.append(msg)
try:
    st = offsite.run(config, P["cfg"], cred_dir=cred)
    names = list(S3["objects"])
    check("a run uploads one encrypted archive, under a dated name",
          st.get("ok") and len(names) == 1 and re.fullmatch(
              r"/backups/easymikrotik/\d{4}/\d\d/\d\d/easymikrotik-[\d-]+"
              r"\.tar\.gz\.age", names[0]) is not None)
    check("...with a valid signature on every upload", S3["bad_sig"] == 0)
    check("...and records how it went for Platform admin",
          offsite.read_status(site).get("ok") is True
          and offsite.read_status(site).get("wireguard") is True)
    blob = S3["objects"][names[0]]
    check("what reaches the storage is unreadable without the key",
          blob.startswith(b"age-encryption.org/v1")
          and b"Shop-Admin-1" not in blob and b"SQLite" not in blob)
    enc = os.path.join(tmp, "dl.tar.gz.age")
    with open(enc, "wb") as fh:
        fh.write(blob)
    offsite.decrypt_file(enc, enc + ".tar.gz", ident)
    with tarfile.open(enc + ".tar.gz") as tar:
        members = set(tar.getnames())
    check("inside: the databases, the config, the secrets key and the hub's "
          "WireGuard key", {"auth.db", "devices.db", "config.yaml",
                            "secrets.key", "system/wireguard/wg0.key"}
          <= members)

    S3["deny"] = True
    st = offsite.run(config, P["cfg"], cred_dir=cred)
    check("a refused upload is recorded as a failure, saying why",
          not st.get("ok") and "not allowed to upload" in st.get("error", "")
          and offsite.read_status(site).get("last_ok"))
    check("...and the superadmin is emailed about it",
          any("Off-site backup FAILED" in m["Subject"]
              and "boss@platform.test" in m["To"] for m in mails))
    S3["deny"] = False
    s = auth.get_setting("offsite")
    auth.set_setting("offsite", dict(s, enabled=False))
    n = len(S3["objects"])
    st = offsite.run(config, P["cfg"], cred_dir=cred)
    check("switched off, it uploads nothing -- and does not record that "
          "as a failure", len(S3["objects"]) == n
          and "switched off" in st.get("error", "")
          and "not allowed" in offsite.read_status(site).get("error", ""))
    auth.set_setting("offsite", s)
finally:
    org_email._smtp_send = saved_send

print("\nRebuilding from it")
new = tempfile.mkdtemp()
NP = {k: os.path.join(new, os.path.basename(v)) for k, v in P.items()}
with open(NP["cfg"], "w") as fh:
    fh.write(f"devices_db: {NP['devices']}\nauth_db: {NP['auth']}\n"
             f"metrics_db: {NP['metrics']}\nstate_file: {NP['state']}\n")
keyfile = os.path.join(tmp, "key.txt")
with open(keyfile, "w") as fh:
    fh.write(f"# backup key\n{ident}\n")
rc = cli.main(["restore-server", "-c", NP["cfg"], "--archive", enc,
               "--identity", keyfile, "--apply"])
nd = DevicesStore(NP["devices"])
check("restore-server opens the encrypted backup with the private key and "
      "puts the data and its secrets key back", rc == 0
      and os.path.isfile(os.path.join(new, "secrets.key")))
check("...so the rebuilt server can still log in to every router",
      nd.raw("Shop")["password"] == "Shop-Admin-1")
nd.close()
rc = cli.main(["restore-server", "-c", NP["cfg"], "--archive", enc,
               "--identity", os.path.join(tmp, "missing.txt"), "--apply"])
check("...and refuses without the key", rc == 2)

print("\nPlatform admin")
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    P["metrics"], P["state"], auth, web.SessionManager(), secure_cookies=False,
    devices_db=P["devices"], defaults=DEF, admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
    return r.read().decode("utf-8", "replace")


try:
    req("/login", {"email": "boss@platform.test", "password": "secret123"})
    page = req("/superadmin")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("the Platform page shows off-site backups and the last result "
          "(the refused upload), and when the last good one was",
          "Off-site backups" in page and "FAILED:</b>" in page
          and "not allowed to upload" in page
          and "The last one that worked was" in page)
    page = req("/superadmin/offsite", {"csrf": csrf, "action": "genkey",
                                       "enabled": "1", "bucket": "backups"})
    shown = re.search(r"AGE-SECRET-KEY-1[0-9A-Z]+", page)
    s = auth.get_setting("offsite")
    check("making a key pair shows the private key once and keeps only the "
          "public half", shown is not None
          and s["recipient"] == offsite.recipient_of(shown.group(0))
          and shown.group(0) not in json.dumps(s))
    check("...and the secret access key, left blank, is kept",
          s["secret_key"] == SECRET)
    page = req("/superadmin/offsite", {"csrf": csrf, "action": "test",
                                       "enabled": "1", "bucket": "backups"})
    check("Save and test uploads a test file and says so",
          "a test file reached the storage" in page
          and any(k.endswith("connection-test.txt") for k in S3["objects"]))
    page = req("/superadmin/offsite", {"csrf": csrf, "action": "runnow",
                                       "enabled": "1", "bucket": "backups"})
    check("Back up now asks systemd to run the job",
          os.path.isfile(os.path.join(site, offsite.TRIGGER_NAME))
          and "Backup started" in page)
finally:
    srv.shutdown()
    srv.server_close()
    s3.shutdown()
    s3.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL OFF-SITE BACKUP TESTS PASSED")
