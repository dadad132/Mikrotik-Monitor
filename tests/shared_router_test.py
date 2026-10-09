"""One router, two companies.

A router has one connection to the hub, whoever set it up first. When a
second company sets the same router up, it must not replace the first one's
connection or login: it adds its own login and rides on the connection that
is there. The first company and the superadmin are told. Neither company can
take the other's connection or login away -- deleting a device removes only
that company's own login, and if the one holding the connection leaves, it
passes to the other. Two companies may also name a router alike.

Run:  ./.venv/Scripts/python.exe tests/shared_router_test.py
"""
from __future__ import annotations

import http.client
import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.notify.org_email as org_email
import mikromon.push as push_pkg
import mikromon.push.api as push_api
from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig, build_device
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore
from mikromon.push.audit import AuditLog
from mikromon.push.features import device_offboard

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DEF = dict(DEFAULT_THRESHOLDS)


class FakeRouter:
    """The parts of a router provisioning and offboarding touch."""

    def __init__(self, tunnel_pub="PUBA", users=("mkmonitor",)):
        self.n = 0
        self.rows = {
            ("interface", "wireguard"): [
                {".id": "*w", "name": "mikromon", "public-key": tunnel_pub}],
            ("interface", "wireguard", "peers"): [
                {".id": "*p", "comment": "mikromon:tunnel:hub"}],
            ("ip", "address"): [
                {".id": "*a", "interface": "mikromon",
                 "address": "10.10.5.9/16"}],
            ("user",): [{".id": f"*u{i}", "name": u}
                        for i, u in enumerate(users)],
            ("ip", "service"): [{".id": "*s1", "name": "api",
                                 "disabled": "false"},
                                {".id": "*s2", "name": "telnet",
                                 "disabled": "true"},
                                {".id": "*s3", "name": "ftp",
                                 "disabled": "true"}],
        }
        self.calls = 0
        self.writes = 0

    def fetch(self, path):
        self.calls += 1
        return [dict(r) for r in self.rows.get(tuple(path), [])]

    def execute(self, op):
        self.calls += 1
        self.writes += 1
        rows = self.rows.setdefault(tuple(op.path), [])
        if op.action == "add":
            self.n += 1
            rows.append(dict(op.params, **{".id": f"*n{self.n}"}))
        elif op.action == "remove":
            self.rows[tuple(op.path)] = [r for r in rows
                                         if r[".id"] != op.params[".id"]]
        elif op.action == "set":
            for r in rows:
                if r[".id"] == op.params.get(".id"):
                    r.update(op.params)

    def users(self):
        return sorted(r["name"] for r in self.rows[("user",)])

    def has_tunnel(self):
        return bool(self.rows[("interface", "wireguard")]
                    and self.rows[("interface", "wireguard", "peers")]
                    and self.rows[("ip", "address")])


# ---------------------------------------------------------------- bookkeeping
print("The hub's records")
hub = {"leases": {"A": "10.10.5.9", "B": "10.10.7.7"},
       "leases_meta": {"A": {"ip": "10.10.5.9", "pubkey": "PUBA"},
                       "B": {"ip": "10.10.7.7", "pubkey": "PUBB"}}}
ip = web._join_tunnel(hub, "B", "A")
check("a second device rides on the first one's connection: same address, "
      "and no record of its own left to fight over the key",
      ip == "10.10.5.9" and hub["joined"] == {"B": "A"}
      and "B" not in hub["leases"] and "B" not in hub["leases_meta"])
check("deleting the rider leaves the connection in place",
      web._release_shared(json.loads(json.dumps(hub)), "B") is True)
h2 = json.loads(json.dumps(hub))
check("deleting the device that holds the connection passes it to the rider",
      web._release_shared(h2, "A") is True
      and h2["leases_meta"].get("B", {}).get("pubkey") == "PUBA"
      and "A" not in h2["leases_meta"] and not h2["joined"])
check("...and a router nobody shares is not affected",
      web._release_shared({"leases": {"Z": "1"}}, "Z") is False)
h3 = json.loads(json.dumps(hub))
h3["prov_tokens"] = {"t1": {"name": "B", "expires": time.time() + 60}}
web._migrate_device_name(h3, "B", "B2")
web._migrate_device_name(h3, "A", "A2")
check("renaming either device carries the sharing along",
      h3["joined"] == {"B2": "A2"} and h3["prov_tokens"]["t1"]["name"] == "B2")
check("each company's routers get their own login name",
      web._default_login(7) == "mkm-7" and web._default_login(8) == "mkm-8")

print("\nOffboarding on a shared router")
r = FakeRouter(users=("mkmonitor", "mkm-2"))
cfg = build_device({"name": "B", "host": "10.10.5.9", "username": "mkm-2",
                    "password": "x"}, DEF)
device_offboard(r, cfg, keep_tunnel=True)
check("a company leaving a shared router removes only its own login -- "
      "never the other's, never the connection",
      r.users() == ["mkmonitor"] and r.has_tunnel())
device_offboard(r, build_device({"name": "A", "host": "10.10.5.9",
                                 "username": "mkmonitor", "password": "x"},
                                DEF))
check("the last one out takes the connection down as before",
      r.users() == [] and not r.has_tunnel())

print("\nThe script")
s = web._provision_script(
    "Shop", {}, "mkm-2", "pw", hub_ip="203.0.113.5", hub_pubkey="HUBPUB",
    wg_priv="PRIV", wg_pub="NEWPUB", tunnel_ip="10.10.6.6",
    subnet="10.10.0.0/16", prev_pub="OLDPUB",
    join_url="https://easymikrotik.test/provision/join?t=TOK")
check("before touching the connection, it reads whose it is and asks the "
      "server about any key that is not this device's own",
      '$mmpub != "OLDPUB" && $mmpub != "NEWPUB"' in s
      and 'url="https://easymikrotik.test/provision/join?t=TOK"' in s
      and 'x-mm-pub: " . $mmpub' in s)
check("...adds the login only once that is known, and replaces the "
      "connection only when it is this device's own",
      s.index(':if ($mmmode = "own" || $mmmode = "joined") do={')
      < s.index("/user add name=mkm-2")
      < s.index(':if ($mmmode = "own") do={')
      < s.index("/interface wireguard set"))
check("...and stops, changing nothing, when it cannot tell",
      ':if ($mmmode = "unknown") do={' in s
      and "could not be asked whose it is, so nothing was changed" in s)

# -------------------------------------------------------------------- the web
print("\nTwo companies, end to end")
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, pdb = (os.path.join(tmp, x) for x in (
    "m.db", "s.json", "a.db", "d.db", "p.db"))
peers = os.path.join(tmp, "peers.conf")
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
auth.signup("boss@platform.test", "secret123", "Platform")      # superadmin
org_a = auth.signup("owner@alpha.test", "secret123", "Alpha")
org_b = auth.signup("owner@beta.test", "secret123", "Beta Co")
ds = DevicesStore(ddb)
ds.upsert({"name": "Shop", "host": "10.10.5.9", "username": "mkmonitor",
           "password": "pa", "use_ssl": False, "api_port": 8728},
          DEF, org_id=org_a)
ds.close()
with open(web._hub_path(ddb), "w") as fh:
    json.dump({"hub_ip": "203.0.113.5", "hub_pubkey": "HUBPUB",
               "subnet": "10.10.0.0/16", "wg_peers": peers,
               "leases": {"Shop": "10.10.5.9"},
               "leases_meta": {"Shop": {"ip": "10.10.5.9",
                                        "pubkey": "PUBA"}}}, fh)

mails = []
router = FakeRouter()


class _Dev:
    def reachable(self, timeout=None, attempts=None):
        return True

    def close(self):
        pass


class _Api:
    def __init__(self, dev):
        pass

    def connect(self):
        return self

    def close(self):
        pass

    def fetch(self, path):
        return router.fetch(path)

    def execute(self, op):
        return router.execute(op)


saved = (org_email._smtp_send, web._wg_keypair, push_pkg.rw_device,
         push_api.PushApi)
org_email._smtp_send = lambda cfg, msg: mails.append(msg)
web._wg_keypair = lambda: ("PRIVB", "PUBB")
push_pkg.rw_device = lambda cfg: _Dev()
push_api.PushApi = _Api

srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, push_log_db=pdb,
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noc@platform.test")))
PORT = srv.server_address[1]
BASE = f"http://127.0.0.1:{PORT}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        rr = op.open(urllib.request.Request(BASE + path, data=body),
                     timeout=15)
        return rr.status, rr.read().decode("utf-8", "replace"), rr.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), ""


def join(token, pub):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    c.request("POST", f"/provision/join?t={token}", body=b"",
              headers={"x-mm-pub": pub, "Content-Length": "0"})
    resp = c.getresponse()
    out = resp.read().decode()
    c.close()
    return out


def hub_now():
    with open(web._hub_path(ddb)) as fh:
        return json.load(fh)


def wait_mail(n, secs=5):
    end = time.time() + secs
    while len(mails) < n and time.time() < end:
        time.sleep(0.05)


try:
    b = opener()
    req(b, "/login", {"email": "owner@beta.test", "password": "secret123"})
    _, page, _ = req(b, "/devices")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    st, page, url = req(b, "/devices/save", {"csrf": csrf, "name": "Shop"})
    ds = DevicesStore(ddb)
    check("a second company can name its router like another company's: it "
          "is saved as \"Shop (Beta Co)\" instead of being refused",
          ds.org_of("Shop (Beta Co)") == org_b and ds.org_of("Shop") == org_a
          and "Another company already has a device called" in page)
    check("...and the first company's device is untouched",
          ds.raw("Shop")["host"] == "10.10.5.9"
          and ds.raw("Shop")["username"] == "mkmonitor")
    ds.close()
    BDEV = "Shop (Beta Co)"
    check("its login on the router is its own, not the shared 'mkmonitor'",
          f"mkm-{org_b}" in page and "<code>mkmonitor</code>" not in page)

    st, page, _ = req(b, "/device/provision", {
        "csrf": csrf, "device": BDEV, "transport": "wg", "enable_api": "1",
        "lock_api": "1"})
    tok = re.search(r"provision/join\?t=([A-Za-z0-9_-]+)", page)
    check("its script carries the question to ask about an existing "
          "connection", tok is not None and f"/user add name=mkm-{org_b}"
          in page)
    tok = tok.group(1) if tok else ""
    _, page, _ = req(b, "/device/provision", {
        "csrf": csrf, "device": BDEV, "transport": "wg", "pwuser": "mkmonitor"})
    check("Beta cannot choose the login Alpha's routers use -- on a router "
          "they share it would be reset", "used by another account" in page
          and "/user add name=mkmonitor" not in page)
    _, page, _ = req(b, "/device/provision", {
        "csrf": csrf, "device": BDEV, "transport": "wg",
        "pwuser": "x password=1; /system reset-configuration"})
    check("...nor a login that would add commands of its own to the script",
          "letters, digits" in page and "reset-configuration" not in page)

    check("an unknown token gets nowhere", join("nonsense", "PUBA")
          == "expired")
    check("a router with no connection, or this device's own, is set up as "
          "before", join(tok, "PUBB") == "own")
    check("a connection this server does not know is left alone",
          join(tok, "SOMEONE-ELSES") == "unknown")

    answer = join(tok, "PUBA")
    h = hub_now()
    ds = DevicesStore(ddb)
    check("on Alpha's router it joins: Beta rides on Alpha's connection",
          answer == "joined" and h.get("joined") == {BDEV: "Shop"}
          and BDEV not in h["leases_meta"]
          and ds.raw(BDEV)["host"] == "10.10.5.9")
    ds.close()
    with open(peers) as fh:
        pf = fh.read()
    check("...and the hub still has exactly one peer for that router, with "
          "Alpha's key", pf.count("PublicKey = PUBA") == 1
          and "PUBB" not in pf)
    wait_mail(2)
    to_alpha = [m for m in mails if "owner@alpha.test" in m["To"]]
    to_boss = [m for m in mails if "boss@platform.test" in m["To"]]
    check("Alpha is emailed, naming the company that added its login",
          len(to_alpha) == 1
          and "Beta Co added its login to your router Shop"
          in to_alpha[0]["Subject"]
          and f"mkm-{org_b}" in to_alpha[0].get_content())
    check("...and so is the superadmin, naming both",
          len(to_boss) == 1 and "Router shared by two companies: Shop"
          in to_boss[0]["Subject"] and "Alpha" in to_boss[0].get_content()
          and "Beta Co" in to_boss[0].get_content())
    log_a = AuditLog(pdb).recent(device="Shop")
    check("...and it is in Alpha's activity log for that router",
          any("Beta Co added its" in r["summary"] for r in log_a))
    check("pasting the same script again changes nothing and emails nobody",
          join(tok, "PUBA") == "joined" and len(mails) == 2)

    # From before sharing existed: a device whose login is the same as the
    # other company's on that router. It must not reset theirs; it switches
    # to its own company's login name for the next script.
    ds = DevicesStore(ddb)
    ds.upsert({"name": "Old", "host": "10.10.9.9", "username": "mkmonitor",
               "password": "x"}, DEF, org_id=org_b)
    ds.close()
    h = hub_now()
    h.setdefault("prov_tokens", {})["oldtok"] = {"name": "Old",
                                                 "expires": time.time() + 60}
    with open(web._hub_path(ddb), "w") as fh:
        json.dump(h, fh)
    ds = DevicesStore(ddb)
    check("a leftover clash of logins stops the script without touching "
          "the other company's login -- and this device takes its own name "
          "for next time", join("oldtok", "PUBA") == "samelogin"
          and DevicesStore(ddb).raw("Old")["username"] == f"mkm-{org_b}"
          and ds.raw("Shop")["username"] == "mkmonitor"
          and not (hub_now().get("joined") or {}).get("Old"))
    ds.close()

    _, page, _ = req(b, f"/device?name={urllib.parse.quote(BDEV)}"
                        f"&tab=provision")
    check("Beta's provision page says the router is shared, and set up",
          "This router is shared with another account" in page
          and "This router is already set up" in page)
    before = router.writes
    _, page, _ = req(b, "/device/wg-repair", {"csrf": csrf, "device": BDEV})
    check("Beta cannot repair or rewrite Alpha's connection: it is told why, "
          "and nothing is written to the router",
          "shares another account" in page and router.writes == before)
    if "shares another account" not in page:
        print("    page:", re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))[:600])

    # Beta removes its device: only its own login goes.
    router.rows[("user",)].append({".id": "*ub", "name": f"mkm-{org_b}"})
    req(b, "/devices/delete", {"csrf": csrf, "name": BDEV})
    check("Beta removing its device takes only Beta's login off the router",
          router.users() == ["mkmonitor"] and router.has_tunnel()
          and not hub_now().get("joined")
          and hub_now()["leases_meta"]["Shop"]["pubkey"] == "PUBA")

    # Automatic setup on the shared router: joins too.
    req(b, "/devices/save", {"csrf": csrf, "name": "Till"})
    ds = DevicesStore(ddb)
    raw = ds.raw("Till")
    raw["host"] = "198.51.100.4"
    ds.upsert(raw, DEF, original_name="Till")
    ds.close()
    st, page, _ = req(b, "/device/provision", {
        "csrf": csrf, "device": "Till", "auto": "1", "transport": "wg",
        "enable_api": "1", "lock_api": "1"})
    ds = DevicesStore(ddb)
    check("the automatic setup joins as well: Beta's login is added, "
          "Alpha's connection and login are left as they were",
          hub_now().get("joined") == {"Till": "Shop"}
          and ds.raw("Till")["host"] == "10.10.5.9"
          and f"mkm-{org_b}" in router.users() and "mkmonitor" in router.users()
          and router.has_tunnel()
          and router.rows[("interface", "wireguard")][0]["public-key"]
          == "PUBA")
    ds.close()

    # Alpha leaves: the connection passes to Beta's device.
    a = opener()
    req(a, "/login", {"email": "owner@alpha.test", "password": "secret123"})
    _, page, _ = req(a, "/devices")
    csrf_a = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    req(a, "/devices/delete", {"csrf": csrf_a, "name": "Shop"})
    h = hub_now()
    check("when Alpha removes the router, its connection passes to Beta's "
          "device, which keeps working",
          not h.get("joined") and h["leases_meta"].get("Till", {})
          .get("pubkey") == "PUBA" and router.has_tunnel()
          and router.users() == [f"mkm-{org_b}"])
finally:
    srv.shutdown()
    srv.server_close()
    (org_email._smtp_send, web._wg_keypair, push_pkg.rw_device,
     push_api.PushApi) = saved

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SHARED-ROUTER TESTS PASSED")
