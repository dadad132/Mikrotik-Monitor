"""Antivirus agents reporting to EasyMikroTik, and the support team being told.

The agent (agent/antivirus.py) runs on customers' PCs and posts what it
finds to /api/v1/edr/alerts with its company's key. These tests stand in
for it: they post events the way it does, and check who is emailed, what is
held back, and that a key only ever speaks for its own company.

Run:  ./.venv/Scripts/python.exe tests/edr_test.py
"""
from __future__ import annotations

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
from mikromon import edr, web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore
from mikromon.web_shared import _nav_items

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()
T0 = 1_000_000.0


def ev_of(agent="pc1", etype="FILE_QUARANTINED", sev="HIGH", **kw):
    return edr.parse_event({"agent_id": agent, "hostname": agent.upper(),
                            "event_type": etype, "severity": sev, **kw})


print("keys:")
st = edr.EdrStore(os.path.join(tmp, "edr.db"))
k1 = st.new_key(7)
check("a key looks like emk_... and names its company",
      k1.startswith("emk_") and len(k1) > 40 and st.org_for_key(k1) == 7)
rows = [dict(r) for r in st.db.execute("SELECT * FROM edr_keys")]
check("only its hash is kept", k1 not in json.dumps(rows)
      and rows[0]["hint"] == k1[:10])
k2 = st.new_key(7)
check("a new key replaces the old one",
      st.org_for_key(k1) is None and st.org_for_key(k2) == 7)
check("anything else is not a key", st.org_for_key("") is None
      and st.org_for_key("emk_nope") is None
      and st.org_for_key("x" * 500) is None)
st.revoke_key(7)
check("a removed key stops working", st.org_for_key(k2) is None
      and st.keys() == {})

print("reading an event:")


def refused(payload):
    try:
        edr.parse_event(payload)
    except edr.EventError:
        return True
    return False


check("anything but a JSON object is refused",
      refused([1]) and refused("x") and refused(None))
check("no agent_id is refused", refused({"event_type": "FILE_QUARANTINED"}))
check("an event_type that is not LIKE_THIS is refused",
      refused({"agent_id": "a", "event_type": "rm -rf /"}))
check("an unknown severity is refused",
      refused({"agent_id": "a", "event_type": "X_Y", "severity": "DOOM"}))
ev = edr.parse_event({"agent_id": "a", "event_type": "file_quarantined",
                      "severity": "critical", "sha256": "NOTAHASH",
                      "target": "x" * 5000,
                      "details": {"pid": 4, "nested": {"a": 1},
                                  "cmdline": "y" * 5000}})
check("names are upper-cased and other agents' severities understood",
      ev["event_type"] == "FILE_QUARANTINED" and ev["severity"] == "HIGH")
check("a malformed hash is dropped and long text trimmed",
      ev["sha256"] == "" and len(ev["target"]) == 1024
      and len(ev["details"]["cmdline"]) == 1000)
check("nested objects in details are not stored",
      "nested" not in ev["details"] and ev["details"]["pid"] == 4)
first = edr.parse_event({"agent_id": "PC-1", "event_type": "FILE_QUARANTINED",
                         "target": "C:\\x.exe",
                         "details": {"reason": "Known Malware Hash (EICAR)",
                                     "severity": "HIGH", "sha256": "a" * 64}})
st.record(9, first, now=T0)
check("the first agent's format (reason, severity and hash inside details, "
      "PC name as its id) is understood", first["reason"].startswith("Known")
      and first["severity"] == "HIGH" and first["sha256"] == "a" * 64
      and st.agent(9, "PC-1")["hostname"] == "PC-1")

print("what is emailed, and when:")
r = st.record(1, ev_of(sev="MEDIUM"), "203.0.113.9", now=T0)
check("the first alert from a PC is emailed", r["email"] and r["held"] == 0)
r = st.record(1, ev_of(sev="MEDIUM"), now=T0 + 60)
check("a second within the gap is held", not r["email"])
r = st.record(1, ev_of(sev="HIGH"), now=T0 + 120)
check("...unless it is more serious than the last one sent",
      r["email"] and r["held"] == 1)
a = st.record(1, ev_of(sev="HIGH"), now=T0 + 180)
b = st.record(1, ev_of(sev="MEDIUM"), now=T0 + 240)
check("then the same or less is held again", not a["email"] and not b["email"])
r = st.record(1, ev_of(sev="MEDIUM"), now=T0 + 120 + edr.EMAIL_GAP)
check("after the gap the next one is emailed, counting what was held",
      r["email"] and r["held"] == 2)
check("another PC is its own incident",
      st.record(1, ev_of(agent="pc2", sev="MEDIUM"), now=T0 + 300)["email"])
r = st.record(1, ev_of(agent="pc3", etype="SUSPICIOUS_FILE", sev="LOW"),
              now=T0)
check("LOW is listed, not emailed", r["id"] and not r["email"])
for etype in ("AGENT_STARTED", "AGENT_STOPPED"):
    r = st.record(1, ev_of(agent="pc4", etype=etype, sev="MEDIUM"), now=T0)
    check(f"{etype} is listed, not emailed", r["id"] and not r["email"])
check("an agent error IS emailed: that PC is not fully protected",
      st.record(1, ev_of(agent="pc6", etype="AGENT_ERROR", sev="MEDIUM"),
                now=T0)["email"])
before = len(st.recent(1000))
r = st.record(1, ev_of(agent="pc5", etype="HEARTBEAT", sev="LOW"),
              "198.51.100.7", now=T0 + 5)
pc5 = st.agent(1, "pc5")
check("a heartbeat adds no alert, it only refreshes the PC",
      r["id"] is None and len(st.recent(1000)) == before
      and pc5["last_seen"] == T0 + 5 and pc5["public_ip"] == "198.51.100.7")
st.record(1, edr.parse_event({"agent_id": "pc1", "event_type": "HEARTBEAT",
                              "severity": "LOW"}), now=T0 + 10)
check("a report with blank fields keeps the PC's known name and address",
      st.agent(1, "pc1")["hostname"] == "PC1"
      and st.agent(1, "pc1")["public_ip"] == "203.0.113.9")
sent = sum(st.record(2, ev_of(agent=f"flood{i}"), now=T0 + i)["email"]
           for i in range(edr.EMAILS_PER_HOUR + 5))
check(f"a company gets at most {edr.EMAILS_PER_HOUR} emails an hour, however "
      f"many PCs report", sent == edr.EMAILS_PER_HOUR)
check("...and is emailed again the next hour",
      st.record(2, ev_of(agent="late"), now=T0 + 3700)["email"])
r = st.record(3, ev_of(agent="pcf"), now=T0)
st.email_failed(r["id"])
check("an email that did not go is marked on the alert",
      st.event(r["id"])["emailed"] == edr.EMAIL_FAILED)
check("...and the PC's next alert is emailed rather than held behind it",
      st.record(3, ev_of(agent="pcf"), now=T0 + 60)["email"])
st.purge_org(1)
check("deleting a company removes its PCs and alerts",
      st.agents(1) == [] and st.recent(10, org_id=1) == [])
st2 = edr.EdrStore(os.path.join(tmp, "edr2.db"))
st2.record(1, ev_of(), now=T0)
st2.record(1, ev_of(agent="new"), now=T0 + (edr.KEEP_DAYS + 1) * 86400)
check(f"alerts and silent PCs older than {edr.KEEP_DAYS} days are pruned",
      len(st2.recent(10)) == 1 and st2.agent(1, "pc1") is None)

print("the email:")
st3 = edr.EdrStore(os.path.join(tmp, "edr3.db"))
r = st3.record(5, edr.parse_event({
    "agent_id": "abc123", "hostname": "RECEPTION-PC", "user": "thandi",
    "os": "Windows 11", "local_ip": "192.168.88.23",
    "mac": "AA:BB:CC:DD:EE:FF", "version": "1.1",
    "event_type": "FILE_QUARANTINED", "severity": "HIGH",
    "target": "C:\\Users\\thandi\\Downloads\\invoice.pdf.exe",
    "reason": "Known malware hash (Test.Trojan)",
    "action": "Moved to quarantine", "sha256": "b" * 64}), "41.0.0.1", now=T0)
subj, body = edr.build_email(st3.event(r["id"]), st3.agent(5, "abc123"),
                             "Alpha IT", 3, "https://em.test/superadmin/antivirus")
check("the subject says what, on which PC, at which company",
      subj == "[EasyMikrotik] Antivirus: Threat quarantined on RECEPTION-PC "
              "(Alpha IT)")
for frag, why in (
        ("Known malware hash (Test.Trojan)", "what was found"),
        ("C:\\Users\\thandi\\Downloads\\invoice.pdf.exe", "where"),
        ("Moved to quarantine", "what the agent did"),
        ("signed in: thandi", "who was signed in"),
        ("192.168.88.23, network card AA:BB:CC:DD:EE:FF",
         "the PC's address and network card, to find it on the router"),
        ("41.0.0.1", "the site's internet address"),
        ("https://www.virustotal.com/gui/file/" + "b" * 64,
         "a link to look the file up"),
        ("3 more alerts from this PC", "how many were held since the last"),
        ("https://em.test/superadmin/antivirus", "a link to the page"),
        ("Cut this PC off the network: https://em.test/superadmin/antivirus/"
         "isolate?org=5&agent=abc123", "where to cut the PC off the network")):
    check(f"the body says {why}", frag in body)
r = st3.record(5, edr.parse_event({"agent_id": "abc123",
                                   "event_type": "AGENT_ERROR",
                                   "severity": "MEDIUM", "reason": "x"}),
               now=T0 + 10)
_, body = edr.build_email(st3.event(r["id"]), st3.agent(5, "abc123"),
                          "Alpha IT", 0, "https://em.test/superadmin/antivirus")
check("...which only a threat offers, not a problem with the agent itself",
      "Cut this PC off" not in body)

print("switched off:")
DEF = dict(DEFAULT_THRESHOLDS)
check("antivirus is on, now that it installs on Windows without Python",
      edr.ENABLED is True)
edr.ENABLED = False
off_dir = os.path.join(tmp, "off")
os.makedirs(off_dir)
o_mdb, o_sfile, o_adb, o_ddb = (os.path.join(off_dir, x) for x in
                                ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(o_mdb).close()
with open(o_sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
o_auth = AuthStore(o_adb)
o_auth.signup("boss@off.test", "secret123", "Platform")
DevicesStore(o_ddb).close()
off_srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    o_mdb, o_sfile, o_auth, web.SessionManager(), devices_db=o_ddb,
    defaults=DEF, admin_2fa=False))
threading.Thread(target=off_srv.serve_forever, daemon=True).start()
try:
    o_base = f"http://127.0.0.1:{off_srv.server_address[1]}"
    try:
        urllib.request.urlopen(urllib.request.Request(
            o_base + "/api/v1/edr/alerts", data=b"{}",
            headers={"Authorization": "Bearer emk_x"}), timeout=15)
        off_code = 200
    except urllib.error.HTTPError as e:
        off_code = e.code
    o = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    o.open(urllib.request.Request(o_base + "/login", data=urllib.parse.urlencode(
        {"email": "boss@off.test", "password": "secret123"}).encode()),
        timeout=15)
    try:
        o.open(o_base + "/superadmin/antivirus", timeout=15)
        page_code = 200
    except urllib.error.HTTPError as e:
        page_code = e.code
    try:
        o.open(o_base + "/superadmin/antivirus/setup.exe", timeout=15)
        setup_code = 200
    except urllib.error.HTTPError as e:
        setup_code = e.code
    check("...then agents' reports are refused, as from a server without it",
          off_code == 404)
    check("...the Antivirus page is not there",
          page_code == 404)
    check("...nor the Windows setup", setup_code == 404)
    check("...no edr.db is made",
          not os.path.exists(os.path.join(off_dir, "edr.db")))
    check("...and platform admins have no Antivirus link",
          ("/superadmin/antivirus", "Antivirus") not in _nav_items(
              {"role": "owner", "is_superadmin": True}))
finally:
    off_srv.shutdown()
    off_srv.server_close()
edr.ENABLED = True

print("over HTTP:")
# A stand-in for the built setup: the test must not depend on a build.
SETUP_BYTES = b"MZ stand-in for the Windows setup"
SETUP_PATH = os.path.join(tmp, "EasyMikroTik-Antivirus-Setup.exe")
with open(SETUP_PATH, "wb") as fh:
    fh.write(SETUP_BYTES)
edr.SETUP_FILE = SETUP_PATH
web_dir = os.path.join(tmp, "web")      # its own edr.db, beside devices.db
os.makedirs(web_dir)
mdb, sfile, adb, ddb = (os.path.join(web_dir, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
auth.signup("boss@platform.test", "secret123", "Platform")   # superadmin
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha IT")
beta = auth.signup("owner@beta.test", "secret123", "Beta Shop")
gamma = auth.signup("owner@gamma.test", "secret123", "Gamma Ltd")
auth.set_setting("public_base_url", "https://em.test")
DevicesStore(ddb).close()

mails = []
saved_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: mails.append(msg)
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, admin_2fa=False,
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noc@platform.test")))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers


def login(email):
    o = opener()
    req(o, "/login", {"email": email, "password": "secret123"})
    return o


def csrf_of(page):
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


def post_event(key, payload=None, raw=None, headers=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    h = {"Content-Type": "application/json"}
    if key is not None:
        h["Authorization"] = f"Bearer {key}"
    h.update(headers or {})
    rq = urllib.request.Request(BASE + "/api/v1/edr/alerts", data=data,
                                headers=h, method="POST")
    try:
        r = urllib.request.urlopen(rq, timeout=15)
        return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, {"raw": text.decode("utf-8", "replace")}


def wait_mail(n, secs=5):
    end = time.time() + secs
    while len(mails) < n and time.time() < end:
        time.sleep(0.05)


def pc_event(agent, host, etype="FILE_QUARANTINED", sev="HIGH", **kw):
    return {"agent_id": agent, "hostname": host, "os": "Windows 11",
            "user": "thandi", "local_ip": "192.168.88.23", "version": "1.1",
            "timestamp": "2026-10-14T08:00:00+00:00", "event_type": etype,
            "severity": sev, "target": "C:\\Users\\thandi\\Downloads\\x.exe",
            "reason": "Known malware hash (Test.Trojan)",
            "action": "Moved to quarantine", "sha256": "c" * 64, **kw}


try:
    st_, out = post_event(None, pc_event("p1", "PC-1"))
    check("no key: 401", st_ == 401 and out.get("error") == "unknown_key")
    st_, out = post_event("emk_madeup", pc_event("p1", "PC-1"))
    check("a made-up key: 401", st_ == 401)

    boss = login("boss@platform.test")
    st_, page, _ = req(boss, "/superadmin/antivirus")
    check("the platform admin opens the Antivirus page",
          st_ == 200 and "Company keys" in page and "Alpha IT" in page
          and "Beta Shop" in page and "Make a key" in page)
    check("with nothing reported yet", "Nothing reported yet" in page)
    check("which says alerts go to the platform admins until a list is set",
          "boss@platform.test" in page)
    token = csrf_of(page)
    owner = login("owner@alpha.test")
    st_, _, _ = req(owner, "/superadmin/antivirus")
    check("a company owner may not open it", st_ == 403)
    st_, _, _ = req(owner, "/superadmin/antivirus/key",
                    {"csrf": token, "org_id": alpha, "action": "new"})
    check("...nor make keys", st_ in (400, 403))
    check("the sidebar shows Antivirus to platform admins only",
          ("/superadmin/antivirus", "Antivirus") in _nav_items(
              {"role": "owner", "is_superadmin": True})
          and ("/superadmin/antivirus", "Antivirus") not in _nav_items(
              {"role": "owner"}))
    st_, _, _ = req(boss, "/superadmin/antivirus/key",
                    {"csrf": "wrong", "org_id": alpha, "action": "new"})
    check("a bad CSRF token is refused", st_ == 400)

    st_, page, hdrs = req(boss, "/superadmin/antivirus/key",
                          {"csrf": token, "org_id": alpha, "action": "new"})
    m = re.search(r"emk_[A-Za-z0-9_\-]+", page)
    akey = m.group(0) if m else ""
    check("making a key shows it once, not cached",
          st_ == 200 and akey and "Agent key for Alpha IT" in page
          and hdrs.get("Cache-Control") == "no-store")
    check("...with the steps to install the agent, the server address and "
          "the --test check", "agent/antivirus.py" in page
          and f"--install --url https://em.test --key {akey}" in page
          and "--test" in page)
    check("...Windows first, with the setup to download and the address "
          "to leave in it", page.index("Windows PCs") < page.index(
              "agent/antivirus.py")
          and 'href="/superadmin/antivirus/setup.exe"' in page
          and "<code>https://em.test</code>" in page
          and "Run anyway" in page)
    _, page, _ = req(boss, "/superadmin/antivirus")
    check("the Antivirus page offers the Windows setup too",
          "Install on a PC" in page
          and 'href="/superadmin/antivirus/setup.exe"' in page)

    def fetch(op, path):
        try:
            r = op.open(BASE + path, timeout=15)
            return r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers
    st_, body, hdrs = fetch(boss, "/superadmin/antivirus/setup.exe")
    check("a platform admin downloads it, as a file named for what it is",
          st_ == 200 and body == SETUP_BYTES
          and 'filename="EasyMikroTik-Antivirus-Setup.exe"'
          in hdrs.get("Content-Disposition", ""))
    st_, _, _ = fetch(owner, "/superadmin/antivirus/setup.exe")
    check("...a company owner does not: the support team installs it, "
          "holding the keys", st_ == 403)
    edr.SETUP_FILE = os.path.join(tmp, "not-built.exe")
    st_, _, _ = fetch(boss, "/superadmin/antivirus/setup.exe")
    _, nopage, _ = req(boss, "/superadmin/antivirus")
    check("a server without the setup built says so, rather than a "
          "broken link", st_ == 404 and "not on this server yet" in nopage
          and 'href="/superadmin/antivirus/setup.exe"' not in nopage)
    edr.SETUP_FILE = SETUP_PATH
    _, page, _ = req(boss, "/superadmin/antivirus")
    check("afterwards the page shows only the key's first characters",
          akey not in page and akey[:10] in page)
    check("its Replace/Remove buttons ask first, with the apostrophe in "
          "\"Alpha IT's key\" kept out of the script's quotes",
          "confirm(&quot;Replace Alpha IT&#x27;s key?" in page
          and "confirm('" not in page)

    st_, out = post_event(akey, pc_event("p1", "RECEPTION-PC"),
                          headers={"X-Real-IP": "41.0.0.1"})
    check("Alpha's key is taken: 200", st_ == 200 and out == {"ok": True})
    wait_mail(1)
    check("the platform admins are emailed when no list is set",
          len(mails) == 1 and mails[0]["To"] == "boss@platform.test")
    check("...naming the PC and the company", mails and mails[0]["Subject"]
          .endswith("Antivirus: Threat quarantined on RECEPTION-PC "
                    "(Alpha IT)"))
    body = mails[0].get_content() if mails else ""
    check("...with a link back to the Antivirus page",
          "https://em.test/superadmin/antivirus" in body)
    store = edr.EdrStore(edr.edr_path(ddb))
    check("the PC is recorded with the address it reported from",
          (store.agent(alpha, "p1") or {}).get("public_ip") == "41.0.0.1")

    _, page, _ = req(boss, "/superadmin/antivirus")
    check("the alert and the PC are on the page", "RECEPTION-PC" in page
          and "Threat quarantined" in page and "Emailed" in page)

    st_, _, _ = req(boss, "/superadmin/antivirus/recipients",
                    {"csrf": token, "recipients": "not-an-address"})
    check("a list with a bad address is refused",
          edr.saved_recipients(auth) == [])
    req(boss, "/superadmin/antivirus/recipients",
        {"csrf": token,
         "recipients": "support@msp.test; oncall@msp.test, SUPPORT@msp.test"})
    check("a list is saved, without repeats",
          edr.saved_recipients(auth) == ["support@msp.test", "oncall@msp.test"])
    post_event(akey, pc_event("p2", "ACCOUNTS-PC"))
    wait_mail(2)
    check("alerts then go to the support team's addresses", len(mails) == 2
          and mails[1]["To"] == "support@msp.test, oncall@msp.test")

    n = len(mails)
    st_, _ = post_event(akey, pc_event("p2", "ACCOUNTS-PC", "HEARTBEAT", "LOW"))
    st2, _ = post_event(akey, pc_event("p2", "ACCOUNTS-PC", sev="HIGH"))
    time.sleep(0.5)
    check("a heartbeat, and a repeat from the same PC, send no email",
          st_ == 200 and st2 == 200 and len(mails) == n)
    post_event(akey, pc_event("p3", "LAPTOP-7", "AGENT_TEST", "MEDIUM",
                              reason="Test alert sent with --test"))
    wait_mail(n + 1)
    check("the agent's --test alert is emailed as a test",
          len(mails) == n + 1
          and "Antivirus: Test alert on LAPTOP-7" in mails[-1]["Subject"])

    st_, out = post_event(akey, raw=b"{not json")
    check("unreadable JSON: 400", st_ == 400 and out["error"] == "bad_event")
    st_, out = post_event(akey, {"event_type": "FILE_QUARANTINED"})
    check("an event without an agent: 400, saying why",
          st_ == 400 and "agent_id" in out.get("detail", ""))
    st_, _ = post_event(akey, raw=b"x" * (edr.MAX_BODY + 1))
    check("an oversized report: 413", st_ == 413)

    _, page, _ = req(boss, "/superadmin/antivirus/key",
                     {"csrf": token, "org_id": beta, "action": "new"})
    bkey = re.search(r"emk_[A-Za-z0-9_\-]+", page).group(0)
    post_event(bkey, pc_event("p1", "TILL-1"))
    beta_pcs = store.agents(beta)
    check("Beta's key only ever reports Beta's PCs, even with the same agent "
          "id as an Alpha PC", [a["hostname"] for a in beta_pcs] == ["TILL-1"]
          and store.agent(alpha, "p1")["hostname"] == "RECEPTION-PC")

    _, page, _ = req(boss, "/superadmin/antivirus/key",
                     {"csrf": token, "org_id": alpha, "action": "new"})
    akey2 = re.search(r"emk_[A-Za-z0-9_\-]+", page).group(0)
    check("replacing a key says the old one has stopped working",
          "old key has stopped working" in page)
    check("...and it has", post_event(akey, pc_event("p1", "X"))[0] == 401
          and post_event(akey2, pc_event("p9", "X"))[0] == 200)
    req(boss, "/superadmin/antivirus/key",
        {"csrf": token, "org_id": beta, "action": "revoke"})
    check("a removed key is refused", post_event(bkey, pc_event("p1", "X"))[0]
          == 401)

    _, page, _ = req(boss, "/superadmin/antivirus/key",
                     {"csrf": token, "org_id": gamma, "action": "new"})
    gkey = re.search(r"emk_[A-Za-z0-9_\-]+", page).group(0)
    auth.delete_org(gamma)
    check("the key of a company that no longer exists is refused",
          post_event(gkey, pc_event("p1", "X"))[0] == 401)

    def boom(cfg, msg):
        raise OSError("relay down")
    org_email._smtp_send = boom
    post_event(akey2, pc_event("p7", "WAREHOUSE-PC"))
    deadline = time.time() + 5
    failed = []
    while time.time() < deadline and not failed:
        failed = [e for e in store.recent(20, org_id=alpha)
                  if e["hostname"] == "WAREHOUSE-PC"
                  and e["emailed"] == edr.EMAIL_FAILED]
        time.sleep(0.05)
    check("an alert whose email fails is marked so", bool(failed))
    _, page, _ = req(boss, "/superadmin/antivirus")
    check("...and the page says so", "Email failed" in page)
finally:
    srv.shutdown()
    srv.server_close()
    org_email._smtp_send = saved_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ANTIVIRUS (EDR) TESTS PASSED")
