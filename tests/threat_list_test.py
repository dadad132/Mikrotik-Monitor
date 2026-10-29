"""The shared threat list: how one PC's find protects every other PC.

edr.py keeps it and every agent downloads it. It grows from what agents
quarantine, what Windows Defender catches, the MalwareBazaar feed and the
support team's decisions. Pinned here:
  * a find blocks at once on the PCs of each company that reports it, and on
    everyone's only when the support team says so -- however many companies
    report it: anyone can sign up twice, and a leaked key or a made-up company
    must not get one customer's software quarantined at all of them
  * "safe" is never overruled by a PC or the feed; agents put the file back
  * agents get only what changed, only what applies to them, in pages
  * the feed adds, ages off after 30 days, and says on the page how it went

Run:  ./.venv/Scripts/python.exe tests/threat_list_test.py
"""
from __future__ import annotations

import http.cookiejar
import io
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import edr, web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()
T0 = 1_000_000.0
A, B, C, D, E = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64)
ALPHA, BETA, GAMMA = 1, 2, 3


def ev(etype="FILE_QUARANTINED", sha=A, agent="pc1", **kw):
    return edr.parse_event({"agent_id": agent, "event_type": etype,
                            "severity": "HIGH", "sha256": sha,
                            "reason": "YARA rule match (Reverse_Shell)",
                            **kw})


def items(store, org, since=0):
    got, rev, more = store.threats_since(org, since)
    return {i[0]: i[1] for i in got}, rev, more


st = edr.EdrStore(os.path.join(tmp, "edr.db"))

print("Learning from the PCs")
st.record(ALPHA, ev(), now=T0)
t = st.threat(A)
check("a file a PC quarantined goes on the list",
      t and t["verdict"] == "malicious" and t["source"] == "agent"
      and t["name"] == "YARA rule match (Reverse_Shell)")
seen, alpha_rev, _ = items(st, ALPHA)
check("...blocked at once on that company's PCs", seen == {A: "malicious"})
seen, beta_rev, _ = items(st, BETA)
check("...but not yet on another company's: one company's word, which a "
      "leaked key could fake", seen == {} and beta_rev == alpha_rev)
check("...so it waits for a decision on the page",
      [p["sha256"] for p in st.pending_threats()] == [A]
      and st.threat_counts()["pending"] == 1)
st.record(ALPHA, ev(agent="pc2"), now=T0 + 1)
check("the same company finding it again changes nothing",
      st.threat(A)["org_id"] == ALPHA
      and items(st, ALPHA, alpha_rev)[0] == {})
st.record(BETA, ev(agent="beta-pc"), now=T0 + 2)
seen, beta_rev2, _ = items(st, BETA, beta_rev)
check("a second company finding it blocks it on that company's PCs too",
      seen == {A: "malicious"})
check("...but still not on everyone's: two companies are no proof when "
      "anyone can sign up twice",
      st.threat(A)["org_id"] == ALPHA and items(st, GAMMA)[0] == {})
check("...so it still waits for the support team, saying two companies "
      "found it", [(p["sha256"], p["orgs"]) for p in st.pending_threats()]
      == [(A, 2)])
st.record(BETA, ev(agent="beta-pc2"), now=T0 + 2.5)
check("...and the second company finding it again changes nothing",
      items(st, BETA, beta_rev2)[0] == {})
st.record(ALPHA, ev("SUSPICIOUS_FILE", sha=B), now=T0 + 3)
check("a packed program is not learned: as often an ordinary installer",
      st.threat(B) is None)
st.record(ALPHA, ev("AGENT_TEST", sha=B), now=T0 + 3)
check("nor is anything that is not a find", st.threat(B) is None)
st.record(ALPHA, ev("DEFENDER_DETECTION", sha=C,
                    reason="Windows Defender found Trojan:Win32/X",
                    details={"threat": "Trojan:Win32/X"}), now=T0 + 4)
check("Windows Defender's finds are learned, under Defender's name for them",
      st.threat(C)["source"] == "defender"
      and st.threat(C)["name"] == "Trojan:Win32/X")

print("\nThe support team decides")
st.set_verdict(C, "malicious", "boss@platform.test", now=T0 + 5)
check("Block everywhere: on every PC at once",
      st.threat(C)["org_id"] is None
      and st.threat(C)["by_user"] == "boss@platform.test"
      and st.threat(C)["source"] == "defender")
st.set_verdict(A, "safe", "boss@platform.test", now=T0 + 6)
seen, _, _ = items(st, ALPHA, alpha_rev)
check("Safe: every PC hears it, and puts the file back",
      seen.get(A) == "safe" and items(st, BETA, beta_rev2)[0].get(A) == "safe")
st.record(BETA, ev(agent="other"), now=T0 + 7)
check("...and no PC reporting it again overrules that",
      st.threat(A)["verdict"] == "safe")
st.set_verdict(D, "malicious", "boss@platform.test",
               name="Ransomware note dropper", now=T0 + 8)
check("a fingerprint added by hand is blocked everywhere, by name",
      st.threat(D)["source"] == "support" and st.threat(D)["org_id"] is None
      and st.threat(D)["name"] == "Ransomware note dropper")
st.set_verdict(D, "removed", "boss@platform.test", now=T0 + 9)
st.record(ALPHA, ev(sha=D), now=T0 + 10)
check("taken off by a person, a PC reporting it does not put it back",
      st.threat(D)["verdict"] == "removed")
try:
    st.set_verdict("nope", "malicious", "x")
    refused = False
except ValueError as exc:
    refused = "SHA-256" in str(exc)
check("only real fingerprints are taken", refused)
counts = st.threat_counts()
check("the page's counts add up",
      counts["blocked"] == 1 and counts["safe"] == 1
      and counts["by_source"]["defender"] == 1)

print("\nAgents download it")
for i in range(7):
    st.set_verdict(f"{i:x}" * 64, "malicious", "boss", now=T0 + 20 + i)
got, rev, more = st.threats_since(ALPHA, 0, limit=3)
check("in pages, saying there is more", len(got) == 3 and more)
everything = {g[0] for g in got}
while more:
    got, rev, more = st.threats_since(ALPHA, rev, limit=3)
    everything |= {g[0] for g in got}
check("...until they have it all, nothing skipped",
      everything >= {f"{i:x}" * 64 for i in range(7)} | {A, C})
check("...each as [fingerprint, verdict, name, severity]",
      all(len(g) == 4 for g in st.threats_since(ALPHA, 0)[0]))
check("a nonsense starting point starts from the beginning",
      st.threats_since(ALPHA, "junk")[0] == st.threats_since(ALPHA, 0)[0])
check("a PC asking from past the newest change (the list was restored or "
      "started over) is sent everything again, not left waiting forever",
      st.threats_since(ALPHA, 10 ** 9)[0] == st.threats_since(ALPHA, 0)[0])

print("\nThe MalwareBazaar feed")
CSV = '''################################################################
# MalwareBazaar recent malware samples (CSV)                   #
################################################################
#
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-10-29 10:00:00", "%s", "m", "s", "r", "x.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "n/a", "", "", ""
"2026-10-29 10:01:00", "%s", "m", "s", "r", "y.dll", "dll", "application/x-dosexec", "n/a", "n/a", "n/a", "", "", ""
"2026-10-29 10:02:00", "%s", "m", "s", "r", "z.exe", "exe", "application/x-dosexec", "Formbook", "n/a", "n/a", "", "", ""
''' % ("7" * 64, "8" * 64, A)
parsed = edr.parse_feed_csv(CSV)
check("its CSV is read by its own header, named by malware family",
      parsed[:2] == [("7" * 64, "MalwareBazaar: AgentTesla"),
                     ("8" * 64, "MalwareBazaar: dll sample")])
check("...and a file without the header still gives its fingerprints",
      [p[0] for p in edr.parse_feed_csv('"x", "%s"\n' % E)] == [E])


class Settings:
    def __init__(self, **kw):
        self.values = kw

    def get_setting(self, k):
        return self.values.get(k)


calls = []


def fetch(status, body):
    def f(url):
        calls.append(url)
        return status, body
    return f


ok, msg = edr.run_feed(st, Settings(), now=T0)
check("no key: the feed is off, and nothing is fetched",
      not ok and "No abuse.ch key" in msg and calls == [])
keyed = Settings(**{edr.SETTING_FEED_KEY: "k3y"})
ok, msg = edr.run_feed(st, keyed, now=T0 + 100,
                       fetch=fetch(401, b"unauthorized"))
check("a key abuse.ch refuses is said so, on the page too",
      not ok and "did not accept the key" in msg
      and "did not accept" in st.meta("feed_error"))
check("...fetched from the address with the key in it",
      calls[-1].endswith("/exports/k3y/recent.csv"))
zipped = io.BytesIO()
with zipfile.ZipFile(zipped, "w") as z:
    z.writestr("recent.csv", CSV)
ok, msg = edr.run_feed(st, keyed, now=T0 + 200,
                       fetch=fetch(200, zipped.getvalue()))
check("a good import adds the new ones for every PC, zipped or not",
      ok and st.threat("7" * 64)["org_id"] is None
      and st.threat("7" * 64)["source"] == "feed"
      and "2 new fingerprints" in msg)
check("...but never over the support team's 'safe'",
      st.threat(A)["verdict"] == "safe")
check("...and the page shows how it went",
      st.meta("feed_error") == "" and st.meta("feed_added") == "2")
ok, msg = edr.run_feed(st, keyed, now=T0 + 300,
                       fetch=fetch(200, CSV.encode()))
check("the next import adds only what is new", ok and "0 new" in msg)
check("due again 6 hours after a good import, an hour after a failed one",
      not edr.feed_due(st, T0 + 300 + 3600)
      and edr.feed_due(st, T0 + 300 + 6 * 3600))
st.set_meta(feed_tried=T0 + 50000)
check("...", not edr.feed_due(st, T0 + 50000 + 1800)
      and edr.feed_due(st, T0 + 50000 + 3700))
st.set_verdict("8" * 64, "malicious", "boss@platform.test", now=T0 + 400)
later = T0 + 200 + 31 * 86400
expired = st.expire_feed(later)
check("after 30 days a feed sample comes off every PC's list...",
      expired == 1 and st.threat("7" * 64)["verdict"] == "removed"
      and items(st, BETA, rev)[0].get("7" * 64) == "removed")
check("...unless a person decided about it",
      st.threat("8" * 64)["verdict"] == "malicious")
edr.run_feed(st, keyed, now=later + 1, fetch=fetch(200, CSV.encode()))
check("one that turns up again in the feed goes back on",
      st.threat("7" * 64)["verdict"] == "malicious")

check("...counting as freshly seen, so the same import does not age it "
      "straight off again", st.threat("7" * 64)["first_seen"] == later + 1)
ok, msg = edr.run_feed(st, keyed, now=later + 2,
                       fetch=fetch(200, b"PK\x03\x04 not really a zip"))
check("a broken zip is a failed import, said on the page, not a crash",
      not ok and "broken zip" in msg and "broken zip" in st.meta("feed_error"))

print("\nA company that leaves")
F = "f" * 64
st.record(ALPHA, ev(sha=E), now=T0 + 500)
st.record(ALPHA, ev(sha=F), now=T0 + 501)
st.record(BETA, ev(sha=F, agent="beta-pc"), now=T0 + 502)
_, caught_up, _ = st.threats_since(BETA, 0)
st.purge_org(ALPHA)
check("its unconfirmed finds go with it; shared ones stay",
      st.threat(E) is None and st.threat(C) is not None)
check("...and one another company also found stays blocked there",
      st.threat(F) is not None and st.threat(F)["org_id"] == BETA
      and items(st, BETA)[0].get(F) == "malicious"
      and F not in items(st, GAMMA)[0])
st.set_verdict("9" * 64, "malicious", "boss", now=T0 + 600)
check("the next change still reaches agents that had caught up: a deleted "
      "entry's change number is never handed out again",
      "9" * 64 in items(st, BETA, caught_up)[0])

print("\nOver HTTP")
web_dir = os.path.join(tmp, "web")
os.makedirs(web_dir)
mdb, sfile, adb, ddb = (os.path.join(web_dir, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
auth.signup("boss@platform.test", "secret123", "Platform")
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha IT")
beta = auth.signup("owner@beta.test", "secret123", "Beta Shop")
DevicesStore(ddb).close()
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
store = edr.EdrStore(edr.edr_path(ddb))
akey, bkey = store.new_key(alpha), store.new_key(beta)


def api(path, key=None, data=None):
    h = {"Authorization": f"Bearer {key}"} if key else {}
    if data is not None:
        h["Content-Type"] = "application/json"
    rq = urllib.request.Request(BASE + path, headers=h,
                                data=json.dumps(data).encode()
                                if data is not None else None)
    try:
        with urllib.request.urlopen(rq, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(email):
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(
        {"email": email, "password": "secret123"}).encode()), timeout=15)
    return op


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    check("an agent without a key gets nothing",
          api("/api/v1/edr/threats")[0] == 401
          and api("/api/v1/edr/threats", "emk_nope")[0] == 401)
    code, out = api("/api/v1/edr/threats", akey)
    check("with its company's key it gets the list (empty so far)",
          code == 200 and out["items"] == [] and out["more"] is False)
    code, _ = api("/api/v1/edr/alerts", akey, {
        "agent_id": "p1", "hostname": "RECEPTION", "event_type":
        "FILE_QUARANTINED", "severity": "HIGH", "sha256": B,
        "reason": "YARA rule match (Reverse_Shell)", "target": "C:\\x.exe"})
    code, out = api("/api/v1/edr/threats", akey)
    check("a find reported by one of its PCs is on its list next look",
          [i[:2] for i in out["items"]] == [[B, "malicious"]])
    code, out_b = api("/api/v1/edr/threats", bkey)
    check("...and not yet on another company's", out_b["items"] == [])
    code, again = api(f"/api/v1/edr/threats?since={out['rev']}", akey)
    check("asking from where it got to brings nothing new",
          again["items"] == [])

    boss, owner = login("boss@platform.test"), login("owner@alpha.test")
    _, page = req(boss, "/superadmin/antivirus")
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("the page shows the list, the find waiting for a decision, and "
          "where it was found", "Threat list" in page
          and "Waiting for a decision" in page and "Alpha IT" in page
          and B[:16] in page)
    check("...with Block everywhere and Safe on the alert itself",
          page.count('name="sha256" value="%s"' % B) >= 2
          and "Blocked at Alpha IT" in page)
    check("...and the feed, off until a key is saved",
          "MalwareBazaar feed" in page and "auth.abuse.ch" in page)
    st_, _ = req(owner, "/superadmin/antivirus/threat",
                 {"csrf": token, "sha256": B, "action": "block"})
    check("a company owner cannot decide for everyone", st_ in (400, 403))
    st_, _ = req(boss, "/superadmin/antivirus/threat",
                 {"csrf": "wrong", "sha256": B, "action": "block"})
    check("nor can a forged form", st_ == 400)
    st_, page = req(boss, "/superadmin/antivirus/threat",
                    {"csrf": token, "sha256": B, "action": "block"})
    code, out_b = api("/api/v1/edr/threats", bkey)
    check("Block everywhere puts it on every company's list",
          "blocked on every PC" in page
          and [i[:2] for i in out_b["items"]] == [[B, "malicious"]])
    st_, page = req(boss, "/superadmin/antivirus/threat",
                    {"csrf": token, "sha256": B, "action": "safe"})
    code, out_b2 = api(f"/api/v1/edr/threats?since={out_b['rev']}", bkey)
    check("Safe goes out the same way",
          "marked safe" in page and out_b2["items"][0][1] == "safe")
    st_, page = req(boss, "/superadmin/antivirus/threat",
                    {"csrf": token, "sha256": "short", "action": "add"})
    check("a fingerprint typed wrong is refused, saying what one looks like",
          "SHA-256" in page)

    real_fetch = edr.fetch_feed
    edr.fetch_feed = lambda key, fetch=None: CSV
    try:
        st_, page = req(boss, "/superadmin/antivirus/feed",
                        {"csrf": token, "action": "save", "key": "abc123"})
    finally:
        edr.fetch_feed = real_fetch
    check("saving the abuse.ch key imports straight away, and says so",
          "new fingerprint" in page and "On. Last import" in page
          and auth.get_setting(edr.SETTING_FEED_KEY) == "abc123")
    check("...the key itself never shown again",
          "abc123" not in page and "Key saved" in page)
    code, out = api("/api/v1/edr/threats", bkey)
    check("...and its samples reach every company's PCs",
          "7" * 64 in {i[0] for i in out["items"]})
    st_, page = req(boss, "/superadmin/antivirus/feed",
                    {"csrf": token, "action": "clear"})
    check("the feed can be switched off again",
          not auth.get_setting(edr.SETTING_FEED_KEY) and "feed is off" in page)
    st_, page = req(boss, "/superadmin/antivirus/feed",
                    {"csrf": token, "action": "bogus"})
    check("an action the form never sends is refused, not taken as Import",
          "Unknown action" in page)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL THREAT LIST TESTS PASSED")
