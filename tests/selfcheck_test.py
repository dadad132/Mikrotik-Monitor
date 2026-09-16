"""The server self-check: catch the silent failures, and stay quiet otherwise.

Every serious fault this system has had was silent. A reload unit that failed
on every trigger while nothing asked. A peers file the kernel had lost half
of. A service reporting success because its last command was a `while` loop.
None needed cleverness to find -- they needed something to look.

The risk with a health panel is the opposite one: a page of green ticks and
vague warnings that trains people to skip it. So these tests are as much
about what it does NOT say.

Run:  ./.venv/Scripts/python.exe tests/selfcheck_test.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.selfcheck as sc
import mikromon.web_auth as wa

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def one(findings, cid):
    return next((f for f in findings if f["id"] == cid), None)


d = tempfile.mkdtemp()

print("\nA failing reload unit is the thing this exists to catch")

_real_run, _real_state = sc._run, sc._unit_state
try:
    sc._unit_state = lambda u: "failed"
    sc._run = lambda cmd, timeout=6: (
        1, "No module named mikromon", "") if "status" in cmd else (1, "", "")
    f = sc.check_units()
    bad = [x for x in f if not x["ok"]]
    check("a unit in the failed state is reported, not passed over -- a "
          "oneshot that fails on every trigger looks exactly like one that "
          "finished, unless something asks",
          len(bad) == 2)
    check("...naming which capability is dead, not just the unit",
          any("Remote access" in x["title"] for x in bad))
    check("...carrying what systemd actually said",
          any("No module named mikromon" in x["detail"] for x in bad))
    check("...and the command to look further",
          all("systemctl status" in x["fix"] for x in bad))

    sc._unit_state = lambda u: "active"
    check("a healthy unit passes quietly",
          all(x["ok"] for x in sc.check_units()))

    sc._unit_state = lambda u: ""
    check("on a host with no systemd it says NOTHING rather than inventing "
          "failures -- a check that cannot run must not report a problem",
          sc.check_units() == [])
finally:
    sc._run, sc._unit_state = _real_run, _real_state

print("\nReading what WireGuard is really doing")

try:
    sc._run = lambda cmd, timeout=6: (0, "", "") if "sudo" not in cmd else (1, "", "")
    check("readable directly is fine", sc.check_wg_readable()[0]["ok"])

    sc._run = lambda cmd, timeout=6: (0, "", "") if "sudo" in cmd else (1, "", "")
    check("readable only via sudo is also fine -- that is how it is meant to "
          "be set up", sc.check_wg_readable()[0]["ok"])

    sc._run = lambda cmd, timeout=6: (1, "", "Operation not permitted")
    f = sc.check_wg_readable()[0]
    check("unreadable is a real finding: without it a wrong key and a "
          "blocked link look identical, which is what cost a week",
          not f["ok"] and "sudoers.d/mikromon-wg" in f["fix"])

    sc._run = lambda cmd, timeout=6: (None, "", "not installed")
    check("wireguard-tools missing says so plainly",
          "not installed" in sc.check_wg_readable()[0]["title"])
finally:
    sc._run = _real_run

print("\nThe peers file")

p = os.path.join(d, "wg-peers.conf")
open(p, "w").write("[Peer]\nPublicKey = A=\nAllowedIPs = 10.10.0.2/32\n")
check("a file with peers in it passes, and says how many",
      one(sc.check_peers_file(p, 1), "wg:file")["ok"])

open(p, "w").write("# generated, do not edit\n")
f = one(sc.check_peers_file(p, 23), "wg:file")
check("an EMPTY peers file while routers are registered is the loud one -- "
      "the hub discards every router until it is rewritten",
      not f["ok"] and "23 routers" in f["title"])
check("...and points at the one button that fixes it",
      "Reload hub peers" in f["fix"])
check("an empty file with NO routers registered is not a complaint",
      one(sc.check_peers_file(p, 0), "wg:file")["ok"])
check("a path that does not exist yet is silent, not a failure",
      sc.check_peers_file(os.path.join(d, "nope.conf"), 5) == [])

check("a writable directory means the file can be replaced atomically",
      one(sc.check_peers_dir(p), "wg:dir")["ok"])

print("\nThe address the links actually point at")

# Detection falls back to `hostname -I` when the public-IP lookup fails. On a
# NATed server that is 172.16.x.x: grants get created, nginx really listens,
# every tick stays green -- and the browser times out, because the address in
# the link exists only on the server's own LAN. Nothing in the system said so.
for bad in ("172.16.1.246", "10.0.0.5", "192.168.1.10", "127.0.0.1",
            "localhost", "169.254.1.1"):
    f = one(sc.check_access_host({"hub_host": bad}), "access:host")
    check(f"{bad} is called out as unreachable from anywhere else",
          f is not None and not f["ok"] and bad in f["title"])

f = one(sc.check_access_host({"hub_host": "172.16.1.246"}), "access:host")
check("...explaining that the port IS open and it is the address that is "
      "wrong, since 'connection timed out' reads like the opposite",
      "the address just does not reach it" in f["detail"])
check("...and naming the way to set it", "ACCESS_HOST=" in f["fix"])

for good in ("38.54.63.107", "easymikrotik.co.za", "hub.example.com"):
    check(f"{good} is fine and says where links point",
          one(sc.check_access_host({"hub_host": good}), "access:host")["ok"])

check("nothing configured means nothing to say",
      sc.check_access_host({}) == [] and sc.check_access_host(None) == [])

print("\nnginx: a check that cannot tell working from broken")

_rr = sc._run
try:
    # `nginx -t` reads the TLS key, which is root-only. Run as the web service
    # user it fails on a perfectly good config -- and then says "nginx refuses
    # its own configuration" in red, sending you after the wrong thing while
    # the real fault sits elsewhere. That happened, and cost a round trip.
    _denied = ("nginx: [emerg] cannot load certificate key ... "
               "Permission denied:calling fopen(...) "
               "nginx: configuration file /etc/nginx/nginx.conf test failed")

    def _fake(cmd, timeout=6):
        if cmd[0] == "nginx" and "-v" in cmd:
            return 0, "", "nginx/1.24"
        if cmd[:2] == ["sudo", "-n"]:
            return 1, "", _denied          # sudo not permitted either
        if "is-failed" in cmd or "is-active" in cmd:
            return 0, "active", ""
        return 1, "", _denied

    sc._run = _fake
    f = one(sc.check_nginx({"nginx_http_conf": "/etc/nginx/x.conf"}),
            "nginx:conf")
    check("a permission error reading the key is NOT reported as a broken "
          "nginx config -- it is reported as a check that could not run",
          f["ok"] and f["warn"])
    check("...and carries the sudoers line that would let it run",
          "sudoers.d/mikromon-nginx" in f["fix"])

    def _sudo_works(cmd, timeout=6):
        if cmd[0] == "nginx" and "-v" in cmd:
            return 0, "", "nginx/1.24"
        if cmd[:2] == ["sudo", "-n"]:
            return 0, "syntax is ok", ""
        if "is-failed" in cmd or "is-active" in cmd:
            return 0, "active", ""
        return 1, "", _denied

    sc._run = _sudo_works
    check("when sudo IS permitted the config is really tested, and passes",
          one(sc.check_nginx({"nginx_http_conf": "/x"}), "nginx:running")["ok"])

    def _really_broken(cmd, timeout=6):
        if cmd[0] == "nginx" and "-v" in cmd:
            return 0, "", "nginx/1.24"
        if "is-failed" in cmd or "is-active" in cmd:
            return 0, "active", ""
        return 1, "", "nginx: [emerg] unknown directive \"proxy_passs\""

    sc._run = _really_broken
    f = one(sc.check_nginx({"nginx_http_conf": "/x"}), "nginx:conf")
    check("a genuinely bad config is still reported, loudly -- softening the "
          "permission case must not soften this one",
          not f["ok"] and "proxy_passs" in f["detail"])
finally:
    sc._run = _rr

print("\nRetention, which stopped running once and made every page slow")

mdb = os.path.join(d, "m.db")
con = sqlite3.connect(mdb)
con.execute("CREATE TABLE samples (ts REAL, device TEXT, metric TEXT,"
            " label TEXT, value REAL)")
con.execute("INSERT INTO samples VALUES (?,?,?,?,?)",
            (time.time() - 120 * 86400, "R", "cpu", "", 1.0))
con.commit()
con.close()
f = one(sc.check_retention(mdb, 30), "metrics:retention")
check("samples far outside the retention window are flagged -- this is what "
      "turned one dashboard read into 25 seconds",
      not f["ok"] and "120 days" in f["title"])
check("...as a warning, since nothing is broken, it is just growing",
      f["warn"])

con = sqlite3.connect(mdb)
con.execute("DELETE FROM samples")
con.execute("INSERT INTO samples VALUES (?,?,?,?,?)",
            (time.time() - 3600, "R", "cpu", "", 1.0))
con.commit()
con.close()
check("recent-only data passes",
      one(sc.check_retention(mdb, 30), "metrics:retention")["ok"])
check("no metrics database at all is silent",
      sc.check_retention(os.path.join(d, "none.db"), 30) == [])

print("\nEmail, because an alert nobody receives is not an alert")

check("configured passes", sc.check_smtp({"host": "smtp.x"})[0]["ok"])
check("unconfigured warns rather than fails -- the fleet still works",
      not sc.check_smtp({})[0]["ok"] and sc.check_smtp({})[0]["warn"])
check("an SmtpConfig object is read the same as a settings dict",
      sc.check_smtp(types.SimpleNamespace(host="h"))[0]["ok"])

print("\nnginx is only this server's business when remote access is set up")

check("no remote access configured means nothing is said about nginx",
      sc.check_nginx({}) == [] and sc.check_nginx(None) == [])

print("\nOne broken check never stops the rest")

_broken = sc.check_units
try:
    sc.check_units = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    out = sc.run_all(peers_path=p, expected_peers=0, access_cfg={},
                     metrics_db=mdb, smtp_cfg={"host": "x"})
    check("a check that raises becomes a finding rather than an empty panel",
          any(x["id"] == "selfcheck:error" for x in out))
    check("...and the other checks still ran",
          any(x["id"].startswith("metrics") for x in out))
finally:
    sc.check_units = _broken

print("\nWhich commit is actually running")

# `git pull` updates the checkout. The service runs an rsynced COPY of it.
# So a pull alone changes nothing that runs, and the only symptom is a fix
# that appears not to have worked -- which has burnt real days here, with
# everyone reasonably concluding the fix itself was wrong.
vd = tempfile.mkdtemp()
f = one(sc.check_deployed_version(vd), "version")
check("with no VERSION file it asks for one rather than claiming a problem "
      "-- nothing is broken, we simply cannot answer the question",
      f["ok"] and f["warn"] and "install.sh" in f["fix"])

open(os.path.join(vd, "VERSION"), "w").write(
    "abc1234\n2026-09-16T08:00:00+02:00\n")
f = one(sc.check_deployed_version(vd), "version")
check("with one, the panel names the running commit, so \"is my fix even "
      "deployed\" is answerable at a glance",
      f["ok"] and "abc1234" in f["title"])
check("...and when it was deployed", "2026-09-16" in f["detail"])

_rr = sc._run
try:
    sc._run = lambda cmd, timeout=6: (0, "def5678", "")
    f = one(sc.check_deployed_version(vd), "version")
    check("a checkout that has moved PAST the running code is the finding "
          "that matters: the pull happened, the install did not",
          not f["ok"] and "abc1234" in f["title"] and "def5678" in f["title"])
    check("...and says which command deploys it", "install.sh" in f["fix"])

    sc._run = lambda cmd, timeout=6: (0, "abc1234", "")
    check("a checkout sitting at the same commit is not a complaint",
          one(sc.check_deployed_version(vd), "version")["ok"])

    sc._run = lambda cmd, timeout=6: (128, "", "not a git repository")
    check("the app directory is normally not a checkout at all, and that is "
          "the ordinary case rather than an error",
          one(sc.check_deployed_version(vd), "version")["ok"])
finally:
    sc._run = _rr

check("the question is asked by run_all, not left for somebody to remember",
      any(x["id"] == "version"
          for x in sc.run_all(app_dir=vd, smtp_cfg={"host": "x"})))

print("\nThe certificate, which nobody is warned about any more")

# Let's Encrypt stopped sending expiry emails, and certificates last 90 days.
# If this server does not look, nothing looks -- and the first sign is every
# browser refusing the site on the same morning.
_rr, _rcert = sc._run, sc._cert_days_left
try:
    sc._cert_paths = lambda cfg: ["/etc/letsencrypt/live/x.co.za/fullchain.pem"]

    sc._cert_days_left = lambda p: 60.0
    f = one(sc.check_tls_expiry({}), "tls:/etc/letsencrypt/live/x.co.za/fullchain.pem")
    check("a certificate with months left passes quietly, naming the days",
          f["ok"] and "60" in f["title"])

    sc._cert_days_left = lambda p: 14.0
    f = sc.check_tls_expiry({})[0]
    check("two weeks out is a WARNING, not a failure: renewal happens at 30 "
          "days, so something has already stopped working",
          not f["ok"] and f["warn"] and "x.co.za" in f["title"])

    sc._cert_days_left = lambda p: 3.0
    f = sc.check_tls_expiry({})[0]
    check("three days out stops being a warning -- it will not fix itself "
          "now", not f["ok"] and not f["warn"])
    check("...and says so, rather than leaving the reader to infer it",
          "not going to happen on its own" in f["detail"])

    sc._cert_days_left = lambda p: -2.0
    f = sc.check_tls_expiry({})[0]
    check("an already-expired certificate says browsers are refusing the "
          "site NOW, in the present tense",
          not f["ok"] and "EXPIRED" in f["title"]
          and "refusing this site now" in f["detail"])

    sc._cert_days_left = lambda p: None
    f = sc.check_tls_expiry({})[0]
    check("a certificate that cannot be read is reported as unread, not as "
          "fine and not as expired", not f["ok"] and "Cannot read" in f["title"])
finally:
    sc._run, sc._cert_days_left = _rr, _rcert
    del sc._cert_paths

print("\nWhether anything will renew it")

_rs = sc._unit_state
try:
    sc._run = lambda cmd, timeout=6: (0, "certbot 2.9", "")
    sc._unit_state = lambda u: "active" if u == "certbot.timer" else ""
    check("an armed timer passes and names it",
          sc.check_cert_renewal()[0]["ok"])

    sc._unit_state = lambda u: ("active" if u == "snap.certbot.renew.timer"
                                else "inactive")
    check("the snap timer counts too -- certbot installs both ways and only "
          "one of them is called certbot.timer",
          sc.check_cert_renewal()[0]["ok"])

    sc._unit_state = lambda u: "inactive"
    f = sc.check_cert_renewal()[0]
    check("no timer at all is a real finding: the installer used to PRINT "
          "that renewal was handled without anything having checked",
          not f["ok"] and "Nothing is scheduled" in f["title"])
    check("...and gives the one command that arms it",
          "enable --now certbot.timer" in f["fix"])

    sc._run = lambda cmd, timeout=6: (None, "", "not installed")
    check("a server without certbot says nothing -- it may not use "
          "Let's Encrypt at all", sc.check_cert_renewal() == [])
finally:
    sc._run, sc._unit_state = _rr, _rs

print("\nAre the Zoho credentials actually on THIS server?")

zd = tempfile.mkdtemp()
check("no credentials anywhere is not a fault -- it is a feature nobody has "
      "switched on", sc.check_zoho(zd) == [])

f = one(sc.check_zoho("", {"refresh_token": "rt", "organization_name": "EasyMikrotik",
                           "accounts_host": "accounts.zoho.eu"}), "zoho")
check("settings holding a refresh token pass, naming the organisation",
      f["ok"] and "EasyMikrotik" in f["title"])

open(os.path.join(zd, "zoho-oauth.json"), "w").write(
    '{"refresh_token": "rt", "organization_name": "EasyMikrotik"}')
check("credentials written by the setup tool are found on disk, so work done "
      "on the server shows up on the dashboard instead of looking like it "
      "never happened", one(sc.check_zoho(zd), "zoho")["ok"])

open(os.path.join(zd, "zoho-oauth.json"), "w").write('{"client_id": "1000.x"}')
f = one(sc.check_zoho(zd), "zoho")
check("a half-finished setup -- client id but no refresh token -- is called "
      "out, because it looks identical to a finished one from the outside",
      not f["ok"] and "half set up" in f["title"])

open(os.path.join(zd, "zoho-oauth.json"), "w").write("{not json")
check("an unreadable credentials file is reported rather than skipped",
      not one(sc.check_zoho(zd), "zoho")["ok"])

print("\nWhat the panel shows")

_mixed = [sc._finding("fine", True, "fine"),
          sc._finding("warn", False, "warn", warn=True),
          sc._finding("bad", False, "bad")]
_sorted = sorted(_mixed, key=lambda f: (f["ok"], f["warn"]))
check("broken sorts above warnings, which sort above what is fine -- the "
      "order somebody scans in when they came here because something broke",
      [f["id"] for f in _sorted] == ["bad", "warn", "fine"])

html = wa._selfcheck_box([
    sc._finding("a", False, "Something is broken", "why", "the fix"),
    sc._finding("b", False, "Something to watch", "", "", warn=True),
    sc._finding("c", True, "Something fine")])
check("the count says how many need FIXING, not how many checks ran",
      "1 thing needs fixing" in html)
check("what passed is folded away -- a page that opens on twelve green "
      "ticks is a page people stop reading",
      "<details" in html and "1 check(s) passed" in html)
check("an all-clear says so in one line", "Nothing is wrong"
      in wa._selfcheck_box([sc._finding("x", True, "fine")]))
check("nothing to report renders nothing at all",
      wa._selfcheck_box([]) == "")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SELF-CHECK TESTS PASSED")
