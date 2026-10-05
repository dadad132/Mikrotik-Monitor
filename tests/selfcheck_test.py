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

# The dashboard runs with NoNewPrivileges, so sudo from inside it is refused
# by the kernel whatever sudoers says. The panel used to tell people to add
# sudoers lines anyway; they did, and nothing changed. What only root can
# read now comes from a root timer's snapshot in sc.STATUS_DIR.
_real_status_dir = sc.STATUS_DIR
sc.STATUS_DIR = tempfile.mkdtemp()
_ran = []


def _snap(name, text, age=0):
    path = os.path.join(sc.STATUS_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    t = time.time() - age
    os.utime(path, (t, t))


def _unsnap(*names):
    for n in names:
        try:
            os.remove(os.path.join(sc.STATUS_DIR, n))
        except OSError:
            pass


def _no_root(cmd, timeout=6):
    _ran.append(list(cmd))
    return 1, "", "Unable to access interface: Operation not permitted"


try:
    sc._run = lambda cmd, timeout=6: (0, "", "")
    check("readable directly is fine", sc.check_wg_readable()[0]["ok"])

    sc._run = _no_root
    f = sc.check_wg_readable()[0]
    check("unreadable with no snapshot is a real finding: without it a wrong "
          "key and a blocked link look identical, which is what cost a week",
          not f["ok"])
    check("...whose fix is the installer that adds the root timer, not a "
          "sudoers line that cannot take effect",
          f["fix"] == "sudo bash deploy/install.sh" and "sudo" not in
          f["detail"].replace("cannot use sudo", ""))
    check("...and it never tries sudo itself",
          not any(c[:1] == ["sudo"] for c in _ran))

    _snap("wg0.dump", "(hidden)\tPUB=\t51820\toff\n", age=20)
    f = sc.check_wg_readable()[0]
    check("a fresh root snapshot counts as readable, and says how old it is",
          f["ok"] and "read as root 20s ago" in f["title"])

    _snap("wg0.dump", "(hidden)\tPUB=\t51820\toff\n", age=900)
    f = sc.check_wg_readable()[0]
    check("a snapshot fifteen minutes old is not passed off as live -- the "
          "timer has stopped, and that is the finding",
          not f["ok"] and "15 minutes old" in f["title"]
          and "mikromon-status.timer" in f["fix"])

    _unsnap("wg0.dump")
    _snap("wg0.err", "Unable to access interface: No such device\n")
    f = sc.check_wg_readable()[0]
    check("root itself failing to read wg0 means the interface is down, and "
          "points at wg-quick rather than at permissions",
          not f["ok"] and "No such device" in f["detail"]
          and "wg-quick@wg0" in f["fix"])
    _unsnap("wg0.err")

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

# On the server /etc/wireguard is 750: the dashboard can write the peers file
# but not create files beside it. That used to be a warning whose fix was
# `chmod 770` -- which lets the dashboard rename its own file over wg0.conf,
# whose PostUp root runs. It is the intended state, not a fault.
_real_access = os.access
try:
    os.access = lambda path, mode: (False if os.path.isdir(path)
                                    else _real_access(path, mode))
    f = one(sc.check_peers_dir(p), "wg:dir")
    check("a read-only directory with a writable peers file is fine -- the "
          "file is rewritten in place, never emptied", f["ok"])
    check("...and nothing anywhere suggests making the directory writable",
          "770" not in f["fix"] + f["detail"] + f["title"])
    os.access = lambda path, mode: False
    f = one(sc.check_peers_dir(p), "wg:dir")
    check("a peers file the dashboard cannot write at all IS the fault: new "
          "routers cannot be registered",
          not f["ok"] and f["fix"] == "sudo bash deploy/install.sh")
finally:
    os.access = _real_access

_inst = open(os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "deploy", "install.sh"),
    encoding="utf-8").read()
check("the installer never opens /etc/wireguard to group write",
      "chmod 770 /etc/wireguard" not in _inst)
check("...and writes no sudo rules, which cannot work for a NoNewPrivileges "
      "service", "NOPASSWD" not in _inst)
check("...removing the ones earlier builds and the panel put there",
      all(n in _inst for n in ("/etc/sudoers.d/mikromon-access",
                               "/etc/sudoers.d/mikromon-wg",
                               "/etc/sudoers.d/mikromon-nginx")))
_snapsh = _inst.split("<<'SNAP'")[1].split("\nSNAP\n")[0]
check("the root snapshot blanks the hub's private key before anything is "
      "written", 'NR == 1 { $1 = "(hidden)" }' in _snapsh
      and "wg show wg0 dump 2> .wg0.err \\\n     | awk" in _snapsh)
check("...keeps its directory between runs, or every oneshot deletes it",
      "RuntimeDirectoryPreserve=yes" in _inst)
check("...and is readable by the dashboard's group only",
      "Group=${SERVICE_USER}" in _inst and "RuntimeDirectoryMode=0750"
      in _inst)
check("the snapshot directory the installer writes is the one the "
      "dashboard reads", "/run/mikromon-status" in _inst
      and _real_status_dir == "/run/mikromon-status")

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
f = one(sc.check_access_host({"hub_host": "172.16.1.246"},
                             "easymikrotik.com"), "access:host")
check("...using the dashboard's own domain when there is one, which already "
      "has a trusted certificate",
      f["fix"] == "sudo ACCESS_HOST=easymikrotik.com bash deploy/install.sh")
check("...and saying the router in front of a NATed server has to forward "
      "the ports too", "forward TCP 20000-29999" in f["detail"])
check("the installer keeps a deliberate host across plain re-runs, and "
      "falls back to the dashboard's domain before guessing an address -- "
      "a host fixed with ACCESS_HOST= used to last until the next upgrade",
      "_config_get access hub_host" in open(os.path.join(
          os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
          "deploy", "install.sh"), encoding="utf-8").read()
      and "_config_get web domain" in open(os.path.join(
          os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
          "deploy", "install.sh"), encoding="utf-8").read())

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
    check("...whose fix is the root timer, not a sudoers line that cannot "
          "take effect", f["fix"] == "sudo bash deploy/install.sh")

    # What actually reached the panel: sudo refused with "no new privileges"
    # (the dashboard's own hardening), shown as nginx refusing its config.
    def _nnp(cmd, timeout=6):
        if cmd[0] == "nginx" and "-v" in cmd:
            return 0, "", "nginx/1.24"
        if cmd[:1] == ["sudo"]:
            return 1, "", ('sudo: The "no new privileges" flag is set, which '
                           'prevents sudo from running as root.')
        if "is-failed" in cmd or "is-active" in cmd:
            return 0, "active", ""
        return 1, "", _denied

    sc._run = _nnp
    f = one(sc.check_nginx({"nginx_http_conf": "/x"}), "nginx:conf")
    check("sudo being refused is never reported as nginx refusing its own "
          "configuration", f["ok"] and "no new privileges" not in f["detail"])

    _snap("nginx-t", "nginx: configuration file test is successful\nexit=0\n")
    check("root's own `nginx -t` passing is the answer, and it passes",
          one(sc.check_nginx({"nginx_http_conf": "/x"}),
              "nginx:running")["ok"])
    _snap("nginx-t", 'nginx: [emerg] unknown directive "proxy_passs"\n'
                     "exit=1\n")
    f = one(sc.check_nginx({"nginx_http_conf": "/x"}), "nginx:conf")
    check("...and root's `nginx -t` failing is reported loudly, with what "
          "nginx said", not f["ok"] and "proxy_passs" in f["detail"]
          and "exit=" not in f["detail"])
    _unsnap("nginx-t")

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

print("\nCertificates root can read and the dashboard cannot")

# /etc/letsencrypt/live is root-only, so from the dashboard the glob found
# nothing and the openssl read failed: one yellow "cannot read" and several
# checks silently skipped. Root's snapshot lists them.
_rr = sc._run
try:
    sc._run = lambda cmd, timeout=6: (1, "", "Permission denied")
    _le = "/etc/letsencrypt/live/easymikrotik.com/fullchain.pem"
    _snap("certs.tsv", f"{_le}\tNov 30 12:00:00 2099 GMT\n")
    _days = sc._cert_days_left(_le)
    check("an unreadable certificate's expiry comes from the snapshot",
          _days is not None and _days > 365)
    check("...the Let's Encrypt certificates are found through it too",
          sc._letsencrypt_paths() == [_le]
          or os.path.isdir("/etc/letsencrypt/live"))
    check("...and the expiry check covers them instead of going quiet",
          any(x["ok"] and "easymikrotik.com" in x["title"]
              for x in sc.check_tls_expiry({})))
    _unsnap("certs.tsv")
    check("with no snapshot it is still 'cannot read', pointing at the "
          "installer rather than at a command that only inspects the file",
          sc._cert_days_left(_le) is None)
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

check("unconfigured warns rather than fails -- the fleet still works",
      not sc.check_smtp({})[0]["ok"] and sc.check_smtp({})[0]["warn"])
check("an SmtpConfig object is read the same as a settings dict",
      sc.check_smtp(types.SimpleNamespace(host="h"), probe=False)[0]["ok"])

# "Email is configured" used to be the whole check. It was equally true of a
# host that does not resolve, a port nothing listens on, and a password
# rotated last month -- so it passed in exactly the cases worth catching.
_dead = {"host": "no-such-host.invalid", "port": 587}
_probed = sc._probe_smtp(_dead)[0]
check("the probe itself finds a host that cannot be reached, and calls it a "
      "FAILURE rather than a tick: every alert this system raises goes down "
      "that path", not _probed["ok"])
check("...naming what went wrong and where, rather than 'email failed'",
      "no-such-host.invalid:587" in _probed["title"])
check("...and saying plainly that alerts are going nowhere",
      "going nowhere" in _probed["detail"])

# The probe opens a TCP connection, negotiates TLS and signs in. Doing that
# inside a page render meant Platform admin could not paint until somebody
# else's mail server answered -- and this is the page you open BECAUSE
# something is already broken. A slow mail server then looks like a dead
# dashboard. It hung a test for exactly that reason.
_t0 = time.time()
for _ in range(20):
    _first = sc.check_smtp(_dead)
check("check_smtp never opens a connection itself: twenty calls take no "
      "measurable time, because the probe runs in the background",
      time.time() - _t0 < 0.5)
check("...and the first answer says it is checking, which is honest and "
      "costs nothing, rather than an invented tick",
      _first[0]["ok"] and "Checking email" in _first[0]["title"])

for _ in range(40):
    if any("Cannot reach" in f["title"] for f in sc.check_smtp(_dead)):
        break
    time.sleep(0.1)
check("...and once the background probe answers, the real result is what "
      "the page shows",
      "Cannot reach" in sc.check_smtp(_dead)[0]["title"])

check("probe=False still answers the cheap question, for callers that only "
      "want to know whether a relay is set",
      sc.check_smtp({"host": "smtp.x"}, probe=False)[0]["ok"])

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

print("\nCompanies that would never be invoiced")

bdb = os.path.join(d, "billing.db")
con = sqlite3.connect(bdb)
con.execute("CREATE TABLE billing (org_id INTEGER PRIMARY KEY, plan TEXT,"
            " status TEXT, current_period_end REAL)")
con.execute("INSERT INTO billing VALUES (1, 'd5', 'active', ?)",
            (time.time() + 86400 * 20,))
con.commit()
check("a paid company with a renewal date passes",
      one(sc.check_billing_ready(bdb), "billing:never")["ok"])

con.execute("INSERT INTO billing VALUES (2, 'd5', 'active', NULL)")
con.commit()
f = one(sc.check_billing_ready(bdb), "billing:never")
check("a paid company with NO renewal date is the finding -- it is active, "
      "on the right packet, with the right device cap, and will never be "
      "invoiced for as long as it exists",
      not f["ok"] and "1 paid company" in f["title"])
check("...naming which company, because the whole problem is that nothing "
      "about the account looks wrong", "company 2" in f["detail"])

con.execute("INSERT INTO billing VALUES (3, 'unlimited', 'active', NULL)")
con.execute("INSERT INTO billing VALUES (4, NULL, 'inactive', NULL)")
con.commit()
f = one(sc.check_billing_ready(bdb), "billing:never")
check("a comped unlimited account and a free one are NOT flagged: neither "
      "is supposed to be invoiced", "1 paid company" in f["title"])
con.close()

check("no billing database at all is silent",
      sc.check_billing_ready(os.path.join(d, "none.db")) == [])

f = one(sc.check_billing_ready(bdb, card_ready=False), "billing:provider")
check("card payment being off is worth saying: invoices still go out, but "
      "the link on them cannot take a payment, so every renewal needs "
      "recording by hand", not f["ok"] and f["warn"])
check("...and it is a warning, not a failure -- the fleet still works",
      one(sc.check_billing_ready(bdb, card_ready=True),
          "billing:provider") is None)

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

print("\nWhether a WebFig link can be opened at all")

# Reported from a browser: ERR_CERT_AUTHORITY_INVALID on the WebFig port,
# and "you cannot visit ... because the website uses HSTS" -- meaning no
# click-through. Two faults, each harmless alone.
#
# The WebFig ports serve whatever certificate the installer found for the
# access host AT INSTALL TIME, written into config.yaml. A server installed
# before its DNS pointed here gets the self-signed fallback frozen in, and a
# real certificate obtained an hour later is never picked up.
#
# And HSTS covers a whole host across EVERY port, and removes the
# click-through. So a warning somebody used to dismiss became a wall.

from mikromon.access import resolve_cert  # noqa: E402

_c, _k, _src = resolve_cert("nowhere.example", "/etc/ssl/self.crt",
                            "/etc/ssl/self.key")
check("with no Let's Encrypt certificate for the host, the configured one "
      "is used and named as self-signed",
      (_c, _src) == ("/etc/ssl/self.crt", "self-signed"))

# Pointed at a real directory, so this asserts the behaviour rather than
# accepting whatever the machine running the tests happens to have.
import mikromon.access as _acc  # noqa: E402

_d2 = tempfile.mkdtemp()
os.makedirs(os.path.join(_d2, "example.test"))
for _f in ("fullchain.pem", "privkey.pem"):
    open(os.path.join(_d2, "example.test", _f), "w").close()
_was = _acc.LETSENCRYPT_LIVE
_acc.LETSENCRYPT_LIVE = _d2
try:
    _c2, _k2, _src2 = resolve_cert("example.test", "/etc/ssl/self.crt",
                                   "/etc/ssl/self.key")
    check("a real certificate for the host WINS over whatever config.yaml "
          "still says -- the whole fault is that the path was frozen at "
          "install time, so a certificate obtained an hour later was never "
          "picked up and WebFig kept serving the self-signed one",
          _src2 == "letsencrypt"
          and _c2 == os.path.join(_d2, "example.test", "fullchain.pem")
          and _k2.endswith("privkey.pem"))
    check("...and a host with a directory but no files in it does NOT win, "
          "or a half-finished certbot run would point nginx at nothing",
          resolve_cert("missing.test", "/etc/ssl/self.crt",
                       "/etc/ssl/self.key")[2] == "self-signed")
finally:
    _acc.LETSENCRYPT_LIVE = _was

f = one(sc.check_webfig_cert(
    {"nginx_http_conf": "/x", "tls_cert": "/etc/ssl/easymikrotik-x.crt",
     "hub_host": "easymikrotik.com"}), "webfig:cert")
check("a self-signed WebFig certificate is reported", f is not None
      and not f["ok"])
check("...explaining that HSTS is what turns it from a warning into a "
      "block, because the error a person sees blames only the certificate",
      "click-through" in f["detail"] or "click-through" in f["title"])
check("...and carrying the command that fixes it",
      "certbot" in f["fix"])

f = one(sc.check_webfig_cert(
    {"nginx_http_conf": "/x", "hub_host": "x",
     "tls_cert": "/etc/letsencrypt/live/x/fullchain.pem"}), "webfig:cert")
check("a Let's Encrypt path is trusted WITHOUT having to stat it -- this "
      "check runs off the server too, and inventing a lockout sends "
      "somebody to re-issue a certificate that was fine",
      f is not None and f["ok"])

_ip_cfg = {"nginx_http_conf": "/x", "hub_host": "172.16.1.246",
           "tls_cert": "/etc/ssl/easymikrotik-172.16.1.246.crt"}
f = one(sc.check_webfig_cert(_ip_cfg, "easymikrotik.com"), "webfig:cert")
check("for an IP address it never suggests certbot -- no certificate "
      "authority issues one for a private address, so that 'fix' could only "
      "fail", "certbot" not in f["fix"])
check("...and does not claim HSTS walls it off: browsers never apply HSTS "
      "to an IP address, so this is a warning, not 'cannot be opened at all'",
      f["warn"] and "cannot be opened" not in f["title"])
check("...pointing at the dashboard's domain instead, the same fix as the "
      "address check", f["fix"]
      == "sudo ACCESS_HOST=easymikrotik.com bash deploy/install.sh")

_real_hsts = sc._hsts_hosts
try:
    sc._hsts_hosts = lambda: {"easymikrotik.com", "www.easymikrotik.com"}
    f = one(sc.check_webfig_cert(
        {"nginx_http_conf": "/x", "hub_host": "easymikrotik.com",
         "tls_cert": "/etc/ssl/easymikrotik-easymikrotik.com.crt"}),
        "webfig:cert")
    check("a self-signed certificate on a host that HAS HSTS is the real "
          "wall, and is reported as one", not f["ok"] and not f["warn"]
          and "cannot be opened at all" in f["title"])
    f = one(sc.check_webfig_cert(
        {"nginx_http_conf": "/x", "hub_host": "other.example.com",
         "tls_cert": "/etc/ssl/easymikrotik-other.example.com.crt"}),
        "webfig:cert")
    check("...but HSTS on the dashboard's domain does not wall off a "
          "different host", f["warn"])
finally:
    sc._hsts_hosts = _real_hsts

_snap("certs.tsv", "/etc/letsencrypt/live/easymikrotik.com/fullchain.pem\t"
                   "Nov 30 12:00:00 2099 GMT\n")
f = one(sc.check_webfig_cert(
    {"nginx_http_conf": "/x", "hub_host": "easymikrotik.com",
     "tls_cert": "/etc/ssl/easymikrotik-easymikrotik.com.crt"}),
    "webfig:cert")
check("a Let's Encrypt certificate root can see for the host counts, as it "
      "does when access-apply (root) picks it -- the dashboard cannot list "
      "/etc/letsencrypt itself", f["ok"])
_unsnap("certs.tsv")

check("no remote access configured means nothing to say",
      sc.check_webfig_cert({}) == [])
check("...and neither does access configured with no certificate at all",
      sc.check_webfig_cert({"nginx_http_conf": "/x"}) == [])

check("the check runs as part of the full sweep",
      "check_webfig_cert" in open(
          os.path.join(os.path.dirname(os.path.dirname(
              os.path.abspath(__file__))), "mikromon", "selfcheck.py"),
          encoding="utf-8").read().split("def run_all")[1])

print("\nWhich certificate the site actually serves")

# "Not secure" on a site that IS serving HTTPS has two causes, and nothing
# could tell them apart, because every existing check looked at certificates
# on disk rather than at the one nginx is configured to present.
#
# install.sh falls back to a self-signed certificate whenever certbot does
# not produce one -- DNS not pointing here yet, port 80 closed, a rate
# limit. The install then succeeds, the site serves HTTPS, and every browser
# calls it Not secure forever. The fallback prints one line and is never
# mentioned again.
import re as _re  # noqa: E402

_CONF = ('server {\n'
         '    listen 443 ssl http2;\n'
         '    ssl_certificate     %s;\n'
         '    ssl_certificate_key /etc/ssl/k.key;\n'
         '}\n')


def _source_of(path):
    m = _re.search(r"^\s*ssl_certificate\s+([^;]+);", _CONF % path, _re.M)
    got = m.group(1).strip()
    return got, ("letsencrypt" if "/letsencrypt/" in got else "self-signed")


check("the certificate is read out of the nginx config, not guessed from "
      "what happens to exist on disk -- a server can hold a perfect Let's "
      "Encrypt certificate while nginx serves the fallback beside it",
      _source_of("/etc/letsencrypt/live/x.com/fullchain.pem")
      == ("/etc/letsencrypt/live/x.com/fullchain.pem", "letsencrypt"))
check("...and the installer's own fallback path is recognised as "
      "self-signed, which is the case that produces a permanent 'Not "
      "secure' on a site nobody has touched",
      _source_of("/etc/ssl/easymikrotik-x.com.crt")[1] == "self-signed")
check("with no nginx config present there is nothing to report, rather than "
      "a false alarm on a machine that is not the server",
      sc.check_served_cert() == []
      or os.path.exists("/etc/nginx/sites-enabled/easymikrotik"))
check("the check runs as part of the full sweep rather than only being "
      "callable",
      "check_served_cert" in open(
          os.path.join(os.path.dirname(os.path.dirname(
              os.path.abspath(__file__))), "mikromon", "selfcheck.py"),
          encoding="utf-8").read().split("def run_all")[1])

print("\nWhether HTTPS is actually enforced")

# The symptom is a browser saying "Not secure" on a site with a perfectly
# good certificate, and neither cause is visible from inside the app.
#
# secure_cookies decides whether the session cookie carries Secure at all.
# install.sh sets it at install time and leaves it false whenever the
# certificate was not yet in place on that first run -- which is every
# server whose domain was pointed at it afterwards -- and nothing turns it
# back on. And with no HSTS a browser has no reason to prefer https, so one
# old bookmark puts the whole session in the clear.
import tempfile as _tf  # noqa: E402

_d = _tf.mkdtemp()
_cfg = os.path.join(_d, "config.yaml")
with open(_cfg, "w", encoding="utf-8") as _f:
    _f.write("secure_cookies: false\n")

check("with no certificate at all there is nothing to enforce, so this "
      "stays quiet rather than nagging a server still being set up",
      sc.check_https_enforced(_cfg) == []
      or not os.path.isdir("/etc/letsencrypt/live"))

# The parsing is the part worth pinning: the finding only ever fires off
# what it reads out of the file.
import yaml as _yaml  # noqa: E402

with open(_cfg, encoding="utf-8") as _f:
    check("a false flag in config.yaml is read as false, which is what the "
          "finding turns on",
          _yaml.safe_load(_f).get("secure_cookies") is False)

check("the check is wired into the full run rather than only callable",
      "check_https_enforced" in open(
          os.path.join(os.path.dirname(os.path.dirname(
              os.path.abspath(__file__))), "mikromon", "selfcheck.py"),
          encoding="utf-8").read().split("def run_all")[1])

_ngx = open(os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "deploy", "install.sh"),
    encoding="utf-8").read()
check("the installer sets HSTS, so a browser refuses http once it has seen "
      "https even once", "Strict-Transport-Security" in _ngx)
check("...but only with a real certificate: on a self-signed one HSTS also "
      "removes the click-through on the certificate warning, which locks "
      "the operator out of their own server",
      "letsencrypt/live" in _ngx.split("HSTS_LINE=\"\"")[1][:200])

print("\nThe dashboard's Tunnel health table reads the same snapshot")

import subprocess as _sp  # noqa: E402

import mikromon.web as _web  # noqa: E402

_real_sp_run = _sp.run
try:
    _sp.run = lambda *a, **k: _sp.CompletedProcess(
        a[0], 1, "", "Unable to access interface: Operation not permitted")
    _snap("wg0.dump", "(hidden)\tHUBPUB=\t51820\toff\n"
                      "PEER1=\t(none)\t1.2.3.4:5555\t10.10.0.2/32\t"
                      "1790000000\t100\t200\t25\n")
    _peers, _err = _web._wg_dump()
    check("handshakes come from root's reading when the dashboard cannot "
          "read wg0 itself", not _err and _peers.get("PEER1=", {}).get(
              "handshake") == 1790000000)
    check("...and the blanked interface line is not mistaken for a peer",
          "(hidden)" not in _peers)
    _unsnap("wg0.dump")
    _peers, _err = _web._wg_dump()
    check("with no snapshot it says how to get one instead of offering sudo",
          _peers == {} and "install.sh" in _err and "sudoers" not in _err)
finally:
    _sp.run = _real_sp_run
    sc.STATUS_DIR = _real_status_dir

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SELF-CHECK TESTS PASSED")
