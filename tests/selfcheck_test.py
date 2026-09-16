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
