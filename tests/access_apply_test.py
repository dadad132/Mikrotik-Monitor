"""The hub applying remote-access grants: checked, recorded, and explained.

`access-apply` (run as root by easymikrotik-access-reload) used to write the
nginx files, ask for a reload and report success whatever happened. A config
nginx refused, or a port it could not open, left the grant recorded, the
unit green and the customer with "connection refused" -- and the device page
offered the same two shell commands for every cause. Now each step is
checked, a refused config is rolled back (the dashboard sits behind the same
nginx), and the outcome goes to access-status.json for the device page and
the Platform self-check.

Run:  ./.venv/Scripts/python.exe tests/access_apply_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import access, cli, selfcheck

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()
grants = os.path.join(tmp, "access-grants.json")
http_conf = os.path.join(tmp, "conf.d", "easymikrotik-access.conf")
stream_conf = os.path.join(tmp, "streams.d", "easymikrotik-access.conf")
errlog = os.path.join(tmp, "error.log")
access.NGINX_ERROR_LOG = errlog
ACC = {"hub_host": "hub.example.test", "grants_file": grants,
       "tls_cert": os.path.join(tmp, "c.pem"),
       "tls_key": os.path.join(tmp, "k.pem"),
       "nginx_http_conf": http_conf, "nginx_stream_conf": stream_conf}
CONFIG = types.SimpleNamespace(access=ACC)

store = access.AccessStore(grants)
g = store.open("Wikiworx", "webfig", "10.10.1.5")
PORT = g["port"]
check("a grant records when it was opened, so the page waits for THIS open",
      abs(g["opened"] - time.time()) < 5)

# --- a fake nginx/systemctl ------------------------------------------------
SCRIPT = {}
CALLS = []
real_run = subprocess.run


def fake_run(cmd, *a, **kw):
    CALLS.append(list(cmd))
    key = " ".join(cmd[:2])
    rc, out = SCRIPT.get(key, (None, ""))
    if rc is None:
        raise FileNotFoundError(cmd[0])
    return subprocess.CompletedProcess(cmd, rc, out, "")


subprocess.run = fake_run
real_not_open = access.ports_not_open


def run(script, closed=()):
    SCRIPT.clear()
    SCRIPT.update(script)
    CALLS.clear()
    access.ports_not_open = lambda ports, **k: [p for p in ports
                                                if p in closed]
    rc = cli._cmd_access_apply(CONFIG)
    return rc, access.read_status(grants)


try:
    print("When everything works")
    rc, st = run({"nginx -t": (0, "syntax is ok"),
                  "systemctl reload": (0, "")})
    check("it reloads nginx, confirms the port opened and records success",
          rc == 0 and st.get("ok") and st.get("ports") == [PORT]
          and abs(st["ran"] - time.time()) < 30)
    check("nginx is tested before it is reloaded",
          CALLS and CALLS[0][:2] == ["nginx", "-t"])
    with open(http_conf, encoding="utf-8") as fh:
        good_http = fh.read()
    check("the WebFig server block for the grant is written",
          f"listen {PORT} ssl;" in good_http)

    print("\nWhen nginx refuses the configuration")
    store.open("Second", "webfig", "10.10.1.6")
    rc, st = run({"nginx -t": (1, 'nginx: [emerg] cannot load certificate '
                                  '"/etc/x.pem": BIO_new_file() failed\n'
                                  'nginx: configuration file test failed')})
    check("the run fails, so systemd shows the unit failed",
          rc == 1 and not st.get("ok"))
    check("...and says what nginx said, in one line",
          "cannot load certificate" in st.get("error", "")
          and "test failed" in st.get("detail", ""))
    with open(http_conf, encoding="utf-8") as fh:
        check("...and the last configuration nginx accepted is put back, so "
              "a later restart cannot take the dashboard down with it",
              fh.read() == good_http)
    check("...without reloading a configuration known to be bad",
          not any(c[:1] == ["systemctl"] for c in CALLS))

    print("\nWhen nginx reloads but the port does not open")
    with open(errlog, "w", encoding="utf-8") as fh:
        old = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(
            time.time() - 3 * 86400))
        now = time.strftime("%Y/%m/%d %H:%M:%S")
        fh.write(f"{old} [emerg] 9#9: something from days ago\n"
                 f"{now} [notice] 9#9: signal process started\n"
                 f"{now} [emerg] 9#9: bind() to 0.0.0.0:{PORT} failed "
                 f"(98: Address already in use)\n")
    rc, st = run({"nginx -t": (0, "ok"), "systemctl reload": (0, "")},
                 closed=(PORT,))
    check("it is not called a success: the port was the point",
          rc == 1 and not st.get("ok"))
    check("...and nginx's own reason is found in its error log",
          "Address already in use" in st.get("error", "")
          and str(PORT) in st.get("error", ""))
    check("...but not stale complaints from days ago",
          "days ago" not in st.get("detail", ""))

    print("\nWhen nginx cannot be reloaded at all")
    rc, st = run({"nginx -t": (0, "ok")})       # no systemctl, no nginx -s
    check("it says nginx could not be reloaded",
          rc == 1 and "could not be reloaded" in st.get("error", ""))

    print("\nPlatform self-check")
    f = selfcheck.check_access_apply(ACC)
    check("a failed apply is reported, with nginx's words",
          f and not f[0]["ok"] and "could not be reloaded" in f[0]["detail"])
    run({"nginx -t": (0, "ok"), "systemctl reload": (0, "")})
    f = selfcheck.check_access_apply(ACC)
    check("a good one is reported as fine", f and f[0]["ok"])
    st = access.read_status(grants)
    st["ran"] = time.time() - 3600
    access.write_status(grants, st)
    f = selfcheck.check_access_apply(ACC)
    check("an hour with no run means its timer and watcher stopped",
          f and not f[0]["ok"] and "enable --now" in f[0]["fix"])
    os.remove(access.status_path(grants))
    f = selfcheck.check_access_apply(ACC)
    check("no record at all is a warning pointing at the installer",
          f and f[0]["warn"] and "install.sh" in f[0]["fix"])
    check("nothing is said when remote access is not set up",
          selfcheck.check_access_apply({}) == [])

    print("\nHelpers")
    t = [0.0]
    left = real_not_open([1, 2], wait=1.0, probe=lambda p: p == 1 or t[0] > .5,
                         clock=lambda: t[0],
                         sleep=lambda s: t.__setitem__(0, t[0] + s))
    check("a port that opens a moment after the reload counts as open",
          left == [])
    t[0] = 0.0
    left = real_not_open([1, 2], wait=1.0, probe=lambda p: p == 1,
                         clock=lambda: t[0],
                         sleep=lambda s: t.__setitem__(0, t[0] + s))
    check("one that never opens is reported", left == [2])
    check("the first emerg line is the one quoted",
          access.first_complaint("x\nnginx: [emerg] 1#1: bad thing\nmore")
          == "bad thing")
finally:
    subprocess.run = real_run
    access.ports_not_open = real_not_open

print("")
if FAILS:
    print(f"FAILED: {len(FAILS)}: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL ACCESS-APPLY TESTS PASSED")
