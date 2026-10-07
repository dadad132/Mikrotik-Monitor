"""Rate limits on the website: one visitor cannot flood it.

Per visitor address: requests per second (with a burst), logins and sign-up
codes far fewer, oversized bodies refused unread, and a ceiling on open
connections. The visitor address behind nginx comes from X-Real-IP, which is
believed only when nginx (loopback) sent it.

Run:  ./.venv/Scripts/python.exe tests/webguard_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.metrics import MetricsStore
from mikromon.webguard import GuardedHTTPServer, TokenBuckets, WebGuard

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


print("Buckets")
clk = Clock()
b = TokenBuckets(2.0, 5, clock=clk)
got = [b.take("a") for _ in range(6)]
check("a burst is let through, then the next one waits",
      got[:5] == [0.0] * 5 and got[5] > 0)
check("...for as long as the next token takes (here half a second)",
      abs(got[5] - 0.5) < 1e-9)
check("another address has its own bucket", b.take("b") == 0.0)
clk.t += 0.5
check("tokens come back at the steady rate", b.take("a") == 0.0
      and b.take("a") > 0)
clk.t += 3600
b.take("c")
check("idle addresses are forgotten (memory does not grow with every "
      "address ever seen)", "a" not in b._b and "b" not in b._b)

print("\nWho is the visitor")
g = WebGuard(clock=clk)
check("a direct visitor is their own address, whatever header they send",
      g.client_ip("203.0.113.9", {"X-Real-IP": "10.0.0.1"}) == "203.0.113.9")
check("behind nginx (loopback), X-Real-IP names the visitor",
      g.client_ip("127.0.0.1", {"X-Real-IP": "198.51.100.7"})
      == "198.51.100.7")
check("the server's own requests (loopback, no header) are not limited",
      g.client_ip("127.0.0.1", {}) is None
      and g.client_ip("::1", {}) is None)

print("\nThe limits")
clk.t = 5000.0
g = WebGuard(clock=clk)
ip = "198.51.100.20"
h = {"X-Real-IP": ip}
logins = [g.check("127.0.0.1", h, "POST", "/login") for _ in range(21)]
check("20 login tries pass, the 21st in the same moment is refused",
      logins[:20] == [0] * 20 and logins[20] > 0)
check("...but the same visitor can still open pages",
      g.check("127.0.0.1", h, "GET", "/login") == 0
      and g.check("127.0.0.1", h, "GET", "/dashboard") == 0)
sign = [g.check("127.0.0.1", {"X-Real-IP": "198.51.100.21"}, "POST",
                "/signup") for _ in range(9)]
check("8 sign-ups (each sends an email) pass, the 9th is refused, for "
      "about two minutes", sign[:8] == [0] * 8 and 100 <= sign[8] <= 120)
flood = [g.check("127.0.0.1", {"X-Real-IP": "198.51.100.22"}, "GET", "/")
         for _ in range(121)]
check("120 requests at once pass, then a flood is refused",
      flood[:120] == [0] * 120 and flood[120] >= 1)
clk.t += 1
check("...and a second later about ten more are allowed", [
    g.check("127.0.0.1", {"X-Real-IP": "198.51.100.22"}, "GET", "/")
    for _ in range(10)] == [0] * 10)

print("\nOn the wire")
tmp = tempfile.mkdtemp()
mdb, sfile, adb = (os.path.join(tmp, x) for x in ("m.db", "s.json", "a.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
a.signup("boss@platform.test", "secret123", "Platform")
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, a, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS)))
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path, headers=None, method="GET", body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.getheader("Retry-After"), r.read()
    finally:
        c.close()


try:
    who = {"X-Real-IP": "192.0.2.50"}
    # Real time passes while these are sent (and refills ~10 a second), so
    # keep going until the first refusal.
    served = 0
    for _ in range(600):
        st, retry, body = get("/login", who)
        if st != 200:
            break
        served += 1
    check("past the burst a visitor gets 429 with Retry-After",
          served >= 120 and st == 429 and retry and int(retry) >= 1
          and b"Too many requests" in body)
    check("...while a different visitor is served normally",
          get("/login", {"X-Real-IP": "192.0.2.51"})[0] == 200)
    check("...and the server's own requests are never limited",
          all(get("/login")[0] == 200 for _ in range(150)))

    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/login")
    c.putheader("Content-Type", "application/x-www-form-urlencoded")
    c.putheader("Content-Length", str(50 * 1024 * 1024))
    c.endheaders()
    t0 = time.time()
    r = c.getresponse()
    check("a body claiming 50 MB on the login page is refused at once, "
          "without being read", r.status == 413 and time.time() - t0 < 5)
    c.close()
    check("a Content-Length that is not a number is a 400",
          get("/login", {"Content-Length": "abc"}, "POST")[0] == 400)
    check("the handler drops idle connections after a minute",
          getattr(web.make_handler(mdb, sfile, None, web.SessionManager()),
                  "timeout", None) == 60)
finally:
    srv.shutdown()
    srv.server_close()
    a.close()

print("\nConnections")
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, None, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS)))
srv.max_connections = 3
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]
    time.sleep(0.4)
    extra = socket.create_connection(("127.0.0.1", port))
    extra.settimeout(5)
    reply = extra.recv(200)
    extra.close()
    check("past the connection ceiling a new one is answered 503 and closed",
          reply.startswith(b"HTTP/1.1 503"))
    for s in idle:
        s.close()
    time.sleep(0.4)
    st = get("/")[0]
    time.sleep(0.3)
    check("...and once the idle ones go, new visitors are served again",
          st < 500 and srv._total == 0)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL RATE LIMIT TESTS PASSED")
