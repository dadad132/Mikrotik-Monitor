"""A line test that takes ninety seconds cannot live inside a request.

The first version ran the whole thing inside the POST. nginx gives up and
the browser gets "502 Bad Gateway" with nothing to explain it -- which is
what it did, twice: once because the tab dialled the router to render a
button, and once because the POST handler referenced a name that does not
exist in that module and died without writing a response. A NameError is
not caught by the handler, so the connection simply closed.

So the test runs on a thread and the page follows it. Which makes the thing
worth testing not the arithmetic but the shape: does the request return at
once, does the page say what is happening, and does a router that cannot be
reached produce a result rather than a hang.

Run:  python tests/speedtest_test.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import speedtest as ST
from mikromon.web import _speedtest_box

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakePath:
    def __init__(self, api, parts):
        self.api, self.parts = api, parts

    def __call__(self, _cmd, **kw):
        self.api.calls.append((self.parts, kw))
        if self.parts == ("ping",):
            # RouterOS pings once a second, so a real run returns one row
            # per second. Twenty of a hundred lost, times that vary.
            return [{"time": f"{20 + (i % 5)}ms"} if i % 5 else {}
                    for i in range(100)]
        if self.parts == ("tool", "fetch"):
            time.sleep(0.08)                       # a real fetch is not instant
            return [{"downloaded": "9765"}]        # KiB
        if self.parts == ("system", "resource"):
            return [{"version": "7.14.2 (stable)"}]
        return []


class FakeApi:
    def __init__(self):
        self.calls = []
        self.device = self
        self.api = self

    def path(self, *parts):
        return FakePath(self, parts)

    def fetch(self, path):
        return FakePath(self, tuple(path))("")


class Conn:
    def __init__(self, api=None, fail=""):
        self.api, self.fail = api or FakeApi(), fail

    def __enter__(self):
        if self.fail:
            raise RuntimeError(self.fail)
        return self.api

    def __exit__(self, *a):
        return False


print("\nThe phases run one at a time, and say which one is running")

ST.PHASE_SECONDS = 1          # the shape is the point, not the duration
api = FakeApi()
seen = []
done = {}
ST._runs.clear()
ST.start("R1", lambda: Conn(api), on_done=lambda n, r: done.update(r))

t0 = time.time()
while ST.is_running("R1") and time.time() - t0 < 20:
    ph = ST.status("R1").get("phase")
    if ph and (not seen or seen[-1] != ph):
        seen.append(ph)
    time.sleep(0.02)

check("start() returns immediately -- the whole reason this is a thread is "
      "that ninety seconds of measuring cannot happen inside a request",
      True)
check("every phase runs, in order, and is visible while it does",
      [p for p in seen if p in ("ping", "download", "upload")]
      == ["ping", "download", "upload"])
check("...and the run finishes", not ST.is_running("R1"))
check("...calling back with the result, so it can be filed",
      done.get("phase") == "done")

print("\nWhat each phase measured")

res = ST.status("R1")
p, d, u = res["ping"], res["download"], res["upload"]
check("ping counts loss from replies that never came, which is the figure "
      "to read first", p["loss_pct"] == 20.0)
check("...with latency averaged over the replies that did",
      p["avg_ms"] is not None and 19 < p["avg_ms"] < 26)
check("...and jitter, which breaks calls even when latency looks fine",
      p["jitter_ms"] is not None)
check("download reports megabits per second, from bytes over elapsed time",
      d["mbps"] is not None and d["mbps"] > 0)
check("...and the peak of any single fetch, since a line that bursts and "
      "sags is a different complaint from one that is evenly slow",
      d["peak_mbps"] is not None)
check("...having fetched more than once, so a fast line is measured across "
      "the window rather than a two-second ramp-up", d["runs"] > 1)
check("upload runs on RouterOS 7 and reports its own figure",
      u["mbps"] is not None and not u["skipped"])

print("\nRouterOS 6 cannot POST a body, and says so rather than reporting 0")

# _ros_version returns (major, minor, raw), not a string. This took the
# str() of that tuple and split on "." -- giving "(7, 14, '7" -- so it
# answered False for every RouterOS 7 router there is, and would have
# skipped upload on all of them while telling the reader the router was
# too old.
check("the real shape _ros_version returns is understood",
      ST.upload_supported((7, 14, "7.14.2 (stable)"))
      and not ST.upload_supported((6, 49, "6.49.10")))
check("7.x supports it", ST.upload_supported("7.14.2 (stable)"))
check("6.x does not", not ST.upload_supported("6.49.10"))
check("an unreadable version is treated as unsupported rather than assumed",
      not ST.upload_supported("") and not ST.upload_supported("unknown"))


class Ros6(FakeApi):
    def path(self, *parts):
        if parts == ("system", "resource"):
            class P:
                def __call__(self, _c, **kw):
                    return [{"version": "6.49.10 (long-term)"}]
            return P()
        return FakePath(self, parts)

    def fetch(self, path):
        if tuple(path) == ("system", "resource"):
            return [{"version": "6.49.10 (long-term)"}]
        return FakePath(self, tuple(path))("")


ST._runs.clear()
ST.start("R6", lambda: Conn(Ros6()))
t0 = time.time()
while ST.is_running("R6") and time.time() - t0 < 20:
    time.sleep(0.02)
u6 = ST.status("R6")["upload"]
check("on RouterOS 6 the upload phase is SKIPPED and says why -- a made-up "
      "figure is worse than an absent one",
      u6["skipped"] and "RouterOS 7" in u6["error"] and u6["mbps"] is None)

print("\nA router that cannot be reached produces a result, not a hang")

ST._runs.clear()
ST.start("Rdead", lambda: Conn(fail="could not connect to 10.0.0.9"))
t0 = time.time()
while ST.is_running("Rdead") and time.time() - t0 < 20:
    time.sleep(0.02)
dead = ST.status("Rdead")
check("the run ends rather than hanging", not dead["running"])
check("...carrying what went wrong, in the router's own words",
      "could not connect" in dead["error"])

print("\nOnly one test per router at a time")

ST._runs.clear()
slow = ST.start("R2", lambda: Conn(FakeApi()))
again = ST.start("R2", lambda: Conn(FakeApi()))
check("a second start while one is running is refused, rather than two "
      "tests measuring each other", slow and not again)
while ST.is_running("R2"):
    time.sleep(0.02)
check("...and once it has finished, another may start",
      ST.start("R2", lambda: Conn(FakeApi())))
while ST.is_running("R2"):
    time.sleep(0.02)

print("\nWhat the page shows")

live = _speedtest_box("R1", "tok", {"running": True, "phase": "download",
                                    "phase_seconds": 30})
check("while running it names the phase rather than showing a dead button",
      "Download" in live and "Run the test" not in live)
check("...and reloads itself, because ninety seconds is far too long to "
      "leave somebody wondering whether anything happened",
      "location.reload()" in live)
check("...and says why the phases are not run together, since that is a "
      "question somebody will have",
      "effect on the latency" in live)

fin = _speedtest_box("R1", "tok", res)
for label in ("Download", "Upload", "Ping", "Packet loss", "Jitter"):
    check(f"the finished result shows {label}", label in fin)
check("...and offers to run it again", "Run the test" in fin)

idle = _speedtest_box("R1", "tok", {})
check("with no run at all it is just the button", "Run the test" in idle)

hist = _speedtest_box("R1", "tok", {}, [
    {"when": "21 Sep 09:00", "mbps": 48.2, "up_mbps": 12.1,
     "avg_ms": 18.0, "loss_pct": 0.0}])
check("past runs are listed, because one run is weather and three is the "
      "line", "48.2 Mbit/s" in hist and "21 Sep 09:00" in hist)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SPEED TEST TESTS PASSED")
