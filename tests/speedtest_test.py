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

print("\nThe upload that kept dying halfway through")

# Every run ended "Upload did not complete: [Errno 104] Connection reset by
# peer". The payload crosses the API to reach the router, and RouterOS
# closes the connection outright on a sentence past whatever its limit is --
# undocumented, different by version, and fatal to the rest of the run,
# because the connection it kills is the one the test is using.
#
# So the size is no longer asserted. It is probed, largest first, and a
# refusal means reconnecting before trying smaller.


class PickyApi(FakeApi):
    """A router that resets the connection on a body over `limit` bytes."""

    def __init__(self, limit):
        super().__init__()
        self.limit = limit
        self.dead = False
        self.accepted = []

    def path(self, *parts):
        outer = self

        class P(FakePath):
            def __call__(self, _cmd, **kw):
                if outer.dead:
                    raise OSError(104, "Connection reset by peer")
                data = kw.get("http-data")
                if data is not None:
                    if len(data) > outer.limit:
                        outer.dead = True
                        raise OSError(104, "Connection reset by peer")
                    outer.accepted.append(len(data))
                    time.sleep(0.02)
                    return []
                return FakePath.__call__(self, _cmd, **kw)

        return P(self, parts)


ST.PHASE_SECONDS = 1
_apis = []


def _picky_conn(limit):
    def make():
        api = PickyApi(limit)
        _apis.append(api)
        return Conn(api)
    return make


# 128 KiB refused, 64 accepted: the ladder has to come down one rung and
# reconnect to do it, because the first refusal killed the connection.
_mk = _picky_conn(64 * 1024)
_first = _mk()
_up = ST._phase_upload(_first.__enter__(), _mk, seconds=1)
check("a router that refuses the largest body still produces an upload "
      "figure, instead of losing the phase to a dead connection",
      _up["mbps"] is not None and _up["bytes"] > 0)
check("...measured with a body the router actually accepted",
      _up["chunk_kib"] == 64)
check("...and the result says which, because a figure whose payload size "
      "is unknown cannot be compared with another one",
      _up["chunk_kib"] in (s_ // 1024 for s_ in ST.UPLOAD_SIZES))
check("...across more than one connection: a single stream spends most of "
      "its time waiting for round trips, not sending",
      _up["streams"] > 1)
check("...and reports no error, because nothing went wrong -- the router "
      "simply has a smaller limit than the first guess",
      _up["error"] == "")

# A router that refuses everything is a result, not a crash.
_mk = _picky_conn(1)
_first = _mk()
_up = ST._phase_upload(_first.__enter__(), _mk, seconds=1)
check("a router that refuses every size says so rather than reporting zero",
      _up["mbps"] is None and "refused" in _up["error"])

# The old bug, exactly: one oversized body, and the phase returned the bare
# socket error with nothing measured.
check("the probe never sends a body bigger than the largest rung, so the "
      "thing that killed the connection cannot be sent by accident",
      max(ST.UPLOAD_SIZES) == ST.UPLOAD_SIZES[0])

print("\nWhere the test actually went")

# speed.cloudflare.com is anycast: "the server" is whichever PoP is nearest.
# A line in Johannesburg served out of Amsterdam is not a slow line, it is a
# badly routed one, and megabits alone never tell those two apart.


class MetaApi(FakeApi):
    def __init__(self, body):
        super().__init__()
        self.body = body

    def path(self, *parts):
        outer = self

        class P(FakePath):
            def __call__(self, _cmd, **kw):
                if kw.get("output") == "user":
                    return [{"data": outer.body}]
                return FakePath.__call__(self, _cmd, **kw)

        return P(self, parts)


_w = ST._detect_location(MetaApi(
    '{"clientIp":"41.13.2.9","country":"ZA","city":"Johannesburg",'
    '"colo":"JNB","asn":3741,"asOrganization":"Internet Solutions"}'))
check("the run names the PoP that served it",
      _w["colo"] == "JNB" and _w["city"] == "Johannesburg")
check("...the country the router is seen in",
      _w["country"] == "ZA")
check("...and the public address it is seen as, which is the thing to quote "
      "at an ISP", _w["ip"] == "41.13.2.9")

_w = ST._detect_location(FakeApi())
check("a router too old for output=user says so rather than inventing a "
      "location", not _w["colo"] and "RouterOS 7" in _w["error"])

_w = ST._detect_location(MetaApi("<html>not json</html>"))
check("a reply that is not the JSON expected is handled, not raised",
      not _w["colo"] and "JSON" in _w["error"])

print("\nAiming the ping")

check("a preset resolves to its address", ST.ping_target("google") == "8.8.8.8")
check("the default is the nearest anycast, which is what 'auto' means",
      ST.ping_target("auto") == "1.1.1.1")
check("a typed host is taken as given -- somebody testing their line to a "
      "particular place knows where it is better than a list does",
      ST.ping_target("196.25.1.1") == "196.25.1.1")
check("an empty choice falls back rather than pinging nothing",
      ST.ping_target("") == ST.PING_TARGET)

_api = FakeApi()
ST._runs.clear()
ST.start("R-target", lambda: Conn(_api), target="quad9")
for _ in range(120):
    if not ST.is_running("R-target"):
        break
    time.sleep(0.1)
_st = ST.status("R-target")
check("the chosen target is what actually gets pinged, not the default",
      (_st.get("ping") or {}).get("target") == "9.9.9.9")

_box = _speedtest_box("R1", "tok", run=_st)
check("the page names what it pinged, so a figure can be compared with "
      "another one", "9.9.9.9" in _box)
check("...and offers the choice before the next run",
      'name="target"' in _box and "Nearest" in _box)

print("\nFive runs, not ten")

from mikromon import web as _W  # noqa: E402

check("the history keeps five, because ten is more table than anybody "
      "reads and three already tells weather from the line",
      _W._SPEEDTEST_KEEP == 5)

_hist = [{"when": f"22 Sep 1{i}:00", "mbps": 18.0, "up_mbps": 2.0,
          "avg_ms": 55.0, "loss_pct": 0.0, "target": "1.1.1.1",
          "colo": "JNB"} for i in range(5)]
_box = _speedtest_box("R1", "tok", history=_hist)
check("...and the table says what each run was measured against, since a "
      "row against a different host is not comparable with the one above it",
      _box.count("JNB") == 5)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SPEED TEST TESTS PASSED")
