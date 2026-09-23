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
import threading
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
check("...and what ONE connection managed, which is the figure that says "
      "whether adding streams would help or the router's own CPU is the "
      "ceiling -- and which printed as a nonsensical 'peak' below the "
      "average while it was labelled as one",
      d["per_stream_mbps"] is not None)
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

print("\nA 300 Mbit line that read back as 100")

# One fixed 10 MB fetch, one connection at a time, caused both of this
# phase's faults.
#
# At 300 Mbit/s that transfer lasts a quarter of a second, and TCP spends
# most of a quarter-second still opening its window: slow start needs about
# a dozen round trips, which at 20 ms is 240 ms of ramp inside a 270 ms
# transfer. What came out was the average of the ramp, not the line.
#
# At the other end 10 MB needs 80 seconds on a 1 Mbit link, and the API read
# blocks for the whole fetch -- so the slowest devices could not finish one,
# and the phase returned a socket error rather than a slow answer.

MB = 1_000_000


def secs(mbit):
    """How long one chosen fetch lasts on a line of this speed."""
    bps = mbit * MB / 8
    return ST.choose_chunk(bps) / bps


check("a fast line gets a fetch big enough to outlast TCP slow start -- at "
      "300 Mbit a 10 MB fetch is over in a quarter of a second, most of it "
      "ramp, which is how 300 read back as 100",
      ST.choose_chunk(300 * MB / 8) > 100 * MB)
check("...and every speed from a trickle upwards gets a fetch of a few "
      "seconds rather than a fixed size that suits one of them",
      all(2.0 <= secs(m) <= 25.0 for m in (1, 2, 10, 50, 100, 300, 1000)))

# The other half: the API read blocks for the whole fetch, so a fetch longer
# than the device timeout comes back as a socket error with nothing measured.
check("no fetch is ever expected to outlast the API timeout, which is what "
      "made slow devices fail outright instead of answering slowly",
      all(ST.choose_chunk(b, 60.0) / b <= 60.0 * ST.TIMEOUT_SHARE + 0.01
          for b in (3e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9)))
check("...and a shorter configured timeout tightens it rather than being "
      "ignored",
      ST.choose_chunk(100 * MB / 8, 5.0) < ST.choose_chunk(100 * MB / 8, 60.0))
check("a gigabit line does not ask for a gigabyte",
      ST.choose_chunk(1e12) <= ST.DOWNLOAD_MAX_BYTES)
check("and an unknown rate falls back rather than asking for nothing",
      ST.choose_chunk(0) == ST.DOWNLOAD_MIN_BYTES)

print("\nMeasured across several connections, not one")


class CountingApi(FakeApi):
    """Counts fetches and reports a fixed size, like a real /tool/fetch."""

    def __init__(self, kib=2048):
        super().__init__()
        self.kib = kib
        self.fetches = 0
        self.lock = __import__("threading").Lock()

    def path(self, *parts):
        outer = self

        class P(FakePath):
            def __call__(self, _cmd, **kw):
                if parts == ("tool", "fetch") and "http-data" not in kw:
                    with outer.lock:
                        outer.fetches += 1
                    time.sleep(0.05)
                    return [{"downloaded": str(outer.kib)}]
                return FakePath.__call__(self, _cmd, **kw)

        return P(self, parts)


_api = CountingApi()
_made = []


def _conn():
    a = CountingApi()
    _made.append(a)
    return Conn(a)


_d = ST._phase_download(_api, _conn, seconds=1)
check("the phase runs more than one connection at once, so their ramps "
      "overlap instead of being measured end to end",
      _d["streams"] > 1)
check("...and reports how many, because a figure whose stream count is "
      "unknown cannot be compared with another one", _d["streams"] >= 2)
check("...and what size it settled on, for the same reason",
      _d["chunk_mb"] > 0)
check("every stream really fetched: the extra connections are not decoration",
      sum(a.fetches for a in _made) > 0)
check("a speed comes out of it", _d["mbps"] is not None and _d["bytes"] > 0)

# With no way to open more connections -- which is every existing caller and
# every test -- it still has to work on the one it was given.
_d1 = ST._phase_download(CountingApi(), None, seconds=1)
check("with no way to open a second connection it still measures on the one "
      "it has, rather than refusing",
      _d1["streams"] == 1 and _d1["mbps"] is not None)


class DeadApi(FakeApi):
    def path(self, *parts):
        class P(FakePath):
            def __call__(self, _cmd, **kw):
                raise OSError(110, "Connection timed out")
        return P(self, parts)


_d2 = ST._phase_download(DeadApi(), None, seconds=1)
check("a router that cannot fetch at all produces a result carrying the "
      "reason, not a hang",
      _d2["mbps"] is None and "timed out" in _d2["error"])

print("\nA stuck run must not lock the router out of the feature")

# The run is marked running until its thread returns. One blocked read and
# that never happens -- and every later test is refused, which looks exactly
# like the feature being broken.
ST._runs.clear()
ST._runs["R-stuck"] = {"running": True, "started": time.time() - 3600,
                       "phase": "download", "name": "R-stuck"}
check("a run that started an hour ago is not running, whatever it says",
      ST.is_running("R-stuck") is False)
check("...so another test can be started on that router",
      ST.start("R-stuck", lambda: Conn(FakeApi())) is True)

ST._runs.clear()
ST._runs["R-live"] = {"running": True, "started": time.time(),
                      "phase": "download", "name": "R-live"}
check("a run that started a moment ago IS running, and a second is still "
      "refused -- two tests would measure each other",
      ST.is_running("R-live") is True
      and ST.start("R-live", lambda: Conn(FakeApi())) is False)

print("\nUpload, measured on the router rather than through us")

# The old way reported 0.3 Mbit/s on a line measured at 158. Not a slow
# measurement -- the wrong one. /tool/fetch will only POST a body it was
# handed, and the only way to hand a router a body is through the API, so
# every payload travelled from this server into the router before the router
# sent a byte outward, and the timing wrapped that whole journey.
#
# So the sample now lives on the router. Which means the thing to test is
# not the arithmetic but the housekeeping: is the file sized to what the
# device has, does it always get removed, and does a router that cannot do
# this still report something.

MB = 1024 * 1024

check("the sample is a quarter of free space, so a speed test can never be "
      "what fills a router's disk",
      ST.sample_size(40 * MB) == 10 * MB)
check("...capped, because a router with 2 GB free does not need a 500 MB "
      "sample to measure an upload",
      ST.sample_size(4000 * MB) == ST.UPLOAD_FILE_TARGET)
check("a device with too little free space gets no sample at all rather "
      "than a useless one -- a hAP lite has 16 MB of flash in total",
      ST.sample_size(2 * MB) == 0)
check("...and a router that will not say how much it has is treated the "
      "same way", ST.sample_size(0) == 0)


class FileApi(FakeApi):
    """A router with storage, which records what was done to it."""

    def __init__(self, free=200 * MB, refuse_upload=False, fail_seed=False):
        super().__init__()
        self.free = free
        self.refuse_upload = refuse_upload
        self.fail_seed = fail_seed
        self.files = []
        self.uploads = 0
        self.removed = []

    def fetch(self, path):
        if tuple(path) == ("system", "resource"):
            return [{"free-hdd-space": str(self.free),
                     "version": "7.14.2 (stable)"}]
        return FakeApi.fetch(self, path)

    def path(self, *parts):
        outer = self

        class P(FakePath):
            def __call__(self, _cmd, **kw):
                if parts == ("tool", "fetch"):
                    if kw.get("dst-path"):
                        if outer.fail_seed:
                            raise RuntimeError("no space left on device")
                        outer.files.append(kw["dst-path"])
                        return [{"downloaded": "4096"}]
                    if kw.get("upload") == "yes":
                        if outer.refuse_upload:
                            raise RuntimeError(
                                "input does not match any value of upload")
                        outer.uploads += 1
                        time.sleep(0.02)
                        return []
                return FakePath.__call__(self, _cmd, **kw)

            def __iter__(self):
                if parts == ("file",):
                    return iter([{".id": "*1", "name": n}
                                 for n in outer.files])
                return iter([])

            def remove(self, rid):
                outer.removed.append(rid)
                outer.files.clear()

        return P(self, parts)


_api = FileApi()
_u = ST._phase_upload(_api, None, seconds=1)
check("the sample is fetched to the router's own storage, then POSTed from "
      "there -- which is what makes the figure the router's upload rather "
      "than the speed of our link to it",
      _api.files == [] and _api.uploads > 0)
check("...and the result says it was NOT measured through the API, so the "
      "page knows not to hedge it", _u["via_api"] is False)
check("...producing a real figure", _u["mbps"] is not None and _u["bytes"] > 0)
check("the file is removed afterwards: a speed test must not leave "
      "anything on somebody's router", _api.removed and not _api.files)

# The housekeeping that matters most is the failing case.
_api = FileApi(refuse_upload=True)
_u = ST._phase_upload(_api, None, seconds=1)
check("a router that refuses upload=yes falls back rather than spending the "
      "whole window failing", _u["via_api"] is True)
check("...and the sample is STILL removed, because a failed run must not "
      "leave a file behind either", _api.removed and not _api.files)

_api = FileApi(free=2 * MB)
_u = ST._phase_upload(_api, None, seconds=1)
check("a router with no room to spare is not asked for one -- it falls "
      "back, and nothing is written to it at all",
      _u["via_api"] is True and _api.files == [] and not _api.removed)

_api = FileApi(fail_seed=True)
_u = ST._phase_upload(_api, None, seconds=1)
check("a sample that cannot be fetched falls back too, rather than losing "
      "the phase", _u["via_api"] is True)

# RouterOS 6 has neither http-data nor upload=yes worth using.
class OldApi(FileApi):
    def fetch(self, path):
        if tuple(path) == ("system", "resource"):
            return [{"version": "6.48.6 (long-term)",
                     "free-hdd-space": str(self.free)}]
        return FileApi.fetch(self, path)


_api = OldApi()
_u = ST._phase_upload(_api, None, seconds=1)
check("RouterOS 6 is still told it is RouterOS 6, rather than being given a "
      "made-up figure", _u["skipped"] is True and "RouterOS 7" in _u["error"])
check("...and nothing was written to it on the way to finding that out",
      _api.files == [])

print("\nThe arithmetic, against a line of known speed")

# The only way to know a speed test is right is to measure something whose
# speed is already known. This is a fake router attached to a simulated line
# of exactly 50 Mbit/s, shared fairly between however many streams are
# fetching at that moment -- so the answer the phase produces can be checked
# against a number rather than against a hope.
#
# It caught a real mistake. Summing each stream's own rate over its own busy
# time was tried here first, on the theory that a stream idling after the
# deadline drags the average down. It overstated by 25%: when streams finish
# at different moments the survivors speed up, and their individual rates
# stop adding up to anything the line ever did. A speed test that reads high
# is worse than one that reads low.

_LINE_BPS = 50e6 / 8
_active = {"n": 0}
_alock = threading.Lock()


class LineApi(FakeApi):
    """A router on a simulated line shared by whoever is fetching."""

    def path(self, *parts):
        class P(FakePath):
            def __call__(self, _cmd, **kw):
                if parts != ("tool", "fetch"):
                    return []
                url = kw.get("url", "")
                n = (int(url.rsplit("bytes=", 1)[-1].split("&")[0])
                     if "bytes=" in url else 0)
                with _alock:
                    _active["n"] += 1
                    sharing = _active["n"]
                try:
                    time.sleep(n / (_LINE_BPS / max(1, sharing)))
                finally:
                    with _alock:
                        _active["n"] -= 1
                return [{"downloaded": str(n // 1024)}]

            def __iter__(self):
                return iter([])

        return P(self, parts)

    def fetch(self, path):
        return [{"version": "7.14.2 (stable)", "free-hdd-space": "0"}]


class LineConn:
    def __enter__(self):
        return LineApi()

    def __exit__(self, *a):
        return False


def _measure(secs_per_fetch, streams=6, window=3.0):
    chunk = int((_LINE_BPS / streams) * secs_per_fetch)
    return ST._phase_download(LineApi(), (lambda: LineConn()),
                              url=ST.download_url(chunk),
                              seconds=window, streams=streams)


_r = _measure(0.4)
check("a 50 Mbit line measures as 50 Mbit, within a few percent -- which is "
      "the only claim a speed test really makes",
      _r["mbps"] is not None and abs(_r["mbps"] - 50.0) / 50.0 < 0.08)
check("...having fetched many times over the window rather than once",
      _r["runs"] > 10)

# The pathological shape: a fetch sized for the UNLOADED probe rate, so
# under contention it eats most of the window.
_r = _measure(2.4)
check("...and still measures 50 Mbit when each fetch eats most of the "
      "window, which is what an oversized chunk does under contention",
      _r["mbps"] is not None and abs(_r["mbps"] - 50.0) / 50.0 < 0.08)

_r = _measure(0.4, streams=1)
check("one stream on the same line reads the same, because the line is the "
      "line however many connections are pointed at it",
      _r["mbps"] is not None and abs(_r["mbps"] - 50.0) / 50.0 < 0.10)

check("a stream that never fetched anything is not counted as a connection "
      "-- an extra connection that could not be opened used to be counted "
      "anyway, which divided the per-connection figure by streams that were "
      "never there",
      ST.summarise({"lock": threading.Lock(), "error": "",
                    "streams": {0: {"bytes": 100, "busy": 1.0, "runs": 1,
                                    "best": 0.8},
                                1: {"bytes": 0, "busy": 0.0, "runs": 0,
                                    "best": 0.0}}}, 1.0)["live"] == 1)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SPEED TEST TESTS PASSED")
