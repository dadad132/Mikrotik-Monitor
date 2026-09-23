"""A real line test: ping, download, upload — run in the background.

Two things forced this shape.

A proper test takes minutes. Thirty seconds of ping, thirty of download,
thirty of upload is ninety seconds before anything can be said, and an HTTP
request cannot wait that long: nginx gives up at two minutes and the browser
gets 502 with no explanation. So the test runs on its own thread, the page
returns at once, and the tab shows progress while it works.

And the phases run one at a time, on purpose. Downloading while pinging
measures the download's effect on the latency, which is a different and much
less useful number than the idle latency of the line -- and anyone reading
"180 ms" wants to know whether that is the line or the load.

What each phase actually measures:

  WHERE     which Cloudflare PoP serves this router, and the public address
            it is seen as. Download and upload go to an anycast name, so
            "the server" is whichever one is nearest -- and a test that does
            not say where it went cannot be compared with one that does.
  PING      loss, latency and jitter, from the router's own /ping. Loss is
            the figure to read first: a line dropping packets is unusable
            for voice long before a speed figure looks bad.
  DOWNLOAD  repeated fetches for the duration, bytes over seconds. Plain
            HTTP: a small MikroTik doing TLS measures its own CPU, not the
            line.
  UPLOAD    POSTs a payload the router holds, across several connections at
            once -- see _phase_upload for why one is not enough.

Nothing is written to the router's flash in any phase.
"""
from __future__ import annotations

import json
import logging
import threading
import time

log = logging.getLogger(__name__)

PHASE_SECONDS = 30

# Plain HTTP on purpose: HTTPS would make a small router measure its own
# encryption speed rather than the line.
DOWNLOAD_URL = "http://speed.cloudflare.com/__down?bytes=10000000"

# How long ONE fetch should last. Long enough that TCP slow start is a small
# fraction of it -- a quarter-second transfer is mostly ramp, and reports the
# ramp -- and short enough that the phase is made of several fetches rather
# than one long one.
DOWNLOAD_TARGET_SECONDS = 4.0

# The floor and ceiling on that size. The floor keeps a slow line from
# fetching something so small it measures handshakes; the ceiling stops a
# fast line asking for a gigabyte.
DOWNLOAD_MIN_BYTES = 2_000_000
DOWNLOAD_MAX_BYTES = 400_000_000

# The first probe. Small, because it has to complete on the slowest line
# there is before anything is known about the speed.
DOWNLOAD_PROBE_BYTES = 2_000_000

# Below this there is nothing left to measure; asking for fewer bytes than
# this would time the handshake and call it a line speed.
ABSOLUTE_MIN_BYTES = 64_000

# No single fetch may be expected to take more than this share of the API
# timeout. The API read blocks for the whole fetch, so a fetch longer than
# the timeout does not come back slow -- it comes back as a socket error
# with nothing measured.
TIMEOUT_SHARE = 0.4
_DEFAULT_API_TIMEOUT = 60.0

# Same reason as upload: one stream measures round trips and ramps, several
# measure the line.
# Four streams returned 184 Mbit on a measured 306 Mbit line -- about 46 per
# stream, so the streams were the ceiling rather than the line. Six gets
# closer without asking a small router for a lot of simultaneous API
# sessions. If the per-connection figure in the result does not fall when
# this rises, the router's own CPU is the limit and no number of streams
# will help.
DOWNLOAD_STREAMS = 6

UPLOAD_URL = "http://speed.cloudflare.com/__up"
META_URL = "http://speed.cloudflare.com/meta"
PING_TARGET = "1.1.1.1"

# Where a ping can be aimed. Download and upload always go to the nearest
# Cloudflare PoP -- the name is anycast, so there is no choice to make and
# no point pretending there is. Latency to a named host IS a choice, and
# "how far is my line from Google" is a question people really do ask.
#
# Every one of these is a public resolver that has answered on the same
# address for years. A cleverer list of country-specific hosts would be a
# list of addresses that quietly stop working.
PING_CHOICES = (
    ("auto", "Nearest (Cloudflare anycast)", "1.1.1.1"),
    ("google", "Google DNS", "8.8.8.8"),
    ("quad9", "Quad9", "9.9.9.9"),
    ("opendns", "OpenDNS", "208.67.222.222"),
)


def ping_target(choice: str) -> str:
    """The address for a chosen preset, or the choice itself if it is a host.

    A typed-in host is taken as given: somebody testing their line to a
    particular place knows where that place is better than a list does.
    """
    key = (choice or "").strip()
    for name, _label, addr in PING_CHOICES:
        if key == name:
            return addr
    return key or PING_TARGET


# The upload payload crosses the API to reach the router, and RouterOS closes
# the connection outright on a sentence past whatever its limit is -- which
# is not documented, differs by version, and showed up here as a bare
# "[Errno 104] Connection reset by peer" halfway through a run. So the size
# is not asserted: it is probed, largest first, and the first one the router
# accepts is the one used.
UPLOAD_SIZES = (128 * 1024, 64 * 1024, 16 * 1024)

# One POST per connection means one TCP handshake and one response wait for
# every payload, and at 55 ms that overhead is most of a 128 KiB upload. A
# single stream therefore measures round trips, not the line. Several at
# once overlap the waiting, which is how every speed test on the internet
# reaches line rate.
UPLOAD_STREAMS = 3

# A run that has been "running" for longer than this is not running. Without
# it a single stuck read leaves the router unable to start another test ever
# again, which is indistinguishable from the feature being broken.
MAX_RUN_SECONDS = 12 * 60

_runs: dict = {}
_lock = threading.Lock()


def status(name: str) -> dict:
    """What the test for this router is doing, or {} if it never ran."""
    with _lock:
        run = _runs.get(name)
        return dict(run) if run else {}


def is_running(name: str) -> bool:
    """Is a test actually in progress on this router?

    A run that says it started twelve minutes ago is not running: something
    blocked and its thread never came back. Saying so lets a new test start,
    rather than leaving the router locked out of the feature by one stuck
    read.
    """
    run = status(name)
    if not run.get("running"):
        return False
    started = float(run.get("started") or 0)
    if started and (time.time() - started) > MAX_RUN_SECONDS:
        log.warning("speed test for %r has been running %.0f minutes; "
                    "treating it as dead so another can start",
                    name, (time.time() - started) / 60)
        _set(name, running=False, phase="done",
             error=run.get("error") or "the test stopped responding")
        return False
    return True


def _set(name: str, **fields) -> None:
    with _lock:
        _runs.setdefault(name, {}).update(fields)


def start(name: str, connect, on_done=None, target: str = "auto") -> bool:
    """Begin a test. False if one is already running for this router.

    `connect` is a zero-argument callable returning a context manager that
    yields a connected API -- passed in rather than imported so this module
    stays testable without a router, and called again by the upload phase,
    which needs more than one connection.
    """
    if is_running(name):
        return False
    with _lock:
        _runs[name] = {"running": True, "phase": "connecting",
                       "started": time.time(), "name": name,
                       "ping": None, "download": None, "upload": None,
                       "where": None, "target": target,
                       "error": "", "phase_seconds": PHASE_SECONDS}
    threading.Thread(target=_run, args=(name, connect, on_done, target),
                     name=f"speedtest-{name}", daemon=True).start()
    return True


def _run(name, connect, on_done, target="auto") -> None:
    try:
        with connect() as api:
            _set(name, phase="where")
            _set(name, where=_detect_location(api))
            _set(name, phase="ping")
            _set(name, ping=_phase_ping(api, ping_target(target)))
            _set(name, phase="download")
            _set(name, download=_phase_download(api, connect))
            _set(name, phase="upload")
            _set(name, upload=_phase_upload(api, connect))
    except Exception as exc:  # noqa: BLE001 — a failed test is a result
        log.exception("speed test failed for %r", name)
        _set(name, error=str(exc))
    finally:
        _set(name, running=False, phase="done", finished=time.time())
        if on_done:
            try:
                on_done(name, status(name))
            except Exception:  # noqa: BLE001
                log.exception("speed test callback failed for %r", name)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def _detect_location(api, url: str = META_URL) -> dict:
    """Which Cloudflare PoP serves this router, and how it is seen.

    Answers "where did this test actually go", which is the question behind
    a figure that looks wrong. A line in Johannesburg served from Amsterdam
    is not a slow line, it is a badly routed one, and no amount of megabits
    tells those apart.

    `output=user` returns the body in the API reply, so nothing is written
    to the router's storage. Best-effort throughout: not knowing where the
    test went is a smaller problem than not running it.
    """
    out = {"country": "", "city": "", "colo": "", "ip": "", "asn": "",
           "org": "", "error": ""}
    try:
        rows = list(api.device.api.path("tool", "fetch")(
            "", url=url, mode="http", output="user",
            **{"check-certificate": "no"}))
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        return out

    raw = ""
    for r in rows or []:
        for key in ("data", "contents"):
            if r.get(key):
                raw = str(r[key])
                break
        if raw:
            break
    if not raw:
        out["error"] = ("the router returned no body -- /tool/fetch "
                        "output=user needs RouterOS 7")
        return out
    try:
        meta = json.loads(raw)
    except ValueError:
        out["error"] = "the reply was not the JSON that was expected"
        return out
    out["country"] = str(meta.get("country") or "")
    out["city"] = str(meta.get("city") or "")
    out["colo"] = str(meta.get("colo") or "")
    out["ip"] = str(meta.get("clientIp") or "")
    out["asn"] = str(meta.get("asn") or "")
    out["org"] = str(meta.get("asOrganization") or "")
    return out


def _phase_ping(api, target: str = PING_TARGET,
                seconds: int = 0) -> dict:
    """Loss, latency and jitter. RouterOS pings once a second, so the count
    IS the duration."""
    from .push.features import _ms

    seconds = int(seconds or PHASE_SECONDS)
    target = target or PING_TARGET
    out = {"target": target, "seconds": seconds, "sent": 0, "received": 0,
           "loss_pct": None, "min_ms": None, "avg_ms": None, "max_ms": None,
           "jitter_ms": None, "error": ""}
    try:
        rows = list(api.device.api.path("ping")(
            "", address=str(target), count=str(int(seconds))))
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        return out

    times = []
    for r in rows:
        got = r.get("time")
        if got not in (None, ""):
            ms = _ms(got)
            if ms is not None:
                times.append(ms)
    out["sent"] = len(rows) or seconds
    out["received"] = len(times)
    if out["sent"]:
        out["loss_pct"] = round(
            100.0 * (out["sent"] - out["received"]) / out["sent"], 1)
    if times:
        out["min_ms"] = round(min(times), 1)
        out["max_ms"] = round(max(times), 1)
        out["avg_ms"] = round(sum(times) / len(times), 1)
        if len(times) > 1:
            deltas = [abs(b - a) for a, b in zip(times, times[1:])]
            out["jitter_ms"] = round(sum(deltas) / len(deltas), 1)
    return out


def _api_timeout(api) -> float:
    """How long the API will wait on one read, in seconds.

    It matters because the read blocks for the WHOLE fetch: RouterOS sends
    nothing back until the transfer finishes. A fetch expected to outlast
    this does not return a slow answer, it returns a socket error with
    nothing measured -- which is what the slowest devices were doing.
    """
    try:
        return float(api.device.cfg.timeout) or _DEFAULT_API_TIMEOUT
    except Exception:  # noqa: BLE001
        return _DEFAULT_API_TIMEOUT


def download_url(nbytes: int) -> str:
    """Cloudflare's endpoint, asked for a specific size."""
    return f"http://speed.cloudflare.com/__down?bytes={int(nbytes)}"


def choose_chunk(rate_bps: float, api_timeout: float = _DEFAULT_API_TIMEOUT,
                 target: float = DOWNLOAD_TARGET_SECONDS) -> int:
    """How big one fetch should be, for a line running at `rate_bps`.

    Big enough that TCP slow start is a small part of it -- a quarter-second
    transfer is mostly ramp and reports the ramp, which is how a 300 Mbit
    line read back as 100. Small enough that one fetch cannot approach the
    API timeout, which is how the slowest lines failed outright.
    """
    if rate_bps <= 0:
        return DOWNLOAD_MIN_BYTES
    want = min(rate_bps * target, DOWNLOAD_MAX_BYTES)
    # The floor keeps a merely slow line from measuring handshakes...
    want = max(want, DOWNLOAD_MIN_BYTES)
    # ...but the timeout beats it. On a genuinely awful line a 2 MB fetch
    # outlasts the API read and returns a socket error with nothing
    # measured, and a small answer is worth more than no answer.
    want = min(want, rate_bps * api_timeout * TIMEOUT_SHARE)
    return int(max(ABSOLUTE_MIN_BYTES, want))


def _fetch_once(api, url: str) -> tuple:
    """(bytes, seconds) for one fetch. Raises what the router raised."""
    t0 = time.monotonic()
    rows = list(api.device.api.path("tool", "fetch")(
        "", url=url, mode="http", output="none",
        **{"check-certificate": "no"}))
    return _fetched_bytes(rows, url), time.monotonic() - t0


def _probe_download(api) -> tuple:
    """(chunk_bytes, rate_bps, error) -- how fast, and what to ask for next.

    Two probes, because one cannot answer both ends of the range. A 2 MB
    fetch completes on the slowest line there is, but on a fast one it is
    over before TCP has opened its window, so it reports a fraction of the
    truth. When the first probe comes back quickly the second asks for
    something big enough to measure properly.
    """
    timeout = _api_timeout(api)
    try:
        got, took = _fetch_once(api, download_url(DOWNLOAD_PROBE_BYTES))
    except Exception as exc:  # noqa: BLE001
        return 0, 0.0, str(exc)
    if not got:
        return 0, 0.0, "the router reported no bytes"
    rate = got / max(took, 0.001)

    if took < 1.0:
        # Fast enough that the first probe measured mostly the handshake.
        bigger = choose_chunk(rate, timeout)
        try:
            got2, took2 = _fetch_once(api, download_url(bigger))
            if got2 and took2 > 0.05:
                rate = max(rate, got2 / took2)
        except Exception:  # noqa: BLE001 - the first probe still stands
            pass
    return choose_chunk(rate, timeout), rate, ""


def _download_stream(connect, url, deadline, tally, own_api=None):
    """Fetch in a loop until the deadline, counting bytes into `tally`."""
    api = own_api
    ctx = None
    try:
        if api is None:
            ctx = connect()
            api = ctx.__enter__()
        while time.monotonic() < deadline:
            try:
                got, took = _fetch_once(api, url)
            except Exception as exc:  # noqa: BLE001
                with tally["lock"]:
                    tally["error"] = tally["error"] or str(exc)
                return
            if not got:
                with tally["lock"]:
                    tally["error"] = (tally["error"]
                                      or "the router reported no bytes")
                return
            with tally["lock"]:
                tally["bytes"] += got
                tally["runs"] += 1
                if took > 0.05:
                    this = (got * 8) / took / 1_000_000
                    tally["best_stream"] = max(tally["best_stream"], this)
    except Exception as exc:  # noqa: BLE001
        with tally["lock"]:
            tally["error"] = tally["error"] or str(exc)
    finally:
        if ctx is not None:
            try:
                ctx.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass


def _phase_download(api, connect=None, url: str = "", seconds: int = 0,
                    streams: int = DOWNLOAD_STREAMS) -> dict:
    """Fetch repeatedly for the duration, on several connections at once.

    Both of this phase's old faults came from one fixed 10 MB fetch on one
    connection.

    At 300 Mbit/s that transfer lasts a quarter of a second, and TCP spends
    most of a quarter-second still opening its window -- slow start needs
    about a dozen round trips, which at 20 ms is 240 ms of ramp inside a 270
    ms transfer. What came out was the average of the ramp. Add a fresh
    handshake per fetch, since /tool/fetch opens one every time, and the line
    read back at roughly a third of itself.

    At the other end, 10 MB needs 80 seconds on a 1 Mbit link, and the API
    read blocks for the whole fetch -- so the slowest devices could not
    finish one and the phase died with a socket error instead of a slow
    answer.

    Now the size is probed and chosen to last a few seconds whatever the line
    does, and several fetches run at once so their ramps overlap rather than
    being measured end to end.
    """
    seconds = int(seconds or PHASE_SECONDS)
    out = {"url": url or DOWNLOAD_URL, "seconds": 0.0, "bytes": 0,
           "mbps": None, "per_stream_mbps": None, "runs": 0, "error": "",
           "streams": 0, "chunk_mb": 0.0}

    if url:
        chunk, err = 0, ""          # an explicit url is used as given
    else:
        chunk, _rate, err = _probe_download(api)
        if err:
            out["error"] = err
            return out
        url = download_url(chunk)
        out["url"] = url
        out["chunk_mb"] = round(chunk / 1_000_000, 1)

    tally = {"lock": threading.Lock(), "bytes": 0, "runs": 0, "best_stream": 0.0,
             "error": ""}
    deadline = time.monotonic() + seconds
    started = time.monotonic()

    threads = [threading.Thread(
        target=_download_stream, args=(connect, url, deadline, tally, api),
        name="speedtest-down-0", daemon=True)]
    if connect is not None:
        for i in range(1, max(1, int(streams))):
            threads.append(threading.Thread(
                target=_download_stream,
                args=(connect, url, deadline, tally, None),
                name=f"speedtest-down-{i}", daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=seconds + _api_timeout(api) + 10)

    out["seconds"] = round(time.monotonic() - started, 2)
    out["bytes"] = tally["bytes"]
    out["runs"] = tally["runs"]
    out["streams"] = len(threads)
    out["per_stream_mbps"] = round(tally["best_stream"], 2) or None
    # One stream falling over still leaves a measurement; say so without
    # throwing the answer away.
    if tally["error"] and not tally["bytes"]:
        out["error"] = tally["error"]
    elif tally["error"]:
        out["error"] = f"one stream stopped early ({tally['error']})"
    if out["bytes"] and out["seconds"] > 0.05:
        out["mbps"] = round((out["bytes"] * 8) / out["seconds"] / 1_000_000, 2)
    return out


def upload_supported(ros_version: str) -> bool:
    """Can this RouterOS POST a body with /tool/fetch?

    http-data arrived in RouterOS 7. On 6.x the upload phase is skipped and
    said to be skipped, rather than reported as zero -- a made-up figure is
    worse than an absent one.
    """
    # _ros_version returns (major, minor, raw_string), not a string. Taking
    # str() of that and splitting on "." produced "(7, 14, '7" -- so this
    # answered False for every RouterOS 7 router there is, and the upload
    # phase would have been skipped on all of them while saying the router
    # was too old.
    if isinstance(ros_version, (tuple, list)):
        try:
            return int(ros_version[0]) >= 7
        except (ValueError, TypeError, IndexError):
            ros_version = ros_version[-1] if ros_version else ""
    major = str(ros_version or "").strip().split(".", 1)[0].strip()
    try:
        return int(major) >= 7
    except ValueError:
        return False


def _post_once(api, url: str, payload: str) -> None:
    """One POST of `payload` from the router. Raises if the router refuses."""
    list(api.device.api.path("tool", "fetch")(
        "", url=url, mode="http", output="none",
        **{"http-method": "post", "http-data": payload,
           "check-certificate": "no"}))


def _probe_payload(api, connect, url: str, sizes=UPLOAD_SIZES) -> tuple:
    """(api, payload, note) -- the largest body this router will actually send.

    The API connection does not survive an oversized sentence: RouterOS
    resets it, which takes the rest of the run down with it. So each size is
    tried once, and a failure means reconnecting before trying the next --
    the returned api is the live one, which may not be the one passed in.

    Returns payload="" when nothing worked, with the reason in the note.
    """
    last = ""
    for size in sizes:
        payload = "0123456789abcdef" * (size // 16)
        try:
            _post_once(api, url, payload)
            return api, payload, ""
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            log.info("upload: %d KiB refused (%s); reconnecting to try "
                     "smaller", size // 1024, last)
            try:
                api = connect().__enter__()
            except Exception as conn_exc:  # noqa: BLE001
                return None, "", (f"the router stopped answering after a "
                                  f"{size // 1024} KiB body: {conn_exc}")
    return api, "", (f"the router refused every body size down to "
                     f"{sizes[-1] // 1024} KiB: {last}")


def _upload_stream(connect, url, payload, deadline, tally, own_api=None):
    """POST in a loop until the deadline, counting bytes into `tally`."""
    api = own_api
    ctx = None
    try:
        if api is None:
            ctx = connect()
            api = ctx.__enter__()
        while time.monotonic() < deadline:
            t0 = time.monotonic()
            try:
                _post_once(api, url, payload)
            except Exception as exc:  # noqa: BLE001
                with tally["lock"]:
                    tally["error"] = tally["error"] or str(exc)
                return
            took = time.monotonic() - t0
            with tally["lock"]:
                tally["bytes"] += len(payload)
                tally["runs"] += 1
                if took > 0.05:
                    this = (len(payload) * 8) / took / 1_000_000
                    tally["best_stream"] = max(tally["best_stream"], this)
    except Exception as exc:  # noqa: BLE001
        with tally["lock"]:
            tally["error"] = tally["error"] or str(exc)
    finally:
        if ctx is not None:
            try:
                ctx.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass


def _phase_upload(api, connect, url: str = UPLOAD_URL, seconds: int = 0,
                  streams: int = UPLOAD_STREAMS) -> dict:
    """POST a payload, on several connections at once. A LOWER BOUND.

    Read the limitation before the figure. /tool/fetch can only POST a body
    that was handed to it, and the only way to hand a router a body is
    through the API -- so every payload travels from this server, across the
    internet, into the router, before the router sends one byte to
    Cloudflare. The timing wraps that whole journey.

    Which means the number is bounded by OUR path to the router, not by the
    customer's upload, and on a real line it has come out at 0.3 Mbit/s
    against a measured 158. It is reported as a floor, never as the line,
    and `via_api` says so in the result.

    Measuring upload properly needs the payload to originate on the router,
    which means a file on its storage -- a deliberate trade nobody has
    agreed to yet.

    One stream cannot measure an upload. Every POST is a fresh TCP
    connection from the router, so each payload costs a handshake out and a
    response back -- two round trips that no amount of data hides, because
    the payload itself is capped by what the API will carry. At 55 ms and
    128 KiB, most of the elapsed time is waiting, and the answer comes out
    at a third of the real line. Running several at once overlaps the
    waiting, which is the whole trick behind every speed test there is.

    The figure reported is aggregate: total bytes over the wall-clock
    window, which is what the line actually carried.
    """
    from .push.features import _ros_version

    seconds = int(seconds or PHASE_SECONDS)
    out = {"url": url, "seconds": 0.0, "bytes": 0, "mbps": None,
           "per_stream_mbps": None, "runs": 0, "error": "", "skipped": False,
           "streams": 0, "chunk_kib": 0, "via_api": True}
    ros = _ros_version(api)
    if not upload_supported(ros):
        out["skipped"] = True
        shown = (ros[-1] if isinstance(ros, (tuple, list)) and ros
                 else ros) or "on this router"
        out["error"] = (f"RouterOS {shown} cannot POST a body with "
                        f"/tool/fetch; upload needs RouterOS 7.")
        return out

    api, payload, note = _probe_payload(api, connect, url)
    if not payload:
        out["error"] = note
        return out
    out["chunk_kib"] = len(payload) // 1024

    tally = {"lock": threading.Lock(), "bytes": 0, "runs": 0, "best_stream": 0.0,
             "error": ""}
    deadline = time.monotonic() + seconds
    started = time.monotonic()
    threads = [threading.Thread(
        target=_upload_stream,
        args=(connect, url, payload, deadline, tally, api),
        name="speedtest-up-0", daemon=True)]
    for i in range(1, max(1, int(streams))):
        threads.append(threading.Thread(
            target=_upload_stream,
            args=(connect, url, payload, deadline, tally, None),
            name=f"speedtest-up-{i}", daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=seconds + 60)

    out["seconds"] = round(time.monotonic() - started, 2)
    out["bytes"] = tally["bytes"]
    out["runs"] = tally["runs"]
    out["streams"] = len(threads)
    out["per_stream_mbps"] = round(tally["best_stream"], 2) or None
    # A stream that died is worth saying, but only if it cost the answer:
    # with three running, one falling over still leaves a measurement.
    if tally["error"] and not tally["bytes"]:
        out["error"] = tally["error"]
    elif tally["error"]:
        out["error"] = f"one stream stopped early ({tally['error']})"
    if out["bytes"] and out["seconds"] > 0.05:
        out["mbps"] = round((out["bytes"] * 8) / out["seconds"] / 1_000_000, 2)
    return out


def _fetched_bytes(rows, url: str) -> int:
    """How much the router says it pulled. RouterOS reports KiB."""
    got = 0
    for r in rows or []:
        for key in ("downloaded", "total"):
            raw = r.get(key)
            if raw in (None, ""):
                continue
            try:
                got = max(got, int(float(str(raw).strip())) * 1024)
            except ValueError:
                continue
    if got:
        return got
    # Cloudflare's endpoint names the size in the URL, so a router that
    # reports nothing useful still gives a usable figure.
    if "bytes=" in url:
        try:
            return int(url.rsplit("bytes=", 1)[-1].split("&")[0])
        except ValueError:
            return 0
    return 0
