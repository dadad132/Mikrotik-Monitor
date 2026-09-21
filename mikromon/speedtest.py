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

  PING      loss, latency and jitter, from the router's own /ping. Loss is
            the figure to read first: a line dropping packets is unusable
            for voice long before a speed figure looks bad.
  DOWNLOAD  repeated fetches for the duration, bytes over seconds. Plain
            HTTP: a small MikroTik doing TLS measures its own CPU, not the
            line.
  UPLOAD    POSTs a payload the router already holds. Honest about its
            limits -- see upload_supported() -- because a made-up upload
            figure is worse than none.

Nothing is written to the router's flash in any phase.
"""
from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger(__name__)

PHASE_SECONDS = 30

# Plain HTTP on purpose: HTTPS would make a small router measure its own
# encryption speed rather than the line.
DOWNLOAD_URL = "http://speed.cloudflare.com/__down?bytes=10000000"
UPLOAD_URL = "http://speed.cloudflare.com/__up"
PING_TARGET = "1.1.1.1"

# Seeded over the tunnel once per run and then POSTed repeatedly. Small
# because it crosses the tunnel to get there; the measurement itself is of
# the router's own upload, which is what was asked for.
UPLOAD_CHUNK = 256 * 1024

_runs: dict = {}
_lock = threading.Lock()


def status(name: str) -> dict:
    """What the test for this router is doing, or {} if it never ran."""
    with _lock:
        run = _runs.get(name)
        return dict(run) if run else {}


def is_running(name: str) -> bool:
    return bool(status(name).get("running"))


def _set(name: str, **fields) -> None:
    with _lock:
        _runs.setdefault(name, {}).update(fields)


def start(name: str, connect, on_done=None) -> bool:
    """Begin a test. False if one is already running for this router.

    `connect` is a zero-argument callable returning a context manager that
    yields a connected API -- passed in rather than imported so this module
    stays testable without a router.
    """
    with _lock:
        if (_runs.get(name) or {}).get("running"):
            return False
        _runs[name] = {"running": True, "phase": "connecting",
                       "started": time.time(), "name": name,
                       "ping": None, "download": None, "upload": None,
                       "error": "", "phase_seconds": PHASE_SECONDS}
    threading.Thread(target=_run, args=(name, connect, on_done),
                     name=f"speedtest-{name}", daemon=True).start()
    return True


def _run(name, connect, on_done) -> None:
    try:
        with connect() as api:
            _set(name, phase="ping")
            _set(name, ping=_phase_ping(api))
            _set(name, phase="download")
            _set(name, download=_phase_download(api))
            _set(name, phase="upload")
            _set(name, upload=_phase_upload(api))
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

def _phase_ping(api, target: str = PING_TARGET,
                seconds: int = 0) -> dict:
    """Loss, latency and jitter. RouterOS pings once a second, so the count
    IS the duration."""
    from .push.features import _ms

    seconds = int(seconds or PHASE_SECONDS)
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


def _phase_download(api, url: str = DOWNLOAD_URL,
                    seconds: int = 0) -> dict:
    """Fetch repeatedly for the duration; bytes over elapsed time.

    Repeated rather than one huge file so a fast line is measured over the
    whole window rather than finishing in two seconds and reporting the
    average of a ramp-up.
    """
    seconds = int(seconds or PHASE_SECONDS)
    out = {"url": url, "seconds": 0.0, "bytes": 0, "mbps": None,
           "peak_mbps": None, "runs": 0, "error": ""}
    deadline = time.monotonic() + seconds
    started = time.monotonic()
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            rows = list(api.device.api.path("tool", "fetch")(
                "", url=url, mode="http", output="none",
                **{"check-certificate": "no"}))
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
            break
        took = time.monotonic() - t0
        got = _fetched_bytes(rows, url)
        if not got:
            out["error"] = out["error"] or "the router reported no bytes"
            break
        out["bytes"] += got
        out["runs"] += 1
        if took > 0.05:
            this = (got * 8) / took / 1_000_000
            out["peak_mbps"] = round(max(out["peak_mbps"] or 0.0, this), 2)
    out["seconds"] = round(time.monotonic() - started, 2)
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


def _phase_upload(api, url: str = UPLOAD_URL,
                  seconds: int = 0) -> dict:
    """POST a payload the router holds, repeatedly, for the duration."""
    from .push.features import _ros_version

    seconds = int(seconds or PHASE_SECONDS)
    out = {"url": url, "seconds": 0.0, "bytes": 0, "mbps": None,
           "peak_mbps": None, "runs": 0, "error": "", "skipped": False}
    ros = _ros_version(api)
    if not upload_supported(ros):
        out["skipped"] = True
        shown = (ros[-1] if isinstance(ros, (tuple, list)) and ros
                 else ros) or "on this router"
        out["error"] = (f"RouterOS {shown} cannot POST a body with "
                        f"/tool/fetch; upload needs RouterOS 7.")
        return out

    payload = "0123456789abcdef" * (UPLOAD_CHUNK // 16)
    deadline = time.monotonic() + seconds
    started = time.monotonic()
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            list(api.device.api.path("tool", "fetch")(
                "", url=url, mode="http", output="none",
                **{"http-method": "post", "http-data": payload,
                   "check-certificate": "no"}))
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
            break
        took = time.monotonic() - t0
        out["bytes"] += len(payload)
        out["runs"] += 1
        if took > 0.05:
            this = (len(payload) * 8) / took / 1_000_000
            out["peak_mbps"] = round(max(out["peak_mbps"] or 0.0, this), 2)
    out["seconds"] = round(time.monotonic() - started, 2)
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
