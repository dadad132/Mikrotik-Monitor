"""Restarts started from the dashboard, so the monitor can tell them apart
from a router that fell over.

Reboot, an update, a script that restarts the router, a restored backup:
each takes the router offline on purpose, for a minute or three. To the
monitor that looked exactly like a router dying, so it emailed "Device
UNREACHABLE" -- and then "reachable again" -- about something the person
reading it had just done.

The dashboard and the monitor are separate processes. So the dashboard
writes one small JSON file beside the devices database when it restarts a
router, saying when the restart begins and how late it may begin, and the
monitor reads it on every poll. A router it was told about that goes offline
in that window has its alerts held for GRACE_SECONDS, and the dashboard calls
it Restarting rather than Offline. Back within that time, nobody is emailed
at all. Still down after it, the alert goes out, saying it was restarted
from the dashboard and did not come back.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)

FILENAME = "planned_restarts.json"

# How long a router restarted from the dashboard may stay offline before
# anybody is emailed about it. A reboot is a minute or two; an update with
# its install, two or three. Five covers both with room to spare.
GRACE_SECONDS = 5 * 60

# A restart booked to begin at a time is allowed to begin this much early:
# the router's clock and this server's can be a minute apart.
EARLY_SECONDS = 60

# Records long past are dropped the next time the file is written.
_KEEP_SECONDS = 2 * 86400

_lock = threading.Lock()


def path_for(devices_db) -> str:
    """Where the file lives: beside the devices database. "" without one."""
    if not devices_db:
        return ""
    return os.path.join(os.path.dirname(os.path.abspath(devices_db)), FILENAME)


def _load(path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(path, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def plan(path, device, start, latest=None, why="", by="",
         now=None) -> None:
    """Say that `device` is being restarted from the dashboard: going
    offline from `start` (epoch seconds), and beginning no later than
    `latest` -- an update downloads first, which can take a while."""
    if not path or not device:
        return
    now = time.time() if now is None else now
    start = float(start)
    latest = float(latest if latest is not None else start + 120)
    with _lock:
        data = {k: v for k, v in _load(path).items()
                if float((v or {}).get("latest") or 0) + GRACE_SECONDS
                + _KEEP_SECONDS > now}
        data[device] = {"start": start, "latest": latest, "why": str(why),
                        "by": str(by), "set": now}
        try:
            _save(path, data)
        except OSError:
            log.exception("could not record the restart of %s", device)


def cancel(path, device) -> None:
    """The restart booked for `device` is off."""
    if not path:
        return
    with _lock:
        data = _load(path)
        if data.pop(device, None) is not None:
            try:
                _save(path, data)
            except OSError:
                log.exception("could not cancel the restart of %s", device)


def expected(path, now=None) -> dict:
    """{device: record} for every router that may be restarting right now:
    inside the window from (start - EARLY_SECONDS) to latest."""
    if not path:
        return {}
    now = time.time() if now is None else now
    out = {}
    for name, rec in _load(path).items():
        try:
            if (float(rec["start"]) - EARLY_SECONDS <= now
                    <= float(rec["latest"])):
                out[name] = rec
        except (KeyError, TypeError, ValueError):
            continue
    return out


def describe(rec) -> str:
    """"Reboot from the dashboard by owner@alpha.test" -- what the record
    says happened, for the dashboard and the alert."""
    why = (rec or {}).get("why") or "Restarted from the dashboard"
    by = (rec or {}).get("by") or ""
    return f"{why} by {by}" if by else why
