"""Safe mode's server half: confirm a change once the router has survived it,
and notice when one did not.

The router half lives in Pusher.plan_arm_revert: a scheduler, armed BEFORE the
change goes out, that restores the pre-change backup unless something takes
it down. This module is the something.

About a minute after the change the router pings the hub itself. Just after
that, the server logs in over the API -- the same way every later change will
have to -- and removes the timer. Both have to work for a change to be kept:

  * the router cannot reach the hub    -> it restores the backup at once
  * it can, but the server cannot log in -> it restores the backup one
    round later, once the server has had its chance

A change the router had to undo is not left for somebody to discover. The
watcher keeps trying to log in, and when the router is back it checks whether
it rebooted since the change was armed. If it did, the change was undone, and
that is logged and mailed (see the on_event hook web.py passes in). A router
that does not come back at all is reported too: that one needs a person.

Entries live in a small JSON file beside the other stores, so a dashboard
restart in the middle of a change picks up where it left off instead of
abandoning the confirmation -- an abandoned one would mean the router reverts
a perfectly good change.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import uuid

from .api import PushError
from .plan import Operation
from .runner import _REVERT_SCHED, revert_token

log = logging.getLogger(__name__)

# How long after arming the router runs its own check. Each round of the
# timer is this long, so the server's last chance is just before the second.
CHECK_SECONDS = 60
# The server starts logging in just after the router's own check, so a change
# that breaks things a little late is still caught by that check.
CONFIRM_FROM = CHECK_SECONDS + 2
CONFIRM_UNTIL = 2 * CHECK_SECONDS - 5
RETRY_EVERY = 8
# A router that restored its backup reboots. How long to keep looking for it
# before saying it needs a person, and how often to look meanwhile.
WATCH_UNTIL = 15 * 60
WATCH_EVERY = 30
# Finished entries are kept this long so the page that armed a change can
# still show how it ended.
KEEP_FINISHED = 24 * 3600

ACTIVE = ("waiting", "confirming", "unconfirmed")


def new_token() -> str:
    return uuid.uuid4().hex[:12]


def _uptime_seconds(api):
    from ..util import uptime_to_seconds
    try:
        rows = api.fetch(("system", "resource"))
    except Exception:  # noqa: BLE001
        return None
    if not rows:
        return None
    return uptime_to_seconds(rows[0].get("uptime"))


class SafeModeTracker:
    """Pending safe-mode changes, and the worker that settles them.

    `open_api(device)` returns (api, close) for a logged-in read-write
    session, or raises when the router cannot be reached. `on_event(entry,
    event)` is told "confirmed", "reverted" or "lost". Both are injected so
    this can be tested with a fake clock and a fake router.
    """

    def __init__(self, path: str, open_api=None, on_event=None,
                 clock=time.time):
        self.path = path
        self.open_api = open_api
        self.on_event = on_event
        self.clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._entries: dict = self._load()

    # ----- persistence -----------------------------------------------------
    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".safemode-",
                                       suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._entries, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("safe mode: could not save %s: %s", self.path, exc)

    # ----- what the request handlers call ----------------------------------
    def register(self, *, device: str, feature: str, backup: str,
                 token: str, user: str = "", mode: str = "ping",
                 armed_at: float | None = None, org_id=None) -> dict:
        now = self.clock()
        armed = armed_at if armed_at is not None else now
        entry = {"token": token, "device": device, "feature": feature,
                 "backup": backup, "user": user, "mode": mode,
                 "org_id": org_id, "armed_at": armed, "state": "waiting",
                 "next_try": armed + CONFIRM_FROM, "tries": 0,
                 "detail": "", "finished": None, "updated": now}
        with self._lock:
            # A newer change on the same router replaces the timer, so the
            # older entry can never be confirmed now. Say so rather than
            # letting it log in later and report a mismatch.
            for other in self._entries.values():
                if (other.get("device") == device
                        and other.get("state") in ACTIVE):
                    other.update(state="superseded", finished=now,
                                 updated=now,
                                 detail="A newer change replaced this one's "
                                        "safety net.")
            self._entries[token] = entry
            self._prune(now)
            self._save()
        return dict(entry)

    def status(self, device: str, token: str | None = None) -> dict | None:
        """The entry for `token`, or this router's most recent one."""
        with self._lock:
            if token:
                e = self._entries.get(token)
                return dict(e) if e and e.get("device") == device else None
            mine = [e for e in self._entries.values()
                    if e.get("device") == device]
        if not mine:
            return None
        return dict(max(mine, key=lambda e: e.get("armed_at") or 0))

    def active_for(self, device: str) -> dict | None:
        e = self.status(device)
        return e if e and e.get("state") in ACTIVE else None

    def mark_kept(self, device: str, by: str = "") -> None:
        """A person pressed Keep and the timer was taken down by hand."""
        now = self.clock()
        with self._lock:
            for e in self._entries.values():
                if e.get("device") == device and e.get("state") in ACTIVE:
                    e.update(state="confirmed", finished=now, updated=now,
                             detail=f"Kept by {by}." if by else "Kept by hand.")
            self._save()

    def forget(self, token: str) -> None:
        with self._lock:
            self._entries.pop(token, None)
            self._save()

    # ----- the worker ------------------------------------------------------
    def _prune(self, now: float) -> None:
        for tok in [t for t, e in self._entries.items()
                    if e.get("finished") and now - e["finished"] > KEEP_FINISHED]:
            self._entries.pop(tok, None)

    @staticmethod
    def _finish(e: dict, state: str, detail: str, now: float) -> None:
        e.update(state=state, detail=detail, finished=now, updated=now)

    def _fire(self, events) -> None:
        """Run on_event outside the lock: it sends email, which can take a
        while, and the page polling status must not wait on it."""
        for entry, event in events:
            if not self.on_event:
                return
            try:
                self.on_event(entry, event)
            except Exception:  # noqa: BLE001 -- a failed email must not stop the watcher
                log.exception("safe mode: on_event failed for %s",
                              entry.get("device"))

    def _inspect(self, e: dict):
        """Log in and look. Returns (verdict, detail) where verdict is
        "confirmed", "superseded", "reverted", "absent" or "unreachable"."""
        if self.open_api is None:
            return "unreachable", "no way to reach routers is configured"
        try:
            api, close = self.open_api(e["device"])
        except Exception as exc:  # noqa: BLE001 -- unreachable is an answer
            return "unreachable", str(exc) or exc.__class__.__name__
        try:
            try:
                rows = api.fetch(("system", "scheduler"))
            except Exception as exc:  # noqa: BLE001
                return "unreachable", f"logged in but could not read: {exc}"
            timers = [r for r in rows if r.get("name") == _REVERT_SCHED]
            mine = [r for r in timers if revert_token(r) == e["token"]]
            if mine:
                for r in mine:
                    try:
                        api.execute(Operation(
                            "remove", ("system", "scheduler"),
                            {".id": r[".id"]},
                            desc="safe mode: change confirmed"))
                    except PushError as exc:
                        return "unreachable", f"could not remove the timer: {exc}"
                return "confirmed", ""
            if timers:
                return "superseded", "A newer change replaced this one's timer."
            up = _uptime_seconds(api)
            age = self.clock() - e["armed_at"]
            if up is not None and up < age:
                return "reverted", (f"The router restarted {int(up)} s ago, "
                                    f"after the change was made, and its "
                                    f"safety timer is gone.")
            return "absent", "The timer was already gone."
        finally:
            try:
                close()
            except Exception:  # noqa: BLE001
                pass

    def tick(self) -> None:
        """Settle whatever is due. One pass; the thread calls it in a loop."""
        now = self.clock()
        with self._lock:
            due = [dict(e) for e in self._entries.values()
                   if e.get("state") in ACTIVE and now >= e.get("next_try", 0)]
        events = []
        for snap in due:
            # Logging in can take seconds; never with the lock held.
            verdict, detail = self._inspect(snap)
            now = self.clock()
            age = now - snap["armed_at"]
            with self._lock:
                e = self._entries.get(snap["token"])
                if e is None or e.get("state") not in ACTIVE:
                    continue
                e["tries"] = int(e.get("tries", 0)) + 1
                e["updated"] = now
                late = e["state"] == "unconfirmed"
                event = None
                if verdict == "confirmed":
                    self._finish(e, "confirmed",
                                 "Confirmed late: the router could be reached "
                                 "again and still had the change." if late else
                                 "The router can still reach the hub and the "
                                 "server can still log in. The change is kept.",
                                 now)
                    event = "confirmed"
                elif verdict == "superseded":
                    self._finish(e, "superseded", detail, now)
                elif verdict == "reverted":
                    self._finish(e, "reverted", detail, now)
                    event = "reverted"
                elif verdict == "absent":
                    self._finish(e, "confirmed",
                                 detail + " Nothing was undone.", now)
                elif e["state"] in ("waiting", "confirming"):
                    if age < CONFIRM_UNTIL:
                        e.update(state="confirming",
                                 next_try=now + RETRY_EVERY,
                                 detail=f"Could not log in yet: {detail}")
                    else:
                        # Past the server's chance. The router restores its
                        # backup on its next round; look for it coming back.
                        e.update(state="unconfirmed",
                                 next_try=(e["armed_at"]
                                           + 2 * CHECK_SECONDS + 20),
                                 detail="The server could not log in after "
                                        "the change, so the router is "
                                        "putting its previous settings back.")
                elif age >= WATCH_UNTIL:
                    self._finish(e, "lost",
                                 f"The router has not come back "
                                 f"{int(age // 60)} minutes after the change "
                                 f"({detail}). It may need someone on site.",
                                 now)
                    event = "lost"
                else:
                    e["next_try"] = now + WATCH_EVERY
                if event:
                    events.append((dict(e), event))
                self._prune(now)
                self._save()
        self._fire(events)

    def start(self, every: float = 4.0) -> threading.Event:
        def loop():
            while not self._stop.wait(every):
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 -- the watcher must not die
                    log.exception("safe mode watcher tick failed")

        threading.Thread(target=loop, name="mikromon-safemode",
                         daemon=True).start()
        return self._stop


def describe(entry: dict | None, now: float | None = None) -> dict:
    """What the page shows for an entry: {state, headline, detail, wait}."""
    if not entry:
        return {"state": "none", "headline": "", "detail": "", "wait": 0}
    now = now if now is not None else time.time()
    state = entry.get("state", "")
    armed = entry.get("armed_at")
    age = now - (armed if armed is not None else now)
    wait = max(0, int(CHECK_SECONDS - age))
    headline = {
        "waiting": "Watching the change",
        "confirming": "Checking the router can still be managed",
        "confirmed": "Change kept",
        "unconfirmed": "Putting the previous settings back",
        "reverted": "The router put its previous settings back",
        "lost": "The router has not come back",
        "superseded": "Replaced by a newer change",
    }.get(state, state)
    detail = entry.get("detail") or ""
    if state == "waiting":
        detail = (f"In about {wait} s the router checks it can still reach "
                  f"the hub, then the server logs in to confirm. Nothing "
                  f"to do here.")
    return {"state": state, "headline": headline, "detail": detail,
            "wait": wait}
