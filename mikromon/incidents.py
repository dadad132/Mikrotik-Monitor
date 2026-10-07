"""WAN incidents: one row per time a site lost its main line.

An alert is a moment -- "fibre down, on LTE". An incident is the whole
episode: when the line actually went, what the router could see about it,
what the likely cause is (from the router, from the rest of the fleet, and
from a search online), how much of the backup it has used, and when the
people responsible were last reminded that the site is still on its backup.

Written by the monitoring engine and read by the dashboard, so it is SQLite
in WAL mode like the other shared stores: the two processes never step on
each other, and a restart of either loses nothing.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device       TEXT NOT NULL,
    kind         TEXT NOT NULL,          -- wan_failover | internet_down
    started      REAL NOT NULL,          -- best estimate of when the line went
    detected     REAL NOT NULL,          -- when the alert fired
    ended        REAL,
    primary_link TEXT,
    backup_link  TEXT,
    isp          TEXT,
    area         TEXT,
    evidence     TEXT,                   -- JSON: what the router showed
    verdict      TEXT,                   -- see aimonitor.VERDICTS
    confidence   TEXT,
    summary      TEXT,
    action       TEXT,
    sources      TEXT,                   -- JSON [{url, title}]
    ai_state     TEXT NOT NULL DEFAULT 'pending',
    ai_checked   REAL,
    ai_error     TEXT,
    ai_runs      INTEGER NOT NULL DEFAULT 0,
    ai_searches  INTEGER NOT NULL DEFAULT 0,
    cause_mailed REAL,
    reminders    INTEGER NOT NULL DEFAULT 0,
    last_reminder REAL,
    backup_bytes INTEGER
);
CREATE INDEX IF NOT EXISTS ix_inc_device ON incidents(device, ended);
CREATE INDEX IF NOT EXISTS ix_inc_started ON incidents(started);
-- One row per call to the AI, for the daily limit and the Platform panel.
CREATE TABLE IF NOT EXISTS ai_calls (
    ts       REAL NOT NULL,
    device   TEXT,
    searches INTEGER NOT NULL DEFAULT 0,
    ok       INTEGER NOT NULL DEFAULT 1,
    error    TEXT
);
CREATE INDEX IF NOT EXISTS ix_ai_calls_ts ON ai_calls(ts);
"""

_JSON_COLS = ("evidence", "sources")


def incidents_path(devices_db: str | None, explicit: str | None = None) -> str:
    """Where the incidents DB lives: beside devices.db unless configured.

    Both the engine and the dashboard derive it the same way, so neither
    has to be told about the other.
    """
    if explicit:
        return explicit
    base = os.path.dirname(os.path.abspath(devices_db)) if devices_db else "."
    return os.path.join(base, "incidents.db")


def norm_key(text: str) -> str:
    """"Vumatel (Pty) Ltd" and "vumatel" compare equal; so do "Umhlanga,
    Durban" and "umhlanga durban". Used to recognise the same ISP or area
    across sites that typed it slightly differently."""
    t = re.sub(r"\(.*?\)", " ", str(text or "").lower())
    t = re.sub(r"\b(pty|ltd|limited|inc|fibre|fiber|lte|isp)\b", " ", t)
    return " ".join(re.findall(r"[a-z0-9]+", t))


class IncidentStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        with self._lock:
            self.db.close()

    @staticmethod
    def _row(r) -> dict | None:
        if r is None:
            return None
        d = dict(r)
        for c in _JSON_COLS:
            try:
                d[c] = json.loads(d[c]) if d.get(c) else (
                    {} if c == "evidence" else [])
            except ValueError:
                d[c] = {} if c == "evidence" else []
        return d

    # ----- lifecycle --------------------------------------------------------
    def open_incident(self, device: str, kind: str, *, started: float,
                      detected: float, primary_link: str = "",
                      backup_link: str = "", isp: str = "", area: str = "",
                      evidence: dict | None = None, verdict: str = "",
                      confidence: str = "", summary: str = "",
                      action: str = "", ai_state: str = "pending") -> dict:
        """Open an incident, or return the one already open for this device
        and kind -- a restart of the engine re-announces conditions, and that
        must not split one outage into two."""
        with self._lock:
            cur = self.db.execute(
                "SELECT * FROM incidents WHERE device=? AND kind=? AND "
                "ended IS NULL ORDER BY id DESC LIMIT 1", (device, kind))
            row = cur.fetchone()
            if row is not None:
                return self._row(row)
            c = self.db.execute(
                "INSERT INTO incidents (device, kind, started, detected, "
                "primary_link, backup_link, isp, area, evidence, verdict, "
                "confidence, summary, action, ai_state) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (device, kind, float(started), float(detected), primary_link,
                 backup_link, isp, area, json.dumps(evidence or {}), verdict,
                 confidence, summary, action, ai_state))
            self.db.commit()
            return self._row(self.db.execute(
                "SELECT * FROM incidents WHERE id=?", (c.lastrowid,)).fetchone())

    def close_incident(self, device: str, kind: str, ended: float,
                       backup_bytes: int | None = None) -> dict | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM incidents WHERE device=? AND kind=? AND "
                "ended IS NULL ORDER BY id DESC LIMIT 1",
                (device, kind)).fetchone()
            if row is None:
                return None
            self.db.execute(
                "UPDATE incidents SET ended=?, backup_bytes=COALESCE(?, "
                "backup_bytes) WHERE id=?", (float(ended), backup_bytes,
                                             row["id"]))
            self.db.commit()
            return self._row(self.db.execute(
                "SELECT * FROM incidents WHERE id=?", (row["id"],)).fetchone())

    def update(self, incident_id: int, **fields) -> None:
        if not fields:
            return
        for c in _JSON_COLS:
            if c in fields and not isinstance(fields[c], str):
                fields[c] = json.dumps(fields[c])
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self.db.execute(f"UPDATE incidents SET {cols} WHERE id=?",
                            (*fields.values(), int(incident_id)))
            self.db.commit()

    # ----- reads ------------------------------------------------------------
    def get(self, incident_id: int) -> dict | None:
        return self._row(self.db.execute(
            "SELECT * FROM incidents WHERE id=?", (int(incident_id),)).fetchone())

    def open_for(self, device: str, kind: str | None = None) -> dict | None:
        q = "SELECT * FROM incidents WHERE device=? AND ended IS NULL"
        args: list = [device]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        return self._row(self.db.execute(
            q + " ORDER BY id DESC LIMIT 1", args).fetchone())

    def open_all(self) -> list:
        return [self._row(r) for r in self.db.execute(
            "SELECT * FROM incidents WHERE ended IS NULL ORDER BY started")]

    def recent(self, device: str, since: float) -> list:
        """This device's incidents that started after `since`, newest first."""
        return [self._row(r) for r in self.db.execute(
            "SELECT * FROM incidents WHERE device=? AND started>=? "
            "ORDER BY started DESC", (device, float(since)))]

    def latest(self, device: str) -> dict | None:
        return self._row(self.db.execute(
            "SELECT * FROM incidents WHERE device=? ORDER BY id DESC LIMIT 1",
            (device,)).fetchone())

    def around(self, start: float, window: float, exclude_device: str = "") -> list:
        """Other sites' incidents that started within `window` seconds of
        `start` -- the raw material for "is this one site, or everyone on
        that ISP?"."""
        return [self._row(r) for r in self.db.execute(
            "SELECT * FROM incidents WHERE started BETWEEN ? AND ? "
            "AND device<>?", (start - window, start + window, exclude_device))]

    def pending_ai(self, limit: int = 5) -> list:
        return [self._row(r) for r in self.db.execute(
            "SELECT * FROM incidents WHERE ai_state='pending' "
            "ORDER BY detected LIMIT ?", (int(limit),))]

    def recent_ai_result(self, isp_key: str, area_key: str,
                         since: float) -> dict | None:
        """A finished online check for the same ISP in the same area since
        `since`, to reuse instead of searching again -- ten sites on one
        fibre network going down together is one question, not ten."""
        if not isp_key:
            return None
        for r in self.db.execute(
                "SELECT * FROM incidents WHERE ai_state='done' AND "
                "ai_checked>=? ORDER BY ai_checked DESC", (float(since),)):
            d = self._row(r)
            if (norm_key(d.get("isp", "")) == isp_key
                    and norm_key(d.get("area", "")) == area_key):
                return d
        return None

    # ----- AI usage --------------------------------------------------------
    def log_ai_call(self, device: str, searches: int, ok: bool,
                    error: str = "", ts: float | None = None) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO ai_calls (ts, device, searches, ok, error) "
                "VALUES (?,?,?,?,?)", (ts if ts is not None else time.time(),
                                       device, int(searches or 0),
                                       1 if ok else 0, error or ""))
            self.db.commit()

    def ai_usage(self, since: float) -> dict:
        """{"calls", "searches", "failed", "last_error", "last_ts"} since
        `since`."""
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(searches),0), "
            "COALESCE(SUM(1-ok),0), MAX(ts) FROM ai_calls WHERE ts>=?",
            (float(since),)).fetchone()
        err = self.db.execute(
            "SELECT error, ts FROM ai_calls WHERE ok=0 ORDER BY ts DESC "
            "LIMIT 1").fetchone()
        return {"calls": int(row[0] or 0), "searches": int(row[1] or 0),
                "failed": int(row[2] or 0), "last_ts": row[3],
                "last_error": err["error"] if err else "",
                "last_error_ts": err["ts"] if err else None}
