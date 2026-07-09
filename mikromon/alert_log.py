"""Persistent alert history — records every WAN/reachability alert (problem
and recovery) as it's dispatched, so the periodic Account-page status report
can summarize what actually HAPPENED during the chosen time frame (e.g. "3
WAN failovers this week, 42 min total downtime") instead of just the
device's live status at the moment the report happens to fire.

Config (config.yaml):
  alert_log_db: ./alert_log.db
"""
from __future__ import annotations

import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    device   TEXT NOT NULL,
    key      TEXT NOT NULL,
    title    TEXT NOT NULL,
    severity INTEGER NOT NULL,
    recovery INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_log_device_ts ON alert_log(device, ts);
"""


class AlertLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        con = self._con()
        try:
            con.executescript(_SCHEMA)
            con.commit()
        finally:
            con.close()

    def _con(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def append(self, device: str, key: str, title: str, severity: int,
               recovery: bool, ts: float | None = None) -> None:
        con = self._con()
        try:
            with self._lock:
                con.execute(
                    "INSERT INTO alert_log (ts, device, key, title, severity, "
                    "recovery) VALUES (?,?,?,?,?,?)",
                    (ts if ts is not None else time.time(), device, key, title,
                     int(severity), int(recovery)))
                con.commit()
        except sqlite3.Error:
            pass  # history is best-effort — must never break alert delivery
        finally:
            con.close()

    def between(self, devices: list, since: float, until: float) -> list:
        """Every logged event for these devices in [since, until), oldest
        first. Includes recovery rows landing exactly at `since` (a problem
        that started before the window but resolved during it) is NOT
        included — only rows whose own timestamp falls in range; pairing
        logic upstream handles "already in progress" cases."""
        if not devices:
            return []
        con = self._con()
        try:
            qs = ",".join("?" for _ in devices)
            rows = con.execute(
                f"SELECT * FROM alert_log WHERE device IN ({qs}) "
                f"AND ts >= ? AND ts < ? ORDER BY ts ASC",
                (*devices, since, until)).fetchall()
            return [dict(r) for r in rows]
        finally:
            con.close()

    def last_open(self, device: str, key: str, before: float):
        """The most recent problem row for device+key before `before` that
        has no matching recovery before it — i.e. a condition already in
        progress when the report window started. None if it was resolved
        (or never happened)."""
        con = self._con()
        try:
            row = con.execute(
                "SELECT * FROM alert_log WHERE device = ? AND key = ? "
                "AND ts < ? ORDER BY ts DESC LIMIT 1",
                (device, key, before)).fetchone()
            if row and not row["recovery"]:
                return dict(row)
            return None
        finally:
            con.close()

    def prune(self, keep_days: int) -> None:
        cutoff = time.time() - keep_days * 86400
        con = self._con()
        try:
            with self._lock:
                con.execute("DELETE FROM alert_log WHERE ts < ?", (cutoff,))
                con.commit()
        finally:
            con.close()

    def close(self) -> None:
        pass  # each call opens/closes its own short-lived connection
