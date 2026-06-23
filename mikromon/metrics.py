"""SQLite-backed time-series store for metrics.

Each poll records numeric samples (CPU, free memory %, throughput per WAN,
client count, ...). The web dashboard and the Prometheus endpoint read from
here. SQLite is used so there are no extra dependencies and the data survives
restarts and is queryable.

A sample is (ts, device, metric, label, value) — `label` distinguishes series
that share a metric name, e.g. throughput per interface (label=interface).
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts     REAL NOT NULL,
    device TEXT NOT NULL,
    metric TEXT NOT NULL,
    label  TEXT NOT NULL DEFAULT '',
    value  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples ON samples (device, metric, label, ts);
"""


class MetricsStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        # check_same_thread=False: the web server reads from another thread.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def record(self, rows) -> None:
        rows = list(rows)
        if not rows:
            return
        with self._lock:
            self.db.executemany(
                "INSERT INTO samples (ts, device, metric, label, value) "
                "VALUES (?, ?, ?, ?, ?)", rows)
            self.db.commit()

    def prune(self, older_than_days: float = 30) -> None:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            self.db.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            self.db.commit()

    def delete_device(self, name: str) -> int:
        """Delete every sample for a device. Returns the number of rows removed.
        Used when a device is deleted from the dashboard so its stale series
        stop showing up (devices() lists anything with samples)."""
        with self._lock:
            cur = self.db.execute("DELETE FROM samples WHERE device = ?", (name,))
            self.db.commit()
            return cur.rowcount

    # ----- queries ----------------------------------------------------------
    def devices(self) -> list:
        cur = self.db.execute("SELECT DISTINCT device FROM samples ORDER BY device")
        return [r[0] for r in cur.fetchall()]

    def latest(self, device: str) -> dict:
        """Most-recent value per (metric, label) for a device."""
        cur = self.db.execute(
            "SELECT metric, label, value, ts FROM samples "
            "WHERE device = ? ORDER BY ts", (device,))
        out = {}
        for metric, label, value, ts in cur.fetchall():
            out[(metric, label)] = {"value": value, "ts": ts}
        return out

    def all_latest(self) -> list:
        """(device, metric, label, value, ts) latest per series — for Prometheus."""
        cur = self.db.execute("SELECT device, metric, label, value, ts FROM samples "
                              "ORDER BY ts")
        seen = {}
        for device, metric, label, value, ts in cur.fetchall():
            seen[(device, metric, label)] = (device, metric, label, value, ts)
        return list(seen.values())

    def series(self, device: str, metric: str, label: str = "",
               since: float | None = None, limit: int = 500) -> list:
        since = since if since is not None else time.time() - 3600
        cur = self.db.execute(
            "SELECT ts, value FROM samples WHERE device = ? AND metric = ? "
            "AND label = ? AND ts >= ? ORDER BY ts LIMIT ?",
            (device, metric, label, since, limit))
        return cur.fetchall()

    def close(self) -> None:
        with self._lock:
            self.db.close()
