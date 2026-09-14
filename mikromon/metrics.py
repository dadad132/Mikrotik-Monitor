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

-- The most recent value of every series, maintained as samples arrive.
--
-- Reading "the latest value" used to mean GROUP BY over the whole samples
-- table, which costs more every day the service runs: at 30 devices and 30
-- days of history that was 25 seconds to draw one dashboard, since the page
-- asks once per device. This table has one row per series instead of one per
-- sample, so the same read is a few hundred rows regardless of how much
-- history is kept.
CREATE TABLE IF NOT EXISTS latest (
    device TEXT NOT NULL,
    metric TEXT NOT NULL,
    label  TEXT NOT NULL DEFAULT '',
    value  REAL NOT NULL,
    ts     REAL NOT NULL,
    PRIMARY KEY (device, metric, label)
) WITHOUT ROWID;
"""


class MetricsStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        # check_same_thread=False: the web server reads from another thread.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        # WAL's own recommended pairing. The default (FULL) fsyncs on every
        # commit, and record() commits once per poll cycle for the whole
        # fleet. NORMAL can lose the last commit or two if the machine loses
        # power -- which for a monitoring sample means one poll of one metric,
        # against a write cost paid on every cycle forever.
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()
        self._backfill_latest()

    def _backfill_latest(self) -> None:
        """Populate `latest` once, for a database written before it existed.

        Without this an upgraded server opens with an empty `latest` table and
        every dashboard reads nothing at all -- the whole fleet would show no
        CPU, no uptime and no throughput until the next poll refilled it one
        device at a time. The one-off GROUP BY is the very query this table
        exists to stop doing on every page load; paying it once at startup is
        the point.
        """
        with self._lock:
            if self.db.execute(
                    "SELECT 1 FROM latest LIMIT 1").fetchone() is not None:
                return
            if self.db.execute(
                    "SELECT 1 FROM samples LIMIT 1").fetchone() is None:
                return          # a fresh database: nothing to carry over
            started = time.time()
            self.db.execute(
                "INSERT INTO latest (device, metric, label, value, ts) "
                "SELECT device, metric, label, value, MAX(ts) FROM samples "
                "GROUP BY device, metric, label")
            self.db.commit()
            log.info("metrics: built the latest-value index from existing "
                     "history in %.1fs (one-off, on upgrade)",
                     time.time() - started)

    def record(self, rows) -> None:
        rows = list(rows)
        if not rows:
            return
        with self._lock:
            self.db.executemany(
                "INSERT INTO samples (ts, device, metric, label, value) "
                "VALUES (?, ?, ?, ?, ?)", rows)
            # Guarded on ts so an out-of-order write -- a device polled twice
            # concurrently, or a clock stepping backwards -- cannot make an
            # older reading the current one.
            self.db.executemany(
                "INSERT INTO latest (device, metric, label, value, ts) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(device, metric, label) DO UPDATE SET "
                "value=excluded.value, ts=excluded.ts "
                "WHERE excluded.ts >= latest.ts",
                [(d, m, l, v, ts) for ts, d, m, l, v in rows])
            self.db.commit()

    def prune(self, older_than_days: float = 30) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self.db.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            removed = cur.rowcount
            self.db.commit()
        if removed:
            # Worth a log line: this used to run only at startup, so a server
            # left up for weeks kept every sample it had ever taken and got
            # slower the whole time. Seeing the number makes it obvious
            # whether retention is actually being enforced.
            log.info("metrics: pruned %d sample(s) older than %.0f days",
                     removed, older_than_days)
        return removed

    def rename_device(self, old: str, new: str) -> int:
        """Move every sample from one device name to another.

        Without this a rename looks exactly like a delete plus a brand-new
        device: the graphs restart from nothing, and keep_only() then wipes
        the old series for good on the next engine start.
        """
        if not old or not new or old == new:
            return 0
        with self._lock:
            cur = self.db.execute(
                "UPDATE samples SET device = ? WHERE device = ?", (new, old))
            self.db.execute("DELETE FROM latest WHERE device = ?", (new,))
            self.db.execute(
                "UPDATE latest SET device = ? WHERE device = ?", (new, old))
            self.db.commit()
            return cur.rowcount

    def delete_device(self, name: str) -> int:
        """Delete every sample for a device. Returns the number of rows removed.
        Used when a device is deleted from the dashboard so its stale series
        stop showing up (devices() lists anything with samples)."""
        with self._lock:
            cur = self.db.execute("DELETE FROM samples WHERE device = ?", (name,))
            self.db.execute("DELETE FROM latest WHERE device = ?", (name,))
            self.db.commit()
            return cur.rowcount

    def keep_only(self, names) -> int:
        """Delete samples for any device NOT in `names`. Returns rows removed.

        Web-managed mode treats the devices DB as authoritative, so the engine
        calls this each poll to sweep orphan series left by deletes (including
        ones removed in older builds before deletes purged metrics). An empty
        `names` clears everything — correct when no devices are managed."""
        names = list(names)
        with self._lock:
            # Work out whether there is anything to sweep BEFORE touching the
            # samples table. "DELETE ... WHERE device NOT IN (...)" cannot use
            # an index, so it full-scans every sample ever recorded -- and the
            # engine calls this once per poll cycle. At 30 devices and 30 days
            # of history that was a 14-million-row scan every 60 seconds,
            # almost always to delete nothing at all.
            #
            # `latest` holds one row per series rather than one per sample, so
            # asking it which devices exist is a few hundred rows.
            known = {r[0] for r in self.db.execute(
                "SELECT DISTINCT device FROM latest")}
            if names:
                stale = known - set(names)
            else:
                stale = known
            if not stale:
                return 0
            removed = 0
            for dead in stale:
                cur = self.db.execute(
                    "DELETE FROM samples WHERE device = ?", (dead,))
                removed += cur.rowcount
                self.db.execute("DELETE FROM latest WHERE device = ?", (dead,))
            self.db.commit()
            return removed

    # ----- queries ----------------------------------------------------------
    def devices(self) -> list:
        cur = self.db.execute("SELECT DISTINCT device FROM latest ORDER BY device")
        return [r[0] for r in cur.fetchall()]

    def latest(self, device: str) -> dict:
        """Most-recent value per (metric, label) for a device.

        SQLite's bare-column-with-MAX() rule guarantees `value` comes from
        the row holding MAX(ts)."""
        cur = self.db.execute(
            "SELECT metric, label, value, ts FROM latest WHERE device = ?",
            (device,))
        return {(metric, label): {"value": value, "ts": ts}
                for metric, label, value, ts in cur.fetchall()}

    def all_latest(self) -> list:
        """(device, metric, label, value, ts) latest per series — for Prometheus."""
        cur = self.db.execute(
            "SELECT device, metric, label, value, ts FROM latest")
        return cur.fetchall()

    def series(self, device: str, metric: str, label: str = "",
               since: float | None = None, limit: int = 500) -> list:
        since = since if since is not None else time.time() - 3600
        cur = self.db.execute(
            "SELECT ts, value FROM samples WHERE device = ? AND metric = ? "
            "AND label = ? AND ts >= ? ORDER BY ts LIMIT ?",
            (device, metric, label, since, limit))
        return cur.fetchall()

    def up_hourly(self, device: str, since: float, now: float) -> list:
        """Return (hours_ago, avg_value, poll_count) per hour for the 'up' metric.

        Aggregates directly in SQL so the result is always 24 rows or fewer —
        no row-limit truncation regardless of how many raw samples exist."""
        cur = self.db.execute(
            "SELECT CAST((? - ts) / 3600 AS INTEGER) AS h, AVG(value), COUNT(*) "
            "FROM samples "
            "WHERE device = ? AND metric = 'up' AND label = '' "
            "AND ts >= ? AND ts <= ? "
            "GROUP BY h HAVING h >= 0 AND h < 24 "
            "ORDER BY h",
            (now, device, since, now))
        return cur.fetchall()

    def close(self) -> None:
        with self._lock:
            self.db.close()
