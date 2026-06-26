"""Push activity log — a durable record of every config-push attempt.

This is the "what happened / what went wrong" trail: each dry-run, apply,
success and failure (with the full diff and the error/traceback) is written
here so you can see exactly why a push to a real router did or didn't work,
and fix it.

Stored in its own SQLite file. Opened per-operation (volume is low) so it is
safe to use from the threaded web server without shared cursors.
"""
from __future__ import annotations

import logging
import sqlite3
import time

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS push_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        REAL    NOT NULL,
  device    TEXT    NOT NULL,
  username  TEXT    NOT NULL DEFAULT '',
  feature   TEXT    NOT NULL DEFAULT '',
  mode      TEXT    NOT NULL DEFAULT '',   -- dry-run | apply
  status    TEXT    NOT NULL DEFAULT '',   -- ok | error | preview | rolled-back
  summary   TEXT    NOT NULL DEFAULT '',
  detail    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_push_log_dev ON push_log(device, ts);
"""


class AuditLog:
    def __init__(self, path: str):
        self.path = path
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

    def append(self, device, username, feature, mode, status, summary,
               detail="") -> None:
        con = self._con()
        try:
            con.execute(
                "INSERT INTO push_log (ts, device, username, feature, mode, "
                "status, summary, detail) VALUES (?,?,?,?,?,?,?,?)",
                (time.time(), device, username or "", feature or "", mode or "",
                 status or "", summary or "", detail or ""))
            con.commit()
        except sqlite3.Error as exc:  # never let logging break a push
            log.warning("could not write push log: %s", exc)
        finally:
            con.close()

    def recent(self, limit=100, device=None, feature=None) -> list:
        con = self._con()
        try:
            q = "SELECT * FROM push_log"
            where, args = [], []
            if device:
                where.append("device = ?")
                args.append(device)
            if feature:
                where.append("feature = ?")
                args.append(feature)
            if where:
                q += " WHERE " + " AND ".join(where)
            q += " ORDER BY id DESC LIMIT ?"
            args.append(int(limit))
            return [dict(r) for r in con.execute(q, args).fetchall()]
        finally:
            con.close()

    def last_change(self, device):
        """Timestamp + feature of the most recent SUCCESSFUL real config change
        to a device (excludes the auto-backup / arm-revert / confirm sub-steps).
        Used to tell whether a router that just went down was likely broken by a
        change someone pushed. Returns (ts, feature) or (None, None)."""
        con = self._con()
        try:
            row = con.execute(
                "SELECT ts, feature FROM push_log WHERE device = ? AND "
                "mode = 'apply' AND status = 'ok' "
                "AND feature NOT LIKE '%:backup' "
                "AND feature NOT LIKE '%:arm-revert' "
                "AND feature NOT LIKE '%:confirm' "
                "ORDER BY id DESC LIMIT 1", (device,)).fetchone()
            return (row["ts"], row["feature"]) if row else (None, None)
        finally:
            con.close()

    def close(self) -> None:  # symmetry with the other stores (no-op here)
        pass
