"""Web-managed device inventory (SQLite).

When `devices_db` is configured, devices are stored here and managed from the
dashboard's /devices page instead of being hand-edited in YAML. Each device is
one row keyed by name, with its full configuration kept as a JSON blob; the
engine rebuilds DeviceConfig objects from these rows (and picks up changes on
its next poll, so adds/edits take effect without a restart).

Note: device credentials must be usable to log into the router, so they are
stored recoverably (like config.yaml today). Keep the DB file private; it is
gitignored. Encryption-at-rest is a planned enhancement.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time

from .config import ConfigError, build_device, device_to_dict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    name    TEXT PRIMARY KEY,
    config  TEXT NOT NULL,   -- JSON blob of the raw device dict
    updated REAL NOT NULL,
    org_id  INTEGER NOT NULL DEFAULT 1   -- the company that owns this device
);
"""


class DevicesStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        # Add org_id to pre-multi-tenant DBs (all existing devices -> org 1).
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(devices)")]
        if "org_id" not in cols:
            self.db.execute(
                "ALTER TABLE devices ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1")
        self.db.commit()

    # ----- mutations --------------------------------------------------------
    def upsert(self, raw: dict, defaults: dict, original_name: str | None = None,
               org_id: int | None = None):
        """Validate and insert/update a device. Returns the built DeviceConfig.

        `original_name` (when renaming) is removed after the new row is written.
        `org_id` stamps the owning company; when None on an update the existing
        owner is kept (new devices default to org 1).
        """
        dev = build_device(raw, defaults)            # validates required fields
        blob = json.dumps(device_to_dict(dev))
        with self._lock:
            if org_id is None:
                row = self.db.execute(
                    "SELECT org_id FROM devices WHERE name = ?",
                    (original_name or dev.name,)).fetchone()
                org_id = row[0] if row else 1
            self.db.execute(
                "INSERT INTO devices (name, config, updated, org_id) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                "config=excluded.config, updated=excluded.updated, "
                "org_id=excluded.org_id",
                (dev.name, blob, time.time(), int(org_id)))
            if original_name and original_name != dev.name:
                self.db.execute("DELETE FROM devices WHERE name = ?",
                                (original_name,))
            self.db.commit()
        return dev

    def delete(self, name: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM devices WHERE name = ?", (name,))
            self.db.commit()

    def seed_from(self, device_configs, defaults: dict) -> int:
        """Import a list of DeviceConfig into an empty store (one-time migration)."""
        if self.count() or not device_configs:
            return 0
        n = 0
        for cfg in device_configs:
            self.upsert(device_to_dict(cfg), defaults)
            n += 1
        return n

    # ----- queries ----------------------------------------------------------
    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    def raw(self, name: str) -> dict | None:
        row = self.db.execute("SELECT config FROM devices WHERE name = ?",
                              (name,)).fetchone()
        return json.loads(row[0]) if row else None

    def names(self) -> list:
        return [r[0] for r in self.db.execute(
            "SELECT name FROM devices ORDER BY name").fetchall()]

    def names_for_org(self, org_id: int) -> list:
        return [r[0] for r in self.db.execute(
            "SELECT name FROM devices WHERE org_id = ? ORDER BY name",
            (int(org_id),)).fetchall()]

    def org_of(self, name: str) -> int | None:
        row = self.db.execute("SELECT org_id FROM devices WHERE name = ?",
                              (name,)).fetchone()
        return row[0] if row else None

    def list_configs(self, defaults: dict) -> list:
        """All devices as DeviceConfig objects (skips any that fail to build)."""
        out = []
        for r in self.db.execute("SELECT config FROM devices ORDER BY name"):
            try:
                out.append(build_device(json.loads(r[0]), defaults))
            except (ConfigError, json.JSONDecodeError):
                continue
        return out

    def close(self) -> None:
        with self._lock:
            self.db.close()
