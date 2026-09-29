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
import logging
import sqlite3
import threading
import time

from .config import ConfigError, DEFAULT_CHECKS, build_device, device_to_dict

log = logging.getLogger(__name__)

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
        # WAL lets the engine thread read while the web thread writes without
        # "database is locked" errors.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        # Add org_id to pre-multi-tenant DBs (all existing devices -> org 1).
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(devices)")]
        if "org_id" not in cols:
            self.db.execute(
                "ALTER TABLE devices ADD COLUMN org_id INTEGER NOT NULL DEFAULT 1")
        # Departments: a VLAN, a subnet and a NextDNS profile, belonging to
        # one router. Stored here rather than with the org because they are
        # configuration OF a device -- the VLAN exists on a particular
        # bridge, on particular ports, and moving the router moves them.
        self.db.executescript("""
CREATE TABLE IF NOT EXISTS departments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device     TEXT NOT NULL,
    name       TEXT NOT NULL,
    vlan       INTEGER NOT NULL,
    subnet     TEXT NOT NULL,
    profile_id TEXT,
    resolvers  TEXT,
    ports      TEXT,
    note       TEXT,
    created    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dept_device ON departments(device);
CREATE UNIQUE INDEX IF NOT EXISTS ix_dept_name ON departments(device, name);
""")
        self.db.commit()
        self._migrate_checks()

    def _migrate_checks(self) -> None:
        """Strip stored check values that are redundant with the current default,
        so raising a default from False→True automatically applies to devices
        that never explicitly stored anything for that key.

        This only removes values that EQUAL the current default (a pure storage
        compaction — inheriting the default is behaviourally identical to the
        stored value). It must never remove a stored False against a True
        default as "stale": this runs on every DevicesStore() construction (i.e.
        on nearly every request), so that would silently and repeatedly revert
        any device where a user deliberately unchecked a check that defaults to
        on (e.g. turning off "security" or "interfaces" monitoring for one
        site) — the checkbox would look reset the next time the page loads."""
        changed = False
        with self._lock:
            rows = self.db.execute(
                "SELECT name, config FROM devices").fetchall()
            for name, blob in rows:
                raw = json.loads(blob)
                checks = raw.get("checks") or {}
                pruned = {k: v for k, v in checks.items()
                          if v != DEFAULT_CHECKS.get(k)}
                if pruned != checks:
                    raw["checks"] = pruned
                    self.db.execute(
                        "UPDATE devices SET config = ? WHERE name = ?",
                        (json.dumps(raw), name))
                    changed = True
            if changed:
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
                org_id = int(row[0]) if row else 1
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

    def count_for_org(self, org_id: int) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM devices WHERE org_id = ?",
            (int(org_id),)).fetchone()[0]

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
        for r in self.db.execute("SELECT name, config FROM devices ORDER BY name"):
            try:
                out.append(build_device(json.loads(r[1]), defaults))
            except (ConfigError, json.JSONDecodeError) as exc:
                log.warning("device %r has an invalid stored config and is "
                            "NOT being monitored: %s", r[0], exc)
                continue
        return out

    # ----- departments ----------------------------------------------------

    def departments(self, device: str) -> list:
        """Every department on this router, in VLAN order.

        Returned already validated, so a row written by an older version --
        or edited in the database by hand -- surfaces as a problem here
        rather than as a push that half applies.
        """
        from .departments import DepartmentError, make

        rows = self.db.execute(
            "SELECT name, vlan, subnet, profile_id, resolvers, ports, note "
            "FROM departments WHERE device = ? ORDER BY vlan",
            (device,)).fetchall()
        out = []
        for name, vlan, subnet, pid, res, ports, note in rows:
            try:
                out.append(make(name, vlan, subnet, pid or "", res or "",
                                note or "", ports or ""))
            except DepartmentError as exc:
                log.warning("department %r on %s is unusable: %s",
                            name, device, exc)
        return out

    def save_department(self, device: str, dept: dict,
                        original_name: str | None = None) -> None:
        """Add or replace one department. `dept` comes from departments.make."""
        with self._lock:
            self.db.execute(
                "DELETE FROM departments WHERE device = ? AND name = ?",
                (device, original_name or dept["name"]))
            self.db.execute(
                "INSERT INTO departments (device, name, vlan, subnet, "
                "profile_id, resolvers, ports, note, created) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device, dept["name"], dept["vlan"], dept["subnet"],
                 dept.get("profile_id") or "",
                 ",".join(dept.get("resolvers") or []),
                 ",".join(dept.get("ports") or []),
                 dept.get("note") or "", time.time()))
            self.db.commit()

    def delete_department(self, device: str, name: str) -> None:
        with self._lock:
            self.db.execute(
                "DELETE FROM departments WHERE device = ? AND name = ?",
                (device, name))
            self.db.commit()

    def close(self) -> None:
        with self._lock:
            self.db.close()
