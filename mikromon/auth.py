"""User accounts and per-user device authorization.

Stores users in a small SQLite DB. Passwords are salted + PBKDF2-hashed (stdlib,
no dependencies). Each user has a role and a set of devices they may see:

  * role "admin"  -> sees ALL devices and can manage users.
  * role "user"   -> sees only the devices an admin granted (a list, or "*").

Data isolation is enforced at the web layer: every data response is filtered to
`allowed_devices(user, ...)`, so one user can never see another's devices.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time

_ITERATIONS = 200_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    pw_hash    TEXT NOT NULL,
    salt       TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    devices    TEXT NOT NULL DEFAULT '[]',   -- JSON list, or the string "*"
    created    REAL NOT NULL
);
"""


def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = _ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt.hex(), dk.hex(), iterations


def _verify(password: str, salt_hex: str, hash_hex: str, iterations: int) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(dk.hex(), hash_hex)


class AuthError(Exception):
    pass


class AuthStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.db.commit()

    # ----- mutations --------------------------------------------------------
    def add_user(self, username: str, password: str, role: str = "user",
                 devices=None) -> None:
        username = username.strip()
        if not username:
            raise AuthError("Username cannot be empty.")
        if self.get_user(username):
            raise AuthError(f"User {username!r} already exists.")
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters.")
        salt, pw_hash, iters = hash_password(password)
        with self._lock:
            self.db.execute(
                "INSERT INTO users (username, pw_hash, salt, iterations, role, "
                "devices, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, pw_hash, salt, iters, _norm_role(role),
                 _dump_devices(devices), time.time()))
            self.db.commit()

    def set_password(self, username: str, password: str) -> None:
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters.")
        salt, pw_hash, iters = hash_password(password)
        self._update(username, pw_hash=pw_hash, salt=salt, iterations=iters)

    def set_devices(self, username: str, devices) -> None:
        self._update(username, devices=_dump_devices(devices))

    def set_role(self, username: str, role: str) -> None:
        self._update(username, role=_norm_role(role))

    def delete_user(self, username: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM users WHERE username = ?", (username,))
            self.db.commit()

    def _update(self, username: str, **cols) -> None:
        if not self.get_user(username):
            raise AuthError(f"No such user: {username!r}")
        sets = ", ".join(f"{k} = ?" for k in cols)
        with self._lock:
            self.db.execute(f"UPDATE users SET {sets} WHERE username = ?",
                            (*cols.values(), username))
            self.db.commit()

    # ----- queries ----------------------------------------------------------
    def get_user(self, username: str) -> dict | None:
        cur = self.db.execute(
            "SELECT username, pw_hash, salt, iterations, role, devices, created "
            "FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return None
        return {"username": row[0], "pw_hash": row[1], "salt": row[2],
                "iterations": row[3], "role": row[4],
                "devices": _load_devices(row[5]), "created": row[6]}

    def list_users(self) -> list:
        cur = self.db.execute(
            "SELECT username, role, devices, created FROM users ORDER BY username")
        return [{"username": r[0], "role": r[1], "devices": _load_devices(r[2]),
                 "created": r[3]} for r in cur.fetchall()]

    def count_admins(self) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]

    def verify(self, username: str, password: str) -> dict | None:
        user = self.get_user(username)
        if not user:
            # Spend ~equal time to reduce username enumeration via timing.
            hash_password(password)
            return None
        if _verify(password, user["salt"], user["pw_hash"], user["iterations"]):
            return user
        return None

    # ----- authorization ----------------------------------------------------
    @staticmethod
    def is_admin(user: dict) -> bool:
        return bool(user) and user.get("role") == "admin"

    @classmethod
    def can_see(cls, user: dict, device: str) -> bool:
        if cls.is_admin(user):
            return True
        devs = user.get("devices")
        return devs == "*" or (isinstance(devs, list) and device in devs)

    @classmethod
    def allowed_devices(cls, user: dict, all_devices) -> list:
        if cls.is_admin(user) or user.get("devices") == "*":
            return list(all_devices)
        allow = set(user.get("devices") or [])
        return [d for d in all_devices if d in allow]

    def close(self) -> None:
        with self._lock:
            self.db.close()


def _norm_role(role: str) -> str:
    role = (role or "user").strip().lower()
    return "admin" if role == "admin" else "user"


def _dump_devices(devices) -> str:
    if devices in ("*", ["*"]):
        return "*"
    if devices is None:
        return "[]"
    if isinstance(devices, str):
        devices = [d.strip() for d in devices.split(",") if d.strip()]
        if devices == ["*"]:
            return "*"
    return json.dumps(sorted(set(devices)))


def _load_devices(raw: str):
    if raw == "*":
        return "*"
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
