"""User accounts, companies (orgs) and per-user device authorization.

Stores companies and users in a small SQLite DB. Passwords are salted +
PBKDF2-hashed (stdlib, no dependencies). The model is multi-tenant:

  * An **organisation** (company) is the tenant boundary. Devices belong to
    exactly one org; nobody ever sees another org's devices or users.
  * A user logs in with their **email** (the unique identifier — there is no
    separate username). Each user belongs to one org and has a role:
      - "owner"  -> created/owns the company; manages its members and which
                    devices each may see; sees every device in the org.
      - "member" -> sees only the devices the owner allocated (a list, or "*"
                    meaning all of the org's devices).

Anyone can self-sign-up: signing up creates a brand-new company with the new
account as its owner.

Data isolation is enforced at the web layer: every response is filtered to the
user's org and then to `allowed_devices(...)`, so tenants stay separated.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time

_ITERATIONS = 200_000

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    email      TEXT PRIMARY KEY,
    pw_hash    TEXT NOT NULL,
    salt       TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',   -- 'owner' | 'member'
    org_id     INTEGER NOT NULL,
    devices    TEXT NOT NULL DEFAULT '[]',        -- JSON list, or the string "*"
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
        self._ensure_schema()

    # ----- schema / migration ----------------------------------------------
    def _columns(self, table: str) -> list:
        return [r[1] for r in
                self.db.execute(f"PRAGMA table_info({table})").fetchall()]

    def _ensure_schema(self) -> None:
        have = self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone() is not None
        if have and "email" not in self._columns("users"):
            self._migrate_v1()
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def _migrate_v1(self) -> None:
        """Upgrade the legacy single-tenant schema (username-keyed, role
        admin/user, no orgs) into the multi-tenant one. All existing users move
        into one "Default" company; old admins become owners, others members."""
        old = self.db.execute(
            "SELECT username, pw_hash, salt, iterations, role, devices, created "
            "FROM users").fetchall()
        self.db.execute("ALTER TABLE users RENAME TO users_legacy")
        self.db.executescript(_SCHEMA)
        now = time.time()
        self.db.execute("INSERT INTO orgs (id, name, created) VALUES (1, ?, ?)",
                        ("Default", now))
        for username, pw_hash, salt, iters, role, devices, created in old:
            self.db.execute(
                "INSERT INTO users (email, pw_hash, salt, iterations, role, "
                "org_id, devices, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, pw_hash, salt, iters,
                 "owner" if role == "admin" else "member", 1,
                 devices, created or now))
        self.db.execute("DROP TABLE users_legacy")
        self.db.commit()

    # ----- mutations --------------------------------------------------------
    def signup(self, email: str, password: str, company: str,
               role: str = "owner") -> int:
        """Self-service registration: create a new company + its owner.

        Returns the new org id.
        """
        email = _norm_email(email)
        company = (company or "").strip()
        if not company:
            raise AuthError("Company name cannot be empty.")
        self._check_new_user(email, password)
        salt, pw_hash, iters = hash_password(password)
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO orgs (name, created) VALUES (?, ?)",
                (company, time.time()))
            org_id = cur.lastrowid
            self.db.execute(
                "INSERT INTO users (email, pw_hash, salt, iterations, role, "
                "org_id, devices, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (email, pw_hash, salt, iters, _norm_role(role), org_id,
                 _dump_devices("*" if _norm_role(role) == "owner" else None),
                 time.time()))
            self.db.commit()
        return org_id

    def add_member(self, org_id: int, email: str, password: str,
                   role: str = "member", devices=None) -> None:
        """An owner adds a user to their own company."""
        email = _norm_email(email)
        self._check_new_user(email, password)
        salt, pw_hash, iters = hash_password(password)
        with self._lock:
            self.db.execute(
                "INSERT INTO users (email, pw_hash, salt, iterations, role, "
                "org_id, devices, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (email, pw_hash, salt, iters, _norm_role(role), int(org_id),
                 _dump_devices(devices), time.time()))
            self.db.commit()

    def _check_new_user(self, email: str, password: str) -> None:
        if not email:
            raise AuthError("Email cannot be empty.")
        if not _EMAIL_RE.match(email):
            raise AuthError("Enter a valid email address.")
        if self.get_user(email):
            raise AuthError("An account with that email already exists.")
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters.")

    def set_password(self, email: str, password: str) -> None:
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters.")
        salt, pw_hash, iters = hash_password(password)
        self._update(_norm_email(email), pw_hash=pw_hash, salt=salt,
                     iterations=iters)

    def set_email(self, email: str, new_email: str) -> None:
        new_email = _norm_email(new_email)
        if not _EMAIL_RE.match(new_email):
            raise AuthError("Enter a valid email address.")
        if new_email != _norm_email(email) and self.get_user(new_email):
            raise AuthError("An account with that email already exists.")
        self._update(_norm_email(email), email=new_email)

    def set_devices(self, email: str, devices) -> None:
        self._update(_norm_email(email), devices=_dump_devices(devices))

    def set_role(self, email: str, role: str) -> None:
        self._update(_norm_email(email), role=_norm_role(role))

    def delete_user(self, email: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM users WHERE email = ?",
                            (_norm_email(email),))
            self.db.commit()

    def _update(self, _email: str, **cols) -> None:
        if not self.get_user(_email):
            raise AuthError(f"No such user: {_email!r}")
        sets = ", ".join(f"{k} = ?" for k in cols)
        with self._lock:
            self.db.execute(f"UPDATE users SET {sets} WHERE email = ?",
                            (*cols.values(), _email))
            self.db.commit()

    # ----- queries ----------------------------------------------------------
    def get_user(self, email: str) -> dict | None:
        cur = self.db.execute(
            "SELECT email, pw_hash, salt, iterations, role, org_id, devices, "
            "created FROM users WHERE email = ?", (_norm_email(email),))
        row = cur.fetchone()
        if not row:
            return None
        return {"email": row[0], "pw_hash": row[1], "salt": row[2],
                "iterations": row[3], "role": row[4], "org_id": row[5],
                "devices": _load_devices(row[6]), "created": row[7]}

    def list_users(self, org_id: int | None = None) -> list:
        if org_id is None:
            cur = self.db.execute(
                "SELECT email, role, org_id, devices, created FROM users "
                "ORDER BY email")
        else:
            cur = self.db.execute(
                "SELECT email, role, org_id, devices, created FROM users "
                "WHERE org_id = ? ORDER BY email", (int(org_id),))
        return [{"email": r[0], "role": r[1], "org_id": r[2],
                 "devices": _load_devices(r[3]), "created": r[4]}
                for r in cur.fetchall()]

    def count_users(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def org(self, org_id: int) -> dict | None:
        row = self.db.execute("SELECT id, name, created FROM orgs WHERE id = ?",
                              (int(org_id),)).fetchone()
        return {"id": row[0], "name": row[1], "created": row[2]} if row else None

    def org_name(self, org_id) -> str:
        org = self.org(org_id) if org_id is not None else None
        return org["name"] if org else ""

    def verify(self, email: str, password: str) -> dict | None:
        user = self.get_user(email)
        if not user:
            # Spend ~equal time to reduce account enumeration via timing.
            hash_password(password)
            return None
        if _verify(password, user["salt"], user["pw_hash"], user["iterations"]):
            return user
        return None

    # ----- authorization ----------------------------------------------------
    @staticmethod
    def is_owner(user: dict) -> bool:
        return bool(user) and user.get("role") == "owner"

    # An owner has admin rights *within their own company*; the web layer's
    # management gates use is_admin, so keep it as an alias.
    is_admin = is_owner

    @classmethod
    def can_see(cls, user: dict, device: str, device_org=None) -> bool:
        if not user:
            return False
        if device_org is not None and user.get("org_id") != device_org:
            return False
        if cls.is_owner(user):
            return True
        devs = user.get("devices")
        return devs == "*" or (isinstance(devs, list) and device in devs)

    @classmethod
    def allowed_devices(cls, user: dict, org_devices) -> list:
        """Filter `org_devices` (already scoped to the user's org) to what the
        user may see. Owners (and members with "*") see all of them."""
        if cls.is_owner(user) or user.get("devices") == "*":
            return list(org_devices)
        allow = set(user.get("devices") or [])
        return [d for d in org_devices if d in allow]

    def close(self) -> None:
        with self._lock:
            self.db.close()


def _norm_role(role: str) -> str:
    role = (role or "member").strip().lower()
    return "owner" if role == "owner" else "member"


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


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
