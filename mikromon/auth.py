"""User accounts, companies (orgs) and per-user device authorization.

Stores companies and users in a small SQLite DB. Passwords are salted +
PBKDF2-hashed (stdlib, no dependencies). The model is multi-tenant:

  * An **organisation** (company) is the tenant boundary. Devices belong to
    exactly one org; nobody ever sees another org's devices or users.
  * A user belongs to one org and has a role:
      - "owner"  -> created/owns the company; manages its members and which
                    devices each may see; sees every device in the org.
      - "member" -> sees only the devices the owner allocated (a list, or "*"
                    meaning all of the org's devices).
  * **Login identifier:** new accounts sign in by **email** (self-signup
    creates a company with the new account as its owner). **Existing/legacy
    accounts keep their username** and may sign in with EITHER their username
    or an email they add later — so upgrading never locks anyone out. A user
    therefore has an optional `username` and an optional `email`; at least one
    is set and either one works as a login.

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
_PHONE_DIGITS_RE = re.compile(r"\d")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    plan    TEXT NOT NULL DEFAULT 'free',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY,
    username   TEXT UNIQUE,                       -- legacy login id; NULL for
                                                  -- new (email-only) accounts
    email      TEXT UNIQUE,                       -- login id for new accounts;
                                                  -- legacy accounts may add one
    phone      TEXT,                              -- collected at signup to deter abuse
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
        if have:
            cols = self._columns("users")
            if "email" not in cols:
                self._migrate_legacy()        # original single-tenant (username)
            elif "username" not in cols or "id" not in cols:
                self._migrate_intermediate()  # email-keyed multi-tenant build
        self.db.executescript(_SCHEMA)
        self.db.commit()
        # Additive column migrations — safe to run every startup.
        self._add_col_if_missing("users", "phone", "TEXT")
        self._add_col_if_missing("orgs", "plan", "TEXT NOT NULL DEFAULT 'free'")
        self._add_col_if_missing("orgs", "contact", "TEXT")
        self._add_col_if_missing("orgs", "phone", "TEXT")
        self._add_col_if_missing("orgs", "address", "TEXT")
        self._add_col_if_missing("orgs", "vat_number", "TEXT")
        self._add_col_if_missing("orgs", "alert_emails", "TEXT NOT NULL DEFAULT '[]'")

    def _add_col_if_missing(self, table: str, col: str, col_def: str) -> None:
        try:
            if col not in self._columns(table):
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                self.db.commit()
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).warning(
                "Could not add column %s.%s: %s", table, col, exc)

    def _migrate_legacy(self) -> None:
        """Upgrade the original single-tenant schema (username-keyed, role
        admin/user, no orgs). Everyone moves into one "Default" company; old
        admins become owners, others members. Usernames are KEPT (email NULL),
        so legacy logins keep working and an email can be added later."""
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
                "INSERT INTO users (username, email, pw_hash, salt, iterations, "
                "role, org_id, devices, created) "
                "VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)",
                (username, pw_hash, salt, iters,
                 "owner" if role == "admin" else "member", 1,
                 devices, created or now))
        self.db.execute("DROP TABLE users_legacy")
        self.db.commit()

    def _migrate_intermediate(self) -> None:
        """Upgrade the first multi-tenant build (email-keyed PK, no username/id
        columns) to the current schema (surrogate id + optional username). Orgs
        are preserved; each row keeps its email and becomes an email-only
        account (username NULL)."""
        old = self.db.execute(
            "SELECT email, pw_hash, salt, iterations, role, org_id, devices, "
            "created FROM users").fetchall()
        self.db.execute("ALTER TABLE users RENAME TO users_intermediate")
        self.db.executescript(_SCHEMA)        # orgs already exists (IF NOT EXISTS)
        for email, pw_hash, salt, iters, role, org_id, devices, created in old:
            self.db.execute(
                "INSERT INTO users (username, email, pw_hash, salt, iterations, "
                "role, org_id, devices, created) "
                "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
                (email, pw_hash, salt, iters, role, org_id, devices, created))
        self.db.execute("DROP TABLE users_intermediate")
        self.db.commit()

    # ----- mutations --------------------------------------------------------
    def signup(self, email: str, password: str, company: str,
               role: str = "owner", phone: str = "") -> int:
        """Self-service registration: create a new company + its owner.

        Returns the new org id.
        """
        email = _norm_email(email)
        company = (company or "").strip()
        if not company:
            raise AuthError("Company name cannot be empty.")
        self._check_new_user(email, password)
        phone = _norm_phone(phone)
        salt, pw_hash, iters = hash_password(password)
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO orgs (name, plan, created) VALUES (?, 'free', ?)",
                (company, time.time()))
            org_id = cur.lastrowid
            self.db.execute(
                "INSERT INTO users (username, email, phone, pw_hash, salt, "
                "iterations, role, org_id, devices, created) "
                "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (email, phone or None, pw_hash, salt, iters, _norm_role(role),
                 org_id, _dump_devices("*" if _norm_role(role) == "owner" else None),
                 time.time()))
            self.db.commit()
        return org_id

    def add_member(self, org_id: int, email: str, password: str,
                   role: str = "member", devices=None) -> None:
        """An owner adds a user to their own company. New members are
        email-only (no username)."""
        email = _norm_email(email)
        self._check_new_user(email, password)
        salt, pw_hash, iters = hash_password(password)
        with self._lock:
            self.db.execute(
                "INSERT INTO users (username, email, pw_hash, salt, iterations, "
                "role, org_id, devices, created) "
                "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    def set_password(self, identifier: str, password: str) -> None:
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters.")
        salt, pw_hash, iters = hash_password(password)
        self._update(self._require(identifier)["id"], pw_hash=pw_hash, salt=salt,
                     iterations=iters)

    def set_email(self, identifier: str, new_email: str) -> None:
        """Add or change an account's email (legacy username accounts use this
        to add one). The username, if any, is left untouched."""
        user = self._require(identifier)
        new_email = _norm_email(new_email)
        if not _EMAIL_RE.match(new_email):
            raise AuthError("Enter a valid email address.")
        clash = self.get_user(new_email)
        if clash and clash["id"] != user["id"]:
            raise AuthError("An account with that email already exists.")
        self._update(user["id"], email=new_email)

    def set_devices(self, identifier: str, devices) -> None:
        self._update(self._require(identifier)["id"],
                     devices=_dump_devices(devices))

    def set_role(self, identifier: str, role: str) -> None:
        self._update(self._require(identifier)["id"], role=_norm_role(role))

    def delete_user(self, identifier: str) -> None:
        user = self.get_user(identifier)
        if not user:
            return
        with self._lock:
            self.db.execute("DELETE FROM users WHERE id = ?", (user["id"],))
            self.db.commit()

    def _require(self, identifier: str) -> dict:
        user = self.get_user(identifier)
        if not user:
            raise AuthError(f"No such user: {identifier!r}")
        return user

    def _update(self, user_id: int, **cols) -> None:
        sets = ", ".join(f"{k} = ?" for k in cols)
        with self._lock:
            self.db.execute(f"UPDATE users SET {sets} WHERE id = ?",
                            (*cols.values(), user_id))
            self.db.commit()

    # ----- queries ----------------------------------------------------------
    def get_user(self, identifier: str) -> dict | None:
        """Look up by login identifier — matches EITHER email or username,
        case-insensitively."""
        ident = (identifier or "").strip().lower()
        if not ident:
            return None
        cur = self.db.execute(
            "SELECT id, username, email, pw_hash, salt, iterations, role, "
            "org_id, devices, created FROM users "
            "WHERE lower(email) = ? OR lower(username) = ? LIMIT 1",
            (ident, ident))
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "email": row[2],
                "pw_hash": row[3], "salt": row[4], "iterations": row[5],
                "role": row[6], "org_id": row[7],
                "devices": _load_devices(row[8]), "created": row[9],
                "login": row[2] or row[1]}     # email preferred, else username

    def list_users(self, org_id: int | None = None) -> list:
        cols = ("id", "username", "email", "role", "org_id", "devices", "created")
        sql = ("SELECT id, username, email, role, org_id, devices, created "
               "FROM users")
        args: tuple = ()
        if org_id is not None:
            sql += " WHERE org_id = ?"
            args = (int(org_id),)
        sql += " ORDER BY COALESCE(email, username)"
        out = []
        for r in self.db.execute(sql, args).fetchall():
            d = {"id": r[0], "username": r[1], "email": r[2], "role": r[3],
                 "org_id": r[4], "devices": _load_devices(r[5]), "created": r[6]}
            d["login"] = d["email"] or d["username"]
            out.append(d)
        return out

    def count_users(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def org(self, org_id: int) -> dict | None:
        try:
            row = self.db.execute(
                "SELECT id, name, plan, created, contact, phone, address, "
                "vat_number, alert_emails "
                "FROM orgs WHERE id = ?",
                (int(org_id),)).fetchone()
            if not row:
                return None
            try:
                alert_emails = json.loads(row[8] or "[]")
            except (json.JSONDecodeError, TypeError):
                alert_emails = []
            return {"id": row[0], "name": row[1], "plan": row[2], "created": row[3],
                    "contact": row[4] or "", "phone": row[5] or "",
                    "address": row[6] or "", "vat_number": row[7] or "",
                    "alert_emails": alert_emails}
        except Exception:
            row = self.db.execute(
                "SELECT id, name, created FROM orgs WHERE id = ?",
                (int(org_id),)).fetchone()
            return ({"id": row[0], "name": row[1], "plan": "free", "created": row[2],
                     "contact": "", "phone": "", "address": "", "vat_number": "",
                     "alert_emails": []}
                    if row else None)

    def set_org_name(self, org_id: int, name: str) -> None:
        name = name.strip()
        if not name:
            raise AuthError("Company name cannot be empty.")
        with self._lock:
            self.db.execute("UPDATE orgs SET name = ? WHERE id = ?",
                            (name, int(org_id)))
            self.db.commit()

    def set_org_details(self, org_id: int, *, contact: str = "",
                        phone: str = "", address: str = "",
                        vat_number: str = "") -> None:
        with self._lock:
            self.db.execute(
                "UPDATE orgs SET contact=?, phone=?, address=?, vat_number=? "
                "WHERE id = ?",
                (contact.strip() or None, phone.strip() or None,
                 address.strip() or None, vat_number.strip() or None,
                 int(org_id)))
            self.db.commit()

    def get_alert_emails(self, org_id: int) -> list:
        row = self.db.execute(
            "SELECT alert_emails FROM orgs WHERE id = ?",
            (int(org_id),)).fetchone()
        if not row:
            return []
        try:
            return [e for e in json.loads(row[0] or "[]") if e]
        except (json.JSONDecodeError, TypeError):
            return []

    def set_alert_emails(self, org_id: int, emails: list) -> None:
        clean = [e.strip().lower() for e in emails if e.strip()]
        with self._lock:
            self.db.execute(
                "UPDATE orgs SET alert_emails = ? WHERE id = ?",
                (json.dumps(clean), int(org_id)))
            self.db.commit()

    def set_phone(self, identifier: str, phone: str) -> None:
        self._update(self._require(identifier)["id"], phone=_norm_phone(phone) or None)

    def org_name(self, org_id) -> str:
        org = self.org(org_id) if org_id is not None else None
        return org["name"] if org else ""

    def verify(self, identifier: str, password: str) -> dict | None:
        user = self.get_user(identifier)
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


def _norm_phone(phone: str) -> str:
    return (phone or "").strip()


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
