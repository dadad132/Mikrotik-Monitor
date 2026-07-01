"""Stripe billing — per-company subscriptions, device limits, and grace periods.

Design:
  * Each company (org) gets a billing record: Stripe customer, subscription
    status, plan, device_limit (0 = unlimited), and grace period tracking.
  * New orgs automatically receive a 30-day free trial (1 device limit).
  * Owners upgrade via Stripe Checkout; manage card/plan/invoices via the
    Stripe-hosted Customer Portal — no card data stored here.
  * Missed payment → 7-day grace period banner → full org lockout.
  * Stripe POSTs subscription changes to /stripe/webhook; we verify the
    signature (stdlib HMAC) and update status/device_limit/grace fields.

Enabling billing (config.yaml):
  billing:
    db: ./billing.db
    stripe_secret: sk_live_...
    webhook_secret: whsec_...
    prices:                   # Stripe Price IDs, one per plan name below
      starter:  price_...
      small:    price_...
      medium:   price_...
      business: price_...
      pro:      price_...
      ent250:   price_...
      ent500:   price_...
      ent1000:  price_...
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

_STRIPE_API = "https://api.stripe.com/v1"

GRACE_DAYS = 7
_GRACE_SECS = GRACE_DAYS * 86400
_TRIAL_DAYS = 30
_TRIAL_DEVICES = 1

PLANS = [
    {"name": "starter",  "label": "Starter",        "devices": 5,    "price_usd": 25},
    {"name": "small",    "label": "Small",           "devices": 15,   "price_usd": 69},
    {"name": "medium",   "label": "Medium",          "devices": 30,   "price_usd": 135},
    {"name": "business", "label": "Business",        "devices": 50,   "price_usd": 210},
    {"name": "pro",      "label": "Professional",    "devices": 100,  "price_usd": 400},
    {"name": "ent250",   "label": "Enterprise 250",  "devices": 250,  "price_usd": 925},
    {"name": "ent500",   "label": "Enterprise 500",  "devices": 500,  "price_usd": 1750},
    {"name": "ent1000",  "label": "Enterprise 1000", "devices": 1000, "price_usd": 3000},
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS billing (
    org_id             INTEGER PRIMARY KEY,
    stripe_customer_id TEXT,
    subscription_id    TEXT,
    status             TEXT NOT NULL DEFAULT 'inactive',
    plan               TEXT,
    device_limit       INTEGER NOT NULL DEFAULT 0,
    current_period_end REAL,
    grace_period_end   REAL,
    trial_end          REAL,
    updated            REAL NOT NULL
);
"""


# ===== pure helpers ==========================================================
def can_add_device(device_limit: int, current_count: int) -> bool:
    return not device_limit or current_count < device_limit


def limit_from_subscription(sub: dict) -> int:
    meta = sub.get("metadata") or {}
    if str(meta.get("device_limit", "")).strip().isdigit():
        return int(meta["device_limit"])
    items = (sub.get("items") or {}).get("data") or []
    if items and str(items[0].get("quantity", "")).strip().isdigit():
        return int(items[0]["quantity"])
    return 0


def verify_webhook(payload: bytes, sig_header: str, secret: str,
                   tolerance: int = 300) -> dict:
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    ts = parts.get("t")
    if not ts or not ts.isdigit():
        raise ValueError("missing/invalid timestamp")
    if abs(time.time() - int(ts)) > tolerance:
        raise ValueError("timestamp outside tolerance")
    signed = ts.encode() + b"." + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    sent = [v for k, v in (p.split("=", 1) for p in sig_header.split(",")
                           if "=" in p) if k == "v1"]
    if not any(hmac.compare_digest(expected, s) for s in sent):
        raise ValueError("signature mismatch")
    return json.loads(payload.decode("utf-8"))


# ===== persistence ===========================================================
class BillingStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.db.commit()
        self._add_col_if_missing("billing", "grace_period_end", "REAL")
        self._add_col_if_missing("billing", "trial_end", "REAL")

    def _add_col_if_missing(self, table: str, col: str, col_def: str) -> None:
        try:
            cols = [r[1] for r in
                    self.db.execute(f"PRAGMA table_info({table})").fetchall()]
            if col not in cols:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                self.db.commit()
        except Exception:
            pass

    def get(self, org_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT org_id, stripe_customer_id, subscription_id, status, plan, "
            "device_limit, current_period_end, grace_period_end, trial_end "
            "FROM billing WHERE org_id = ?",
            (int(org_id),)).fetchone()
        if not row:
            return None
        keys = ("org_id", "stripe_customer_id", "subscription_id", "status",
                "plan", "device_limit", "current_period_end", "grace_period_end",
                "trial_end")
        return dict(zip(keys, row))

    def device_limit(self, org_id: int) -> int:
        row = self.get(org_id)
        return int(row["device_limit"]) if row else 0

    def can_add(self, org_id: int, current_count: int) -> bool:
        return can_add_device(self.device_limit(org_id), current_count)

    def is_locked(self, org_id: int) -> bool:
        """True when billing has lapsed AND the grace period has expired."""
        row = self.get(org_id)
        if not row:
            return False  # no billing record = unrestricted (self-hosted)
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return False
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return False  # still inside the 30-day trial
        gpe = row.get("grace_period_end")
        if gpe is None:
            return False
        return time.time() > gpe

    def in_grace_period(self, org_id: int) -> bool:
        """True when billing has lapsed but the 7-day grace window is still open."""
        row = self.get(org_id)
        if not row:
            return False
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return False
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return False  # still inside active trial, not yet grace
        gpe = row.get("grace_period_end")
        if gpe is None:
            return False
        return time.time() <= gpe

    def days_left_in_grace(self, org_id: int) -> float:
        row = self.get(org_id)
        if not row:
            return 0.0
        gpe = row.get("grace_period_end") or 0.0
        return max(0.0, (gpe - time.time()) / 86400)

    def billing_status(self, org_id: int) -> str:
        """Returns one of: 'none', 'trial', 'active', 'grace', 'locked'."""
        row = self.get(org_id)
        if not row:
            return "none"
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return "active"
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return "trial"
        if self.is_locked(org_id):
            return "locked"
        if self.in_grace_period(org_id):
            return "grace"
        return "locked"

    def start_trial(self, org_id: int) -> None:
        """Called at new org creation — starts the 30-day free trial."""
        trial_end = time.time() + _TRIAL_DAYS * 86400
        grace_end = trial_end + _GRACE_SECS
        self._upsert(org_id, status="trial", device_limit=_TRIAL_DEVICES,
                     trial_end=trial_end, grace_period_end=grace_end)

    def _upsert(self, org_id: int, **cols) -> None:
        cols["updated"] = time.time()
        keys = ", ".join(cols)
        ph = ", ".join("?" for _ in cols)
        sets = ", ".join(f"{k}=excluded.{k}" for k in cols)
        with self._lock:
            self.db.execute(
                f"INSERT INTO billing (org_id, {keys}) VALUES (?, {ph}) "
                f"ON CONFLICT(org_id) DO UPDATE SET {sets}",
                (int(org_id), *cols.values()))
            self.db.commit()

    def link_customer(self, org_id: int, customer_id: str) -> None:
        self._upsert(org_id, stripe_customer_id=customer_id)

    def org_for_customer(self, customer_id: str) -> int | None:
        row = self.db.execute(
            "SELECT org_id FROM billing WHERE stripe_customer_id = ?",
            (customer_id,)).fetchone()
        return row[0] if row else None

    def apply_event(self, event: dict) -> None:
        """Update local state from a verified Stripe webhook event."""
        etype = event.get("type", "")
        obj = (event.get("data") or {}).get("object") or {}
        if etype == "checkout.session.completed":
            org_id = obj.get("client_reference_id")
            customer = obj.get("customer")
            if org_id and customer:
                self.link_customer(int(org_id), customer)
            return
        if etype.startswith("customer.subscription."):
            org_id = self.org_for_customer(obj.get("customer", ""))
            if org_id is None:
                return
            status = "canceled" if etype.endswith("deleted") \
                else obj.get("status", "inactive")
            limit = 0 if status not in ("active", "trialing") \
                else limit_from_subscription(obj)
            plan = None
            items = (obj.get("items") or {}).get("data") or []
            if items:
                plan = ((items[0].get("price") or {}).get("nickname")
                        or (items[0].get("price") or {}).get("id"))
            existing = self.get(org_id)
            if status in ("active", "trialing"):
                grace_end = None  # payment received — clear grace period
            elif status in ("past_due", "unpaid", "canceled", "incomplete",
                            "incomplete_expired"):
                existing_gpe = (existing or {}).get("grace_period_end")
                if existing_gpe and time.time() <= existing_gpe:
                    grace_end = existing_gpe  # preserve running grace window
                else:
                    grace_end = time.time() + _GRACE_SECS
            else:
                grace_end = (existing or {}).get("grace_period_end")
            self._upsert(org_id, subscription_id=obj.get("id"), status=status,
                         plan=plan, device_limit=limit,
                         current_period_end=obj.get("current_period_end"),
                         grace_period_end=grace_end)

    def close(self) -> None:
        with self._lock:
            self.db.close()


# ===== Stripe REST calls =====================================================
def _post(path: str, data: dict, secret: str) -> dict:
    body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(f"{_STRIPE_API}/{path}", data=body, headers={
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def create_customer(secret: str, email: str, company: str) -> str:
    return _post("customers", {"email": email, "name": company}, secret)["id"]


def create_checkout_session(secret: str, *, price_id: str, customer_id: str,
                            org_id: int, success_url: str, cancel_url: str,
                            quantity: int = 1) -> str:
    sess = _post("checkout/sessions", {
        "mode": "subscription",
        "customer": customer_id,
        "client_reference_id": str(org_id),
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": quantity,
        "success_url": success_url,
        "cancel_url": cancel_url,
    }, secret)
    return sess["url"]


def create_portal_session(secret: str, *, customer_id: str,
                          return_url: str) -> str:
    return _post("billing_portal/sessions",
                 {"customer": customer_id, "return_url": return_url},
                 secret)["url"]
