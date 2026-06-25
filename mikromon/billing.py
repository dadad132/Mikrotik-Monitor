"""Stripe billing — per-company device limits and subscriptions.

============================================================================
 DORMANT / NOT WIRED IN YET.  This module is complete but nothing calls it:
 the dashboard enforces no device limits and talks to no payment provider
 until billing is deliberately switched on.  See "ENABLING BILLING LATER"
 at the bottom of this file for the exact steps.  Until then the site
 behaves exactly as before.
============================================================================

Design (once enabled):
  * Each company (org) gets a row here: its Stripe customer, subscription
    status, plan and `device_limit` (0 = unlimited).
  * Adding a device is blocked once a company is at its `device_limit`.
  * Owners upgrade via Stripe **Checkout** and manage their card / plan /
    invoices via the Stripe-hosted **Customer Portal** — so there is no card
    data or billing UI to build or secure here.
  * Stripe POSTs subscription changes to `/stripe/webhook`; we verify the
    signature (stdlib HMAC — no Stripe SDK) and update `device_limit`/`status`.

Everything here uses only the standard library (urllib + hmac/hashlib), so it
keeps mikromon dependency-light (librouteros stays the only third-party dep).
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

_SCHEMA = """
CREATE TABLE IF NOT EXISTS billing (
    org_id             INTEGER PRIMARY KEY,
    stripe_customer_id TEXT,
    subscription_id    TEXT,
    status             TEXT NOT NULL DEFAULT 'inactive',
    plan               TEXT,
    device_limit       INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited
    current_period_end REAL,
    updated            REAL NOT NULL
);
"""


# ===== pure helpers (no network, no DB) — the risky bits, unit-tested ========
def can_add_device(device_limit: int, current_count: int) -> bool:
    """A company may add another device when it has no limit (0 = unlimited)
    or it is still under that limit."""
    return not device_limit or current_count < device_limit


def limit_from_subscription(sub: dict) -> int:
    """Derive the device allowance from a Stripe subscription object.

    Preference order: an explicit `metadata.device_limit`, else the quantity of
    the first line item (per-seat = per-device), else 0 (unlimited)."""
    meta = sub.get("metadata") or {}
    if str(meta.get("device_limit", "")).strip().isdigit():
        return int(meta["device_limit"])
    items = (sub.get("items") or {}).get("data") or []
    if items and str(items[0].get("quantity", "")).strip().isdigit():
        return int(items[0]["quantity"])
    return 0


def verify_webhook(payload: bytes, sig_header: str, secret: str,
                   tolerance: int = 300) -> dict:
    """Verify a Stripe webhook signature (the `Stripe-Signature` header) and
    return the parsed event. Raises ValueError on any mismatch.

    Implements Stripe's scheme with the stdlib: signed_payload = "{t}.{body}",
    HMAC-SHA256 with the endpoint signing secret, constant-time compared to the
    header's v1 value(s), within `tolerance` seconds."""
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

    def get(self, org_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT org_id, stripe_customer_id, subscription_id, status, plan, "
            "device_limit, current_period_end FROM billing WHERE org_id = ?",
            (int(org_id),)).fetchone()
        if not row:
            return None
        keys = ("org_id", "stripe_customer_id", "subscription_id", "status",
                "plan", "device_limit", "current_period_end")
        return dict(zip(keys, row))

    def device_limit(self, org_id: int) -> int:
        row = self.get(org_id)
        return int(row["device_limit"]) if row else 0

    def can_add(self, org_id: int, current_count: int) -> bool:
        return can_add_device(self.device_limit(org_id), current_count)

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
                plan = (items[0].get("price") or {}).get("nickname") \
                    or (items[0].get("price") or {}).get("id")
            self._upsert(org_id, subscription_id=obj.get("id"), status=status,
                         plan=plan, device_limit=limit,
                         current_period_end=obj.get("current_period_end"))

    def close(self) -> None:
        with self._lock:
            self.db.close()


# ===== Stripe REST calls (network — only used once enabled) ==================
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
    """Returns a Stripe-hosted Checkout URL to redirect the owner to."""
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
    """Returns a Stripe-hosted Customer Portal URL (manage card/plan/invoices)."""
    return _post("billing_portal/sessions",
                 {"customer": customer_id, "return_url": return_url},
                 secret)["url"]


# ============================================================================
# ENABLING BILLING LATER (when the rest of the site is solid)
# ----------------------------------------------------------------------------
# 1. Stripe dashboard: create a Product + recurring Price (per-device seat or
#    flat tiers), turn on the Customer Portal, and add a webhook endpoint
#    pointing at https://<your-host>/stripe/webhook. Copy the secret key and
#    the webhook signing secret.
# 2. config.yaml: fill in the (currently commented) billing keys —
#       billing:
#         db: ./billing.db
#         stripe_secret: sk_live_...
#         stripe_price: price_...
#         webhook_secret: whsec_...
# 3. web.py: uncomment the three blocks marked "BILLING (disabled)" —
#       (a) device-add guard in _devices_post  -> 402 / upgrade prompt
#       (b) GET  /billing  -> usage + Upgrade / Manage-billing buttons
#       (c) POST /stripe/webhook -> verify_webhook() + BillingStore.apply_event()
# 4. Make /stripe/webhook publicly reachable over HTTPS (Cloudflare Tunnel /
#    Tailscale Funnel — same options as remote dashboard access). For local
#    testing: `stripe listen --forward-to localhost:8090/stripe/webhook`.
# Until all of the above is done, importing this module changes nothing.
# ============================================================================
