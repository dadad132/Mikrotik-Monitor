"""PayFast billing — per-company subscriptions with device limits.

Design:
  * Orgs without a billing record are on the FREE plan (FREE_DEVICES cap).
  * New orgs get a 30-day free trial (FREE_DEVICES limit).
  * Owners subscribe via PayFast's hosted payment page; the subscription token
    arrives via ITN and is stored for recurring billing tracking.
  * Missed payment → 7-day grace period banner → full org lockout.
  * PayFast POSTs ITN to /billing/itn; we verify the MD5 signature.

Config (config.yaml):
  billing:
    db: ./billing.db
    payfast_merchant_id: "10000100"
    payfast_merchant_key: "46f0cd694581a"
    payfast_passphrase: "jt7NOE43FZPn"   # strongly recommended
    sandbox: false
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

GRACE_DAYS = 7
_GRACE_SECS = GRACE_DAYS * 86400
_TRIAL_DAYS = 30
FREE_DEVICES = 5     # cap for free plan and trial
_TRIAL_DEVICES = FREE_DEVICES

_PF_LIVE_URL = "https://www.payfast.co.za/eng/process"
_PF_SANDBOX_URL = "https://sandbox.payfast.co.za/eng/process"
_PF_VALIDATE_LIVE = "https://www.payfast.co.za/eng/query/validate"
_PF_VALIDATE_SANDBOX = "https://sandbox.payfast.co.za/eng/query/validate"

PLANS = [
    {"name": "starter",  "label": "Starter",        "devices": 5,    "price_zar": 460.00},
    {"name": "small",    "label": "Small",           "devices": 15,   "price_zar": 1270.00},
    {"name": "medium",   "label": "Medium",          "devices": 30,   "price_zar": 2490.00},
    {"name": "business", "label": "Business",        "devices": 50,   "price_zar": 3870.00},
    {"name": "pro",      "label": "Professional",    "devices": 100,  "price_zar": 7360.00},
    {"name": "ent250",   "label": "Enterprise 250",  "devices": 250,  "price_zar": 17030.00},
    {"name": "ent500",   "label": "Enterprise 500",  "devices": 500,  "price_zar": 32210.00},
    {"name": "ent1000",  "label": "Enterprise 1000", "devices": 1000, "price_zar": 55230.00},
]

_PLAN_MAP = {p["name"]: p for p in PLANS}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS billing (
    org_id             INTEGER PRIMARY KEY,
    pf_token           TEXT,              -- PayFast subscription token
    payment_id         TEXT,              -- our m_payment_id sent to PayFast
    status             TEXT NOT NULL DEFAULT 'inactive',
    plan               TEXT,
    device_limit       INTEGER NOT NULL DEFAULT 0,
    current_period_end REAL,
    grace_period_end   REAL,
    trial_end          REAL,
    updated            REAL NOT NULL
);
"""


# ===== pure helpers ===========================================================

def can_add_device(device_limit: int, current_count: int) -> bool:
    """device_limit 0 = unlimited."""
    return not device_limit or current_count < device_limit


def payment_url(sandbox: bool = False) -> str:
    return _PF_SANDBOX_URL if sandbox else _PF_LIVE_URL


def _pf_signature(params: dict, passphrase: str = "") -> str:
    """MD5 signature over sorted, URL-encoded params (PayFast spec)."""
    parts = [f"{k}={urllib.parse.quote_plus(str(v)).replace('%20', '+')}"
             for k, v in sorted(params.items()) if str(v) != ""]
    data = "&".join(parts)
    if passphrase:
        data += f"&passphrase={urllib.parse.quote_plus(passphrase).replace('%20', '+')}"
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def build_payment_data(*, merchant_id: str, merchant_key: str,
                       passphrase: str = "", sandbox: bool = False,
                       org_id: int, plan_name: str,
                       buyer_email: str = "", buyer_name: str = "",
                       notify_url: str, return_url: str,
                       cancel_url: str) -> dict:
    """Build the signed form-data dict to POST to the PayFast payment page.

    Returns a dict of field_name → value ready to be serialised as a hidden
    HTML form or a URL-encoded POST body.
    """
    plan = _PLAN_MAP.get(plan_name)
    if plan is None:
        raise ValueError(f"Unknown plan: {plan_name!r}")

    payment_id = f"{org_id}:{int(time.time())}"
    amount = f"{plan['price_zar']:.2f}"
    item_name = f"EasyMikrotik {plan['label']} Plan"

    params: dict = {
        "merchant_id": merchant_id,
        "merchant_key": merchant_key,
        "return_url": return_url,
        "cancel_url": cancel_url,
        "notify_url": notify_url,
        "m_payment_id": payment_id,
        "amount": amount,
        "item_name": item_name,
        "item_description": f"{plan['devices']} devices · monthly subscription",
        "subscription_type": "1",
        "billing_date": time.strftime("%Y-%m-%d"),
        "recurring_amount": amount,
        "frequency": "3",    # 3 = monthly
        "cycles": "0",       # 0 = recurring until cancelled
    }
    if buyer_email:
        parts = buyer_name.strip().split(" ", 1)
        params["name_first"] = parts[0]
        params["name_last"] = parts[1] if len(parts) > 1 else ""
        params["email_address"] = buyer_email

    # merchant_key is NOT included in the signature data
    sig_params = {k: v for k, v in params.items() if k != "merchant_key"}
    params["signature"] = _pf_signature(sig_params, passphrase)
    # Store plan and org in custom fields so ITN can route back to the right org
    params["custom_int1"] = str(org_id)
    params["custom_str1"] = plan_name
    return params


def verify_itn(post_data: dict, passphrase: str = "",
               sandbox: bool = False) -> bool:
    """Verify a PayFast ITN POST.

    Checks the MD5 signature and (optionally) the PayFast validate endpoint.
    Returns True if the notification is authentic.
    """
    received_sig = post_data.get("signature", "")
    params = {k: v for k, v in post_data.items() if k != "signature"}
    expected = _pf_signature(params, passphrase)
    if not received_sig or received_sig != expected:
        return False
    # Secondary: ask PayFast's validate endpoint
    try:
        validate_url = _PF_VALIDATE_SANDBOX if sandbox else _PF_VALIDATE_LIVE
        body = urllib.parse.urlencode(post_data).encode()
        req = urllib.request.Request(validate_url, data=body, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode().strip().upper() == "VALID"
    except Exception as exc:
        # Validate endpoint unreachable. With a passphrase set the signature
        # is a shared-secret check and can stand alone; without one the MD5
        # is computable by anyone, so fail closed.
        log.warning("PayFast validate endpoint unreachable (%s); %s", exc,
                    "trusting signed ITN" if passphrase
                    else "rejecting ITN (no passphrase configured)")
        return bool(passphrase)


def cancel_subscription(token: str, *, merchant_id: str, merchant_key: str,
                        passphrase: str = "", sandbox: bool = False) -> bool:
    """Cancel a PayFast subscription via the API. Returns True on success."""
    endpoint = ("https://sandbox.payfast.co.za" if sandbox
                else "https://www.payfast.co.za")
    url = f"{endpoint}/eng/recurring/cancel/{token}"
    ts = time.strftime("%Y-%m-%dT%H:%M:%S+02:00")
    headers_dict = {
        "merchant-id": merchant_id,
        "timestamp": ts,
        "version": "v1",
    }
    sig = _pf_signature({**headers_dict}, passphrase)
    headers_dict["signature"] = sig
    try:
        req = urllib.request.Request(url, method="PUT", headers=headers_dict)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


# ===== persistence ============================================================

class BillingStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.db.commit()
        self._add_col_if_missing("billing", "grace_period_end", "REAL")
        self._add_col_if_missing("billing", "trial_end", "REAL")
        self._add_col_if_missing("billing", "pf_token", "TEXT")
        self._add_col_if_missing("billing", "payment_id", "TEXT")

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
            "SELECT org_id, pf_token, payment_id, status, plan, "
            "device_limit, current_period_end, grace_period_end, trial_end "
            "FROM billing WHERE org_id = ?",
            (int(org_id),)).fetchone()
        if not row:
            return None
        keys = ("org_id", "pf_token", "payment_id", "status", "plan",
                "device_limit", "current_period_end", "grace_period_end",
                "trial_end")
        return dict(zip(keys, row))

    def device_limit(self, org_id: int) -> int:
        """Returns the device cap for this org. 0 = unlimited."""
        row = self.get(org_id)
        if not row:
            return FREE_DEVICES  # no billing record → free plan cap
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return int(row.get("device_limit") or 0)
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return int(row.get("device_limit") or FREE_DEVICES)
        # lapsed / grace / locked — still enforce the cap from last sub, or free
        return int(row.get("device_limit") or FREE_DEVICES)

    def can_add(self, org_id: int, current_count: int) -> bool:
        return can_add_device(self.device_limit(org_id), current_count)

    def is_locked(self, org_id: int) -> bool:
        row = self.get(org_id)
        if not row:
            return False
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return False
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return False
        gpe = row.get("grace_period_end")
        if gpe is None:
            return False
        return time.time() > gpe

    def in_grace_period(self, org_id: int) -> bool:
        row = self.get(org_id)
        if not row:
            return False
        status = row.get("status", "inactive")
        if status in ("active", "trialing"):
            return False
        if status == "trial":
            te = row.get("trial_end")
            if te and time.time() <= te:
                return False
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
        """Returns: 'none' | 'trial' | 'active' | 'grace' | 'locked'."""
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
        if self.in_grace_period(org_id):
            return "grace"
        if self.is_locked(org_id):
            return "locked"
        # No grace deadline set (e.g. a lapsed row that never had one):
        # is_locked() is False for this state, so stay consistent with it.
        return "none"

    def set_plan(self, org_id: int, plan_name: str) -> None:
        """Superadmin MANUALLY activates a paid plan for a company (payment
        handled off-platform, e.g. EFT/manual). Sets the device cap from the
        plan and marks the org active with no grace deadline."""
        plan = _PLAN_MAP.get(plan_name)
        if plan is None:
            raise ValueError(f"Unknown plan: {plan_name!r}")
        self._upsert(org_id, status="active", plan=plan_name,
                     device_limit=plan["devices"], grace_period_end=None,
                     pf_token=None)

    def set_unlimited(self, org_id: int) -> None:
        """Grant a company an UNLIMITED device cap (device_limit 0), active."""
        self._upsert(org_id, status="active", plan="unlimited",
                     device_limit=0, grace_period_end=None)

    def set_free(self, org_id: int) -> None:
        """Put a company back on the FREE plan (no paid subscription)."""
        self._upsert(org_id, status="inactive", plan=None,
                     device_limit=FREE_DEVICES, grace_period_end=None,
                     pf_token=None)

    def start_trial(self, org_id: int) -> None:
        trial_end = time.time() + _TRIAL_DAYS * 86400
        grace_end = trial_end + _GRACE_SECS
        self._upsert(org_id, status="trial", device_limit=_TRIAL_DEVICES,
                     trial_end=trial_end, grace_period_end=grace_end)

    def apply_itn(self, itn: dict) -> None:
        """Update billing state from a verified PayFast ITN notification."""
        payment_status = itn.get("payment_status", "").upper()
        token = itn.get("token", "")
        plan_name = itn.get("custom_str1", "")
        try:
            org_id = int(itn.get("custom_int1", 0))
        except (ValueError, TypeError):
            return
        if not org_id:
            return

        plan = _PLAN_MAP.get(plan_name)
        device_limit = plan["devices"] if plan else FREE_DEVICES

        if payment_status == "COMPLETE":
            self._upsert(org_id, pf_token=token or None,
                         payment_id=itn.get("m_payment_id"),
                         status="active", plan=plan_name,
                         device_limit=device_limit,
                         grace_period_end=None)
        elif payment_status in ("FAILED", "CANCELLED"):
            existing = self.get(org_id)
            existing_gpe = (existing or {}).get("grace_period_end")
            grace_end = (existing_gpe if existing_gpe and time.time() <= existing_gpe
                         else time.time() + _GRACE_SECS)
            self._upsert(org_id, status="canceled",
                         grace_period_end=grace_end)

    def org_for_token(self, token: str) -> int | None:
        row = self.db.execute(
            "SELECT org_id FROM billing WHERE pf_token = ?",
            (token,)).fetchone()
        return row[0] if row else None

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

    def close(self) -> None:
        with self._lock:
            self.db.close()
