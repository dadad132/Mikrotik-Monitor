"""PayFast billing — per-company subscriptions with device limits.

Design:
  * Orgs without a billing record are on the FREE plan (FREE_DEVICES cap).
  * New orgs get a 30-day free trial (TRIAL_DEVICES limit).
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
import logging
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

GRACE_DAYS = 7
_GRACE_SECS = GRACE_DAYS * 86400
_TRIAL_DAYS = 30
# Cap once a company has no active billing (lapsed, or never paid). Matches
# the trial cap on purpose: the free tier is there so an evaluation does not
# go dark, not as a product. A company that lapses keeps one device watched
# and has to choose a packet to get the rest back.
FREE_DEVICES = 1
TRIAL_DEVICES = 1   # cap for a brand-new company's 30-day trial

_PF_LIVE_URL = "https://www.payfast.co.za/eng/process"
_PF_SANDBOX_URL = "https://sandbox.payfast.co.za/eng/process"
_PF_VALIDATE_LIVE = "https://www.payfast.co.za/eng/query/validate"
_PF_VALIDATE_SANDBOX = "https://sandbox.payfast.co.za/eng/query/validate"

# price_usd is what's shown to users everywhere (a universal, ISP-agnostic
# figure) — price_zar is ONLY used internally to build the actual PayFast
# charge (build_payment_data below), since PayFast is a South African
# gateway that settles in ZAR regardless of what currency is displayed.
# Packets step in fives all the way to 100 devices. Anything larger is a
# quote, not a tier: at that size the shape of the deal (support terms,
# on-boarding, payment cycle) stops being something a price table can answer,
# and a customer who needs 340 devices is better served by a conversation than
# by being pushed into a 500 bracket they will not fill.
TIER_STEP = 5
MAX_TIER_DEVICES = 100
QUOTE_ABOVE_DEVICES = MAX_TIER_DEVICES

# PayFast settles in ZAR whatever currency we display, so every USD price
# carries a ZAR twin built at this rate. It is a constant rather than a live
# lookup on purpose -- a subscription amount that drifted with the exchange
# rate would re-quote every existing customer every month.
_ZAR_PER_USD = 18.4


def tier_rate_usd(devices: int) -> float:
    """Per-device monthly price at a given packet size.

    Volume discount, flat and predictable: $5.00 at the smallest packet, then
    ten cents off per five-device step from 15 devices up, bottoming out at
    $2.90 for 100. The two steps below 15 fall twice as fast (5.00 -> 4.80 ->
    4.60) because the smallest packets carry the same fixed per-account cost
    over far fewer devices, so the curve has further to come down there.

    Expressed as a rate rather than a price list because the rate is the thing
    that was decided; the prices are what fall out of it, and deriving them
    means a tier cannot silently disagree with its neighbours.
    """
    if devices <= 5:
        return 5.00
    if devices <= 10:
        return 4.80
    return round(4.60 - 0.10 * ((devices - 15) // TIER_STEP), 2)


def _make_tier(devices: int) -> dict:
    usd = int(round(devices * tier_rate_usd(devices)))
    return {
        "name": f"d{devices}",
        "label": f"{devices} devices",
        "devices": devices,
        "price_usd": usd,
        "price_zar": round(usd * _ZAR_PER_USD, 2),
    }


PLANS = [_make_tier(n)
         for n in range(TIER_STEP, MAX_TIER_DEVICES + 1, TIER_STEP)]

_PLAN_MAP = {p["name"]: p for p in PLANS}

# Plan names sold before the ladder existed. A company still on one of these
# keeps the cap it paid for: dropping an unknown name back to the free cap
# would lock devices a customer is currently paying to monitor, and they would
# find out by being unable to work rather than by being told.
_LEGACY_PLAN_DEVICES = {
    "starter": 5, "small": 15, "medium": 30, "business": 50, "pro": 100,
    "ent250": 250, "ent500": 500, "ent1000": 1000,
}


def plan_by_name(plan_name: str):
    """A tier by name, or None. Resolves retired plan names to the tier that
    matches the cap they were sold, and synthesises an entry for the old
    enterprise plans, which are larger than any tier now on sale."""
    plan = _PLAN_MAP.get(plan_name)
    if plan is not None:
        return plan
    devices = _LEGACY_PLAN_DEVICES.get(plan_name)
    if devices is None:
        return None
    tier = _PLAN_MAP.get(f"d{devices}")
    if tier is not None:
        return tier
    return {"name": plan_name, "label": f"Custom ({devices} devices)",
            "devices": devices, "price_usd": 0, "price_zar": 0.0}


def needs_quote(devices: int) -> bool:
    """Whether a device count is past the last tier and has to be quoted."""
    return int(devices or 0) > QUOTE_ABOVE_DEVICES

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

-- A company past the last tier asking to be contacted. Kept in the billing
-- db rather than emailed and forgotten, because an email that bounces or
-- lands in a spam folder loses a customer silently -- here the request sits
-- in the admin panel until somebody marks it handled.
CREATE TABLE IF NOT EXISTS quote_requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id       INTEGER NOT NULL,
    devices      INTEGER NOT NULL,
    contact      TEXT,
    note         TEXT,
    created      REAL NOT NULL,
    handled      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_quote_open ON quote_requests(handled, created);
"""


# ===== pure helpers ===========================================================

# Prefix for the EFT reference each company quotes when paying by bank
# transfer. Short on purpose: banking apps truncate the reference field
# (Capitec's is 20 characters), and every character a customer has to retype
# is a character they can get wrong.
_PAYREF_PREFIX = "EMK"
_PAYREF_SLUG_MAX = 12
# Letters, then the org id. Bounded to 5 digits so an 8-digit date in a
# statement description ("EFT 20260825 ...") cannot be mistaken for an id.
_PAYREF_RE = re.compile(r"[A-Za-z]{2,14}[\s-]?0*(\d{1,5})(?!\d)")


def _payref_slug(name: str) -> str:
    """A company name reduced to something a bank reference can carry: LETTERS
    only, upper case, truncated. Spaces and punctuation go because reference
    fields mangle them inconsistently between banks.

    Digits go for a sharper reason. A statement arrives as one mangled string,
    and the id is found by looking for the digits at the end -- so a name that
    itself ends in digits ("Net24") would run into the id and read as a
    different account entirely. Dropping them from the slug costs a little
    fidelity in the name half and makes the half that decides identity
    unambiguous."""
    out = re.sub(r"[^A-Za-z]+", "", str(name or "")).upper()
    return out[:_PAYREF_SLUG_MAX]


def payment_reference(org_id: int, name: str = "") -> str:
    """The reference a company puts on a manual EFT, e.g. "MYITAFRICA-0042".

    The company name is in it so a bank statement line says WHO paid without
    a lookup. The org id is what actually identifies the account: names get
    edited and two companies can reduce to the same letters, so the number is
    the part that has to be unique and stable, and it is kept even when the
    name changes underneath it. Falls back to a plain "EMK-0042" when there
    is no usable name, which is also the format issued before names were
    included -- both still resolve to the same account.

    Deliberately NOT in here: the device count or plan. Those change as an
    account grows, and a reference that changes is a reference a customer's
    saved beneficiary no longer matches -- they would go on paying the old
    one for months. The org list shows devices and plan beside this instead,
    where being current costs nothing.

    Note the direction this runs in. A reference cannot be generated from an
    incoming payment -- by the time money lands it already carries whatever
    the payer typed. It only identifies an account if the customer was given
    it BEFORE paying, which is why it appears on their billing page.
    """
    slug = _payref_slug(name) or _PAYREF_PREFIX
    return f"{slug}-{int(org_id):04d}"


def org_id_from_reference(ref: str):
    """The org a payment reference belongs to, or None if it is not one of
    ours. Tolerates what statements actually do to a reference -- lower case,
    a dropped hyphen, and the payer's own description wrapped around it -- and
    reads both the current "MYITAFRICA-0042" form and the earlier "EMK-0042"
    one, so a customer still paying with the reference they saved months ago
    is matched to the same account."""
    found = _PAYREF_RE.findall(str(ref or ""))
    return int(found[-1]) if found else None


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
    plan = plan_by_name(plan_name)
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
                return int(row.get("device_limit") or TRIAL_DEVICES)
        # lapsed / grace / locked — still enforce the cap from last sub, or free
        return int(row.get("device_limit") or FREE_DEVICES)

    def can_add(self, org_id: int, current_count: int) -> bool:
        return can_add_device(self.device_limit(org_id), current_count)

    def is_locked(self, org_id: int) -> bool:
        row = self.get(org_id)
        if not row:
            return False
        status = row.get("status", "inactive")
        # A manual suspension is a decision, not a deadline. It outranks every
        # date on the row -- including an unexpired trial or a paid period
        # still running -- because the whole point is to act on an account the
        # dates say is fine but the bank says is not.
        if status == "suspended":
            return True
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
        """Returns: 'none' | 'trial' | 'active' | 'grace' | 'locked' |
        'suspended'."""
        row = self.get(org_id)
        if not row:
            return "none"
        status = row.get("status", "inactive")
        if status == "suspended":
            return "suspended"
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
        plan = plan_by_name(plan_name)
        if plan is None:
            raise ValueError(f"Unknown plan: {plan_name!r}")
        self._upsert(org_id, status="active", plan=plan_name,
                     device_limit=plan["devices"], grace_period_end=None,
                     pf_token=None)

    # --- quote requests (companies past the last tier) --------------------

    def add_quote_request(self, org_id: int, devices: int,
                          contact: str = "", note: str = "") -> None:
        """Record a company asking to be contacted about a custom packet.

        Deliberately allows more than one open request per company: a second
        one usually means the first went unanswered, and collapsing them would
        hide exactly the signal worth seeing.
        """
        with self._lock:
            self.db.execute(
                "INSERT INTO quote_requests (org_id, devices, contact, note, "
                "created) VALUES (?,?,?,?,?)",
                (int(org_id), int(devices), str(contact or "")[:200],
                 str(note or "")[:2000], time.time()))
            self.db.commit()

    def quote_requests(self, include_handled: bool = False) -> list:
        """Quote requests, newest first. Open ones only unless asked."""
        keys = ("id", "org_id", "devices", "contact", "note", "created",
                "handled")
        sql = f"SELECT {', '.join(keys)} FROM quote_requests"
        if not include_handled:
            sql += " WHERE handled = 0"
        sql += " ORDER BY created DESC"
        with self._lock:
            rows = self.db.execute(sql).fetchall()
        return [dict(zip(keys, r)) for r in rows]

    def open_quote_count(self) -> int:
        with self._lock:
            row = self.db.execute(
                "SELECT COUNT(*) FROM quote_requests "
                "WHERE handled = 0").fetchone()
        return int(row[0]) if row else 0

    def mark_quote_handled(self, quote_id: int, handled: bool = True) -> None:
        with self._lock:
            self.db.execute("UPDATE quote_requests SET handled = ? WHERE id = ?",
                            (1 if handled else 0, int(quote_id)))
            self.db.commit()

    def suspend(self, org_id: int) -> None:
        """Cut a company off until they pay, by hand.

        Keeps `plan` and `device_limit` untouched. Restoring is then a single
        flip back rather than an admin trying to remember what the customer
        was on -- and a customer who pays should be working again in seconds,
        not waiting for someone to reconstruct their account.
        """
        self._upsert(org_id, status="suspended", grace_period_end=None)

    def unsuspend(self, org_id: int) -> None:
        """Undo a suspension, putting the company back on the plan it kept
        throughout. A company with no plan returns to the free cap rather
        than to a paid state it never had."""
        row = self.get(org_id) or {}
        if row.get("status") != "suspended":
            return
        plan = row.get("plan")
        if plan:
            self._upsert(org_id, status="active", grace_period_end=None)
        else:
            self._upsert(org_id, status="inactive", grace_period_end=None,
                         device_limit=FREE_DEVICES)

    def is_suspended(self, org_id: int) -> bool:
        return (self.get(org_id) or {}).get("status") == "suspended"

    def suspended_orgs(self) -> set:
        """Every org currently suspended, in one query.

        Batched because the alert path asks this for a whole run of alerts at
        once, and per-org lookups there would put a query on the hot path of
        something that fires during an outage.
        """
        with self._lock:
            rows = self.db.execute(
                "SELECT org_id FROM billing WHERE status = 'suspended'"
            ).fetchall()
        return {int(r[0]) for r in rows}

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
        self._upsert(org_id, status="trial", device_limit=TRIAL_DEVICES,
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

        plan = plan_by_name(plan_name)
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
