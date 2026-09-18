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

# What customers are invoiced in. It is USD because that is the currency the
# prices were decided in and the currency every page quotes -- and because
# the alternative was a rand figure derived from a constant that was right on
# the day it was written and silently wrong every day after.
BILLING_CURRENCY = "USD"
CURRENCY_SYMBOL = {"USD": "$", "ZAR": "R", "EUR": "\u20ac", "GBP": "\u00a3"}

# ONLY for the card gateways. PayFast and Yoco settle in ZAR and cannot take
# anything else, so a rand figure has to exist for them. It is not a price:
# nothing is quoted or invoiced from it, and no invoice is raised in rands.
# A constant rather than a live rate on purpose -- an amount that drifted
# with the exchange rate would re-quote every existing customer every month.
_ZAR_PER_USD = 18.4


def money(amount, currency: str = BILLING_CURRENCY) -> str:
    """Format an amount for a person to read, in the currency it is in.

    Takes the currency explicitly rather than assuming, because the whole
    fault this replaces was a figure displayed in one currency and charged
    in another.
    """
    sym = CURRENCY_SYMBOL.get((currency or "").upper(), "")
    return f"{sym}{float(amount):,.2f}" if sym else \
        f"{float(amount):,.2f} {currency}"


# Every account renews on this day of the month. The 28th because it is the
# only late-month day that exists in February, so there is no clamping rule
# and therefore no clamping bug. Periods used to advance by 30-day steps,
# which drifted a packet's renewal date backwards about five days a year.
BILLING_DAY = 28


def next_billing_date(after: float | None = None) -> float:
    """The next BILLING_DAY strictly after `after`, at the start of that day.

    Start of day rather than the same clock time, so two accounts created
    minutes apart do not renew minutes apart, and so a renewal never lands
    at 23:58 and looks like it happened the day before.
    """
    now = after if after is not None else time.time()
    lt = time.localtime(now)
    year, month = lt.tm_year, lt.tm_mon
    if lt.tm_mday >= BILLING_DAY:
        month += 1
        if month > 12:
            month, year = 1, year + 1
    return time.mktime((year, month, BILLING_DAY, 0, 0, 0, 0, 0, -1))


def add_billing_months(period_end: float, months: int = 1) -> float:
    """Advance a paid-up date by whole calendar months, staying on the 28th.

    Adding 30 days repeatedly is what made the date drift. Adding months
    keeps it exactly where the customer expects it, in every month, without
    a special case for February.
    """
    lt = time.localtime(period_end)
    month = lt.tm_mon + max(1, int(months))
    year = lt.tm_year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    return time.mktime((year, month, BILLING_DAY, 0, 0, 0, 0, 0, -1))


def days_in_period(period_end: float) -> float:
    """The length of the period ENDING at `period_end`, in days."""
    lt = time.localtime(period_end)
    month = lt.tm_mon - 1
    year = lt.tm_year
    if month < 1:
        month, year = 12, year - 1
    start = time.mktime((year, month, BILLING_DAY, 0, 0, 0, 0, 0, -1))
    return max(1.0, (period_end - start) / 86400)


def prorata(amount: float, period_end: float,
            now: float | None = None) -> dict:
    """What to charge for the part of a period that is actually left.

    Returns {"amount", "days_left", "days_in_period", "fraction"}.

    Used for two things that are the same sum: the first part-month after
    signing up, and the difference owed when somebody upgrades mid-month.
    Charging a full month for four days of service, or nothing at all for
    twenty-six, are both ways of being wrong about the same number.

    Rounded to the cent, and never negative -- a downgrade produces no
    credit here, because refunding money automatically is a decision nobody
    made.
    """
    now = now if now is not None else time.time()
    total_days = days_in_period(period_end)
    days_left = max(0.0, (period_end - now) / 86400)
    days_left = min(days_left, total_days)
    fraction = days_left / total_days if total_days else 0.0
    return {"amount": max(0.0, round(float(amount) * fraction, 2)),
            "days_left": days_left, "days_in_period": total_days,
            "fraction": fraction}


def upgrade_quote(old_plan: dict | None, new_plan: dict,
                  period_end: float, now: float | None = None) -> dict:
    """What changing packet costs, and when it takes effect.

    An UPGRADE is charged the difference between the two packets for the
    days remaining in the period they have already paid for -- so nobody
    pays twice for the same days, and nobody gets a bigger packet free until
    the 28th. Their renewal date does not move: they keep the billing day
    they already have, and the next full invoice is the new price.

    A DOWNGRADE takes effect at the next renewal and costs nothing now. No
    automatic refund: money going back out without a person deciding is not
    something this should do on its own.
    """
    now = now if now is not None else time.time()
    old_price = float((old_plan or {}).get("price") or 0.0)
    new_price = float(new_plan.get("price") or 0.0)
    pr = prorata(new_price - old_price, period_end, now)
    if new_price > old_price:
        return {"kind": "upgrade", "due_now": pr["amount"],
                "effective": now, "period_end": period_end,
                "days_left": pr["days_left"],
                "currency": new_plan.get("currency", BILLING_CURRENCY),
                "old_price": old_price, "new_price": new_price}
    if new_price < old_price:
        return {"kind": "downgrade", "due_now": 0.0,
                "effective": period_end, "period_end": period_end,
                "days_left": pr["days_left"],
                "currency": new_plan.get("currency", BILLING_CURRENCY),
                "old_price": old_price, "new_price": new_price}
    return {"kind": "same", "due_now": 0.0, "effective": now,
            "period_end": period_end, "days_left": pr["days_left"],
            "currency": new_plan.get("currency", BILLING_CURRENCY),
            "old_price": old_price, "new_price": new_price}


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
        # `price` is what is charged, in BILLING_CURRENCY. The two named
        # fields exist so nothing has to guess which one a caller meant --
        # picking the wrong one is precisely what charged rands for a price
        # quoted in dollars.
        "price": float(usd),
        "currency": BILLING_CURRENCY,
        "price_usd": usd,
        "price_zar": round(usd * _ZAR_PER_USD, 2),   # card gateways only
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
            "devices": devices, "price": 0.0,
            "currency": BILLING_CURRENCY, "price_usd": 0, "price_zar": 0.0}


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

-- One row per "this company asked to buy this packet". Created BEFORE the
-- customer is sent to the payment page, so the amount and the packet are
-- fixed on our side and cannot be edited in the browser on the way through.
-- It is also what makes payment idempotent: the webhook finds this row, and
-- a row already marked paid is not applied a second time. Yoco retries
-- webhooks, so that is not a theoretical concern.
CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id       INTEGER NOT NULL,
    plan         TEXT NOT NULL,        -- the packet being bought
    months       INTEGER NOT NULL DEFAULT 1,
    amount_cents INTEGER NOT NULL,     -- minor units; money is never a float
    currency     TEXT NOT NULL DEFAULT 'ZAR',
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending|paid|cancelled
    checkout_id  TEXT,                 -- Yoco's id for the hosted page
    payment_id   TEXT,                 -- Yoco's id for the settled payment
    created      REAL NOT NULL,
    paid         REAL
);
CREATE INDEX IF NOT EXISTS ix_orders_org ON orders(org_id, created);
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
        # Orders predate Invoice Ninja, so these are added rather than being
        # in the CREATE TABLE -- an existing server must not need its
        # database rebuilt to take an update.
        self._add_col_if_missing("orders", "provider", "TEXT")
        self._add_col_if_missing("orders", "external_id", "TEXT")
        self._add_col_if_missing("orders", "due", "REAL")
        # An amount with no currency is a number waiting to be read in
        # the wrong one. Orders raised before this default to the
        # currency they were actually raised in at the time.
        self._add_col_if_missing("orders", "currency", "TEXT")
        # A packet change that has been asked for but has not taken effect.
        self._add_col_if_missing("billing", "pending_plan", "TEXT")
        self._add_col_if_missing("billing", "pending_from", "REAL")
        # Renewal or upgrade. A renewal extends the period; an upgrade
        # changes the packet and leaves the renewal date exactly where it
        # is, so nobody pays twice for the same days.
        self._add_col_if_missing("orders", "kind", "TEXT")
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
            "device_limit, current_period_end, grace_period_end, trial_end, "
            "pending_plan, pending_from "
            "FROM billing WHERE org_id = ?",
            (int(org_id),)).fetchone()
        if not row:
            return None
        keys = ("org_id", "pf_token", "payment_id", "status", "plan",
                "device_limit", "current_period_end", "grace_period_end",
                "trial_end", "pending_plan", "pending_from")
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

    def set_plan(self, org_id: int, plan_name: str, months: int = 1,
                 period_end: float | None = None) -> None:
        """Superadmin MANUALLY activates a paid plan for a company (payment
        handled off-platform, e.g. EFT/manual). Sets the device cap from the
        plan and marks the org active with no grace deadline.

        It also sets a paid-up date, which it did not used to. Renewal
        invoicing only considers companies with one, so an account activated
        by hand looked perfectly correct on the Billing page -- active, right
        packet, right device cap -- and was never invoiced again, for as long
        as it existed. Nothing could report that, because nothing was wrong
        with it except an absence.

        An existing date in the future is kept: re-saving a packet to correct
        a device cap must not silently move somebody's paid-up date, in
        either direction.
        """
        plan = plan_by_name(plan_name)
        if plan is None:
            raise ValueError(f"Unknown plan: {plan_name!r}")
        end = period_end
        if end is None:
            now = time.time()
            current = float((self.get(org_id) or {}).get(
                "current_period_end") or 0.0)
            end = current if current > now else next_billing_date(now)
            if months > 1 and end == next_billing_date(now):
                end = add_billing_months(end, months - 1)
        self._upsert(org_id, status="active", plan=plan_name,
                     device_limit=plan["devices"], grace_period_end=None,
                     current_period_end=float(end), pf_token=None)

    def orgs_never_invoiced(self) -> list:
        """Companies on a priced packet with no paid-up date.

        They are invisible to renewal invoicing: it selects on
        current_period_end, so a NULL there means this company is never
        billed and nothing anywhere says so.
        """
        rows = self.db.execute(
            "SELECT org_id, plan FROM billing "
            "WHERE current_period_end IS NULL "
            "AND plan IS NOT NULL AND plan != '' "
            "AND status IN ('active','grace')").fetchall()
        return [{"org_id": r[0], "plan": r[1]} for r in rows
                if plan_by_name(r[1]) is not None]

    def schedule_plan_change(self, org_id: int, plan_name: str,
                             effective: float) -> None:
        """Record a packet change that has not happened yet.

        Kept as an intention rather than applied early, because "you will be
        on 25 devices from the 28th" and "you are on 25 devices" are
        different statements and only one of them is true today.
        """
        if plan_by_name(plan_name) is None:
            raise ValueError(f"Unknown plan: {plan_name!r}")
        self._upsert(org_id, pending_plan=str(plan_name),
                     pending_from=float(effective))

    def cancel_plan_change(self, org_id: int) -> None:
        self._upsert(org_id, pending_plan=None, pending_from=None)

    def pending_change(self, org_id: int) -> dict | None:
        """The packet change waiting to happen, or None."""
        row = self.get(org_id) or {}
        name = row.get("pending_plan")
        if not name:
            return None
        plan = plan_by_name(name)
        return {"plan": name, "label": (plan or {}).get("label", name),
                "devices": (plan or {}).get("devices"),
                "price": (plan or {}).get("price"),
                "from": float(row.get("pending_from") or 0.0)}

    def apply_pending_change(self, org_id: int,
                             now: float | None = None) -> str:
        """Put a due packet change into effect. Returns the plan name or "".

        Called when a period rolls over. A change scheduled for the 28th has
        to be applied by something on the 28th, or it is not a scheduled
        change, it is a note in a database.
        """
        now = now if now is not None else time.time()
        pend = self.pending_change(org_id)
        if not pend or pend["from"] > now:
            return ""
        plan = plan_by_name(pend["plan"])
        if plan is None:
            self.cancel_plan_change(org_id)
            return ""
        self._upsert(org_id, plan=plan["name"],
                     device_limit=plan["devices"],
                     pending_plan=None, pending_from=None)
        return plan["name"]

    def apply_upgrade(self, org_id: int, plan_name: str) -> None:
        """A paid mid-period upgrade: bigger packet, same renewal date.

        The date deliberately does not move. They already paid for these
        days on the old packet and have just paid the difference; extending
        the period as well would be giving away a month for the price of a
        fortnight.
        """
        plan = plan_by_name(plan_name)
        if plan is None:
            raise ValueError(f"Unknown plan: {plan_name!r}")
        self._upsert(org_id, status="active", plan=plan["name"],
                     device_limit=plan["devices"], grace_period_end=None,
                     pending_plan=None, pending_from=None)

    # --- orders (a packet somebody is paying for) --------------------------

    _ORDER_COLS = ("id", "org_id", "plan", "months", "amount_cents",
                   "provider", "external_id", "due",
                   "currency", "status", "checkout_id", "payment_id",
                   "created", "paid", "kind")

    def create_order(self, org_id: int, plan: str, amount_cents: int,
                     months: int = 1, currency: str = BILLING_CURRENCY,
                     provider: str = "yoco", due: float | None = None,
                     kind: str = "renewal") -> int:
        """Record what is being bought, before sending anyone to pay.

        The amount is stored here rather than recomputed when the webhook
        lands, so a price change between clicking Pay and the card settling
        cannot charge one figure and grant another.

        `currency` defaults to what we bill in rather than to rands. It used
        to default to ZAR and no caller passed it, so every order recorded a
        currency it was not raised in -- the same fault as the price itself,
        one layer down.
        """
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO orders (org_id, plan, months, amount_cents, "
                "currency, created, provider, due, kind) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (int(org_id), str(plan), max(1, int(months)),
                 int(amount_cents), str(currency), time.time(),
                 str(provider), due, str(kind)))
            self.db.commit()
            return int(cur.lastrowid)

    def set_order_checkout(self, order_id: int, checkout_id: str) -> None:
        with self._lock:
            self.db.execute("UPDATE orders SET checkout_id = ? WHERE id = ?",
                            (str(checkout_id), int(order_id)))
            self.db.commit()

    def order(self, order_id: int) -> dict | None:
        row = self.db.execute(
            f"SELECT {', '.join(self._ORDER_COLS)} FROM orders WHERE id = ?",
            (int(order_id),)).fetchone()
        return dict(zip(self._ORDER_COLS, row)) if row else None

    def orders_for_org(self, org_id: int, limit: int = 24) -> list:
        rows = self.db.execute(
            f"SELECT {', '.join(self._ORDER_COLS)} FROM orders "
            f"WHERE org_id = ? ORDER BY created DESC LIMIT ?",
            (int(org_id), int(limit))).fetchall()
        return [dict(zip(self._ORDER_COLS, r)) for r in rows]

    def set_order_external(self, order_id: int, external_id: str) -> None:
        """Record the id this order has at the invoicing provider, so a
        payment recorded over there can be found back here."""
        with self._lock:
            self.db.execute("UPDATE orders SET external_id = ? WHERE id = ?",
                            (str(external_id), int(order_id)))
            self.db.commit()

    def order_by_external(self, external_id: str, provider: str = ""):
        """The order holding this provider-side id, or None."""
        if not external_id:
            return None
        sql = (f"SELECT {', '.join(self._ORDER_COLS)} FROM orders "
               f"WHERE external_id = ?")
        args = [str(external_id)]
        if provider:
            sql += " AND provider = ?"
            args.append(provider)
        row = self.db.execute(sql + " ORDER BY created DESC LIMIT 1",
                              args).fetchone()
        return dict(zip(self._ORDER_COLS, row)) if row else None

    def open_orders(self, provider: str = "", limit: int = 500) -> list:
        """Orders raised but not yet paid.

        The reconcile pass walks these and asks the provider whether each one
        has been settled. That is what makes a webhook optional: a callback
        that never arrives costs a few minutes, not a suspended customer who
        has already paid.
        """
        sql = (f"SELECT {', '.join(self._ORDER_COLS)} FROM orders "
               f"WHERE status != 'paid' AND external_id IS NOT NULL "
               f"AND external_id != ''")
        args: list = []
        if provider:
            sql += " AND provider = ?"
            args.append(provider)
        rows = self.db.execute(sql + " ORDER BY created LIMIT ?",
                               args + [int(limit)]).fetchall()
        return [dict(zip(self._ORDER_COLS, r)) for r in rows]

    def has_open_order_for_period(self, org_id: int, period_end: float,
                                  provider: str = "") -> bool:
        """Whether a renewal invoice already covers this billing period.

        Stops a daily job raising the same invoice every morning for a week.
        Matched on the period the invoice was raised against rather than on a
        date window, so it stays correct if the job misses a day or the
        server's clock moves.
        """
        sql = ("SELECT 1 FROM orders WHERE org_id = ? AND status != 'paid' "
               "AND due IS NOT NULL AND ABS(due - ?) < 86400")
        args: list = [int(org_id), float(period_end or 0.0)]
        if provider:
            sql += " AND provider = ?"
            args.append(provider)
        return self.db.execute(sql + " LIMIT 1", args).fetchone() is not None

    def orgs_due_for_renewal(self, within_days: float,
                             now: float | None = None) -> list:
        """Companies whose paid-up date falls inside the next `within_days`.

        Only companies actually on a paid packet: a trial has nothing to
        renew, and invoicing one would be the single worst first impression
        the product could make.
        """
        now = now if now is not None else time.time()
        horizon = now + float(within_days) * 86400
        rows = self.db.execute(
            "SELECT org_id, plan, device_limit, current_period_end, status "
            "FROM billing WHERE current_period_end IS NOT NULL "
            "AND current_period_end <= ? AND status IN "
            "('active','grace','suspended','canceled') "
            "ORDER BY current_period_end", (horizon,)).fetchall()
        return [{"org_id": r[0], "plan": r[1], "device_limit": r[2],
                 "current_period_end": r[3], "status": r[4]} for r in rows]

    def mark_order_paid(self, order_id: int, payment_id: str = "") -> bool:
        """Mark an order paid. True only the FIRST time.

        Yoco retries a webhook until it gets a 2xx, and a retry after our own
        timeout is normal rather than exceptional. Returning False on the
        second call is what stops one payment granting two months.
        """
        with self._lock:
            cur = self.db.execute(
                "UPDATE orders SET status = 'paid', paid = ?, payment_id = ? "
                "WHERE id = ? AND status != 'paid'",
                (time.time(), str(payment_id), int(order_id)))
            self.db.commit()
            return cur.rowcount > 0

    def apply_paid_order(self, order: dict) -> None:
        """Give the company what it paid for.

        Sets the packet's device cap, pushes the paid-until date out by the
        months bought, and lifts any suspension -- somebody who has just paid
        should not have to wait for a human to switch them back on, which was
        the whole point of taking the card.

        The period extends from whichever is later: what they already had, or
        now. Renewing early therefore adds to the end of the current period
        instead of throwing away what is left of it.
        """
        plan = plan_by_name(order.get("plan", ""))
        if plan is None:
            log.error("paid order %s names an unknown plan %r",
                      order.get("id"), order.get("plan"))
            return
        org_id = int(order["org_id"])
        row = self.get(org_id) or {}
        # An upgrade is not a renewal: the customer paid the difference for
        # days they had already bought, so the packet changes and the
        # renewal date stays exactly where it was. Extending it as well
        # would hand over a month for the price of a fortnight.
        if str(order.get("kind") or "") == "upgrade":
            self.apply_upgrade(int(order["org_id"]), order["plan"])
            return
        base = max(float(row.get("current_period_end") or 0.0), time.time())
        months = max(1, int(order.get("months") or 1))
        self._upsert(org_id, status="active", plan=plan["name"],
                     device_limit=plan["devices"],
                     current_period_end=add_billing_months(base, months),
                     grace_period_end=None)

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
