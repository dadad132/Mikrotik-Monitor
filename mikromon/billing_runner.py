"""Invoice on a timer, take the card, and carry the packet on. No humans.

One rail: mikromon raises its own invoice and Yoco takes the payment. There
is no external invoicing service and no second gateway, because every one of
them wanted a registered company and a VAT number — and Yoco onboards a sole
proprietor on an ID number, which is what actually exists today.

The shape that makes it hands-off is the webhook. A customer clicks the pay
link on their invoice, pays on Yoco's page, and Yoco tells this server the
payment succeeded. The packet extends, any suspension lifts, and nobody here
sees it happen. You find out because the service kept working.

Three jobs, on two clocks:

  DAILY, after 08:00   raise the invoices due in the next seven days, and
                       email each one a link that pays it. Once a day,
                       because "whose packet lapses this week" has the same
                       answer at 09:00 and 09:15.
  DAILY                lapse the unpaid into grace, and grace into
                       suspension. A payment at any point undoes both.
                       Each step emails the company the link that pays
                       it, and two days before a suspension the
                       platform admins are told too.
  EVERY 15 MINUTES     nothing, unless somebody paid by bank transfer and a
                       human recorded it. The card path does not need a
                       poll: the webhook already said so.
"""
from __future__ import annotations

import logging
import threading
import time

from .billing import (BILLING_CURRENCY, add_billing_months, money,
                      plan_by_name, plan_for)

log = logging.getLogger(__name__)

# Often enough that an invoice goes out on the right morning, rare enough
# that it is invisible.
_TICK_SECONDS = 900

_DEFAULT_DAYS_BEFORE = 7
_DEFAULT_DUE_DAYS = 7

# Raising invoices is a once-a-day decision. Asking every fifteen minutes
# would send the same invoice ninety-six times or learn nothing, depending
# on the guard that stopped it.
_RAISE_HOUR = 8                 # local; nobody wants a 03:00 invoice
_RAISE_STATE_KEY = "billing_last_raise"

# The last reminder goes out this long before a suspension: time to pay on
# a working day, close enough to the date that it is the email acted on.
FINAL_REMINDER_DAYS = 2

# What the last pass did, so the panel can show it. A thread that stopped
# looks exactly like a quiet month until somebody can see when it last ran.
_last = {"ran": 0.0, "raised": 0, "applied": 0, "error": "", "started": 0.0}


class BillingError(Exception):
    """Something went wrong raising or recording a payment."""


def status() -> dict:
    """When the billing pass last ran, and what it did."""
    return dict(_last)


def _cfg(auth) -> dict:
    """The card gateway's settings. {} when it is not switched on."""
    try:
        return (auth.get_yoco() or {}) if auth else {}
    except Exception:  # noqa: BLE001
        return {}


def card_ready(auth) -> bool:
    """Can a customer actually pay? Both keys, or the link goes nowhere."""
    cfg = _cfg(auth)
    return bool(cfg.get("secret_key") and cfg.get("webhook_secret"))


# ---------------------------------------------------------------------------
# The daily gate
# ---------------------------------------------------------------------------

def raise_is_due(auth, now: float | None = None) -> bool:
    """Has today's invoice run already happened?

    Kept in settings rather than memory so a restart does not repeat it. It
    could not double-invoice anybody either way -- has_open_order_for_period
    sees to that -- but a service restarting in a loop would otherwise walk
    every due company on every boot for nothing.
    """
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    if lt.tm_hour < _RAISE_HOUR:
        return False
    try:
        last = str((auth.get_setting(_RAISE_STATE_KEY) or "") if auth else "")
    except Exception:  # noqa: BLE001
        last = ""
    return last != time.strftime("%Y-%m-%d", lt)


def mark_raised(auth, now: float | None = None) -> None:
    now = now if now is not None else time.time()
    try:
        if auth:
            auth.set_setting(_RAISE_STATE_KEY,
                             time.strftime("%Y-%m-%d", time.localtime(now)))
    except Exception:  # noqa: BLE001
        log.exception("could not record the daily invoice run")


def pay_link(auth, order_id: int, base_url: str = "") -> str:
    """The public URL that pays one order, or "".

    Without a base URL there is nothing to build a link from, and an invoice
    that goes out with a broken link is worse than one that goes out with
    none -- so this returns "" and the caller says so.

    The same goes for card payment being off: the link would open a page
    saying so. "" then too, and the invoice offers the bank details instead.
    Whether there is a link is the one thing every invoice, email and
    reminder decides "card or bank transfer" by, so they cannot disagree.
    """
    if not card_ready(auth):
        return ""
    try:
        from . import paylink
        base = base_url or str(
            (auth.get_setting("public_base_url") or "")).strip()
        if not base:
            return ""
        return paylink.url(auth, base, int(order_id))
    except Exception:  # noqa: BLE001
        log.exception("could not build a pay link")
        return ""


# ---------------------------------------------------------------------------
# Raising
# ---------------------------------------------------------------------------

def raise_due_invoices(billing, auth, now: float | None = None,
                       send=None) -> int:
    """Invoice every company whose packet is about to lapse. Returns how many.

    The invoice is for the packet they are ON -- this is a renewal, not an
    upsell. Somebody who wants more devices changes packet from their own
    Account tab; putting a bigger number on a renewal than the one they
    agreed to would be a genuinely serious thing to get wrong.
    """
    now = now if now is not None else time.time()
    cfg = _cfg(auth)
    days_before = float(cfg.get("days_before") or _DEFAULT_DAYS_BEFORE)
    due_days = int(cfg.get("due_days") or _DEFAULT_DUE_DAYS)
    raised = 0

    for row in billing.orgs_due_for_renewal(days_before, now=now):
        org_id = int(row["org_id"])
        # A packet change booked for this renewal takes effect BEFORE the
        # invoice is worked out, or they are billed for the packet they are
        # leaving -- the one figure on an invoice anybody checks.
        try:
            moved = billing.apply_pending_change(org_id, now)
            if moved:
                log.info("renewal: org %s moves to %s as booked", org_id, moved)
                row = dict(row, plan=moved)
        except Exception:  # noqa: BLE001 - one company must not stop the pass
            log.exception("could not apply the booked change for org %s", org_id)

        period_end = float(row.get("current_period_end") or 0.0)
        # A company still suspended a whole month after its paid-up date is
        # not invoiced for that month: it was never given it. It starts
        # again, pro rata from the day it pays, when it comes back -- and
        # without this the invoice withdrawn as stale would be raised again
        # the next morning.
        if period_end and add_billing_months(period_end, 1) <= now:
            continue
        # plan_for, not plan_by_name: a quoted company is not on a tier, and
        # looking their plan name up in the ladder is what returned nothing
        # and skipped them at every single renewal.
        try:
            plan = plan_for(row)
            if plan is None:
                # Still no price: unlimited or hand-granted with nothing
                # agreed. Inventing a figure would be worse than leaving it to
                # a person, but it is reported now instead of only logged --
                # see orgs_without_a_price and the Platform admin check.
                log.warning("renewal: org %s is on %r with no agreed price -- "
                            "NOT invoiced. Set the quoted price in Platform "
                            "admin or this repeats every month.", org_id,
                            row.get("plan"))
                continue
            if billing.has_open_order_for_period(org_id, period_end):
                continue

            amount = float(plan["price"])
            currency = str(plan.get("currency") or BILLING_CURRENCY)
            order_id = billing.create_order(
                org_id, plan["name"], int(round(amount * 100)), months=1,
                currency=currency, provider="yoco", due=period_end)
        except Exception:  # noqa: BLE001 - one company must not stop the pass
            # Without this, one company's bad row stopped every company
            # after it from being invoiced, the same way every morning.
            log.exception("renewal: could not invoice org %s; the others "
                          "still are", org_id)
            continue
        raised += 1
        log.info("renewal: invoiced org %s %s, packet lapses %s",
                 org_id, money(amount, currency),
                 time.strftime("%Y-%m-%d", time.localtime(period_end)))

        if send:
            try:
                send(org_id, order_id, plan, amount, currency, period_end,
                     due_days)
            except Exception:  # noqa: BLE001 - the invoice exists either way
                log.exception("renewal: org %s was invoiced but could not be "
                              "emailed", org_id)
    return raised


# ---------------------------------------------------------------------------
# Recording a payment that did not come through the card
# ---------------------------------------------------------------------------

def mark_paid(billing, auth, order_id: int, on_replaced=None) -> str:
    """Record a bank transfer against an invoice. "" when it worked.

    The card path never needs this -- Yoco's webhook records itself. This is
    for somebody who paid by EFT anyway, which people do, and which nothing
    can detect because the money lands where this server cannot see it.
    """
    order = billing.order(int(order_id))
    if not order:
        raise BillingError("No such invoice.")
    if order.get("paid"):
        return "That invoice was already marked paid."
    if not billing.mark_order_paid(int(order_id), f"eft:{order_id}"):
        return "That invoice was already marked paid."
    replaced = billing.apply_paid_order(order) or []
    if replaced and on_replaced:
        try:
            on_replaced(replaced)
        except Exception:  # noqa: BLE001 - the payment is recorded either way
            log.exception("could not send the re-priced renewal for order %s",
                          order_id)
    log.info("payment recorded by hand for order %s", order_id)
    return ""


# ---------------------------------------------------------------------------
# What is coming, and what is owed
# ---------------------------------------------------------------------------

def upcoming(billing, auth, limit: int = 20) -> list:
    """Who gets invoiced next, and when. Read-only; raises nothing.

    Seeing next month's invoices before they go out is the difference
    between billing you trust and billing you hope about.
    """
    if billing is None:
        return []
    cfg = _cfg(auth)
    days_before = float(cfg.get("days_before") or _DEFAULT_DAYS_BEFORE)
    now = time.time()
    out = []
    for row in billing.orgs_due_for_renewal(400, now=now):
        org_id = int(row["org_id"])
        plan = plan_for(row)
        end = float(row.get("current_period_end") or 0.0)
        org = (auth.org(org_id) if auth else None) or {}
        out.append({
            "org_id": org_id,
            "name": org.get("name") or f"Company {org_id}",
            "plan": row.get("plan") or "",
            "amount": float(plan["price"]) if plan else None,
            "currency": (str(plan.get("currency") or BILLING_CURRENCY)
                         if plan else BILLING_CURRENCY),
            "period_end": end,
            "invoice_on": end - days_before * 86400,
            "days_until_invoice": (end - days_before * 86400 - now) / 86400,
            "already_raised": billing.has_open_order_for_period(org_id, end),
        })
    out.sort(key=lambda r: r["invoice_on"])
    return out[:limit]


def outstanding(billing, auth, limit: int = 50) -> list:
    """Invoices raised and not yet paid, newest first."""
    if billing is None:
        return []
    out = []
    for order in billing.open_orders(provider="yoco", require_external=False):
        org_id = int(order.get("org_id") or 0)
        org = (auth.org(org_id) if auth else None) or {}
        from .billing import payment_reference
        out.append({
            "order_id": order.get("id"),
            "org_id": org_id,
            "name": org.get("name") or f"Company {org_id}",
            "plan": order.get("plan") or "",
            "kind": order.get("kind") or "renewal",
            "amount": (order.get("amount_cents") or 0) / 100.0,
            "currency": order.get("currency") or BILLING_CURRENCY,
            "invoice_id": order.get("external_id") or "",
            "raised": order.get("created") or 0,
            "due": order.get("due") or 0,
            "reference": payment_reference(org_id, org.get("name", "")),
        })
    out.sort(key=lambda r: r["raised"], reverse=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

def _remind(remind, org_id: int, stage: str) -> bool:
    """Ask for one reminder to go out. True when it was dealt with.

    A reminder that fails is logged and reported, never raised: the lapse it
    belongs to has already happened, and one company's mail must not stop
    the pass for the rest.
    """
    if not remind:
        return True
    try:
        return bool(remind(org_id, stage))
    except Exception:  # noqa: BLE001
        log.exception("billing: could not send the %s reminder to org %s",
                      stage, org_id)
        return False


def run_once(billing, auth, now: float | None = None,
             force_raise: bool = False, send=None, lapsed_upgrade=None,
             remind=None) -> tuple:
    """One pass. Returns (invoices_raised, accounts_lapsed).

    Lapsing and invoicing both happen once a day; nothing else needs a
    poll, because a card payment announces itself. Upgrade invoices that
    ran past their three days are withdrawn on every pass, so one lapses
    within a quarter of an hour rather than at tomorrow's run.

    `remind(org_id, stage)` chases an unpaid renewal: "overdue" the day it
    lapses into grace, "final" FINAL_REMINDER_DAYS before it would be
    suspended, and "suspended" when it is. So a company is not cut off
    without first being sent, twice, the link that pays it. The final
    one is recorded once sent, so it goes out once per lapse; a send that
    fails (False) is tried again at tomorrow's pass.
    """
    if billing is None:
        return (0, 0)
    raised = lapsed = 0
    try:
        for order in billing.lapse_upgrades(now):
            log.info("billing: upgrade invoice %s for org %s lapsed unpaid; "
                     "the company stays on its packet", order.get("id"),
                     order.get("org_id"))
            if lapsed_upgrade:
                try:
                    lapsed_upgrade(order)
                except Exception:  # noqa: BLE001 - the lapse stands
                    log.exception("could not tell org %s its upgrade lapsed",
                                  order.get("org_id"))
    except Exception:  # noqa: BLE001
        log.exception("the upgrade lapse pass failed")
    if force_raise or raise_is_due(auth, now):
        # Lapse BEFORE invoicing: an account suspended this morning should
        # not also be invoiced for next month in the same pass.
        moved = {"grace": [], "suspended": []}
        try:
            moved = billing.lapse_due(now)
            lapsed = len(moved["grace"]) + len(moved["suspended"])
            for org_id in moved["grace"]:
                log.info("billing: org %s has lapsed into the grace period",
                         org_id)
                _remind(remind, org_id, "overdue")
            for org_id in moved["suspended"]:
                log.warning("billing: org %s suspended, grace expired with "
                            "no payment", org_id)
                # Somebody who asked to cancel was not cut off for an unpaid
                # invoice, and an email saying they were would be wrong.
                if not (billing.get(org_id) or {}).get("cancel_requested"):
                    _remind(remind, org_id, "suspended")
        except Exception:  # noqa: BLE001
            log.exception("the lapse pass failed")
        try:
            for row in billing.orgs_suspending_soon(
                    FINAL_REMINDER_DAYS * 86400, now):
                org_id = int(row["org_id"])
                # Lapsed into grace on this very pass (the server was off
                # for days): the overdue email just sent already names the
                # date. The last reminder follows tomorrow, not now.
                if org_id in moved["grace"]:
                    continue
                if _remind(remind, org_id, "final"):
                    billing.mark_final_reminded(org_id,
                                                row["grace_period_end"])
        except Exception:  # noqa: BLE001
            log.exception("the final reminder pass failed")
        try:
            # An invoice for a month that is over is no longer owed: a
            # company still suspended by then starts again from the day it
            # pays (billing.outstanding_renewal).
            for order in billing.lapse_stale_renewals(now):
                log.info("billing: renewal invoice %s for org %s lapsed "
                         "unpaid; its month is over", order.get("id"),
                         order.get("org_id"))
        except Exception:  # noqa: BLE001
            log.exception("the stale invoice pass failed")
        try:
            raised = raise_due_invoices(billing, auth, now=now, send=send)
            if not force_raise:
                mark_raised(auth, now)
        except Exception:  # noqa: BLE001
            log.exception("renewal invoicing pass failed")
    return (raised, lapsed)


def start(billing, auth, stop: threading.Event | None = None, send=None,
          lapsed_upgrade=None, remind=None):
    """Run the billing pass on a timer for the life of the process.

    A daemon thread rather than cron: it needs the same billing database the
    dashboard is holding open, and a second process writing it is a race
    worth not having.
    """
    stop = stop or threading.Event()
    _last["started"] = time.time()

    def loop():
        # Nothing on the first tick: a restart should not fire off invoices
        # before anybody has seen the server come up.
        while not stop.wait(_TICK_SECONDS):
            try:
                raised, lapsed = run_once(billing, auth, send=send,
                                          lapsed_upgrade=lapsed_upgrade,
                                          remind=remind)
                _last.update({"ran": time.time(), "raised": raised,
                              "applied": lapsed, "error": ""})
                if raised or lapsed:
                    log.info("billing: %d invoice(s) raised, %d account(s) "
                             "lapsed", raised, lapsed)
            except Exception as exc:  # noqa: BLE001
                _last.update({"ran": time.time(), "error": str(exc)})
                log.exception("billing runner tick failed")

    threading.Thread(target=loop, name="mikromon-billing",
                     daemon=True).start()
    return stop
