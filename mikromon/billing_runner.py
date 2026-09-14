"""The unattended half of billing: raise the renewal invoice, notice payment.

Two jobs on a timer, and the second is the one that matters:

  * **Invoicing.** A company whose paid-up date is a few days out gets an
    invoice raised in Invoice Ninja and emailed. Raised once per billing
    period, keyed on the period itself rather than on "did we run today", so
    a missed day or a clock change does not produce a second invoice.

  * **Reconciling.** Every unpaid invoice is checked against Invoice Ninja.
    This is not a backstop for the webhook -- it is the primary mechanism,
    and the webhook merely makes it faster.

    That split is deliberate. Invoice Ninja signs nothing: its webhooks carry
    at most a static header, which is a password in a header rather than
    proof of anything. And if the callback is the only path, then a webhook
    lost to a restart or a DNS blip means somebody who has paid gets
    suspended anyway -- the single worst failure this system can have. Asking
    the API on a timer costs one HTTP call per open invoice and removes that
    failure entirely.

Runs in the dashboard process, which is the one that already holds the
billing database and the platform settings.
"""
from __future__ import annotations

import logging
import threading
import time

from .billing import plan_by_name
from .invoiceninja import (InvoiceNinjaError, create_invoice, email_invoice,
                           ensure_client, invoice_status)

log = logging.getLogger(__name__)

# Often enough that an invoice goes out on the right morning, rare enough
# that it is invisible. The work is skipped entirely when Invoice Ninja is
# not configured, which is the normal state for most installs.
_TICK_SECONDS = 900
_DEFAULT_DAYS_BEFORE = 7
_DEFAULT_DUE_DAYS = 7


def _cfg(auth) -> dict:
    try:
        return auth.get_invoiceninja() or {}
    except Exception:  # noqa: BLE001
        return {}


def _enabled(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("token"))


def raise_due_invoices(billing, auth, cfg, now: float | None = None) -> int:
    """Invoice every company whose packet is about to lapse. Returns how many.

    The invoice is for the packet they are ON -- this is a renewal, not an
    upsell. Somebody who wants more devices upgrades from the Account tab and
    pays by card; putting a bigger number on a renewal invoice than the one
    they agreed to would be a genuinely serious thing to get wrong.
    """
    now = now if now is not None else time.time()
    base, token = cfg["url"], cfg["token"]
    days_before = float(cfg.get("days_before") or _DEFAULT_DAYS_BEFORE)
    due_days = int(cfg.get("due_days") or _DEFAULT_DUE_DAYS)
    raised = 0
    for row in billing.orgs_due_for_renewal(days_before, now=now):
        org_id = int(row["org_id"])
        period_end = float(row.get("current_period_end") or 0.0)
        plan = plan_by_name(row.get("plan") or "")
        if plan is None:
            # An unlimited or hand-granted packet has no price list entry.
            # Silently invoicing it for some default would be worse than
            # leaving it to a person.
            log.info("renewal: org %s is on %r, which has no standard price "
                     "-- leaving it to be invoiced by hand", org_id,
                     row.get("plan"))
            continue
        if billing.has_open_order_for_period(org_id, period_end):
            continue
        org = (auth.org(org_id) if auth else None) or {}
        name = org.get("name") or f"Company {org_id}"
        emails = list((org.get("alert_emails") or []))
        owner = ""
        for u in (auth.list_users(org_id) if auth else []) or []:
            if u.get("role") == "owner" and u.get("email"):
                owner = u["email"]
                break
        to = owner or (emails[0] if emails else "")
        amount = float(plan["price_zar"])
        try:
            client_id = ensure_client(
                base, token, org_id, name, email=to,
                address=org.get("address", ""), phone=org.get("phone", ""),
                vat=org.get("vat_number", ""))
            from .billing import payment_reference
            when = time.strftime("%d %B %Y", time.localtime(period_end))
            inv = create_invoice(
                base, token, client_id,
                description=(f"Router monitoring — up to {plan['devices']} "
                             f"devices. Renewal for the period starting "
                             f"{when}."),
                amount=amount, due_days=due_days,
                reference=payment_reference(org_id, name))
        except InvoiceNinjaError as exc:
            log.error("renewal: could not invoice org %s (%s): %s",
                      org_id, name, exc)
            continue
        order_id = billing.create_order(
            org_id, plan["name"], int(round(amount * 100)), months=1,
            provider="invoiceninja", due=period_end)
        billing.set_order_external(order_id, inv["id"])
        raised += 1
        log.info("renewal: invoice %s (%s) raised for org %s (%s), R%.2f, "
                 "packet lapses %s", inv["number"], inv["id"], org_id, name,
                 amount, time.strftime("%Y-%m-%d", time.localtime(period_end)))
        try:
            email_invoice(base, token, inv["id"])
        except InvoiceNinjaError as exc:
            # The invoice exists and will be reconciled either way; only the
            # email failed, and Invoice Ninja's own reminders still run.
            log.error("renewal: invoice %s was raised but could not be "
                      "emailed: %s", inv["id"], exc)
    return raised


def reconcile_payments(billing, cfg, only_invoice: str = "") -> int:
    """Ask Invoice Ninja which open invoices have been settled. Returns how many.

    `only_invoice` narrows it to one, which is what a webhook does: the
    callback says "look at this one now" rather than being believed.
    """
    base, token = cfg["url"], cfg["token"]
    applied = 0
    orders = billing.open_orders(provider="invoiceninja")
    if only_invoice:
        orders = [o for o in orders if o.get("external_id") == only_invoice]
    for order in orders:
        inv_id = order.get("external_id") or ""
        try:
            st = invoice_status(base, token, inv_id)
        except InvoiceNinjaError as exc:
            log.warning("reconcile: could not read invoice %s: %s", inv_id, exc)
            continue
        if st.get("is_deleted"):
            log.info("reconcile: invoice %s was deleted in Invoice Ninja; "
                     "cancelling order %s", inv_id, order["id"])
            continue
        if not st.get("paid"):
            continue
        # mark_order_paid returns True only the first time, so a webhook and
        # the timer both finding the same payment applies it once.
        if not billing.mark_order_paid(order["id"], f"in:{inv_id}"):
            continue
        billing.apply_paid_order(order)
        applied += 1
        log.info("reconcile: invoice %s (%s) is paid — org %s continues on "
                 "%s", st.get("number") or inv_id, inv_id, order["org_id"],
                 order["plan"])
    return applied


def run_once(billing, auth, now: float | None = None) -> tuple:
    """One pass of both jobs. Returns (invoices_raised, payments_applied)."""
    cfg = _cfg(auth)
    if not _enabled(cfg) or billing is None:
        return (0, 0)
    raised = applied = 0
    try:
        applied = reconcile_payments(billing, cfg)
    except Exception:  # noqa: BLE001 — never let one pass kill the thread
        log.exception("reconcile pass failed")
    try:
        raised = raise_due_invoices(billing, auth, cfg, now=now)
    except Exception:  # noqa: BLE001
        log.exception("renewal invoicing pass failed")
    return (raised, applied)


def start(billing, auth, stop: threading.Event | None = None):
    """Run both jobs on a timer for the life of the process.

    A daemon thread rather than cron: it has to reach the same billing
    database and platform settings the dashboard is holding open, and a
    second process writing that database is a race worth not having.
    """
    stop = stop or threading.Event()

    def loop():
        # Nothing on the first tick: a restart should not fire off invoices
        # before the admin has had a chance to see the server came up.
        while not stop.wait(_TICK_SECONDS):
            try:
                raised, applied = run_once(billing, auth)
                if raised or applied:
                    log.info("billing: %d invoice(s) raised, %d payment(s) "
                             "applied", raised, applied)
            except Exception:  # noqa: BLE001
                log.exception("billing runner tick failed")

    t = threading.Thread(target=loop, name="mikromon-billing", daemon=True)
    t.start()
    return stop
