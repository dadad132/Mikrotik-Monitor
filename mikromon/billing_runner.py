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

from . import zoho as _z
from .billing import BILLING_CURRENCY, money, plan_by_name

log = logging.getLogger(__name__)

# Often enough that an invoice goes out on the right morning, rare enough
# that it is invisible. The work is skipped entirely when Invoice Ninja is
# not configured, which is the normal state for most installs.
_TICK_SECONDS = 900

# What the last pass did, so the panel can show it. A thread that stopped
# looks exactly like a quiet month until somebody can see when it last ran.
_last = {"ran": 0.0, "raised": 0, "applied": 0, "error": "", "started": 0.0}


def status() -> dict:
    """When the billing pass last ran, and what it did."""
    return dict(_last)
_DEFAULT_DAYS_BEFORE = 7

# Raising invoices is a once-a-day decision: "whose packet lapses within
# seven days" does not change between 09:00 and 09:15. Asking every fifteen
# minutes spent 96x the API calls to learn the same thing.
_RAISE_HOUR = 8                 # local time; nobody wants a 03:00 invoice
_RAISE_STATE_KEY = "billing_last_raise"

# Payments DO want to be noticed promptly, but one call per open invoice
# every fifteen minutes is 1440 calls/day at fifteen invoices -- over Zoho's
# free cap of 1000. A callback still triggers an immediate re-read, so this
# only paces the safety net.
_RECONCILE_COOLDOWN = 1800.0
_checked: dict = {}             # invoice id -> when it was last read
_DEFAULT_DUE_DAYS = 7


class ProviderError(Exception):
    """Whatever the invoicing system said, in one type the runner can catch."""


class _Zoho:
    """Zoho Invoice, reached with an OAuth refresh token.

    Two shape differences are absorbed here rather than leaking upward:
    Zoho wants an absolute due DATE where Invoice Ninja takes a number of
    days, and it works in rands where this system counts in cents.
    """

    name = "zoho"

    def __init__(self, cfg):
        self.cfg = cfg

    def ensure_client(self, org_id, name, **kw):
        try:
            return _z.ensure_client(self.cfg, name, email=kw.get("email", ""),
                                 phone=kw.get("phone", ""))
        except _z.ZohoError as exc:
            raise ProviderError(str(exc)) from exc

    def create_invoice(self, client_id, *, description, amount, due_days,
                       reference, currency=""):
        due = time.strftime("%Y-%m-%d",
                            time.localtime(time.time() + due_days * 86400))
        try:
            return _z.create_invoice(self.cfg, client_id, description=description,
                                  amount_cents=int(round(amount * 100)),
                                  due_date=due, reference=reference,
                                     currency=currency)
        except _z.ZohoError as exc:
            raise ProviderError(str(exc)) from exc

    def email_invoice(self, invoice_id):
        try:
            _z.email_invoice(self.cfg, invoice_id)
        except _z.ZohoError as exc:
            raise ProviderError(str(exc)) from exc

    def invoice_status(self, invoice_id):
        try:
            return _z.invoice_status(self.cfg, invoice_id)
        except _z.ZohoError as exc:
            raise ProviderError(str(exc)) from exc

    def record_payment(self, invoice_id, customer_name, amount,
                       reference=""):
        try:
            contact_id = _z.ensure_client(self.cfg, customer_name)
            return _z.record_payment(self.cfg, invoice_id, contact_id,
                                     amount, reference=reference)
        except _z.ZohoError as exc:
            raise ProviderError(str(exc)) from exc


def provider_from_cfg(cfg):
    """The adapter for a settings dict, whichever provider it belongs to.

    Callers that were handed a cfg should use it rather than going back to
    the settings store: it is what they were given, and re-reading could
    quietly act on a different provider than the caller meant.
    """
    cfg = cfg or {}
    if cfg.get("refresh_token") and cfg.get("api_base"):
        return _Zoho(cfg)
    return None


def provider_for(auth):
    """Whichever invoicing system is connected, or None.

    Zoho is the only one now. Invoice Ninja was retired: its hosted free
    plan has no API at all, and keeping a second provider alive meant two
    code paths for the same job where only one of them was ever exercised.
    """
    if auth is None:
        return None
    try:
        z = auth.get_zoho() or {}
    except Exception:  # noqa: BLE001
        z = {}
    if z.get("refresh_token") and z.get("api_base"):
        return _Zoho(z)
    return None


def _cfg(auth) -> dict:
    """The settings of whichever provider is connected. {} if none."""
    p = provider_for(auth)
    return dict(p.cfg) if p else {}


def _enabled(cfg: dict) -> bool:
    return bool(cfg.get("refresh_token"))


def raise_due_invoices(billing, auth, cfg, now: float | None = None,
                       provider=None) -> int:
    """Invoice every company whose packet is about to lapse. Returns how many.

    The invoice is for the packet they are ON -- this is a renewal, not an
    upsell. Somebody who wants more devices upgrades from the Account tab and
    pays by card; putting a bigger number on a renewal invoice than the one
    they agreed to would be a genuinely serious thing to get wrong.
    """
    now = now if now is not None else time.time()
    prov = provider or provider_from_cfg(cfg) or provider_for(auth)
    if prov is None:
        return 0
    days_before = float(cfg.get("days_before") or _DEFAULT_DAYS_BEFORE)
    due_days = int(cfg.get("due_days") or _DEFAULT_DUE_DAYS)
    raised = 0
    for row in billing.orgs_due_for_renewal(days_before, now=now):
        org_id = int(row["org_id"])
        # A packet change booked for this renewal takes effect BEFORE the
        # invoice is worked out. The other order would bill them for the
        # packet they are leaving, which is the one figure on the invoice
        # they would certainly notice.
        try:
            moved = billing.apply_pending_change(org_id, now)
            if moved:
                log.info("renewal: org %s moves to %s as booked",
                         org_id, moved)
                row = dict(row, plan=moved)
        except Exception:  # noqa: BLE001 — one company must not stop the pass
            log.exception("could not apply the booked packet change for "
                          "org %s", org_id)
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
        # The price, in the currency it was decided and advertised in. This
        # read price_zar, so the site quoted dollars and the invoice charged
        # rands converted at a constant in the source -- under-charging by
        # the drift, every month, on every account, silently.
        amount = float(plan["price"])
        currency = str(plan.get("currency") or BILLING_CURRENCY)
        try:
            client_id = prov.ensure_client(
                org_id, name, email=to,
                address=org.get("address", ""), phone=org.get("phone", ""),
                vat=org.get("vat_number", ""))
            from .billing import payment_reference
            when = time.strftime("%d %B %Y", time.localtime(period_end))
            ref = payment_reference(org_id, name)
            inv = prov.create_invoice(
                client_id,
                # The reference is written into the description as well as
                # the reference field. It cannot be reconstructed afterwards
                # from money arriving in a bank account, so it must not be
                # possible for a template setting to hide it.
                description=(f"Router monitoring — up to {plan['devices']} "
                             f"devices. Renewal for the period starting "
                             f"{when}. Please quote {ref} on your payment."),
                amount=amount, due_days=due_days,
                reference=ref, currency=currency)
        except ProviderError as exc:
            log.error("renewal: could not invoice org %s (%s): %s",
                      org_id, name, exc)
            continue
        order_id = billing.create_order(
            org_id, plan["name"], int(round(amount * 100)), months=1,
            currency=currency, provider=prov.name, due=period_end)
        billing.set_order_external(order_id, inv["id"])
        raised += 1
        log.info("renewal: invoice %s (%s) raised for org %s (%s), %s, "
                 "packet lapses %s", inv["number"], inv["id"], org_id, name,
                 money(amount, currency),
                 time.strftime("%Y-%m-%d", time.localtime(period_end)))
        try:
            prov.email_invoice(inv["id"])
        except ProviderError as exc:
            # The invoice exists and will be reconciled either way; only the
            # email failed, and Invoice Ninja's own reminders still run.
            log.error("renewal: invoice %s was raised but could not be "
                      "emailed: %s", inv["id"], exc)
    return raised


def reconcile_payments(billing, cfg, only_invoice: str = "",
                       provider=None, auth=None) -> int:
    """Ask Invoice Ninja which open invoices have been settled. Returns how many.

    `only_invoice` narrows it to one, which is what a webhook does: the
    callback says "look at this one now" rather than being believed.
    """
    prov = provider or provider_from_cfg(cfg) or provider_for(auth)
    if prov is None:
        return 0
    applied = 0
    orders = billing.open_orders(provider=prov.name)
    if only_invoice:
        orders = [o for o in orders if o.get("external_id") == only_invoice]
    now = time.time()
    for order in orders:
        inv_id = order.get("external_id") or ""
        # A callback names one invoice and that one is always re-read: it is
        # the fast path, and the whole point of treating it as a nudge is
        # that acting on it is cheap. The rest are paced.
        if not only_invoice:
            last = _checked.get(inv_id, 0.0)
            if now - last < _RECONCILE_COOLDOWN:
                continue
            _checked[inv_id] = now
        try:
            st = prov.invoice_status(inv_id)
        except ProviderError as exc:
            log.warning("reconcile: could not read invoice %s: %s", inv_id, exc)
            continue
        if st.get("is_deleted"):
            log.info("reconcile: invoice %s was deleted at the provider; "
                     "cancelling order %s", inv_id, order["id"])
            continue
        if not st.get("paid"):
            continue
        # mark_order_paid returns True only the first time, so a webhook and
        # the timer both finding the same payment applies it once.
        if not billing.mark_order_paid(order["id"],
                                       f"{prov.name[:2]}:{inv_id}"):
            continue
        billing.apply_paid_order(order)
        applied += 1
        log.info("reconcile: invoice %s (%s) is paid — org %s continues on "
                 "%s", st.get("number") or inv_id, inv_id, order["org_id"],
                 order["plan"])
    return applied


def _today() -> str:
    return time.strftime("%Y-%m-%d")


def raise_is_due(auth, now: float | None = None) -> bool:
    """Has the daily invoice run already happened today?

    Kept in settings rather than in memory so a restart does not re-run it.
    It cannot double-invoice anybody either way -- has_open_order_for_period
    sees to that -- but a service that restarts in a loop would otherwise
    re-read every due company on every boot, for nothing.
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


def upcoming(billing, auth, limit: int = 20) -> list:
    """Who gets invoiced next, and when. Read-only -- raises nothing.

    The same query the renewal pass uses, run far enough ahead to show what
    is coming. Being able to see next month's invoices before they go out is
    the difference between billing you trust and billing you hope about.
    """
    if billing is None:
        return []
    cfg = _cfg(auth)
    days_before = float(cfg.get("days_before") or _DEFAULT_DAYS_BEFORE)
    now = time.time()
    out = []
    for row in billing.orgs_due_for_renewal(400, now=now):
        org_id = int(row["org_id"])
        plan = plan_by_name(row.get("plan") or "")
        end = float(row.get("current_period_end") or 0.0)
        org = (auth.org(org_id) if auth else None) or {}
        out.append({
            "org_id": org_id,
            "name": org.get("name") or f"Company {org_id}",
            "plan": row.get("plan") or "",
            "amount": float(plan["price"]) if plan else None,
            "currency": str(plan.get("currency") or BILLING_CURRENCY)
            if plan else BILLING_CURRENCY,
            "period_end": end,
            "invoice_on": end - days_before * 86400,
            "days_until_invoice": (end - days_before * 86400 - now) / 86400,
            "already_raised": billing.has_open_order_for_period(org_id, end),
        })
    out.sort(key=lambda r: r["invoice_on"])
    return out[:limit]


def outstanding(billing, auth, limit: int = 50) -> list:
    """Invoices raised and not yet settled, newest first.

    Read from our own orders rather than from the provider: this is the list
    somebody works through with a bank statement open, and it has to render
    even when the provider is unreachable.
    """
    if billing is None:
        return []
    prov = provider_for(auth)
    out = []
    for order in billing.open_orders(provider=prov.name if prov else "zoho"):
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


def settle_matching_invoice(billing, auth, paid_order) -> str:
    """Tell the invoicing provider about a payment taken somewhere else.

    Returns a note for the log, or "" when there was nothing to settle.

    A card payment and an invoice are two records of one transaction. When
    the card is taken by a different provider from the one that raised the
    invoice -- which is the whole point of using a local gateway with a
    cheaper rate -- the invoice has to be told, or it keeps chasing money
    that has arrived.

    The packet is NOT extended again. It moved when the card was paid;
    doing it twice would hand over a second month for nothing.
    """
    if billing is None or not paid_order:
        return ""
    prov = provider_for(auth)
    if prov is None or not hasattr(prov, "record_payment"):
        return ""
    org_id = int(paid_order.get("org_id") or 0)
    # Any other open order for this company at the invoicing provider. The
    # period is not compared: a company with one open invoice and a card
    # payment has just paid that invoice, and matching on an exact period
    # would miss a part-month upgrade paying off its own invoice.
    others = [o for o in billing.open_orders(provider=prov.name)
              if int(o.get("org_id") or 0) == org_id
              and int(o.get("id") or 0) != int(paid_order.get("id") or 0)]
    if not others:
        return ""
    target = others[0]
    inv_id = target.get("external_id") or ""
    if not inv_id:
        return ""

    org = (auth.org(org_id) if auth else None) or {}
    name = org.get("name") or f"Company {org_id}"
    amount = (target.get("amount_cents") or 0) / 100.0
    try:
        from .billing import payment_reference
        prov.record_payment(inv_id, name, amount,
                            reference=payment_reference(org_id,
                                                        org.get("name", "")))
    except ProviderError as exc:
        # Worth saying loudly: the customer is fine and the service is fine,
        # but the books now disagree and somebody will be chased for money
        # they have paid.
        log.error("card payment for org %s could not be recorded against "
                  "invoice %s: %s", org_id, inv_id, exc)
        return f"invoice {inv_id} still reads unpaid: {exc}"

    # Marked paid so the reconcile pass stops asking about it. NOT applied:
    # apply_paid_order already ran for the payment that actually happened.
    billing.mark_order_paid(int(target["id"]), f"card:{paid_order.get('id')}")
    log.info("org %s paid by card; invoice %s recorded as settled",
             org_id, inv_id)
    return ""


def mark_paid(billing, auth, order_id: int) -> str:
    """Record an EFT payment: at the provider AND here, in that order.

    The provider first, because that is the one that can refuse -- a wrong
    scope, a deleted invoice, a rate limit. Recording it here first and
    failing there would leave a customer switched on with an invoice that
    still says unpaid, which is the version somebody discovers a month
    later while reconciling.
    """
    order = billing.order(int(order_id))
    if not order:
        raise ProviderError("No such invoice.")
    if order.get("paid"):
        return "That invoice was already marked paid."
    prov = provider_for(auth)
    inv_id = order.get("external_id") or ""
    amount = (order.get("amount_cents") or 0) / 100.0

    if prov is not None and inv_id and hasattr(prov, "record_payment"):
        org = (auth.org(int(order["org_id"])) if auth else None) or {}
        from .billing import payment_reference
        try:
            prov.record_payment(
                inv_id, org.get("name") or f"Company {order['org_id']}",
                amount,
                reference=payment_reference(int(order["org_id"]),
                                            org.get("name", "")))
        except ProviderError as exc:
            raise ProviderError(
                f"The payment was NOT recorded, so nothing has changed: "
                f"{exc}") from exc

    if not billing.mark_order_paid(int(order_id), f"eft:{inv_id or order_id}"):
        return "That invoice was already marked paid."
    billing.apply_paid_order(order)
    return ""


def run_once(billing, auth, now: float | None = None,
             force_raise: bool = False) -> tuple:
    """One pass of both jobs. Returns (invoices_raised, payments_applied).

    The two run on different clocks: payments are reconciled every tick so a
    customer who has paid is not left suspended, while invoices are raised
    once a day. `force_raise` is the "Run the billing pass now" button, which
    means exactly that and does not consume the day's run.
    """
    prov = provider_for(auth)
    if prov is None or billing is None:
        return (0, 0)
    cfg = prov.cfg
    raised = applied = 0
    try:
        applied = reconcile_payments(billing, cfg, provider=prov)
    except Exception:  # noqa: BLE001 — never let one pass kill the thread
        log.exception("reconcile pass failed")
    # The invoice run is daily; reconciliation above is not.
    if force_raise or raise_is_due(auth, now):
        # Lapse BEFORE invoicing, and only on the daily pass. An account
        # whose period ended without payment moves to grace and then to
        # suspension -- nothing did this before, so every customer had in
        # effect a free account after their first month. It runs first
        # because an account that has just been suspended should not also
        # be invoiced for the next month in the same pass.
        try:
            moved = billing.lapse_due(now)
            for org_id in moved["grace"]:
                log.info("billing: org %s has lapsed into the grace period",
                         org_id)
            for org_id in moved["suspended"]:
                log.warning("billing: org %s suspended, grace expired "
                            "with no payment", org_id)
        except Exception:  # noqa: BLE001 — never let this kill the pass
            log.exception("the lapse pass failed")

        try:
            raised = raise_due_invoices(billing, auth, cfg, now=now,
                                        provider=prov)
            if not force_raise:
                mark_raised(auth, now)
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
    _last["started"] = time.time()

    def loop():
        # Nothing on the first tick: a restart should not fire off invoices
        # before the admin has had a chance to see the server came up.
        while not stop.wait(_TICK_SECONDS):
            try:
                raised, applied = run_once(billing, auth)
                _last.update({"ran": time.time(), "raised": raised,
                              "applied": applied, "error": ""})
                if raised or applied:
                    log.info("billing: %d invoice(s) raised, %d payment(s) "
                             "applied", raised, applied)
            except Exception as exc:  # noqa: BLE001
                _last.update({"ran": time.time(), "error": str(exc)})
                log.exception("billing runner tick failed")

    t = threading.Thread(target=loop, name="mikromon-billing", daemon=True)
    t.start()
    return stop
