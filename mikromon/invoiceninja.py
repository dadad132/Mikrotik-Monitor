"""Invoice Ninja — raise the renewal invoice, and find out when it is paid.

Invoice Ninja owns the paperwork: the layout, the logo, the sequential
numbering, the reminder emails, and the switch to a real Tax Invoice once a
VAT number exists. mikromon owns what a payment MEANS -- which company, which
packet, and until when.

The one rule worth stating up front: **a webhook is a nudge, never proof.**
Invoice Ninja's webhooks carry no signature (only optional static headers,
which are a bearer token by another name), and their payload shape has
changed between releases. So the webhook only tells us *which invoice to go
and look at*; whether it is actually paid is then read back from the API.
That also means a webhook that never arrives is survivable: `open_invoices`
exists so a reconcile pass can ask the same question on a timer, and a lost
callback cannot leave somebody who has paid getting suspended.

Stdlib only, like the rest of this project.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

_TIMEOUT = 25.0


class InvoiceNinjaError(Exception):
    """A call did not succeed. The message is fit to show an admin, who is
    usually looking at a settings page wondering what they typed wrong."""


def _api(base: str, token: str, path: str, *, method: str = "GET",
         body: dict | None = None, timeout: float = _TIMEOUT):
    """One Invoice Ninja API call. Returns the decoded `data` payload.

    v5 renamed the auth header from v4's `X-Ninja-Token`; sending the old one
    fails as an authorisation error that says nothing about why.
    """
    if not base or not token:
        raise InvoiceNinjaError("Invoice Ninja is not configured on this "
                                "server.")
    url = base.rstrip("/") + "/api/v1/" + path.lstrip("/")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"X-API-TOKEN": token,
                 "Content-Type": "application/json",
                 "Accept": "application/json",
                 # Invoice Ninja rejects some calls without this; it is their
                 # CSRF-ish guard and costs nothing to send.
                 "X-Requested-With": "XMLHttpRequest",
                 "User-Agent": "mikromon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8") or "{}"
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        log.error("Invoice Ninja %s %s -> HTTP %s %s", method, path,
                  exc.code, detail)
        if exc.code in (401, 403):
            raise InvoiceNinjaError(
                "Invoice Ninja rejected the API token. Check it was copied "
                "in full, and that it belongs to this company.") from None
        if exc.code == 404:
            raise InvoiceNinjaError(
                f"Invoice Ninja has no such record ({path}).") from None
        raise InvoiceNinjaError(
            f"Invoice Ninja returned HTTP {exc.code}. {detail[:160]}".strip()
        ) from None
    except Exception as exc:  # noqa: BLE001 — DNS, TLS, timeout
        log.error("Invoice Ninja %s %s failed: %s", method, path, exc)
        raise InvoiceNinjaError(
            "Could not reach Invoice Ninja. Check the URL and that the "
            "server can get to it.") from None
    try:
        out = json.loads(raw)
    except ValueError:
        raise InvoiceNinjaError(
            "Invoice Ninja returned something that was not JSON. If the URL "
            "points at a login page rather than the API, that is what this "
            "looks like.") from None
    return out.get("data", out)


def ping(base: str, token: str) -> str:
    """Prove the URL and token work, and say who they belong to.

    Worth its own call: the settings page can then confirm the connection at
    the moment it is saved, rather than the first failure being a renewal
    invoice that silently never went out.
    """
    data = _api(base, token, "company_users?include=company")
    company = ""
    if isinstance(data, dict):
        company = ((data.get("company") or {}).get("settings") or {}).get(
            "name", "")
    elif isinstance(data, list) and data:
        company = (((data[0] or {}).get("company") or {}).get("settings")
                   or {}).get("name", "")
    return company or "connected"


# --------------------------------------------------------------- clients
def find_client(base: str, token: str, org_id: int) -> str:
    """The Invoice Ninja client for one mikromon company, or "".

    Matched on `id_number`, which is set to our own org id when the client is
    created. Matching on the company NAME would break the first time somebody
    corrects a spelling on the Account tab, and would quietly start invoicing
    a second client instead.
    """
    want = str(int(org_id))
    data = _api(base, token,
                "clients?id_number=" + urllib.parse.quote(want) + "&per_page=50")
    for row in data if isinstance(data, list) else []:
        if str(row.get("id_number") or "") == want and not row.get("is_deleted"):
            return str(row.get("id") or "")
    return ""


def create_client(base: str, token: str, org_id: int, name: str,
                  email: str = "", address: str = "", phone: str = "",
                  vat: str = "") -> str:
    body: dict = {"name": name or f"Company {org_id}",
                  "id_number": str(int(org_id))}
    if address:
        body["address1"] = address
    if phone:
        body["phone"] = phone
    if vat:
        body["vat_number"] = vat
    if email:
        # Without a contact there is nobody to email the invoice to, and
        # Invoice Ninja will happily create the client anyway.
        body["contacts"] = [{"email": email, "send_email": True}]
    data = _api(base, token, "clients", method="POST", body=body)
    cid = str((data or {}).get("id") or "")
    if not cid:
        raise InvoiceNinjaError("Invoice Ninja did not return a client id.")
    log.info("Invoice Ninja: created client %s for org %s (%s)", cid, org_id,
             name)
    return cid


def ensure_client(base: str, token: str, org_id: int, name: str, **kw) -> str:
    """The client id for this company, creating it the first time."""
    return find_client(base, token, org_id) or create_client(
        base, token, org_id, name, **kw)


# -------------------------------------------------------------- invoices
def create_invoice(base: str, token: str, client_id: str, *, description: str,
                   amount: float, due_days: int = 7,
                   reference: str = "", terms: str = "") -> dict:
    """Raise one invoice. Returns {"id", "number", "link"}.

    `reference` goes in `po_number` so a bank statement, an Invoice Ninja
    record and a mikromon order can all be tied together by eye later --
    which is the only thing that makes a disputed payment resolvable.
    """
    body = {
        "client_id": client_id,
        "date": time.strftime("%Y-%m-%d"),
        "due_date": time.strftime("%Y-%m-%d",
                                  time.localtime(time.time() + due_days * 86400)),
        "line_items": [{"quantity": 1, "cost": round(float(amount), 2),
                        "product_key": "Monitoring",
                        "notes": description}],
    }
    if reference:
        body["po_number"] = reference
    if terms:
        body["terms"] = terms
    data = _api(base, token, "invoices", method="POST", body=body) or {}
    inv_id = str(data.get("id") or "")
    if not inv_id:
        raise InvoiceNinjaError("Invoice Ninja did not return an invoice id.")
    link = ""
    for inv in (data.get("invitations") or []):
        if inv.get("link"):
            link = str(inv["link"])
            break
    return {"id": inv_id, "number": str(data.get("number") or ""), "link": link}


def email_invoice(base: str, token: str, invoice_id: str) -> None:
    """Send it. A GET, oddly, but that is the documented endpoint."""
    _api(base, token, f"invoices/{invoice_id}/email")
    log.info("Invoice Ninja: emailed invoice %s", invoice_id)


def invoice_status(base: str, token: str, invoice_id: str) -> dict:
    """{"paid", "balance", "amount", "number", "status_id"} for one invoice.

    This is the authority on whether money arrived -- not the webhook that
    prompted us to ask. `balance` reaching zero is what "paid" means, and it
    covers a part payment topped up later, which a status flag alone does not.
    """
    data = _api(base, token, f"invoices/{invoice_id}") or {}
    try:
        balance = float(data.get("balance") or 0.0)
    except (TypeError, ValueError):
        balance = 0.0
    try:
        amount = float(data.get("amount") or 0.0)
    except (TypeError, ValueError):
        amount = 0.0
    status_id = str(data.get("status_id") or "")
    # 4 = paid in Invoice Ninja's own enum. Both conditions are checked
    # because a zero-amount invoice has a zero balance without anyone having
    # paid anything.
    paid = (amount > 0 and balance <= 0.0) or status_id == "4"
    return {"paid": paid, "balance": balance, "amount": amount,
            "number": str(data.get("number") or ""), "status_id": status_id,
            "is_deleted": bool(data.get("is_deleted"))}


def invoice_ids_in(payload) -> list:
    """Every invoice id mentioned anywhere in a webhook body.

    Deliberately a recursive sweep rather than a fixed path. Invoice Ninja
    sends the payment entity for a payment event, the invoice entity for an
    invoice event, and has moved where the invoice sits between releases. All
    we need from the webhook is a hint about where to look; the answer comes
    from invoice_status() afterwards, so casting a wide net here is safe and
    a missed path is not.
    """
    found: list = []

    def walk(node, key=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("invoice_id", "id") and isinstance(v, str) and v:
                    # A bare "id" only counts inside something invoice-shaped.
                    if k == "invoice_id" or key in ("invoices", "invoice",
                                                    "paymentables"):
                        found.append(v)
                else:
                    walk(v, k)
        elif isinstance(node, list):
            for item in node:
                walk(item, key)

    walk(payload)
    seen, out = set(), []
    for i in found:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out
