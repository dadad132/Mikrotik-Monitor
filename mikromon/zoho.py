"""Zoho Invoice — raise the renewal invoice, and find out when it is paid.

Same division of labour as the Invoice Ninja module: Zoho owns the paperwork
(layout, sequential numbering, reminder emails, the switch to a real Tax
Invoice once a VAT number exists), and mikromon owns what a payment MEANS --
which company, which packet, and until when. The same rule applies too: **a
callback is a nudge, never proof.** Whether an invoice is paid is read back
from the API, so a callback that never arrives delays a reactivation by
minutes instead of leaving somebody who has paid switched off.

What is different from Invoice Ninja is the credential. Zoho uses OAuth, so
there is no single API token to paste: you exchange a short-lived, single-use
grant code for a refresh token that never expires, and mint hour-long access
tokens from it as you go. That exchange is done ONCE, and it is done here
rather than on a terminal, because the alternative is retyping a 42-character
secret and a two-part code against a clock on a server console -- which is
how a character goes missing, and every resulting error says "invalid_client"
regardless of which mistake you made.

Two further things Zoho does that will otherwise waste an afternoon:

  * The account lives in ONE data centre and every URL must match it. The
    wrong one fails as "invalid_client", indistinguishable from a bad secret.
    So `exchange_code` simply tries them and records which one answered.
  * Scopes are COMMA separated. A space anywhere and the whole string is
    rejected at code-generation time as "invalid scope".

Stdlib only, like the rest of this project.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

_TIMEOUT = 25.0

# Zoho has no South African data centre, so an account opened from here lands
# on .com or .eu depending on where it was registered. Nobody should have to
# know which: we try, and remember the answer.
DATA_CENTRES = (
    ("accounts.zoho.com", "https://www.zohoapis.com/invoice/v3"),
    ("accounts.zoho.eu", "https://www.zohoapis.eu/invoice/v3"),
    ("accounts.zoho.in", "https://www.zohoapis.in/invoice/v3"),
    ("accounts.zoho.com.au", "https://www.zohoapis.com.au/invoice/v3"),
    ("accounts.zoho.jp", "https://www.zohoapis.jp/invoice/v3"),
    ("accounts.zohocloud.ca", "https://www.zohoapis.ca/invoice/v3"),
)

# Comma separated, no spaces. This is the exact string to paste into the
# Self Client's "Generate Code" box.
SCOPES = ("ZohoInvoice.contacts.CREATE,ZohoInvoice.contacts.READ,"
          "ZohoInvoice.invoices.CREATE,ZohoInvoice.invoices.READ,"
          "ZohoInvoice.invoices.UPDATE,ZohoInvoice.settings.READ")

# Access tokens last an hour. Refresh a little early so a call never goes out
# holding one that expires mid-flight.
_EARLY_REFRESH = 300.0

# Zoho publishes 100 requests/minute per organisation and, on the free plan,
# 1000/day. Both figures are shaded down: sitting exactly on a published
# limit means one retry or one clock skew puts you over it, and what comes
# back then is a 429 that looks like an outage.
_LIMIT_PER_MINUTE = 80
_LIMIT_PER_DAY = 900


def _limiter():
    from .ratelimit import limiter
    return limiter("Zoho Invoice", _LIMIT_PER_MINUTE, _LIMIT_PER_DAY)


_tokens: dict = {}          # refresh_token -> (access_token, expires_at)
_tokens_lock = threading.Lock()


class ZohoError(Exception):
    """A call did not succeed. The message is fit to show an admin, who is
    usually looking at a settings page wondering what they typed wrong."""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _request(url: str, *, method: str = "GET", headers: dict | None = None,
             form: dict | None = None, body: dict | None = None,
             timeout: float = _TIMEOUT) -> dict:
    """One HTTP call returning decoded JSON. Errors carry Zoho's own words.

    Zoho answers a failure with a perfectly good JSON body and an HTTP error
    status, so the body has to be read off the exception or the only thing
    left is the status code -- which never says which field was wrong.
    """
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.setdefault("Accept", "application/json")
    hdrs.setdefault("User-Agent", "mikromon")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    # Counted before it is sent, so a burst waits here rather than arriving
    # at Zoho and being refused.
    from .ratelimit import RateLimited, retry_after_seconds
    lim = _limiter()
    try:
        lim.acquire()
    except RateLimited as exc:
        raise ZohoError(str(exc)) from exc
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            lim.note_429(retry_after_seconds(exc.headers))
            raise ZohoError(
                "Zoho is rate limiting us. The call was not made; it will be "
                "retried on the next pass.") from exc
        raw = ""
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        msg = (payload.get("message") or payload.get("error")
               or f"HTTP {exc.code}")
        raise ZohoError(str(msg)) from exc
    except urllib.error.URLError as exc:
        raise ZohoError(f"Could not reach Zoho: {exc.reason}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ZohoError(str(exc)) from exc
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise ZohoError("Zoho returned something that is not JSON") from exc


# ---------------------------------------------------------------------------
# OAuth — done once, from the settings page
# ---------------------------------------------------------------------------

def exchange_code(client_id: str, client_secret: str, code: str,
                  accounts_host: str = "") -> dict:
    """Trade a grant code for a refresh token. Returns settings to save.

    The grant code is single-use and lives for minutes, so this is the one
    call that cannot be casually retried: a second attempt with the same code
    fails as "invalid_code" whatever else is right. Hence the care taken to
    get everything else out of the way first.

    Tries each data centre unless one is named. A bad code fails identically
    everywhere, so that case stops immediately rather than burning the little
    time the code has left.
    """
    client_id = (client_id or "").strip()
    client_secret = (client_secret or "").strip()
    code = (code or "").strip()
    if not (client_id and client_secret and code):
        raise ZohoError("Client ID, client secret and grant code are all "
                        "needed.")
    hosts = [d for d in DATA_CENTRES
             if not accounts_host or d[0] == accounts_host] or list(DATA_CENTRES)

    last = ""
    for host, api_base in hosts:
        try:
            res = _request(f"https://{host}/oauth/v2/token", method="POST",
                           form={"grant_type": "authorization_code",
                                 "client_id": client_id,
                                 "client_secret": client_secret,
                                 "code": code})
        except ZohoError as exc:
            last = str(exc)
            if "invalid_code" in last:
                break
            continue
        if res.get("refresh_token"):
            return {"client_id": client_id, "client_secret": client_secret,
                    "refresh_token": res["refresh_token"],
                    "accounts_host": host, "api_base": api_base}
        last = str(res.get("error") or res)
        if "invalid_code" in last:
            break

    if "invalid_code" in last:
        raise ZohoError(
            "That grant code was already used, or it expired. They are "
            "single-use and last only a few minutes -- generate a fresh one "
            "and paste it straight in. Everything else here is remembered.")
    if "invalid_client" in last:
        raise ZohoError(
            "Zoho rejected the client ID or secret. Every data centre was "
            "tried, so this is not the region -- re-copy both from the API "
            "console.")
    if "invalid_scope" in last or "scope" in last.lower():
        raise ZohoError(
            "Zoho rejected the scopes. They must be comma separated with no "
            f"spaces: {SCOPES}")
    raise ZohoError(last or "Zoho issued no refresh token.")


def access_token(cfg: dict, force: bool = False) -> str:
    """A live access token, minted from the refresh token when needed.

    Access tokens last an hour and refresh tokens never expire, so this is
    what every other call goes through. Cached per refresh token: Zoho counts
    tokens, and minting one per API call would burn the allowance for nothing.
    """
    cfg = cfg or {}
    refresh = str(cfg.get("refresh_token") or "").strip()
    if not refresh:
        raise ZohoError("Zoho is not connected on this server.")
    with _tokens_lock:
        tok, exp = _tokens.get(refresh, ("", 0.0))
        if tok and not force and time.time() < exp - _EARLY_REFRESH:
            return tok
    host = str(cfg.get("accounts_host") or DATA_CENTRES[0][0])
    res = _request(f"https://{host}/oauth/v2/token", method="POST",
                   form={"grant_type": "refresh_token",
                         "refresh_token": refresh,
                         "client_id": str(cfg.get("client_id") or ""),
                         "client_secret": str(cfg.get("client_secret") or "")})
    tok = str(res.get("access_token") or "")
    if not tok:
        raise ZohoError(str(res.get("error")
                            or "Zoho would not issue an access token. If the "
                               "refresh token was revoked, reconnect."))
    ttl = float(res.get("expires_in") or 3600)
    with _tokens_lock:
        _tokens[refresh] = (tok, time.time() + ttl)
    return tok


def forget_tokens(cfg: dict | None = None) -> None:
    """Drop cached access tokens — on disconnect, or after a credential
    change, so nothing keeps working on a token that should be gone."""
    with _tokens_lock:
        if cfg and cfg.get("refresh_token"):
            _tokens.pop(str(cfg["refresh_token"]), None)
        else:
            _tokens.clear()


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _api(cfg: dict, path: str, *, method: str = "GET",
         body: dict | None = None, params: dict | None = None,
         retry: bool = True) -> dict:
    """One Zoho Invoice API call.

    Retries once on an authorisation failure with a freshly minted token: an
    access token can be invalidated before its hour is up, and the failure
    reads as a configuration problem when it is really just a stale token.
    """
    cfg = cfg or {}
    base = str(cfg.get("api_base") or "").rstrip("/")
    if not base:
        raise ZohoError("Zoho is not connected on this server.")
    url = base + "/" + path.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Authorization": f"Zoho-oauthtoken {access_token(cfg)}"}
    org = str(cfg.get("organization_id") or "")
    if org:
        headers["X-com-zoho-invoice-organizationid"] = org
    try:
        res = _request(url, method=method, headers=headers, body=body)
    except ZohoError as exc:
        low = str(exc).lower()
        if retry and ("oauth" in low or "token" in low or "unauthor" in low):
            access_token(cfg, force=True)
            return _api(cfg, path, method=method, body=body, params=params,
                        retry=False)
        raise
    # Zoho signals application-level failure with a non-zero code in a 200.
    if isinstance(res, dict) and res.get("code") not in (None, 0):
        raise ZohoError(str(res.get("message") or f"Zoho code {res['code']}"))
    return res


def organizations(cfg: dict) -> list:
    """Every organisation the credential can see."""
    return list(_api(cfg, "/organizations").get("organizations") or [])


def ping(cfg: dict) -> str:
    """Prove the credential works, and say whose books it opens.

    A token that was issued is not the same as a token the API accepts -- a
    missing scope gives you the first without the second, and the difference
    would otherwise surface as an invoice that silently never went out.
    """
    orgs = organizations(cfg)
    if not orgs:
        raise ZohoError("The credential works but no organisation came back. "
                        "Check ZohoInvoice.settings.READ is in the scopes.")
    want = str(cfg.get("organization_id") or "")
    for o in orgs:
        if not want or str(o.get("organization_id")) == want:
            return str(o.get("name") or o.get("organization_id") or "Zoho")
    raise ZohoError(f"Organisation {want} is not one this credential can see.")


def find_client(cfg: dict, email: str = "", name: str = "") -> str:
    """The Zoho contact id for a company, or "" — email first, then name.

    Email is tried first because a company can be renamed here without
    anything changing in Zoho, and matching on a stale name would create a
    second contact and start invoicing the same customer twice.
    """
    for params in ([{"email": email}] if email else []) + \
                  ([{"contact_name": name}] if name else []):
        got = _api(cfg, "/contacts", params=params).get("contacts") or []
        if got:
            return str(got[0].get("contact_id") or "")
    return ""


def create_client(cfg: dict, name: str, email: str = "",
                  phone: str = "") -> str:
    body: dict = {"contact_name": name, "company_name": name}
    if email:
        body["contact_persons"] = [{"email": email, "is_primary_contact": True}]
        body["email"] = email
    if phone:
        body["phone"] = phone
    res = _api(cfg, "/contacts", method="POST", body=body)
    cid = str((res.get("contact") or {}).get("contact_id") or "")
    if not cid:
        raise ZohoError("Zoho created no contact.")
    return cid


def ensure_client(cfg: dict, name: str, email: str = "", phone: str = "",
                  known_id: str = "") -> str:
    """The contact id for a company, creating it the first time.

    `known_id` short-circuits the search. Callers should store what comes
    back: it makes every later run one call instead of three, and it is what
    keeps a renamed company attached to the contact it already had.
    """
    if known_id:
        return known_id
    return find_client(cfg, email, name) or create_client(cfg, name, email,
                                                          phone)


def create_invoice(cfg: dict, contact_id: str, *, description: str,
                   amount_cents: int, due_date: str = "",
                   reference: str = "") -> dict:
    """Raise an invoice. Returns {"id", "number"}.

    Zoho works in major units, so the cents this system counts in have to be
    divided exactly once -- and dividing twice, or not at all, is an error
    nobody spots until a customer is billed a hundredth of what they owe.
    """
    if not contact_id:
        raise ZohoError("No Zoho contact to invoice.")
    body: dict = {
        "customer_id": str(contact_id),
        "line_items": [{"name": description[:100] or "Service",
                        "description": description,
                        "rate": round(int(amount_cents) / 100.0, 2),
                        "quantity": 1}],
    }
    if due_date:
        body["due_date"] = due_date
    if reference:
        body["reference_number"] = reference
    inv = _api(cfg, "/invoices", method="POST", body=body).get("invoice") or {}
    iid = str(inv.get("invoice_id") or "")
    if not iid:
        raise ZohoError("Zoho created no invoice.")
    return {"id": iid, "number": str(inv.get("invoice_number") or "")}


def email_invoice(cfg: dict, invoice_id: str) -> None:
    """Send it. Zoho keeps a draft until it is marked sent, and a draft
    invoice is one nobody has been asked to pay."""
    _api(cfg, f"/invoices/{invoice_id}/status/sent", method="POST")
    _api(cfg, f"/invoices/{invoice_id}/email", method="POST")


def invoice_status(cfg: dict, invoice_id: str) -> dict:
    """{"paid", "status", "balance", "total"} read from Zoho itself.

    Paid means the balance is settled, not that the status string says so:
    a partly-paid invoice reads "partially_paid" with money still owing, and
    treating that as paid would reactivate a service that was half bought.
    """
    inv = _api(cfg, f"/invoices/{invoice_id}").get("invoice") or {}
    total = float(inv.get("total") or 0.0)
    balance = float(inv.get("balance") or 0.0)
    status = str(inv.get("status") or "")
    return {"paid": bool(total > 0 and balance <= 0) or status == "paid",
            "status": status, "balance": balance, "total": total,
            "number": str(inv.get("invoice_number") or "")}


def invoice_ids_in(payload) -> list:
    """Every invoice id anywhere in a callback body.

    Zoho's payload shape varies by the automation that sent it, so rather
    than betting on one layout this sweeps for the key. The ids are only used
    to decide what to go and re-read from the API, so a false positive costs
    one wasted lookup and a missed one is caught by the next reconcile pass.
    """
    found: list = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "invoice_id" and isinstance(v, (str, int)):
                    found.append(str(v))
                elif k == "invoice" and isinstance(v, dict):
                    walk(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(payload)
    seen = set()
    return [i for i in found if not (i in seen or seen.add(i))]
