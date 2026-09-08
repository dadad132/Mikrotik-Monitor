"""Yoco Checkout — take a card payment for a packet, and trust only the webhook.

Two jobs, and the split between them is the whole security model:

  * `create_checkout` asks Yoco for a hosted payment page and gets back a URL
    to send the customer to. The amount is computed here, from our own plan
    table, and never read from the browser.
  * `verify_webhook` proves that the "this was paid" callback really came from
    Yoco. Yoco's own documentation is blunt about the alternative: "Do not use
    successUrl from the response to verify payment success. Always use
    webhooks for confirmation." A customer can navigate to a success URL
    without paying; they cannot forge an HMAC.

Yoco follows the Standard Webhooks specification, so verification is the
usual three headers over `id.timestamp.body`.

Stdlib only, like the rest of this project: no requests, no svix package.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request

log = logging.getLogger(__name__)

_CHECKOUT_URL = "https://payments.yoco.com/api/checkouts"
# Yoco recommends rejecting anything older than this, to stop a captured
# callback being replayed later.
_MAX_SKEW_SECONDS = 180


class YocoError(Exception):
    """A checkout could not be created. Carries a message fit to show a
    customer -- they are standing at a payment page that did not open."""


def create_checkout(secret_key: str, amount_cents: int, *, currency: str = "ZAR",
                    metadata: dict | None = None, success_url: str = "",
                    cancel_url: str = "", failure_url: str = "",
                    timeout: float = 20.0) -> dict:
    """Create a hosted checkout and return Yoco's response.

    `amount_cents` is an integer of the minor unit, because that is what the
    API takes and because money in floats is how you end up charging R19.99
    as R19.990000000000002.

    `metadata` is echoed back on the webhook. It is the only thread tying a
    payment to the order it belongs to, so the caller puts the order id in
    there -- not the org, not the plan, which are looked up from the order.
    Trusting a plan name that came back through the customer's browser would
    let anyone pay for the smallest packet and receive the largest.
    """
    if not secret_key:
        raise YocoError("Card payment is not configured on this server.")
    amount_cents = int(amount_cents)
    if amount_cents <= 0:
        raise YocoError("Nothing to pay.")

    body: dict = {"amount": amount_cents, "currency": currency}
    if metadata:
        body["metadata"] = {str(k): str(v) for k, v in metadata.items()}
    if success_url:
        body["successUrl"] = success_url
    if cancel_url:
        body["cancelUrl"] = cancel_url
    if failure_url:
        body["failureUrl"] = failure_url

    req = urllib.request.Request(
        _CHECKOUT_URL, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {secret_key}",
                 "Content-Type": "application/json",
                 "Accept": "application/json",
                 # An idempotency key would be better still, but Yoco does not
                 # document one for checkouts; the order row is what stops a
                 # double charge being applied twice on our side.
                 "User-Agent": "mikromon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        log.error("Yoco checkout failed: HTTP %s %s", exc.code, detail)
        raise YocoError(
            f"The payment page could not be opened (Yoco returned "
            f"{exc.code}). Nothing has been charged.") from None
    except Exception as exc:  # noqa: BLE001 — network, DNS, timeout
        log.error("Yoco checkout failed: %s", exc)
        raise YocoError(
            "The payment page could not be opened just now. Nothing has been "
            "charged — please try again in a moment.") from None


def _secret_bytes(secret: str) -> bytes:
    """The signing key from a Yoco webhook secret.

    The secret is handed out as `whsec_` followed by base64. The prefix is
    stripped and the remainder decoded: signing against the printable string
    instead of the decoded bytes verifies nothing and fails against every
    real event, which is a mistake that only shows up in production.
    """
    raw = (secret or "").strip()
    if raw.startswith("whsec_"):
        raw = raw[len("whsec_"):]
    try:
        return base64.b64decode(raw)
    except Exception:  # noqa: BLE001 — a mistyped secret, not an attack
        return b""


def verify_webhook(secret: str, headers, raw_body: bytes,
                   now: float | None = None) -> bool:
    """Whether this request really came from Yoco, unmodified and recent.

    `headers` is anything with .get() -- an http.client.HTTPMessage or a plain
    dict. `raw_body` must be the bytes exactly as received: re-serialising the
    JSON changes the signature and every event fails.
    """
    key = _secret_bytes(secret)
    if not key:
        return False
    wid = (headers.get("webhook-id") or "").strip()
    wts = (headers.get("webhook-timestamp") or "").strip()
    wsig = (headers.get("webhook-signature") or "").strip()
    if not (wid and wts and wsig):
        return False

    # Reject anything stale, so a callback captured once cannot be replayed
    # tomorrow to grant another month.
    try:
        skew = abs((now if now is not None else time.time()) - int(wts))
    except (TypeError, ValueError):
        return False
    if skew > _MAX_SKEW_SECONDS:
        log.warning("Yoco webhook rejected: timestamp %ss out of date", int(skew))
        return False

    signed = wid.encode() + b"." + wts.encode() + b"." + raw_body
    expected = base64.b64encode(
        hmac.new(key, signed, hashlib.sha256).digest()).decode()

    # The header carries space-separated "v1,<sig>" entries: a secret being
    # rotated means two valid signatures at once, and rejecting the second
    # would drop real payments for the length of the rotation.
    for part in wsig.split(" "):
        _, _, sig = part.partition(",")
        if sig and hmac.compare_digest(sig, expected):
            return True
    log.warning("Yoco webhook rejected: no signature matched")
    return False


def event_of(payload: dict) -> tuple:
    """(type, metadata, payment_id, amount_cents) from a webhook body.

    Yoco nests the interesting parts under `payload`; older shapes put them at
    the top level. Both are read so a format change does not silently stop
    every upgrade from completing.
    """
    body = payload if isinstance(payload, dict) else {}
    inner = body.get("payload") if isinstance(body.get("payload"), dict) else body
    meta = inner.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    amount = inner.get("amount")
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        amount = 0
    return (str(body.get("type") or ""), meta,
            str(inner.get("id") or body.get("id") or ""), amount)


_WEBHOOK_URL = "https://payments.yoco.com/api/webhooks"


def register_webhook(secret_key: str, url: str, name: str = "mikromon",
                     timeout: float = 20.0) -> dict:
    """Tell Yoco where to send payment events, and get back the signing secret.

    There is no way to do this from the Yoco Business Portal: registration is
    API-only, and the response carries the signing secret **once and never
    again**. Doing it from the server means the secret is written straight to
    settings and nobody ever has to copy it out of a terminal, which is the
    step where a "provided only once" value gets lost.

    Yoco requires the endpoint to be HTTPS. That is checked here rather than
    left to a rejection from their side, because the error that comes back
    otherwise does not say which of the two URLs it disliked.
    """
    if not secret_key:
        raise YocoError("Add the Yoco secret key first.")
    if not url.lower().startswith("https://"):
        raise YocoError(
            "Yoco will only send payment notifications to an https:// "
            "address, and this server is currently reachable over plain "
            "http. Put it behind HTTPS first, then register the webhook.")
    req = urllib.request.Request(
        _WEBHOOK_URL, data=json.dumps({"name": name, "url": url}).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {secret_key}",
                 "Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": "mikromon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out = json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        log.error("Yoco webhook registration failed: HTTP %s %s",
                  exc.code, detail)
        if exc.code in (401, 403):
            raise YocoError(
                "Yoco rejected that secret key. Check it was copied in "
                "full, and that it is the key for the right mode "
                "(test or live).") from None
        raise YocoError(
            f"Yoco would not register the webhook (HTTP {exc.code}). "
            f"{detail[:160]}".strip()) from None
    except Exception as exc:  # noqa: BLE001 — network, DNS, timeout
        log.error("Yoco webhook registration failed: %s", exc)
        raise YocoError(
            "Could not reach Yoco to register the webhook. Check the "
            "server's internet connection and try again.") from None
    if not out.get("secret"):
        # Without this the webhook cannot be verified, so treat it as a
        # failure rather than saving a half-configured state that looks
        # fine on screen and silently drops every payment.
        raise YocoError(
            "Yoco accepted the webhook but did not return a signing "
            "secret, so payments could not be verified. Please contact "
            "Yoco support before switching card payment on.")
    log.info("Registered Yoco webhook %s -> %s", out.get("id"), url)
    return out
