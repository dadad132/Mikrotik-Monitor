"""A settled invoice is confirmed with a payslip, in the same email.

The receipt alone said what was paid but not what it bought or when the
packet now ends. Now every "Payment received" email -- a Yoco card payment or
an EFT recorded by Platform admin -- carries two PDFs: the invoice marked PAID
and a single-page payslip made from the very same invoice values. Neither PDF
can stop the email; if one cannot be drawn the other still goes out.

Run:  .venv/bin/python tests/payslip_pdf_test.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.billing as B  # noqa: E402
import mikromon.invoice_pdf as invoice_pdf  # noqa: E402
import mikromon.notify.org_email as org_email  # noqa: E402
import mikromon.payslip_pdf as P  # noqa: E402
from mikromon import web, web_auth  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


NOW = time.time()
PAID_UNTIL = time.mktime((2026, 11, 28, 0, 0, 0, 0, 0, -1))
CONTACT = {"name": "Sales", "email": "sales@easymikrotik.test",
           "web": "https://easymikrotik.test", "bank_name": "FNB",
           "bank_account": "62000000000"}
ORG = {"name": "ECA Consulting (Pty) Ltd", "email": "jp@eca.test"}
SECRET = "whsec_" + base64.b64encode(
    b"payslip-test-signing-key-32-bytes!!").decode()
SMTP = SmtpConfig(host="smtp.test", from_addr="billing@easymikrotik.test")


def order(**kw):
    base = {"id": 7, "org_id": 2, "plan": "d5", "months": 1,
            "amount_cents": 2500, "currency": "USD", "created": NOW,
            "due": NOW + 7 * 86400, "kind": "renewal", "status": "pending"}
    base.update(kw)
    return base


def invoice_data(o, org=None):
    return web_auth._invoice_data(org or ORG, o, CONTACT, pay_link="")


def pdf_text(pdf: bytes) -> str:
    """The text ReportLab wrote into the content streams, for assertions."""
    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = m.group(1).rstrip(b"\r\n")
        if b"~>" in data:
            data = data[:data.index(b"~>") + 2]
        for decode in (lambda x: zlib.decompress(base64.a85decode(x, adobe=True)),
                       lambda x: zlib.decompress(x), lambda x: x):
            try:
                out.append(decode(data).decode("latin1"))
                break
            except Exception:  # noqa: BLE001 - try the next PDF filter
                continue
    # ReportLab escapes literal parentheses and backslashes in PDF strings.
    return re.sub(r"\\([()\\])", r"\1", "\n".join(out))


def pdf_parts(msg):
    return [p for p in (msg.iter_attachments() if msg else [])
            if p.get_content_type() == "application/pdf"]


def body_of(msg):
    return (msg.get_body(("plain",)).get_content()
            if msg is not None else "")


class FakeAuth:
    def org(self, org_id):
        return ORG

    def org_name(self, org_id):
        return ORG["name"]

    def list_users(self, org_id):
        return [{"role": "owner", "email": "jp@eca.test"}]

    def get_alert_emails(self, org_id):
        return []

    def get_billing_contact(self):
        return CONTACT

    def get_smtp(self):
        return None

    def get_yoco(self):
        return {"secret_key": "sk_test", "webhook_secret": SECRET}

    def get_setting(self, key, default=None):
        return "https://easymikrotik.test" if key == "public_base_url" else default

    def set_setting(self, key, value):
        pass


print("The payslip PDF")
card = order(paid=NOW, status="paid", payment_id="p_abc123",
             charged_cents=41123, charged_currency="ZAR", fx_rate=16.4492,
             fx_basis="ECB reference rate of 2026-10-20 (1 USD = 16.4492 ZAR)")
d = invoice_data(card)
pdf = P.render(d, payment_id="p_abc123", paid_until=PAID_UNTIL)
text = pdf_text(pdf)
check("a card-paid order draws as a crisp, single-page PDF",
      pdf.startswith(b"%PDF") and b"/Count 1" in pdf and len(pdf) > 4000)
check("...named for the invoice it confirms",
      P.filename(d) == "EasyMikroTik-payslip-EMT-"
      + time.strftime("%Y", time.localtime(NOW)) + "-0007.pdf")
check("...with the invoice number and the word PAYSLIP on it",
      "PAYSLIP" in text and d["invoice_no"] in text)
check("...marked PAID, with the amount, balance and full status",
      "PAID" in text and "Amount Paid" in text and "R411.23" in text
      and "Balance Due" in text and "R0.00" in text and "PAID IN FULL" in text)
check("...saying how and when it was paid",
      "Card (Yoco)" in text and "p_abc123" in text and "Paid Up Until" in text
      and "28 November 2026" in text)
check("...carrying the exact FX note from the paid invoice",
      bool(d["fx_note"]) and d["fx_note"] in text)
check("...and an explicit, unambiguous no-VAT confirmation",
      "No VAT has been charged." in text)
check("it is a confirmation, not a bill: no tax invoice and no pay link",
      "Tax Invoice" not in text and "Tax Invoice" not in pdf.decode("latin1")
      and b"/URI" not in pdf and "/URI" not in text)
check("...and no bank details that would invite a second payment",
      "FNB" not in text and "62000000000" not in text)

eft = order(paid=NOW, status="paid", payment_id="eft:7")
de = invoice_data(eft)
eft_pdf = P.render(de, payment_id="eft:7", paid_until=PAID_UNTIL)
eft_text = pdf_text(eft_pdf)
check("an EFT-paid order is a one-page PDF with no pay link",
      eft_pdf.startswith(b"%PDF") and b"/Count 1" in eft_pdf
      and b"/URI" not in eft_pdf)
check("...and names the bank transfer as the payment method",
      "Bank Transfer (EFT)" in eft_text and "eft:7" in eft_text)

sample = P.render(d, payment_id="p_abc123", paid_until=PAID_UNTIL, sample=True)
check("a sample payslip says so but is still marked paid",
      "SAMPLE" in pdf_text(sample) and "PAID" in pdf_text(sample)
      and sample.startswith(b"%PDF"))

odd = invoice_data(order(paid=NOW, status="paid", payment_id="eft:9"),
                   dict(ORG, name="Café Ñandú · Δοκιμή"))
check("a company name in any script still draws safely",
      P.render(odd, payment_id="eft:9").startswith(b"%PDF"))

long_name = "A Very Long Company Name That Goes On And On " * 10
long_pdf = P.render(invoice_data(
    order(paid=NOW, status="paid", payment_id="eft:12"),
    dict(ORG, name=long_name)), payment_id="eft:12", paid_until=PAID_UNTIL)
check("an unusually long party name still fits on one A4 page",
      long_pdf.startswith(b"%PDF") and b"/Count 1" in long_pdf)
check("a missing paid-until timestamp is not printed as 1 January 1970",
      "1 January 1970" not in pdf_text(
          P.render(d, payment_id="p_abc123", paid_until=0)))

print("\nThe email helper")
tmp = tempfile.mkdtemp()
st = B.BillingStore(os.path.join(tmp, "payslip.db"))
st.set_plan(2, "d5", period_end=PAID_UNTIL)
pending_id = st.create_order(2, "d5", 2500, currency="USD", due=PAID_UNTIL)
check("an unpaid order gets no payslip at all",
      web._payslip_pdf(FakeAuth(), st, st.order(pending_id)) is None)
check("...and neither does a missing order",
      web._payslip_pdf(FakeAuth(), st, None) is None)
st.mark_order_paid(pending_id, "eft:11")
st.apply_paid_order(st.order(pending_id))
paid_order = st.order(pending_id)
slip = web._payslip_pdf(FakeAuth(), st, paid_order)
check("a paid order gets a PDF and its filename",
      bool(slip) and slip[0].startswith(b"%PDF")
      and slip[1] == f"EasyMikroTik-payslip-{invoice_data(paid_order)['invoice_no']}.pdf")
check("...with the payment method taken from the recorded payment id",
      "Bank Transfer (EFT)" in pdf_text(slip[0]))
check("...even when there is no billing store to read a paid-up date from",
      web._payslip_pdf(FakeAuth(), None, paid_order) is not None)

for attached, payslip in ((True, True), (True, False),
                          (False, True), (False, False)):
    closing = web._payment_received_text(
        paid_order, ORG["name"], PAID_UNTIL, attached=attached,
        payslip=payslip).split("\n\n")[-1].strip()
    expected = {
        (True, True): "Your receipt is attached as a PDF along with your "
                      "payslip, and both are also on the Billing page of the "
                      "dashboard, under Payments.",
        (True, False): "Your receipt is attached as a PDF, and is also on the "
                       "Billing page of the dashboard, under Payments.",
        (False, True): "Your payslip is attached as a PDF, and your invoice is "
                       "on the Billing page of the dashboard, under Payments.",
        (False, False): "Your invoice is on the Billing page of the dashboard, "
                        "under Payments.",
    }[(attached, payslip)]
    check(f"the closing line for attached={attached}, payslip={payslip}",
          closing == expected)

print("\nEnd to end: card, EFT and failure fallbacks")
mdb, sfile, adb, bdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "e2e-a.db", "e2e-b.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
owner = auth.signup("jp@eca.test", "secret123", ORG["name"])
auth.set_superadmin("jp@eca.test", True)
auth.set_yoco({"secret_key": "sk_test", "webhook_secret": SECRET})
auth.set_setting("public_base_url", "https://easymikrotik.test")
bs = B.BillingStore(bdb)
sent = []
orig_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"), smtp_cfg=SMTP, admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def get(path):
    try:
        r = op.open(urllib.request.Request(BASE + path), timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def post_form(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        r = op.open(urllib.request.Request(BASE + path, data=data), timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def post_webhook(payload):
    raw = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = base64.b64encode(hmac.new(
        base64.b64decode(SECRET[len("whsec_"):]),
        b"msg_1." + ts.encode() + b"." + raw, hashlib.sha256).digest()).decode()
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=15)
    c.request("POST", "/billing/yoco-webhook", body=raw, headers={
        "Content-Type": "application/json", "webhook-id": "msg_1",
        "webhook-timestamp": ts, "webhook-signature": f"v1,{sig}"})
    status = c.getresponse().status
    c.close()
    return status


def mark_paid(order_id):
    status, page = get("/superadmin")
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    if status != 200 or not m:
        return False
    st_, _ = post_form("/superadmin/mark-paid", {"csrf": m.group(1),
                                                 "order": str(order_id)})
    return st_ in (200, 302)


def wait_for_mail(count=1, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if len(sent) >= count:
            return True
        time.sleep(0.05)
    return False


def new_org(email):
    oid = auth.signup(email, "secret123", ORG["name"])
    bs.set_plan(oid, "d5", period_end=PAID_UNTIL)
    return oid


try:
    op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(
        {"email": "jp@eca.test", "password": "secret123"}).encode()), timeout=15)

    card_org = new_org("card@eca.test")
    card_id = bs.create_order(card_org, "d5", 2500, currency="USD",
                              due=PAID_UNTIL, fx_rate=16.4492,
                              fx_basis="ECB reference rate of 2026-10-20 "
                                       "(1 USD = 16.4492 ZAR)")
    sent.clear()
    status = post_webhook({"type": "payment.succeeded", "payload": {
        "id": "p_card", "amount": 41123,
        "metadata": {"order": str(card_id)}}})
    got_mail = wait_for_mail()
    msg = sent[-1] if sent else None
    parts = pdf_parts(msg)
    names = sorted(p.get_filename() or "" for p in parts)
    check("the Yoco webhook still answers and sends one payment email",
          status == 200 and got_mail and len(sent) == 1)
    check("...with exactly two PDFs: the paid invoice and the payslip",
          len(parts) == 2 and any("receipt" in n for n in names)
          and any("payslip" in n for n in names)
          and all(p.get_content().startswith(b"%PDF") for p in parts))
    check("...and the body says both are attached",
          "Your receipt is attached as a PDF along with your payslip"
          in body_of(msg))
    slip_parts = [p for p in parts if "payslip" in (p.get_filename() or "")]
    check("...with a payslip that has no pay link in it",
          len(slip_parts) == 1 and b"/URI" not in slip_parts[0].get_content())

    eft_org = new_org("eft@eca.test")
    eft_id = bs.create_order(eft_org, "d5", 2500, currency="USD",
                             due=PAID_UNTIL)
    sent.clear()
    check("Platform admin can record an EFT payment", mark_paid(eft_id))
    got_mail = wait_for_mail()
    msg = sent[-1] if sent else None
    parts = pdf_parts(msg)
    names = sorted(p.get_filename() or "" for p in parts)
    check("...which sends the paid invoice and payslip in one email",
          got_mail and len(parts) == 2
          and any("receipt" in n for n in names)
          and any("payslip" in n for n in names))
    check("...saying the receipt and payslip are both attached",
          "Your receipt is attached as a PDF along with your payslip"
          in body_of(msg))

    broken_slip_org = new_org("noslip@eca.test")
    broken_slip_id = bs.create_order(broken_slip_org, "d5", 2500,
                                     currency="USD", due=PAID_UNTIL)
    real_slip_render = P.render
    P.render = lambda d, **kw: (_ for _ in ()).throw(
        RuntimeError("no payslip fonts"))
    sent.clear()
    mark_paid(broken_slip_id)
    got_mail = wait_for_mail()
    msg = sent[-1] if sent else None
    parts = pdf_parts(msg)
    P.render = real_slip_render
    check("a payslip that cannot be drawn never stops the payment email",
          got_mail and len(parts) == 1 and "receipt" in (
              parts[0].get_filename() or ""))
    check("...and it does not claim to carry a payslip it has not got",
          "payslip" not in body_of(msg).lower())

    broken_invoice_org = new_org("noreceipt@eca.test")
    broken_invoice_id = bs.create_order(broken_invoice_org, "d5", 2500,
                                        currency="USD", due=PAID_UNTIL)
    real_invoice_render = invoice_pdf.render
    invoice_pdf.render = lambda d: (_ for _ in ()).throw(
        RuntimeError("no invoice fonts"))
    sent.clear()
    mark_paid(broken_invoice_id)
    got_mail = wait_for_mail()
    msg = sent[-1] if sent else None
    parts = pdf_parts(msg)
    invoice_pdf.render = real_invoice_render
    check("a receipt that cannot be drawn never stops the payment email",
          got_mail and len(parts) == 1 and "payslip" in (
              parts[0].get_filename() or ""))
    check("...and it says the payslip is attached, not a receipt",
          "payslip" in body_of(msg).lower()
          and "Your receipt is attached" not in body_of(msg))

    smtp_org = new_org("smtp@eca.test")
    smtp_id = bs.create_order(smtp_org, "d5", 2500, currency="USD",
                              due=PAID_UNTIL)
    real_send = org_email._smtp_send

    def failing_send(cfg, message):
        sent.append(message)
        raise RuntimeError("mail relay is down")

    org_email._smtp_send = failing_send
    sent.clear()
    posted = mark_paid(smtp_id)
    got_mail = wait_for_mail()
    msg = sent[-1] if sent else None
    parts = pdf_parts(msg)
    org_email._smtp_send = real_send
    check("a mail-relay failure is contained: the EFT still records and "
          "builds both PDFs", posted and got_mail and len(parts) == 2)
finally:
    srv.shutdown()
    org_email._smtp_send = orig_send
    st.close()
    bs.close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PAYSLIP PDF TESTS PASSED")
