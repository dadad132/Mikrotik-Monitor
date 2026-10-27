"""Every email about an invoice carries the invoice, as a PDF.

The invoice existed only as a web page, so the email that went out with it
carried a link and nothing else: nothing for whoever pays the bills to file,
forward or print. Now:
  * the invoice is drawn as a PDF from the same values as the page, with the
    pay link in it as a real link
  * the renewal, upgrade and re-priced invoice emails, and the payment
    reminders, attach it and say so; the payment email attaches the receipt
  * a PDF that cannot be drawn never stops the email -- it goes with its link
  * the invoice page offers the PDF to download, and Platform admin's preview
    shows the one the email carries

Run:  ./.venv/Scripts/python.exe tests/invoice_pdf_test.py
"""
from __future__ import annotations

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
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.billing as B  # noqa: E402
import mikromon.invoice_pdf as P  # noqa: E402
import mikromon.notify.org_email as org_email  # noqa: E402
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
LINK = "https://easymikrotik.test/pay?t=7.1790000000.AbCdEf"
CONTACT = {"name": "Sales", "email": "sales@easymikrotik.test",
           "bank_name": "FNB", "bank_account": "62000000000"}
ORG = {"name": "ECA Consulting (Pty) Ltd", "email": "jp@eca.test"}
ORDER = {"id": 7, "org_id": 2, "plan": "d5", "months": 1, "amount_cents": 2500,
         "currency": "USD", "created": NOW, "due": NOW + 7 * 86400,
         "kind": "renewal", "status": "pending"}


def pdf_of(order, link="", contact=CONTACT):
    d = web_auth._invoice_data(ORG, order, contact, pay_link=link)
    return P.render(d), P.filename(d), d


print("The PDF")
card, name, d = pdf_of(ORDER, LINK)
check("an unpaid invoice draws as a one-page PDF",
      card.startswith(b"%PDF") and b"/Count 1" in card and len(card) > 5000)
check("...carrying the pay link as a real link, to click from the PDF",
      LINK.encode() in card and b"/URI" in card)
check("...named for what it is", name == "EasyMikroTik-invoice-EMT-"
      + time.strftime("%Y", time.localtime(NOW)) + "-0007.pdf")
check("...from the same values as the page, so the two agree",
      d["total"] == 25.0 and d["pay"] == "card" and d["invoice_no"] in name)
bank, _, d = pdf_of(ORDER)
check("with card payment off it carries the bank details instead, and no "
      "link", d["pay"] == "bank" and b"/URI" not in bank
      and bank.startswith(b"%PDF"))
paid, pname, d = pdf_of(dict(ORDER, paid=NOW, status="paid",
                             payment_id="p_1"))
check("a paid one is a receipt: named so, and no way to pay it again",
      "receipt" in pname and d["pay"] == "paid" and b"/URI" not in paid)
odd = dict(ORG, name="Café Ñandú · Δοκιμή")
d = web_auth._invoice_data(odd, ORDER, CONTACT, pay_link=LINK)
check("a company name in any script still draws",
      P.render(d).startswith(b"%PDF"))

print("\nThe emails")
st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
st.set_plan(2, "d5", period_end=NOW + 7 * 86400)
oid = st.create_order(2, "d5", 2500, currency="USD", due=NOW + 7 * 86400)
sent = []
_orig_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
SMTP = SmtpConfig(host="smtp.test", from_addr="billing@easymikrotik.test")


class FakeAuth:
    def org(self, org_id):
        return {"name": "ECA Consulting (Pty) Ltd"}

    def org_name(self, org_id):
        return "ECA Consulting (Pty) Ltd"

    def list_users(self, org_id):
        return [{"role": "owner", "email": "jp@eca.test"}]

    def get_billing_contact(self):
        return CONTACT

    def get_yoco(self):
        return {"secret_key": "k", "webhook_secret": "w"}

    def get_setting(self, key, default=None):
        return "https://easymikrotik.test" if key == "public_base_url" \
            else default

    def set_setting(self, key, value):
        pass

    def superadmin_emails(self):
        return []


def pdf_parts(msg):
    return [p for p in msg.iter_attachments()
            if p.get_content_type() == "application/pdf"]


A = FakeAuth()
to = web._email_renewal(A, SMTP, 2, oid, B.plan_by_name("d5"), 25.0, "USD",
                        NOW + 7 * 86400, 7, LINK, billing=st)
m = sent[-1] if sent else None
parts = pdf_parts(m) if m else []
check("the renewal invoice email carries the invoice as a PDF",
      to and len(parts) == 1
      and parts[0].get_filename().startswith("EasyMikroTik-invoice-EMT-")
      and parts[0].get_content().startswith(b"%PDF"))
body = m.get_body(("plain",)).get_content() if m else ""
check("...says so, and still leads with the link that pays it",
      "The invoice is attached as a PDF." in body and f"Pay now: {LINK}"
      in body)
sent.clear()
web._email_renewal(A, SMTP, 2, oid, B.plan_by_name("d10"), 3.0, "USD",
                   NOW + 7 * 86400, 3, LINK, kind="upgrade", days=4,
                   billing=st)
check("...and so does an upgrade invoice", sent and pdf_parts(sent[-1]))

_orig_render = P.render


def broken(d):
    raise RuntimeError("no fonts on this server")


P.render = broken
sent.clear()
to = web._email_renewal(A, SMTP, 2, oid, B.plan_by_name("d5"), 25.0, "USD",
                        NOW + 7 * 86400, 7, LINK, billing=st)
body = sent[-1].get_content() if sent else ""
check("a PDF that cannot be drawn does not stop the email: it goes, with "
      "its link, and does not claim an attachment it has not got",
      to and not sent[-1].is_multipart() and f"Pay now: {LINK}" in body
      and "attached" not in body)
P.render = _orig_render

st.set_plan(3, "d5", period_end=NOW - 3600)
due = st.create_order(3, "d5", 2500, currency="USD",
                      due=st.get(3)["current_period_end"])
st.lapse_due()
sent.clear()
web._email_reminder(A, st, SMTP, 3, "overdue", "https://easymikrotik.test")
check("a payment reminder carries the invoice it is about",
      sent and pdf_parts(sent[0])
      and "The invoice is attached as a PDF." in
      sent[0].get_body(("plain",)).get_content())

st.mark_order_paid(due, "p_9")
st.record_charged(due, 41123, "ZAR")
text = web._payment_received_text(st.order(due), "ECA", None, attached=True)
check("the payment email says the receipt is attached",
      "Your receipt is attached as a PDF" in text)
pdf = web._invoice_pdf(A, st, st.order(due), "", ["jp@eca.test"])
check("...and the receipt it attaches is the paid one, in the rand charged",
      pdf and "receipt" in pdf[1] and pdf[0].startswith(b"%PDF"))
org_email._smtp_send = _orig_send

print("\nOn the invoice page")
tmp = tempfile.mkdtemp()
mdb, sfile, adb, bdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "b.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
org = auth.signup("jp@eca.test", "secret123", "ECA Consulting (Pty) Ltd")
other = auth.signup("x@other.test", "secret123", "Other")
auth.set_superadmin("jp@eca.test", True)
bs = B.BillingStore(bdb)
bs.set_plan(org, "d5", period_end=NOW + 7 * 86400)
mine = bs.create_order(org, "d5", 2500, currency="USD", due=NOW + 7 * 86400)
theirs = bs.create_order(other, "d5", 2500, currency="USD", due=NOW)
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def get(path):
    try:
        r = op.open(urllib.request.Request(BASE + path), timeout=15)
        return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


try:
    op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(
        {"email": "jp@eca.test", "password": "secret123"}).encode()),
        timeout=15)
    st_, page, _ = get(f"/billing/invoice?id={mine}")
    check("the invoice page offers the PDF to download",
          st_ == 200 and f"/billing/invoice.pdf?id={mine}".encode() in page
          and b"Download PDF" in page)
    st_, body, hdr = get(f"/billing/invoice.pdf?id={mine}")
    check("...which comes back as the PDF, as a download",
          st_ == 200 and body.startswith(b"%PDF")
          and hdr.get("Content-Type") == "application/pdf"
          and re.search(r'attachment; filename="EasyMikroTik-invoice-EMT-\d+-'
                        + f"{mine:04d}" + r'\.pdf"',
                        hdr.get("Content-Disposition", "")))
    st_, body, _ = get(f"/billing/invoice.pdf?id={theirs}")
    check("another company's invoice PDF cannot be had by guessing its id",
          st_ == 404 and not body.startswith(b"%PDF"))
    st_, body, _ = get("/superadmin/test-invoice?doc=pdf")
    check("Platform admin's preview shows the PDF the email carries",
          st_ == 200 and body.startswith(b"%PDF"))
    st_, page, _ = get("/superadmin/test-invoice")
    check("...linked from the preview page", b"doc=pdf" in page)
finally:
    srv.shutdown()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL INVOICE PDF TESTS PASSED")
