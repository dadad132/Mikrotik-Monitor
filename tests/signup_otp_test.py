"""Signing up confirms the email address with a code.

The very first account on a server (its superadmin, before mail is set up)
is made straight away. Every account after it waits: a 6-digit code goes to
the address, and the company and its owner exist only once the code is typed
back. Wrong codes run out, codes expire, and one address cannot be sent a
flood of them.

Run:  ./.venv/Scripts/python.exe tests/signup_otp_test.py
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

from mikromon import auth as A
from mikromon import web
from mikromon.auth import AuthError, AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig
from mikromon.metrics import MetricsStore
from mikromon.web_terms import TERMS_VERSION

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()

print("The store")

st = AuthStore(os.path.join(tmp, "store.db"))
st.signup("boss@platform.test", "secret123", "Platform")
T = 1_800_000_000.0
tok, code = st.start_signup("new@acme.test", "secret123", "Acme", "0821234567",
                            {"alert_emails": ["ops@acme.test"]}, now=T)
check("starting a signup creates nobody yet",
      st.get_user("new@acme.test") is None and len(code) == 6
      and code.isdigit())
check("...the waiting signup is found by its token",
      st.pending_signup(tok, now=T)["company"] == "Acme")
row = st.db.execute("SELECT data, code_hash FROM pending_signups").fetchone()
check("...the password is kept only hashed, and the code only as a hash",
      "secret123" not in row[0] and code not in row[0] and code not in row[1])
try:
    st.start_signup("boss@platform.test", "secret123", "Again", now=T)
    taken = False
except AuthError:
    taken = True
check("an address that already has an account is refused at the start",
      taken)

wrong = "000000" if code != "000000" else "111111"
msgs = []
for _ in range(4):
    try:
        st.finish_signup(tok, wrong, now=T + 10)
    except AuthError as exc:
        msgs.append(str(exc))
check("a wrong code says how many tries are left",
      msgs[0].endswith("4 tries left.") and msgs[3].endswith("1 try left."))
try:
    st.finish_signup(tok, wrong, now=T + 10)
    fifth = ""
except AuthError as exc:
    fifth = str(exc)
check("the fifth wrong code ends the signup",
      "sign up again" in fifth and st.pending_signup(tok, now=T + 10) is None)
try:
    st.finish_signup(tok, code, now=T + 11)
    late_ok = True
except AuthError:
    late_ok = False
check("...after which even the right code does nothing", not late_ok
      and st.get_user("new@acme.test") is None)

tok, code = st.start_signup("new@acme.test", "secret123", "Acme", now=T + 20)
try:
    st.finish_signup(tok, code, now=T + 20 + A.OTP_TTL + 1)
    expired = False
except AuthError as exc:
    expired = "expired" in str(exc)
check("a code expires after 15 minutes", expired)

tok, code = st.start_signup("new@acme.test", "secret123", "Acme", "0821234567",
                            {"alert_emails": ["ops@acme.test"]}, now=T + 30)
try:
    st.resend_signup_code(tok, now=T + 40)
    too_soon = ""
except AuthError as exc:
    too_soon = str(exc)
check("a new code cannot be asked for within a minute of the last",
      "50 seconds" in too_soon)
st.resend_signup_code(tok, now=T + 100)   # the 4th code this hour
st.resend_signup_code(tok, now=T + 170)   # the 5th
try:
    st.resend_signup_code(tok, now=T + 240)
    capped = ""
except AuthError as exc:
    capped = str(exc)
check("one address gets at most 5 codes an hour (start, retries and resends "
      "together)", "Too many codes" in capped)
try:
    st.start_signup("new@acme.test", "secret123", "Acme", now=T + 300)
    capped2 = ""
except AuthError as exc:
    capped2 = str(exc)
check("...starting over does not get round it", "Too many codes" in capped2)

T2 = T + 4000
tok, first = st.start_signup("new@acme.test", "secret123", "Acme",
                             "0821234567", {"alert_emails": ["ops@acme.test"]},
                             now=T2)
email, second = st.resend_signup_code(tok, now=T2 + 61)
try:
    st.finish_signup(tok, first, now=T2 + 62) if first != second else None
    old_ok = first == second
except AuthError:
    old_ok = False
check("after an hour it may send again; a new code replaces the old one",
      email == "new@acme.test" and not old_ok)
org_id, email, extra = st.finish_signup(tok, f" {second[:3]} {second[3:]} ",
                                        now=T2 + 63)
u = st.get_user("new@acme.test")
check("the right code (spaces and all) creates the company and its owner",
      u is not None and u["role"] == "owner" and u["org_id"] == org_id
      and st.org(org_id)["name"] == "Acme")
check("...with the password chosen at the start",
      st.verify("new@acme.test", "secret123") is not None)
check("...and what the form carried comes back for the web page to apply",
      extra == {"alert_emails": ["ops@acme.test"]})
check("...and the waiting signup is gone",
      st.pending_signup(tok, now=T2 + 64) is None)
st.close()

print("\nThe pages")

mdb, sfile, adb = (os.path.join(tmp, x) for x in ("m.db", "s.json", "a.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
bdb = os.path.join(tmp, "b.db")
sent = []
send_fails = []


def fake_send(smtp, to, code, company):
    if send_fails:
        raise OSError("relay down")
    sent.append({"to": to, "code": code, "company": company})


web._send_signup_code = fake_send
smtp = SmtpConfig(host="smtp.test", from_addr="noreply@platform.test")
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    smtp_cfg=smtp))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def opener(follow=True):
    jar = urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    return (urllib.request.build_opener(jar) if follow
            else urllib.request.build_opener(jar, _NoRedirect))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=10)
        return (getattr(r, "status", r.code), r.read().decode("utf-8", "replace"),
                r.geturl(), r.headers)
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "replace"),
                e.headers.get("Location", ""), e.headers)


FORM = {"company": "Beta", "email": "own@beta.test", "password": "secret123",
        "phone": "0821234567", "agree": "1",
        "alert_emails": "noc@beta.test"}

try:
    o = opener()
    req(o, "/signup", dict(FORM, company="Platform", email="boss@platform.test"))
    a = AuthStore(adb)
    check("the first account on a server is made straight away (no mail "
          "server needed yet)", a.get_user("boss@platform.test") is not None
          and not sent)
    a.close()

    _, page, _, _ = req(opener(), "/signup")
    check("after that, the form says a code will be emailed",
          "6-digit code" in page and ">Continue</button>" in page)

    o = opener()
    _, page, url, hdrs = req(o, "/signup", FORM)
    a = AuthStore(adb)
    check("signing up sends a code to the address and creates nobody yet",
          len(sent) == 1 and sent[0]["to"] == "own@beta.test"
          and sent[0]["company"] == "Beta"
          and a.get_user("own@beta.test") is None)
    check("...and asks for it on the next page",
          "/signup/verify?t=" in url and "Check your email" in page
          and "own@beta.test" in page and 'autocomplete="one-time-code"' in page)
    check("...a page kept out of caches and other sites' Referer",
          hdrs.get("Referrer-Policy") == "no-referrer"
          and hdrs.get("Cache-Control") == "no-store")
    check("...and the code itself is never on the page", sent[0]["code"] not in page)
    t = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["t"][0]

    _, page, _, _ = req(o, "/dashboard")
    check("without the code there is no session", "Check your email" not in page
          and "Sign in" in page)

    wrong = "000000" if sent[0]["code"] != "000000" else "111111"
    _, page, url, _ = req(o, "/signup/verify", {"t": t, "code": wrong})
    check("a wrong code stays on the page and says so",
          "/signup/verify" in url and "That code is not right" in page)

    _, page, url, _ = req(o, "/signup/resend", {"t": t})
    check("asking for a new code straight away is refused politely",
          "moments ago" in page and len(sent) == 1)

    _, page, url, _ = req(o, "/signup/verify",
                          {"t": t, "code": sent[0]["code"]})
    a = AuthStore(adb)
    u = a.get_user("own@beta.test")
    check("the right code creates the account and logs them in",
          u is not None and url.endswith("/dashboard"))
    check("...recording the terms they accepted on the form",
          a.terms_of("own@beta.test")[0] == TERMS_VERSION)
    check("...with the alert addresses from the form",
          a.org(u["org_id"])["alert_emails"] == ["noc@beta.test"])
    a.close()
    from mikromon import billing as B
    bs = B.BillingStore(bdb)
    check("...and starts the free trial", bs.get(u["org_id"]) is not None
          and bs.billing_status(u["org_id"]) in ("trial", "trialing", "active"))
    bs.db.close()

    _, page, url, _ = req(opener(), "/signup/verify",
                          {"t": t, "code": sent[0]["code"]})
    check("a used code cannot make a second account",
          url.split("?")[0].endswith("/signup") and "expired" in page)
    _, page, url, _ = req(opener(), "/signup/verify?t=nonsense")
    check("an unknown or expired sign-up link goes back to the form",
          url.split("?")[0].endswith("/signup") and "expired" in page)

    send_fails.append(1)
    _, page, url, _ = req(opener(), "/signup",
                          dict(FORM, email="two@gamma.test", company="Gamma"))
    a = AuthStore(adb)
    check("if the code cannot be emailed, the form says so and nothing waits",
          "could not send a code" in page and a.db.execute(
              "SELECT COUNT(*) FROM pending_signups WHERE email=?",
              ("two@gamma.test",)).fetchone()[0] == 0)
    a.close()
    send_fails.clear()
finally:
    srv.shutdown()
    srv.server_close()

# No mail server at all: sign-ups after the first are paused, not let through
# unconfirmed.
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb}))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    n = len(sent)
    _, page, url, _ = req(opener(), "/signup",
                          dict(FORM, email="three@delta.test", company="Delta"))
    a = AuthStore(adb)
    check("with no mail server, a new sign-up is paused rather than let in "
          "unconfirmed", "paused" in page and len(sent) == n
          and a.get_user("three@delta.test") is None)
    a.close()
finally:
    srv.shutdown()
    srv.server_close()

subject, text, html = web._signup_code_email("042917", "Beta <Ltd>")
check("the code leads the email's subject, so a phone shows it",
      subject.startswith("042917 is your"))
check("...and the email says what to do if it was not you",
      "Not you? Ignore this email" in text and "&lt;Ltd&gt;" in html)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SIGNUP CODE TESTS PASSED")
