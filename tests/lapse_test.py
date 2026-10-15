"""Pay and carry on; do not pay and stop. The second half was never wired.

The grace and suspension machinery all existed -- in_grace_period, is_locked,
suspend, GRACE_DAYS -- and nothing called any of it on a timer. `suspend()`
had exactly one caller: a button in the superadmin panel. And billing_status
short-circuits on status == "active", so a lapsed account kept reporting
itself active whatever its paid-up date said.

Confirmed by running it before the fix: three months past the renewal date,
no payment, and the account was still fully active on its whole device cap.
Which means every customer had, in effect, a free account after their first
month -- the invoice went out, nobody had to pay it, and nothing anywhere
noticed.

The other half of the same question is how anybody learns a bank transfer
arrived. Nothing can: an EFT lands where the invoicing system has no sight of
it. So a person says so, once, in one place, and both systems are told.

Run:  python tests/lapse_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import billing_runner as R
from mikromon import web_auth

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DAY = 86400.0
PLAN = B.PLANS[0]["name"]


class FakeAuth:
    """Only what the runner asks of a settings store."""

    def get_yoco(self):
        return {"secret_key": "k", "webhook_secret": "w"}

    def get_setting(self, key, default=None):
        return default

    def set_setting(self, key, value):
        pass

    def org(self, org_id):
        return {"name": "Alpha Freight"}

    def list_users(self, org_id):
        return []


def lapsed(days_ago=1.0):
    st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
    st.set_plan(1, PLAN)
    st._upsert(1, current_period_end=time.time() - days_ago * DAY)
    return st


print("\nAn account that stops paying actually stops")

st = lapsed()
check("before the pass it still reads active, because nothing has looked yet",
      st.billing_status(1) == "active")

moved = st.lapse_due()
check("the pass moves a lapsed account into the grace period",
      moved["grace"] == [1] and st.billing_status(1) == "grace")
check("...and it still WORKS during grace: a payment in transit and a "
      "customer who has stopped paying look identical for a few days, and "
      "only one of them deserves to be cut off",
      st.device_limit(1) == B.PLANS[0]["devices"])
check("...with the grace deadline measured from when the period ended, not "
      "from when the pass happened to run",
      0 < st.days_left_in_grace(1) <= B.GRACE_DAYS)

check("running the pass again the next day changes nothing -- it is not a "
      "countdown that restarts every time something looks at it",
      st.lapse_due(time.time() + DAY)["grace"] == [])

moved = st.lapse_due(time.time() + (B.GRACE_DAYS + 1) * DAY)
check("when the grace period expires the account is suspended",
      moved["suspended"] == [1] and st.billing_status(1) == "suspended")
check("and a suspended account is not suspended a second time",
      st.lapse_due(time.time() + 100 * DAY)["suspended"] == [])

print("\nPaying at any point undoes all of it")

for when, label in ((0.0, "during grace"), (B.GRACE_DAYS + 1, "after suspension")):
    st = lapsed()
    st.lapse_due()
    if when:
        st.lapse_due(time.time() + when * DAY)
    oid = st.create_order(1, PLAN, 2500, kind="renewal", provider="zoho")
    st.mark_order_paid(oid, "x")
    st.apply_paid_order(st.order(oid))
    row = st.get(1)
    check(f"paying {label} switches the account back on",
          st.billing_status(1) == "active")
    check(f"...and clears the grace deadline, so it is not still counting "
          f"down behind the scenes ({label})",
          row["grace_period_end"] is None)
    check(f"...and the packet runs to a real date in the future ({label})",
          row["current_period_end"] > time.time())

print("\nWho is never lapsed")

st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
st.set_free(2)
check("a company on the free packet is not lapsed -- there is nothing to "
      "lapse", st.lapse_due()["grace"] == [])

st.set_plan(3, PLAN)
check("a company paid up into the future is left alone",
      st.lapse_due()["grace"] == [])

st.set_unlimited(4)
check("a comped unlimited account is not lapsed either, since nobody is "
      "invoicing it", 4 not in st.lapse_due()["grace"])

print("\nRecording a bank transfer by hand")

# The card path never needs this: Yoco's webhook records itself, which is
# the whole reason it is the only rail. This is for somebody who paid by
# EFT anyway, which people do, and which nothing can detect because the
# money lands where this server cannot see it.
st = lapsed()
st.lapse_due()
oid = st.create_order(1, PLAN, 2500, kind="renewal", provider="yoco",
                      currency="USD")

check("recording it switches the account back on immediately, rather than "
      "at some next pass -- somebody who has paid should not wait",
      R.mark_paid(st, FakeAuth(), oid) == ""
      and st.billing_status(1) == "active")
check("recording the same invoice twice does nothing the second time",
      "already" in R.mark_paid(st, FakeAuth(), oid).lower())

try:
    R.mark_paid(st, FakeAuth(), 99999)
    check("an unknown invoice raises", False)
except R.BillingError as exc:
    check("an invoice that does not exist is refused rather than silently "
          "doing nothing", "No such invoice" in str(exc))

print("\nThe panel somebody works through with a bank statement open")

html = web_auth._outstanding_box(
    [{"order_id": 1, "org_id": 1, "name": "Alpha Freight", "plan": "d5",
      "kind": "renewal", "amount": 25.0, "currency": "USD",
      "invoice_id": "INV-1", "raised": time.time() - 20 * DAY,
      "due": time.time(), "reference": "ALPHAFREIGHT-0001"}], "tok")
check("it names the company, the amount and the reference a bank statement "
      "will show",
      "Alpha Freight" in html and "$25.00" in html
      and "ALPHAFREIGHT-0001" in html)
check("...and how long it has been outstanding, in red once it is well past "
      "due", "20 days outstanding" in html)
check("...with the one button that does the whole job", "Paid</button>" in html)
check("...which asks first, because it takes money-received as fact",
      "confirm(" in html)
check("nothing outstanding renders nothing at all, rather than an empty "
      "table", web_auth._outstanding_box([], "tok") == "")

print("\nHow long until the lights go out")

# The panel showed "Grace" and a date. Turning that into "am I about to lose
# this customer" meant knowing grace runs seven days past a paid period and
# then doing arithmetic on a date, which nobody does while scanning a table.
NOW = time.time()

check("a paid company counts down from its renewal date plus the grace "
      "period -- the cut-off is knowable long before anything lapses",
      round(B.days_until_suspension(
          {"status": "active", "current_period_end": NOW + 3 * DAY},
          "active", now=NOW)) == 3 + B.GRACE_DAYS)

check("once it has lapsed, the countdown follows the grace deadline itself",
      round(B.days_until_suspension(
          {"status": "grace", "current_period_end": NOW - DAY,
           "grace_period_end": NOW + 5 * DAY}, "grace", now=NOW)) == 5)

check("an account already past its deadline reads zero, not minus three -- "
      "it is suspended on the next pass, and a negative number only invites "
      "the question",
      B.days_until_suspension(
          {"status": "grace", "grace_period_end": NOW - 3 * DAY},
          "grace", now=NOW) == 0.0)

check("a company already suspended has nothing left to count down",
      B.days_until_suspension(
          {"status": "suspended", "current_period_end": NOW - 30 * DAY},
          "suspended", now=NOW) is None)

check("a free company is not counting down towards anything",
      B.days_until_suspension({"status": "inactive"}, "none",
                              now=NOW) is None)

check("...and neither is a company with no billing row at all",
      B.days_until_suspension(None, "none", now=NOW) is None)

# The row's own status column lags: lapse_due runs daily, so an account can
# be past every date it has and still say "active" until the pass catches up.
check("the resolved status wins over the stale column, so a row the daily "
      "pass has not reached yet still shows the right countdown",
      round(B.days_until_suspension(
          {"status": "active", "current_period_end": NOW - 2 * DAY,
           "grace_period_end": NOW + 5 * DAY}, "grace", now=NOW)) == 5)

print("\n...and that it reaches the panel")

_rows = [{"id": 1, "name": "Alpha Freight", "owner_email": "a@example.com",
          "user_count": 1, "created": NOW - 90 * DAY, "device_count": 3,
          "active_count": 3,
          "bill": {"status": "grace", "plan": PLAN,
                   "current_period_end": NOW - 2 * DAY,
                   "grace_period_end": NOW + 5 * DAY, "device_limit": 5}}]
html = web_auth._render_superadmin(
    {"email": "me@example.com", "role": "owner", "is_superadmin": True},
    _rows, [], csrf="tok", billing_on=True)
check("the superadmin row says how many days are left, in words, rather "
      "than leaving a date to be subtracted by eye",
      "suspends in 5 days" in html)

_rows[0]["bill"] = {"status": "active", "plan": PLAN,
                    "current_period_end": NOW + 20 * DAY, "device_limit": 5}
html = web_auth._render_superadmin(
    {"email": "me@example.com", "role": "owner", "is_superadmin": True},
    _rows, [], csrf="tok", billing_on=True)
check("a healthy account shows its cut-off too -- the point is to see it "
      "coming, not to be told once it has happened",
      f"suspends in {20 + B.GRACE_DAYS} days" in html)

_rows[0]["bill"] = {"status": "none", "plan": "", "device_limit": 1}
html = web_auth._render_superadmin(
    {"email": "me@example.com", "role": "owner", "is_superadmin": True},
    _rows, [], csrf="tok", billing_on=True)
check("a free company's row stays quiet rather than saying 'n/a', because "
      "a row that says nothing is read faster", "suspends" not in html)

print("\nNobody is cut off without being sent the link that pays")

# A card payment records itself; the risk left is a company that simply
# forgot. So every step towards suspension emails the pay link: the day the
# paid-up date passes, two days before the cut-off, and the day it happens.
told = []


def spy(org_id, stage):
    told.append((org_id, stage))
    return True


T0 = time.time()
st = lapsed(days_ago=0.5)
R.run_once(st, FakeAuth(), now=T0, force_raise=True, remind=spy)
check("the day the paid-up date passes, the company is sent the overdue "
      "reminder", told == [(1, "overdue")])
told.clear()
R.run_once(st, FakeAuth(), now=T0 + DAY, force_raise=True, remind=spy)
check("...and nothing the next day: one email per step, not one per pass",
      told == [])
gpe = st.get(1)["grace_period_end"]
R.run_once(st, FakeAuth(), now=gpe - 1.5 * DAY, force_raise=True, remind=spy)
check(f"{R.FINAL_REMINDER_DAYS} days before the cut-off, the last reminder",
      told == [(1, "final")])
told.clear()
R.run_once(st, FakeAuth(), now=gpe - 0.5 * DAY, force_raise=True, remind=spy)
check("...sent once, not again on the last day", told == [])
R.run_once(st, FakeAuth(), now=gpe + 3600, force_raise=True, remind=spy)
check("the day it is suspended, one more with the link that switches it "
      "back on", told == [(1, "suspended")]
      and st.billing_status(1) == "suspended")

tries = []
st = lapsed(days_ago=0.5)
R.run_once(st, FakeAuth(), now=T0, force_raise=True)
gpe = st.get(1)["grace_period_end"]
R.run_once(st, FakeAuth(), now=gpe - 1.5 * DAY, force_raise=True,
           remind=lambda o, s: tries.append(s) or False)
R.run_once(st, FakeAuth(), now=gpe - 0.6 * DAY, force_raise=True,
           remind=lambda o, s: tries.append(s) or True)
check("a last reminder that could not be sent is tried again at the next "
      "pass rather than lost", tries == ["final", "final"])


def _boom(org_id, stage):
    raise RuntimeError("mail server on fire")


st = lapsed(days_ago=0.5)
R.run_once(st, FakeAuth(), now=T0, force_raise=True, remind=_boom)
check("a reminder that blows up does not stop the account lapsing",
      st.billing_status(1) == "grace")

told.clear()
st = lapsed(days_ago=6)
R.run_once(st, FakeAuth(), now=T0, force_raise=True, remind=spy)
check("a company that lapses with the cut-off already near (the server was "
      "off for days) gets the overdue email naming the date, not two at "
      "once", told == [(1, "overdue")])

told.clear()
st = lapsed(days_ago=0.5)
st._upsert(1, cancel_requested=time.time() - 30 * DAY)
R.run_once(st, FakeAuth(), now=T0, force_raise=True, remind=spy)
check("a company that asked to cancel is not told it was cut off for not "
      "paying", st.billing_status(1) == "suspended" and told == [])

st = lapsed(days_ago=0.5)
_cpe = st.get(1)["current_period_end"]
_next = st.create_order(1, PLAN, 2500, due=_cpe + 30 * DAY)
_mine = st.create_order(1, PLAN, 2500, due=_cpe)
check("the reminder chases the invoice for the period that ran out, not "
      "another month's", (st.open_renewal(1) or {}).get("id") == _mine)
st.mark_order_paid(_mine, "x")
check("...and there is nothing to chase once it is paid",
      st.open_renewal(1) is None)

print("\nWhat the reminders say")

import mikromon.notify.org_email as org_email  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.config import SmtpConfig  # noqa: E402

sent = []
_orig_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
SMTP = SmtpConfig(host="smtp.test", from_addr="billing@easymikrotik.test")


class MailAuth(FakeAuth):
    card = {"secret_key": "k", "webhook_secret": "w"}

    def get_yoco(self):
        return self.card

    def get_setting(self, key, default=None):
        return "https://easymikrotik.test" if key == "public_base_url" \
            else default

    def list_users(self, org_id):
        return [{"role": "owner", "email": "owner@alpha.test"}]

    def get_billing_contact(self):
        return {"email": "accounts@easymikrotik.test"}

    def superadmin_emails(self):
        return ["me@easymikrotik.test"]


st = lapsed(days_ago=0.5)
_inv = st.create_order(1, PLAN, 2500, currency="USD",
                       due=st.get(1)["current_period_end"])
st.lapse_due()
_ma = MailAuth()
ok = web._email_reminder(_ma, st, SMTP, 1, "overdue",
                         "https://easymikrotik.test")
_txt = sent[-1].get_content() if sent else ""
check("the overdue reminder goes to the company's owner",
      ok and len(sent) == 1 and sent[0]["To"] == "owner@alpha.test")
check("...says it is overdue, what is owed and the day it will be "
      "suspended", "overdue" in sent[0]["Subject"] and "$25.00" in _txt
      and time.strftime("%d %B %Y", time.localtime(
          st.get(1)["grace_period_end"])) in _txt)
check("...and carries the link that pays it -- and no bank transfer, which "
      "would need somebody here to record it", "Pay now: https://"
      "easymikrotik.test/pay?t=" in _txt and "bank transfer" not in _txt)
check("...with somewhere to say 'I already paid'",
      "accounts@easymikrotik.test" in _txt)
check("the platform admins are not told about an ordinary overdue invoice",
      all("me@easymikrotik.test" not in m["To"] for m in sent))

sent.clear()
web._email_reminder(_ma, st, SMTP, 1, "final", "https://easymikrotik.test")
_co = [m for m in sent if m["To"] == "owner@alpha.test"]
_ad = [m for m in sent if m["To"] == "me@easymikrotik.test"]
check("the last reminder tells the company the date it will be suspended",
      len(_co) == 1 and "will be suspended on" in _co[0]["Subject"]
      and "Pay now:" in _co[0].get_content())
check("...and warns the platform admins, with the reference a bank "
      "statement would show and what to press if they paid by transfer",
      len(_ad) == 1 and "ALPHAFREIGHT-0001" in _ad[0].get_content()
      and "Waiting for payment" in _ad[0].get_content()
      and "Paid" in _ad[0].get_content())

sent.clear()
web._email_reminder(_ma, st, SMTP, 1, "suspended", "https://easymikrotik.test")
check("the suspension email says so, and that paying switches it back on",
      sent and "suspended" in sent[0]["Subject"]
      and "back on as soon as the payment clears" in sent[0].get_content()
      and "Pay now:" in sent[0].get_content())

sent.clear()
_ma.card = {}
web._email_reminder(_ma, st, SMTP, 1, "overdue", "https://easymikrotik.test")
_txt = sent[-1].get_content() if sent else ""
check("with card payment off there is no link to send, so it gives the "
      "reference for a bank transfer instead -- never a link to a page "
      "saying card payment is off", "Pay now" not in _txt
      and "Quote ALPHAFREIGHT-0001" in _txt)
_ma.card = MailAuth.card

sent.clear()
st.mark_order_paid(_inv, "x")
check("nothing is sent when there is no unpaid invoice to chase, and that "
      "counts as done", web._email_reminder(
          _ma, st, SMTP, 1, "final", "https://easymikrotik.test") is True
      and sent == [])
st2 = lapsed(days_ago=0.5)
st2.create_order(1, PLAN, 2500, due=st2.get(1)["current_period_end"])
check("with no mail server it reports not-sent, so the pass tries again",
      web._email_reminder(_ma, st2, SmtpConfig(host=""), 1, "final") is False)
org_email._smtp_send = _orig_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL LAPSE TESTS PASSED")
