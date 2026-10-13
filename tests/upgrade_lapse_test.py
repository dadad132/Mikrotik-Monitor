"""An upgrade that is asked for and not paid lapses after three days.

"Change now" raises an invoice for the difference; the bigger packet arrives
only when it is paid. An invoice nobody paid used to sit there for ever --
on a server without card payment it was not even shown, and nothing the
customer could do would clear it. Now it lapses after three days (the
company stays on the packet it paid for, and is told), it can be withdrawn
from the Billing page, asking for another packet replaces it, and a pay link
for a lapsed one says so instead of taking money for it. A payment that
still arrives is honoured.

Also: a company whose paid month had already ended could press Change now,
have the difference priced at nothing, and be switched to the bigger packet
and back to Active for free.

Run:  ./.venv/Scripts/python.exe tests/upgrade_lapse_test.py
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

import mikromon.notify.org_email as org_email
from mikromon import billing as B
from mikromon import billing_runner, web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig
from mikromon.metrics import MetricsStore
from mikromon.web_terms import render_terms

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DAY = 86400
print("The store")
tmp = tempfile.mkdtemp()
bs = B.BillingStore(os.path.join(tmp, "unit.db"))
pe = time.time() + 10 * DAY
bs.set_plan(1, "d5", period_end=pe)
old_up = bs.create_order(1, "d10", 500, kind="upgrade")
new_up = bs.create_order(1, "d10", 500, kind="upgrade")
old_renewal = bs.create_order(1, "d5", 2500, due=pe)
paid_up = bs.create_order(1, "d10", 500, kind="upgrade")
bs.mark_order_paid(paid_up, "p")
bs.db.execute("UPDATE orders SET created = ? WHERE id IN (?, ?, ?)",
              (time.time() - 3 * DAY - 60, old_up, old_renewal, paid_up))
bs.db.commit()
gone = bs.lapse_upgrades()
check("an upgrade invoice unpaid for three days lapses",
      [o["id"] for o in gone] == [old_up]
      and bs.order(old_up)["status"] == "lapsed")
check("...but not a newer one, a paid one, or a renewal of the same age",
      bs.order(new_up)["status"] == "pending"
      and bs.order(paid_up)["status"] == "paid"
      and bs.order(old_renewal)["status"] == "pending")
check("a lapsed invoice is no longer outstanding",
      old_up not in [o["id"] for o in bs.open_orders(require_external=False)])
check("...and lapsing twice does nothing", bs.lapse_upgrades() == [])
check("the company's packet is untouched", bs.get(1)["plan"] == "d5")
check("a payment that still arrives is honoured, not refused",
      bs.mark_order_paid(old_up, "late"))
bs.apply_paid_order(bs.order(old_up))
check("...and gives them the packet they paid for",
      bs.get(1)["plan"] == "d10" and bs.get(1)["current_period_end"] == pe)

told = []
bs.set_plan(2, "d5", period_end=pe)
o2 = bs.create_order(2, "d10", 500, kind="upgrade")
bs.db.execute("UPDATE orders SET created = ? WHERE id = ?",
              (time.time() - 4 * DAY, o2))
bs.db.commit()
billing_runner.run_once(bs, None, lapsed_upgrade=told.append)
check("the billing runner lapses them on every pass, not once a day, and "
      "says which", [o["id"] for o in told] == [o2])
bs.db.close()

print("\nOn the Billing page")
mdb, sfile, adb, bdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "b.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
org = auth.signup("jp@eca.test", "secret123", "ECA")
auth.set_setting("public_base_url", "https://easymikrotik.test")
bs = B.BillingStore(bdb)
period_end = B.first_billing_date(time.time())
if period_end - time.time() < 2 * DAY:      # keep some days to charge for
    period_end = B.add_billing_months(period_end, 1)
bs.set_plan(org, "d5", period_end=period_end)

sent = []
orig_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
SMTP = SmtpConfig(host="smtp.test", from_addr="billing@eca.test")
# No card payment on this server: the EFT-only case is the one that used to
# hide the request altogether.
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"), smtp_cfg=SMTP, admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), ""


def upgrades():
    return [o for o in bs.orders_for_org(org) if o.get("kind") == "upgrade"]


try:
    req("/login", {"email": "jp@eca.test", "password": "secret123"})
    st, page, _ = req("/billing")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    st, page, _ = req("/billing/change-plan", {"csrf": csrf, "plan": "d10",
                                               "when": "now"})
    check("Change now says the invoice must be paid within 3 days, and what "
          "happens if it is not", "Pay it within 3 days" in page
          and "the request lapses" in page)
    check("...and the emailed invoice says the same",
          sent and "Payable within 3 days" in sent[-1].get_content()
          and "lapses" in sent[-1].get_content())
    first = upgrades()[0]
    check("the invoice is due in three days, not seven",
          abs(first["due"] - (first["created"] + 3 * DAY)) < 5)
    check("with no card payment the request is still shown at the top, with "
          "the transfer reference, the day it lapses and a way to cancel it",
          "Upgrade to 10 devices" in page and "waiting for payment" in page
          and "Pay by bank transfer quoting" in page and "Not paid by" in page
          and 'name="withdraw"' in page)

    st, page, _ = req("/billing/change-plan", {"csrf": csrf, "plan": "d15",
                                               "when": "now"})
    ups = upgrades()
    check("asking for a different packet replaces the waiting request: one "
          "upgrade at a time, never two invoices",
          [o["status"] for o in ups if o["plan"] == "d10"] == ["cancelled"]
          and [o["status"] for o in ups if o["plan"] == "d15"] == ["pending"])

    d15 = [o for o in ups if o["plan"] == "d15"][0]
    st, page, _ = req("/billing/change-plan", {"csrf": csrf,
                                               "withdraw": str(d15["id"])})
    check("Cancel this upgrade withdraws it: nothing owed, packet unchanged",
          "Upgrade request cancelled" in page
          and bs.order(d15["id"])["status"] == "cancelled"
          and bs.get(org)["plan"] == "d5" and "Not paid by" not in page)
    check("...and it shows as cancelled in the payments list",
          "Cancelled</span>" in page)

    other = auth.signup("x@other.test", "secret123", "Other")
    bs.set_plan(other, "d5", period_end=period_end)
    foreign = bs.create_order(other, "d10", 500, kind="upgrade")
    st, page, _ = req("/billing/change-plan", {"csrf": csrf,
                                               "withdraw": str(foreign)})
    check("another company's upgrade cannot be withdrawn from here",
          "was not found" in page
          and bs.order(foreign)["status"] == "pending")

    req("/billing/change-plan", {"csrf": csrf, "plan": "d10", "when": "now"})
    up = [o for o in upgrades() if o["status"] == "pending"][0]
    link = billing_runner.pay_link(auth, int(up["id"]),
                                   "https://easymikrotik.test")
    token = link.split("t=", 1)[1]
    bs.db.execute("UPDATE orders SET created = ? WHERE id = ?",
                  (time.time() - 3 * DAY - 60, up["id"]))
    bs.db.commit()
    st, page, _ = req("/pay?t=" + token)
    check("a pay link for an upgrade past its three days says it lapsed, and "
          "offers no way to pay it", "lapsed" in page
          and "Pay by card" not in page
          and bs.order(up["id"])["status"] == "lapsed")
    st, page, _ = req("/billing")
    check("Billing shows it lapsed, and the company is still on its packet",
          "Lapsed &mdash; not paid within 3 days" in page
          and "Not paid by" not in page and bs.get(org)["plan"] == "d5")

    sent.clear()
    to = web._email_upgrade_lapsed(auth, SMTP, bs.order(up["id"]))
    check("the company is emailed that it lapsed, that nothing is owed and "
          "how to ask again", to == ["jp@eca.test"] and sent
          and "lapsed" in sent[-1]["Subject"]
          and "Nothing is owed" in sent[-1].get_content()
          and "ask for it again from Billing" in sent[-1].get_content())

    print("\nAn upgrade paid after the month's renewal invoice went out")
    ren = bs.create_order(org, "d5", 2500, due=period_end)
    ren_link = billing_runner.pay_link(auth, int(ren),
                                       "https://easymikrotik.test")
    st, page, _ = req("/billing/change-plan", {"csrf": csrf, "plan": "d10",
                                               "when": "now"})
    up = [o for o in upgrades() if o["status"] == "pending"][0]
    st, sa, _ = req("/superadmin")
    sent.clear()
    st, page, _ = req("/superadmin/mark-paid", {
        "csrf": re.search(r'name="csrf" value="([^"]+)"', sa).group(1),
        "order": str(up["id"])})
    renewals = [o for o in bs.orders_for_org(org)
                if (o.get("kind") or "renewal") == "renewal"]
    fresh = [o for o in renewals if o["status"] == "pending"]
    check("paying the upgrade replaces the old-price renewal invoice with "
          "one at the new packet's price, for the same date",
          bs.get(org)["plan"] == "d10"
          and bs.order(ren)["status"] == "replaced"
          and len(fresh) == 1 and fresh[0]["plan"] == "d10"
          and fresh[0]["amount_cents"]
          == round(B.plan_by_name("d10")["price"] * 100)
          and abs(fresh[0]["due"] - period_end) < 5)
    for _ in range(50):
        if any("replaces the one sent earlier" in m.get_content()
               for m in sent):
            break
        time.sleep(0.1)
    check("...and the new invoice is emailed, saying which one it replaces",
          any("replaces the one sent earlier for 5 devices" in m.get_content()
              and "pay this one instead" in m.get_content() for m in sent))
    st, page, _ = req("/pay?t=" + ren_link.split("t=", 1)[1])
    check("the old invoice's pay link says it was replaced, and takes no "
          "money", "replaced by a newer one" in page
          and "Pay by card" not in page)
    st, page, _ = req("/billing")
    check("Billing lists it as replaced",
          "Replaced by the invoice for your new packet" in page)
    bs.mark_order_paid(fresh[0]["id"], "p")
    bs.apply_paid_order(bs.order(fresh[0]["id"]))
    check("paying the new renewal keeps them on the bigger packet -- before, "
          "paying the old one put them straight back on the smaller one",
          bs.get(org)["plan"] == "d10")

    late = B.BillingStore(os.path.join(tmp, "late.db"))
    late.set_plan(9, "d5", period_end=time.time() + 5 * DAY)
    old_ren = late.create_order(9, "d5", 2500,
                                due=late.get(9)["current_period_end"])
    u = late.create_order(9, "d10", 300, kind="upgrade")
    late.mark_order_paid(u, "p")
    (_old, new_ren), = late.apply_paid_order(late.order(u))
    before_end = late.get(9)["current_period_end"]
    stale = late.order(old_ren)            # read before it is marked paid
    late.mark_order_paid(old_ren, "late")
    late.apply_paid_order(stale)
    check("the replaced invoice paid anyway (a checkout opened earlier) is "
          "honoured without shrinking the packet, and the replacement is "
          "withdrawn", late.get(9)["plan"] == "d10"
          and late.get(9)["current_period_end"] > before_end
          and late.order(new_ren)["status"] == "cancelled")
    late.db.close()

    print("\nA paid month that has already ended")
    bs.set_plan(org, "d5", period_end=time.time() - 2 * DAY)
    st, page, _ = req("/billing/change-plan", {"csrf": csrf, "plan": "d20",
                                               "when": "now"})
    row = bs.get(org)
    check("Change now is refused instead of upgrading for free",
          "Pay the renewal invoice first" in page and row["plan"] == "d5"
          and not [o for o in upgrades() if o["plan"] == "d20"])
    st, page, _ = req("/billing/change-plan", {"csrf": csrf, "plan": "d20",
                                               "when": "renewal"})
    check("...and so is booking one, which would have switched on at the "
          "next pass with the old renewal still unpaid",
          "Pay the renewal invoice first" in page
          and not bs.pending_change(org))

    print("\nThe Terms")
    terms = render_terms()
    check("the Terms say an upgrade invoice lapses after 3 days",
          "not paid within 3 days lapses" in terms)
finally:
    org_email._smtp_send = orig_send
    srv.shutdown()

print("")
if FAILS:
    print(f"FAILED: {len(FAILS)}: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL UPGRADE-LAPSE TESTS PASSED")
