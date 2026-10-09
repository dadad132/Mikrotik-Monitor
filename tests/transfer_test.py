"""Transferring a router to another company.

Sharing gives someone access; a transfer hands the router over for good.
It is an offer the receiving company's owner accepts -- the router then
counts towards their packet -- and until then nothing changes. On accepting,
the router moves with its history and settings, and every access the old
company gave out (shares, members' allocations) goes with the old company.

Run:  ./.venv/Scripts/python.exe tests/transfer_test.py
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
from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore
from mikromon.push.audit import AuditLog

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DEF = dict(DEFAULT_THRESHOLDS)
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, bdb, pdb = (os.path.join(tmp, x) for x in (
    "m.db", "s.json", "a.db", "d.db", "b.db", "p.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
auth.signup("boss@platform.test", "secret123", "Platform")
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha IT")
beta = auth.signup("owner@beta.test", "secret123", "Beta Shop")
auth.add_member(alpha, "tech@alpha.test", "secret123", role="member",
                devices=["Till", "Office"])
ds = DevicesStore(ddb)
for n in ("Till", "Office", "Grouped"):
    ds.upsert({"name": n, "host": "10.10.1.1"}, DEF, org_id=alpha)
ds.close()
auth.share_device("Till", "guest@else.test", alpha, False, "owner@alpha.test")
with open(web._hub_path(ddb), "w") as fh:
    json.dump({"vpn_groups": {"Grouped": {"subnet": "192.168.9.0/24",
                                          "members": {}}}}, fh)
bs = B.BillingStore(bdb)
bs.set_plan(beta, "d5")
bs.db.close()

mails = []
saved = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: mails.append(msg)
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, billing_cfg={"db": bdb}, push_log_db=pdb,
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noc@platform.test")))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def login(email):
    o = opener()
    req(o, "/login", {"email": email, "password": "secret123"})
    _, page = req(o, "/devices")
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return o, (m.group(1) if m else "")


def org_of(name):
    d = DevicesStore(ddb)
    try:
        return d.org_of(name)
    finally:
        d.close()


def wait_mail(n, secs=5):
    end = time.time() + secs
    while len(mails) < n and time.time() < end:
        time.sleep(0.05)


try:
    a, acsrf = login("owner@alpha.test")
    b, bcsrf = login("owner@beta.test")

    st, page = req(a, "/device?name=Till&tab=share")
    check("the Share tab offers a transfer as well as sharing",
          "Transfer to another company" in page and "Offer to transfer" in page)

    def offer(dev, email, op=a, token=None):
        return req(op, "/device/transfer", {
            "csrf": token or acsrf, "device": dev, "action": "offer",
            "email": email})

    _, page = offer("Till", "nobody@nowhere.test")
    check("offering to someone with no account is refused",
          "No account signs in as nobody@nowhere.test" in page)
    _, page = offer("Grouped", "owner@beta.test")
    check("a router in a VPN group with the company's other sites cannot be "
          "transferred until it is taken out", "VPN group" in page
          and auth.transfer_offer("Grouped") is None)
    _, page = offer("Till", "owner@beta.test")
    check("offering it to Beta's owner makes an offer -- nothing moves yet",
          auth.transfer_offer("Till") is not None and org_of("Till") == alpha
          and "Offered to owner@beta.test" in page)
    wait_mail(1)
    check("...and Beta's owner is emailed about it",
          any("owner@beta.test" in m["To"]
              and "Alpha IT wants to transfer a router to you" in m["Subject"]
              for m in mails))
    _, page = req(a, "/device?name=Till&tab=share")
    check("the Share tab then shows the offer, and a way to cancel it",
          "Offered to <b>owner@beta.test</b> (Beta Shop)" in page
          and "Cancel the transfer" in page)

    _, page = req(b, "/devices")
    check("Beta sees the offer on its Devices page, with Accept and Decline",
          "Routers offered to you" in page and "<b>Till</b>" in page
          and "Accept" in page and "Decline" in page)
    st, _ = req(b, "/device/transfer", {"csrf": bcsrf, "device": "Till",
                                        "action": "cancel"})
    check("Beta cannot cancel or redirect Alpha's offer",
          st == 403 and auth.transfer_offer("Till") is not None)

    req(a, "/device/transfer", {"csrf": acsrf, "device": "Till",
                                "action": "cancel"})
    check("Alpha can cancel its offer; the router stays put",
          auth.transfer_offer("Till") is None and org_of("Till") == alpha)
    _, page = req(b, "/transfer/answer", {"csrf": bcsrf, "unit": "Till",
                                          "answer": "accept"})
    check("...after which accepting it does nothing",
          "no longer open" in page and org_of("Till") == alpha)

    offer("Office", "owner@beta.test")
    _, page = req(b, "/transfer/answer", {"csrf": bcsrf, "unit": "Office",
                                          "answer": "decline"})
    check("declining leaves it with Alpha, and says so",
          org_of("Office") == alpha and auth.transfer_offer("Office") is None
          and "Declined" in page)

    # Beta's packet is full: the accept waits for a bigger one.
    d = DevicesStore(ddb)
    for i in range(5):
        d.upsert({"name": f"BetaR{i}", "host": "10.10.2.2"}, DEF, org_id=beta)
    d.close()
    offer("Till", "owner@beta.test")
    _, page = req(b, "/transfer/answer", {"csrf": bcsrf, "unit": "Till",
                                          "answer": "accept"})
    check("a company whose packet is full is asked to choose a bigger one "
          "first; nothing moves", "bigger packet" in page
          and org_of("Till") == alpha
          and auth.transfer_offer("Till") is not None)
    d = DevicesStore(ddb)
    d.delete("BetaR4")
    d.close()

    _, page = req(b, "/transfer/answer", {"csrf": bcsrf, "unit": "Till",
                                          "answer": "accept"})
    check("accepting moves the router to Beta, with its settings",
          org_of("Till") == beta and "Till is yours now" in page
          and DevicesStore(ddb).raw("Till")["host"] == "10.10.1.1")
    check("...the share Alpha gave out goes with Alpha",
          auth.shares_for_device("Till") == [])
    member = auth.get_user("tech@alpha.test")
    check("...and so does the router's place in Alpha's members' lists, "
          "leaving their others", member.get("devices") == ["Office"])
    check("...Alpha no longer sees it, Beta does",
          "Till" not in req(a, "/devices")[1].split("Routers offered")[0]
          or org_of("Till") == beta)
    st, _ = req(a, "/device?name=Till")
    check("...and Alpha cannot open it any more", st in (403, 404))
    log = AuditLog(pdb).recent(device="Till")
    check("its activity log records the transfer, by whom and to whom",
          any("transferred from Alpha IT to Beta Shop" in r["summary"]
              and "accepted by owner@beta.test" in r["summary"] for r in log))
    wait_mail(3)
    check("Alpha's owner is told it was accepted",
          any("owner@alpha.test" in m["To"]
              and "Beta Shop accepted the router Till" in m["Subject"]
              for m in mails))
finally:
    srv.shutdown()
    srv.server_close()
    org_email._smtp_send = saved

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL TRANSFER TESTS PASSED")
