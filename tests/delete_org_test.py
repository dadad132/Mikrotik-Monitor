"""Platform admin -> delete a company.

Only a company that is suspended, has no device that ever reported in, holds
no platform admin and is not the superadmin's own can be deleted -- checked
on the server, whatever the page offered. Its logins, its devices that never
connected, the routers shared with its people and their Personal VPN peers
go, and so does its billing status and any invoice it never paid. Paid
invoices stay: they are the record of money received.

Run:  ./.venv/Scripts/python.exe tests/delete_org_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DEF = dict(DEFAULT_THRESHOLDS)
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, bdb = (os.path.join(tmp, x) for x in (
    "m.db", "s.json", "a.db", "d.db", "b.db"))
peers = os.path.join(tmp, "peers.conf")
MetricsStore(mdb).close()
# BetaR1 has reported in (it is in the monitor's state); AlphaR1 never has.
with open(sfile, "w") as fh:
    json.dump({"devices": {"BetaR1": {"facts": {}}}}, fh)

auth = AuthStore(adb)
staff = auth.signup("boss@platform.test", "secret123", "Platform")
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha")
beta = auth.signup("owner@beta.test", "secret123", "Beta")
gamma = auth.signup("owner@gamma.test", "secret123", "Gamma")

ds = DevicesStore(ddb)
ds.upsert({"name": "AlphaR1", "host": "10.10.1.1"}, DEF, org_id=alpha)
ds.upsert({"name": "BetaR1", "host": "10.10.2.2"}, DEF, org_id=beta)
ds.upsert({"name": "GammaR1", "host": "10.10.3.3"}, DEF, org_id=gamma)
ds.close()
auth.share_device("GammaR1", "owner@alpha.test", gamma, False,
                  "owner@gamma.test")
with open(web._hub_path(ddb), "w") as fh:
    json.dump({"wg_peers": peers, "roadwarriors": {
        "k1": {"label": "Alpha laptop", "org_id": alpha,
               "ip": "10.10.44.44", "pubkey": "RWALPHA"},
        "k2": {"label": "Gamma laptop", "org_id": gamma,
               "ip": "10.10.55.55", "pubkey": "RWGAMMA"}}}, fh)

bs = B.BillingStore(bdb)
for org in (alpha, beta, gamma):
    bs.set_plan(org, "d5")
bs.suspend(alpha)
bs.suspend(beta)
paid = bs.create_order(alpha, "d5", 2500)
bs.mark_order_paid(paid, "p1")
unpaid = bs.create_order(alpha, "d5", 2500)
bs.db.close()

srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, billing_cfg={"db": bdb}))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), ""


def login(email):
    o = opener()
    req(o, "/login", {"email": email, "password": "secret123"})
    return o


try:
    boss = login("boss@platform.test")
    ao = login("owner@alpha.test")
    st, page, _ = req(ao, "/billing")
    check("(Alpha's owner is logged in before the delete)", st == 200)

    st, page, _ = req(boss, "/superadmin")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    offers = re.findall(r'name="org_id" value="(\d+)">\s*<button class="btn '
                        r'red"[^>]*>Delete company', page)
    check("the Delete button is offered only for a suspended company with "
          "no active devices", offers == [str(alpha)])
    check("...and its confirmation says what goes, and that it cannot be "
          "undone", "1 login and 1 device that never connected" in page
          and "cannot be undone" in page)

    def delete(op, org, token=csrf):
        return req(op, "/superadmin/delete-org",
                   {"csrf": token, "org_id": str(org)})

    _, page, _ = delete(boss, beta)
    check("a suspended company with a device that has reported in is "
          "refused", "still has 1 device(s) that have reported in" in page
          and auth.get_user("owner@beta.test") is not None)
    _, page, _ = delete(boss, gamma)
    check("a company that is not suspended is refused",
          "is not suspended" in page
          and auth.get_user("owner@gamma.test") is not None)
    _, page, _ = delete(boss, staff)
    check("the platform's own company is refused",
          "cannot be deleted" in page
          and auth.get_user("boss@platform.test") is not None)
    _, gpage, _ = req(login("owner@gamma.test"), "/billing")
    gcsrf = re.search(r'name="csrf" value="([^"]+)"', gpage).group(1)
    st, _, _ = req(login("owner@gamma.test"), "/superadmin/delete-org",
                   {"csrf": gcsrf, "org_id": str(alpha)})
    check("someone who is not a superadmin cannot delete anything",
          st == 403 and auth.get_user("owner@alpha.test") is not None)

    st, page, _ = delete(boss, alpha)
    check("deleting Alpha says what went, and what was kept",
          "Deleted Alpha: 1 login(s) and 1 device(s) that never connected "
          "removed. Its 1 paid invoice(s) are kept." in page)
    check("...its logins and the company are gone",
          auth.get_user("owner@alpha.test") is None
          and not auth.org_name(alpha))
    ds = DevicesStore(ddb)
    check("...so is its device that never connected; other companies' "
          "devices are untouched", ds.raw("AlphaR1") is None
          and ds.raw("BetaR1") is not None and ds.raw("GammaR1") is not None)
    ds.close()
    with open(web._hub_path(ddb)) as fh:
        hub = json.load(fh)
    check("...and its people's Personal VPN peers, but no one else's",
          "k1" not in hub["roadwarriors"] and "k2" in hub["roadwarriors"])
    with open(peers) as fh:
        pf = fh.read()
    check("...which the hub stops accepting", "RWALPHA" not in pf
          and "RWGAMMA" in pf)
    check("...and the router another company had shared with them is no "
          "longer shared", not any(
              r[0] == "owner@alpha.test" for r in auth.db.execute(
                  "SELECT email FROM device_shares").fetchall()))
    bs = B.BillingStore(bdb)
    check("its billing status and unpaid invoice go; the paid invoice stays",
          bs.get(alpha) is None and bs.order(unpaid) is None
          and bs.order(paid) is not None)
    bs.db.close()
    st, page, url = req(ao, "/billing")
    check("Alpha's owner, still holding a session, is logged out",
          "/login" in url or "Sign in" in page)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DELETE-COMPANY TESTS PASSED")
