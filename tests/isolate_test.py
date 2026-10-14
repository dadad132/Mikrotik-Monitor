"""Cutting a PC off the network at its router (push/isolate.py), and the
support team's pages that do it.

No router here: a stand-in keeps the filter list, address lists and
connection table in order -- including where `place-before` puts a rule,
because the rules only work at the top, the accept above the drop.

Run:  ./.venv/Scripts/python.exe tests/isolate_test.py
"""
from __future__ import annotations

import copy
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

import mikromon.notify.org_email as org_email  # noqa: E402
import mikromon.push as P  # noqa: E402
import mikromon.push.api as PA  # noqa: E402
from mikromon import edr, web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import Pusher, PushError  # noqa: E402
from mikromon.push import isolate as I  # noqa: E402
from mikromon.push.audit import AuditLog  # noqa: E402

edr.ENABLED = True   # switched off in the product until the agent ships
FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


FILTER, ADDR, CONN = I._FILTER, I._ADDR, I._CONN


class Router:
    """A router's lists, kept in order like RouterOS keeps them."""

    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.n = 100
        self.fail_on = None

    def fetch(self, path):
        if path == ("ip", "address") and "addr_fail" in self.state:
            raise PushError("read failed")
        return [dict(r) for r in self.state.get(tuple(path), [])]

    def execute(self, op):
        if self.fail_on and self.fail_on in op.desc:
            raise PushError("simulated failure")
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self.n += 1
            row = {k: v for k, v in op.params.items() if k != "place-before"}
            row[".id"] = f"*{self.n}"
            before = op.params.get("place-before")
            at = next((i for i, r in enumerate(rows) if r[".id"] == before),
                      len(rows))
            if before and at == len(rows):
                raise PushError(f"no such item {before}")
            rows.insert(at, row)
            return row[".id"]
        if op.action == "remove":
            ids = str(op.params[".id"]).split(",")
            if any(i not in {r[".id"] for r in rows} for i in ids):
                raise PushError("no such item")
            self.state[tuple(op.path)] = [r for r in rows if r[".id"] not in ids]
            return None
        if op.action == "set":
            for r in rows:
                if r[".id"] == op.params[".id"]:
                    r.update({k: v for k, v in op.params.items() if k != ".id"})
            return None
        raise PushError("unexpected " + op.action)

    def comments(self, path=FILTER):
        return [r.get("comment", "") for r in self.state.get(path, [])]


PC_IP = "192.168.88.23"
START = {
    FILTER: [
        {".id": "*1", "chain": "forward", "action": "passthrough",
         "comment": "special dummy rule to show fasttrack counters",
         "dynamic": "true"},
        {".id": "*2", "chain": "forward", "action": "fasttrack-connection",
         "connection-state": "established,related", "comment": "fasttrack"},
        {".id": "*3", "chain": "forward", "action": "accept",
         "connection-state": "established,related", "comment": "established"},
        {".id": "*4", "chain": "forward", "action": "drop",
         "connection-state": "invalid", "comment": "invalid"},
    ],
    ADDR: [{".id": "*20", "list": "trusted", "address": "10.10.0.0/24",
            "comment": "hand-made"}],
    CONN: [{".id": "*30", "src-address": f"{PC_IP}:51234",
            "dst-address": "93.184.216.34:443"},
           {".id": "*31", "src-address": "41.0.0.9:443",
            "dst-address": f"{PC_IP}:51235"},
           {".id": "*32", "src-address": "192.168.88.40:5000",
            "dst-address": "8.8.8.8:53"},
           {".id": "*33", "src-address": "192.168.88.230:5000",
            "dst-address": "8.8.8.8:53"}],
    ("ip", "address"): [{".id": "*40", "address": "192.168.88.1/24",
                         "interface": "bridge"}],
}


def push(router, plan):
    return Pusher(type("C", (), {"name": "Shop-1"})(), router,
                  dry_run=False).apply(plan)


print("the address:")
check("a PC's IPv4 address is taken", I.check_ip(" 192.168.88.23 ") == PC_IP)
for bad in ("", "abc", "127.0.0.1", "224.0.0.1", "0.0.0.0", "169.254.1.1",
            "255.255.255.255", "2001:db8::1", "192.168.88.0/24"):
    try:
        I.check_ip(bad)
        check(f"{bad!r} is refused", False)
    except I.IsolateError:
        check(f"{bad!r} is refused", True)

print("isolating:")
r = Router(START)
plan = I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="RECEPTION",
                      hub_host="easymikrotik.com")
check("the preview says what it will do, in words",
      "add RECEPTION (192.168.88.23) to the address list mikromon-isolated"
      in plan.diff_text() and "easymikrotik.com" in plan.diff_text())
push(r, plan)
check("the PC is on the isolation list, tagged as this PC",
      {"list": "mikromon-isolated", "address": PC_IP,
       "comment": "mikromon:edr:pc:a1"}.items()
      <= next(x for x in r.state[ADDR] if x.get("list") == I.LIST).items())
check("the two rules go to the very top -- under only the dynamic FastTrack "
      "counter, and above FastTrack itself -- the accept above the drop",
      r.comments() == ["special dummy rule to show fasttrack counters",
                       "mikromon:edr:hub", "mikromon:edr:block",
                       "fasttrack", "established", "invalid"])
hub = next(x for x in r.state[FILTER] if x.get("comment") == "mikromon:edr:hub")
check("the accept is HTTPS from isolated PCs to EasyMikroTik only",
      hub["src-address-list"] == I.LIST and hub["dst-address-list"] == I.HUB_LIST
      and hub["protocol"] == "tcp" and hub["dst-port"] == "443"
      and hub["action"] == "accept" and hub["chain"] == "forward")
check("...which is on its own address list, by name",
      any(x.get("list") == I.HUB_LIST and x["address"] == "easymikrotik.com"
          for x in r.state[ADDR]))
check("the hand-made address list entry is untouched",
      {"list": "trusted", "address": "10.10.0.0/24", "comment": "hand-made",
       ".id": "*20"} in r.state[ADDR])
check("isolating it again sends nothing",
      I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="RECEPTION",
                     hub_host="easymikrotik.com").empty)
check("the PC's open connections are found, either way round, and only its",
      sorted(I.connection_ids(r, PC_IP)) == ["*30", "*31"])
check("...and cleared", I.clear_connections(r, PC_IP) == 2
      and [c[".id"] for c in r.state[CONN]] == ["*32", "*33"])

print("a second PC, a PC that moved, and letting them back:")
push(r, I.isolate_plan("Shop-1", r, ip="192.168.88.24", agent_id="a2",
                       label="ACCOUNTS", hub_host="easymikrotik.com"))
check("a second PC only adds its own entry",
      r.comments().count("mikromon:edr:block") == 1
      and len([x for x in r.state[ADDR] if x.get("list") == I.LIST]) == 2)
moved = I.isolate_plan("Shop-1", r, ip="192.168.88.99", agent_id="a2",
                       label="ACCOUNTS", hub_host="easymikrotik.com")
check("a PC isolated again at a new address has its entry moved",
      [o.action for o in moved.ops] == ["set"])
push(r, moved)
push(r, I.release_plan("Shop-1", r, agent_id="a1", label="RECEPTION"))
check("releasing one PC takes only it off; the rules stay for the other",
      [x["address"] for x in r.state[ADDR] if x.get("list") == I.LIST]
      == ["192.168.88.99"] and "mikromon:edr:block" in r.comments())
push(r, I.release_plan("Shop-1", r, agent_id="a2", label="ACCOUNTS"))
check("releasing the last one leaves the router exactly as it was found",
      r.state[FILTER] == START[FILTER] and r.state[ADDR] == START[ADDR])
check("releasing a PC that is not isolated sends nothing",
      I.release_plan("Shop-1", r, agent_id="a1", label="RECEPTION").empty)

print("odd states:")
r = Router(START)
r.fail_on = "drop everything else"
try:
    push(r, I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1",
                           label="RECEPTION", hub_host="easymikrotik.com"))
    check("a failure part-way raises", False)
except PushError:
    check("a failure part-way is undone, leaving the router as it was",
          r.state[FILTER] == START[FILTER] and r.state[ADDR] == START[ADDR])
r = Router(START)
r.state[FILTER].insert(2, {".id": "*9", "chain": "forward",
                           "comment": "mikromon:edr:hub", "action": "accept"})
push(r, I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="R",
                       hub_host="easymikrotik.com"))
check("with the accept already there, the drop goes straight after it",
      r.comments()[1:4] == ["fasttrack", "mikromon:edr:hub",
                            "mikromon:edr:block"])
r = Router(START)
push(r, I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="R"))
check("without EasyMikroTik's address, only the drop is added",
      "mikromon:edr:hub" not in r.comments()
      and r.comments()[1] == "mikromon:edr:block")
for x in r.state[FILTER]:
    if x.get("comment") == "mikromon:edr:block":
        x["disabled"] = "true"
fix = I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="R")
check("a drop rule someone switched off is switched back on",
      [(o.action, o.params.get("disabled")) for o in fix.ops] == [("set", "no")])
r = Router({FILTER: [], ADDR: []})
push(r, I.isolate_plan("Shop-1", r, ip=PC_IP, agent_id="a1", label="R",
                       hub_host="em.test"))
check("on a router with no filter rules at all, they are added in order",
      r.comments() == ["mikromon:edr:hub", "mikromon:edr:block"])
r = Router(START)
check("an address on the router's own network is recognised",
      I.on_router_network(r, PC_IP) is True)
check("one that is not is caught -- usually the wrong router",
      I.on_router_network(r, "10.20.0.5") is False)
r.state["addr_fail"] = True
check("unreadable addresses are reported as unknown, not as a no",
      I.on_router_network(r, PC_IP) is None)
r = Router(START)
real_execute = r.execute
calls = []


def flaky(op):
    calls.append(op.params.get(".id"))
    if "," in str(op.params.get(".id")):
        raise PushError("no such item")   # one ended while this ran
    return real_execute(op)


r.execute = flaky
check("when a connection ends on its own meanwhile, the rest are still "
      "cleared one by one", I.clear_connections(r, PC_IP) == 2
      and calls == ["*30,*31", "*30", "*31"])

print("the support team's pages:")
tmp = tempfile.mkdtemp()
DEF = dict(DEFAULT_THRESHOLDS)
mdb, sfile, adb, ddb, pdb = (os.path.join(tmp, x) for x in
                             ("m.db", "s.json", "a.db", "d.db", "p.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
auth.signup("boss@platform.test", "secret123", "Platform")
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha IT")
beta = auth.signup("owner@beta.test", "secret123", "Beta Shop")
auth.add_member(alpha, "tech@alpha.test", "secret123", role="member",
                devices="*")
auth.set_setting("public_base_url", "https://em.test")
ds = DevicesStore(ddb)
ds.upsert({"name": "Shop-1", "host": "10.10.0.5"}, DEF, org_id=alpha)
ds.upsert({"name": "Beta-Till", "host": "10.10.0.6"}, DEF, org_id=beta)
ds.close()
store = edr.EdrStore(edr.edr_path(ddb))
store.record(alpha, edr.parse_event({
    "agent_id": "a1", "hostname": "RECEPTION-PC", "local_ip": PC_IP,
    "mac": "AA:BB:CC:DD:EE:01", "event_type": "FILE_QUARANTINED",
    "severity": "HIGH", "reason": "Known malware hash (X)"}))

ROUTER = Router(START)


class FakeDev:
    def connect(self):
        pass

    def close(self):
        pass


class FakePushApi:
    def __init__(self, dev):
        pass

    def connect(self):
        return self

    def fetch(self, path):
        return ROUTER.fetch(path)

    def execute(self, op):
        return ROUTER.execute(op)


real_rw, real_api = P.rw_device, PA.PushApi
P.rw_device = lambda cfg: FakeDev()
PA.PushApi = FakePushApi
saved_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: None
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, push_log_db=pdb, admin_2fa=False,
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noc@platform.test")))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def login(email):
    o = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req(o, "/login", {"email": email, "password": "secret123"})
    return o


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    boss = login("boss@platform.test")
    _, page = req(boss, "/superadmin/antivirus")
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("each PC on the Antivirus page has an Isolate button",
          "/superadmin/antivirus/isolate?org=" in page and "Isolate&hellip;"
          in page)
    st, page = req(boss, f"/superadmin/antivirus/isolate?org={alpha}&agent=a1")
    check("it asks which router, offering only the company's own -- the "
          "only one already chosen", st == 200 and "Shop-1" in page
          and "Beta-Till" not in page and 'value="Shop-1" selected' in page)
    check("...with the PC's last address filled in, and what isolating "
          "cannot do", f'value="{PC_IP}"' in page
          and "own switch or Wi-Fi" in page)
    form = {"csrf": token, "org": alpha, "agent": "a1", "ip": PC_IP,
            "device": "Shop-1", "step": "preview"}
    st, page = req(boss, "/superadmin/antivirus/isolate", form)
    check("the preview shows exactly what will be sent, and sends nothing",
          st == 200 and "mikromon-isolated" in page
          and "Nothing has been sent" in page
          and ROUTER.state[FILTER] == START[FILTER])
    check("...including the connections it will clear",
          "the 2 connections it has open now are cleared" in page)
    check("...and nothing is flagged: the PC is on the router's network",
          "would change nothing" not in page)
    st, page = req(boss, "/superadmin/antivirus/isolate",
                   {**form, "ip": "10.20.0.5"})
    check("an address not on the router's networks is flagged before "
          "anything is sent", "would change nothing" in page)
    st, page = req(boss, "/superadmin/antivirus/isolate",
                   {**form, "device": "Beta-Till"})
    check("another company's router is refused",
          "Choose one of the company" in page
          and ROUTER.state[FILTER] == START[FILTER])
    st, page = req(boss, "/superadmin/antivirus/isolate",
                   {**form, "ip": "not-an-ip"})
    check("a bad address is refused, saying why",
          "not an IPv4 address" in page)
    st, page = req(boss, "/superadmin/antivirus/isolate",
                   {**form, "step": "apply"})
    check("confirming isolates it on the router",
          st == 200 and "RECEPTION-PC is cut off the network at Shop-1" in page
          and "mikromon:edr:block" in ROUTER.comments())
    check("...clears its open connections",
          [c[".id"] for c in ROUTER.state[CONN]] == ["*32", "*33"])
    check("...lets it keep reporting to this server",
          any(x.get("address") == "em.test" for x in ROUTER.state[ADDR]))
    check("...and the page says so, with a Release button",
          "Isolated</span>" in page and "on Shop-1 since" in page
          and "/superadmin/antivirus/release" in page)
    log = AuditLog(pdb).recent(device="Shop-1")
    check("the router's activity log records the preview and the change",
          [x["mode"] for x in log if x["feature"] == "isolate"][:2]
          == ["apply", "dry-run"])
    owner = login("owner@alpha.test")
    st, page = req(owner, "/antivirus")
    check("the company's owner sees it isolated on their own Antivirus page",
          st == 200 and "RECEPTION-PC" in page and "Isolated" in page
          and "/superadmin/antivirus/release" not in page)
    _, dash = req(owner, "/dashboard")
    check("...which is in their sidebar, now their company uses the agent",
          'href="/antivirus"' in dash)
    member = login("tech@alpha.test")
    check("a member does not get the page", req(member, "/antivirus")[0] == 403)
    beta_owner = login("owner@beta.test")
    st, page = req(beta_owner, "/antivirus")
    _, dash = req(beta_owner, "/dashboard")
    check("another company's owner sees none of Alpha's PCs, and no link",
          "RECEPTION-PC" not in page and 'href="/antivirus"' not in dash)
    otoken = re.search(r'name="csrf" value="([^"]+)"', dash).group(1)
    st, _ = req(owner, "/superadmin/antivirus/isolate",
                {**form, "csrf": otoken, "step": "apply"})
    check("only platform admins can isolate", st in (400, 403))
    st, page = req(boss, "/superadmin/antivirus/release",
                   {"csrf": token, "org": alpha, "agent": "a1"})
    check("Release lets it back on, and the router is as it was",
          "RECEPTION-PC can use the network again" in page
          and ROUTER.state[FILTER] == START[FILTER]
          and not [x for x in ROUTER.state[ADDR]
                   if str(x.get("comment", "")).startswith("mikromon:edr:")])
    check("...and it is no longer listed as isolated",
          store.isolations() == {})
    ROUTER.fail_on = "drop everything else"
    st, page = req(boss, "/superadmin/antivirus/isolate",
                   {**form, "step": "apply"})
    check("a failure on the router is reported, undone, and not recorded",
          "rolled back" in page and store.isolations() == {}
          and ROUTER.state[FILTER] == START[FILTER])
finally:
    srv.shutdown()
    srv.server_close()
    P.rw_device, PA.PushApi = real_rw, real_api
    org_email._smtp_send = saved_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ISOLATE TESTS PASSED")
