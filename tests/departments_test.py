"""One company, several networks, each filtered differently.

Sales needs Facebook and Instagram because that is where the customers are.
Support does not, but wants YouTube for the guides. Accounts wants neither,
and would rather nobody could reach the accounts machines from the guest
Wi-Fi at all.

The network half is ordinary RouterOS and most of this file is about getting
it wrong safely: two departments on one VLAN, overlapping ranges, a public
range typed into a LAN field. Every one of those fails intermittently rather
than obviously, which is the expensive way for a network to be broken.

The filtering half runs into a wall worth restating, because it is why the
design looks like this: RouterOS's DNS client speaks DoH and nothing else,
and use-doh-server is a SINGLE GLOBAL SETTING. The router can only ever be
on one NextDNS profile. So departments do not use the router's resolver --
each VLAN's DHCP hands out its own profile's addresses and clients talk to
NextDNS directly.

Which leaves exactly one thing this module must not do: guess what those
addresses are. It asks for them, because NextDNS publishes each profile's
own endpoints on that profile's setup page and the form they take is
NextDNS's business, not an assumption to bake in here.

Run:  python tests/departments_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import departments as D

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def refuses(fn, *a, **kw):
    """(was it refused, the reason given)."""
    try:
        fn(*a, **kw)
        return False, ""
    except D.DepartmentError as exc:
        return True, str(exc)


print("A department, described")

sales = D.make("Sales", 20, "10.20.20.0/24", "abc123",
               "2a07:a8c0::ab:cd, 2a07:a8c1::ab:cd")
check("the range is taken as given and its gateway derived, so nobody has "
      "to type the same network twice and get it different the second time",
      sales["subnet"] == "10.20.20.0/24" and sales["gateway"] == "10.20.20.1")
check("...with a DHCP pool that starts AFTER the gateway, or the router "
      "hands its own address to a laptop",
      sales["pool_from"] == "10.20.20.2"
      and sales["pool_to"] == "10.20.20.254")
check("...and a RouterOS-safe name, since a space in an interface name is a "
      "syntax error rather than a cosmetic problem",
      sales["slug"] == "sales" and D.slug("Front Desk / Reception")
      == "front-desk-reception")
check("the resolvers are kept as given, in order",
      sales["resolvers"] == ["2a07:a8c0::ab:cd", "2a07:a8c1::ab:cd"])

print("\nWhat it refuses, and whether it says why")

bad, why = refuses(D.make, "Sales", 20, "8.8.8.0/24")
check("a PUBLIC range as a department LAN is refused -- that is handing a "
      "company addresses somebody else owns and watching half the internet "
      "stop working from that VLAN",
      bad and "public" in why.lower())

bad, why = refuses(D.make, "Sales", 1, "10.20.20.0/24")
check("VLAN 1 is refused: it is the untagged VLAN on nearly every switch, "
      "so a department put on it leaks onto the trunk",
      bad and "untagged" in why)

bad, why = refuses(D.make, "Sales", 4095, "10.20.20.0/24")
check("...and 4095, which is reserved", bad)

bad, why = refuses(D.make, "Sales", 20, "10.20.20.0/31")
check("a range with no room for clients is refused before it becomes a "
      "DHCP server that hands out nothing", bad and "no room" in why)

bad, why = refuses(D.make, "Sales", 20, "not-an-ip")
check("a typo in the range is refused with an example of the right shape, "
      "rather than a stack trace",
      bad and "10.20.10.0/24" in why)

bad, why = refuses(D.make, "", 20, "10.20.20.0/24")
check("an unnamed department is refused", bad)

bad, why = refuses(D.make, "Sales", 20, "10.20.20.0/24", "id", "8.8.8.8, nope")
check("a resolver that is not an address is refused, and says where the "
      "real ones come from",
      bad and "NextDNS setup page" in why)

print("\nClashes between departments, which is where the real faults are")

support = D.make("Support", 30, "10.20.30.0/24", "def456", "2a07:a8c0::ef:01")
accounts = D.make("Accounts", 40, "10.20.40.0/24")
check("three properly separate departments have no problems",
      D.check_set([sales, support, accounts]) == [])

same_vlan = D.make("Marketing", 20, "10.20.50.0/24")
probs = D.check_set([sales, same_vlan])
check("two departments on one VLAN are caught, because two departments on "
      "one VLAN are one department",
      any("VLAN 20" in p for p in probs))

overlap = D.make("Marketing", 50, "10.20.20.128/25")
probs = D.check_set([sales, overlap])
check("an overlapping range is caught -- it routes unpredictably and fails "
      "in a way that looks intermittent",
      any("overlaps" in p for p in probs))

dupe = D.make("sales", 60, "10.20.60.0/24")
check("...as is the same name twice, whatever the capitals",
      any("two departments called" in p.lower()
          for p in D.check_set([sales, dupe])))

print("\nThe department that will not actually be filtered")

# This is the one that matters. RouterOS can only hold ONE NextDNS profile,
# so a department without its own resolver addresses silently inherits
# everyone else's filtering -- Sales and Support blocking exactly the same
# things, which is the opposite of the point.
todo = D.unfinished([sales, support, accounts])
check("a department with no resolvers is reported as unfinished",
      [t["name"] for t in todo] == ["Accounts"])
check("...saying plainly that it gets everyone else's filtering, rather "
      "than leaving somebody to discover it",
      "same filtering as everyone else" in todo[0]["why"])
check("...and where the addresses come from",
      "setup page" in todo[0]["why"])
check("departments that ARE set up are not nagged about",
      D.unfinished([sales, support]) == [])

print("\nWhat it does to the router")

plan = D.build_plan("My IT Office", [sales, support, accounts])
text = plan.diff_text()
check("every department gets its own VLAN interface",
      all(f"VLAN {d['vlan']}" in text for d in (sales, support, accounts)))
check("...its own gateway address", "10.20.20.1/24" in text)
check("...and its own DHCP pool", "10.20.20.2-10.20.20.254" in text)

check("a department WITH resolvers has them pushed as its DHCP dns-server, "
      "which is the whole mechanism: its clients go to ITS NextDNS profile "
      "rather than to the router's single global one",
      "10.20.20.0/24 -> DNS 2a07:a8c0::ab:cd" in text)
check("a department WITHOUT them is pushed with no dns-server at all, not a "
      "wrong one, and the plan says so where somebody reading it will see",
      "NOT filtered separately" in text)

check("the departments are walled off from each other",
      "drop department-to-department" in text)
check("...with established/related accepted FIRST, or the replies to "
      "allowed traffic get dropped and everything looks broken",
      text.index("established/related") < text.index("drop department-to"))
check("...and each still reaching its own gateway, or DHCP and DNS to the "
      "router stop working",
      all(f"{d['name']} may reach its own gateway" in text
          for d in (sales, support, accounts)))
check("the internet is deliberately NOT blocked: the drop matches only "
      "department-to-department",
      "the internet is untouched" in text)

check("the summary says how many are really filtered, which is not the same "
      "as how many exist", "3 department(s), 2 with their own DNS" in
      plan.summary)

print("\nAnd it refuses to half-apply a broken set")

bad, why = refuses(D.build_plan, "R1", [sales, overlap])
check("a clashing set produces NO plan at all -- half-applying overlapping "
      "subnets fails intermittently, which is the most expensive way for a "
      "network to be wrong", bad and "overlaps" in why)

check("one department needs no isolation rules, because there is nothing to "
      "isolate it from",
      "drop department-to-department" not in
      D.build_plan("R1", [sales]).diff_text())
check("no departments is an empty plan rather than an error",
      D.build_plan("R1", []).empty)

print("\nPorts, which is how a laptop ends up on the right network")

with_ports = D.make("Sales", 20, "10.20.20.0/24", ports="ether3, ether4")
check("ports are taken as a list, however they were typed",
      with_ports["ports"] == ["ether3", "ether4"])
check("a department with no ports is allowed -- a trunk to a managed switch "
      "is a perfectly good way to run one",
      D.make("Sales", 20, "10.20.20.0/24")["ports"] == [])

bad, why = refuses(D.make, "Sales", 20, "10.20.20.0/24", ports="ether 3!")
check("a name that is not an interface is refused, with the router's own "
      "naming as the example", bad and "ether3" in why)

clash = D.make("Support", 30, "10.20.30.0/24", ports="ether4")
check("two departments cannot claim the same port, because a cable goes to "
      "one place",
      any("both claim ether4" in p for p in D.check_set([with_ports, clash])))

text = D.build_plan("R1", [with_ports, D.make("Support", 30,
                                              "10.20.30.0/24",
                                              ports="ether5")]).diff_text()
check("each port is stamped with its department's VLAN, so a device that "
      "knows nothing about VLANs still lands on the right network",
      "ether3 -> VLAN 20 (Sales), untagged" in text)
check("...and the bridge is TAGGED on every department VLAN, since the "
      "router is the gateway for all of them",
      "bridge VLAN 20: tagged bridge, untagged ether3, ether4" in text)
check("a department with no ports says so rather than looking configured",
      "no ports yet -- trunk only" in
      D.build_plan("R1", [D.make("Sales", 20, "10.20.20.0/24"),
                          D.make("Support", 30, "10.20.30.0/24",
                                 ports="e5")]).diff_text())
check("vlan-filtering is NOT switched on by the same push that creates the "
      "VLANs -- that is the moment a mis-tagged trunk stops passing traffic, "
      "and doing it unattended is how somebody loses the link they are "
      "managing the router over",
      "vlan-filtering" not in text)

print("\nWhen a second NextDNS profile is worth having")

one = [D.make("Main", 20, "10.20.20.0/24")]
two = [D.make("Sales", 20, "10.20.20.0/24", "p1", "2a07:a8c0::1"),
       D.make("Support", 30, "10.20.30.0/24")]
check("a single department needs no profile of its own: the router's own "
      "one already filters all of it, and a second would be an account to "
      "maintain and a bill to pay in exchange for nothing",
      D.needs_own_profiles(one) is False and D.profiles_to_create(one) == [])
check("...and none is proposed for it however long it stays that way",
      D.profiles_to_create(one) == [])
check("the moment there is a SECOND department that stops being true, "
      "because the whole point of the second one is different filtering",
      D.needs_own_profiles(two) is True)
check("...and only the ones actually missing a profile are named",
      D.profiles_to_create(two) == ["Support"])
check("no departments at all needs nothing",
      D.needs_own_profiles([]) is False)

print("\nThe tab somebody actually uses")

from mikromon.web import _departments_box  # noqa: E402

box = _departments_box("R1", "tok", two, ports=["ether1", "ether2"],
                       problems=[], todo=D.unfinished(two),
                       plan_text=D.build_plan("R1", two).diff_text())
check("every department is listed with its VLAN and range",
      "Sales" in box and "10.20.30.0/24" in box)
check("...and the profile links straight to its NextDNS setup page, which "
      "is where the resolver addresses have to be copied from",
      "my.nextdns.io/p1/setup" in box)
check("a department with no DNS of its own is flagged in the page, not just "
      "in a log", "not filtered separately" in box)
check("the plan is shown BEFORE the form, so nobody fills in a sixth "
      "department without reading that two of them clash",
      box.index("What the router would be told") < box.index("Add a department"))
check("the port picker offers the router's real interface names",
      "ether1" in box and "datalist" in box)
check("the RouterOS limit is explained where the decision is made, rather "
      "than left for somebody to rediscover",
      "only hold ONE DNS-over-HTTPS profile" in box)

box = _departments_box("R1", "tok", [], ports=[])
check("a router with no departments says what that means rather than "
      "showing an empty table",
      "shares one network and one NextDNS profile" in box)

box = _departments_box("R1", "tok", two, problems=["Sales and Support are "
                                                   "both on VLAN 20."])
check("a clash is shown loudly, and no plan is offered beside it",
      "both on VLAN 20" in box
      and "What the router would be told" not in box)

print("\nThrough a real server, because rendering is not serving")

# The tab drew correctly in isolation and did nothing whatsoever in the
# browser. Two separate reasons, neither visible from calling the function
# that builds the page: a tab has to be registered in FEATURES to be
# dispatched, and a device POST has to be on the _DEVICE_WRITE whitelist or
# it is simply a 404. So this asks the server.
import html as _html  # noqa: E402
import http.cookiejar  # noqa: E402
import json  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402

from mikromon import web as _web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.push import FEATURES as _FEATURES  # noqa: E402

check("the tab is registered, or the device page never dispatches it and "
      "clicking Departments does nothing at all",
      "departments" in _FEATURES)

_d = tempfile.mkdtemp()
_adb = os.path.join(_d, "auth.db")
_wdb = os.path.join(_d, "dev.db")
_sfile = os.path.join(_d, "state.json")
_a = AuthStore(_adb)
_org = _a.signup("o@x.test", "a-password-for-the-test", "Acme")
_a.close()
_ds = DevicesStore(_wdb)
_ds.upsert({"name": "R1", "host": "10.10.0.2", "org_id": _org}, {})
_ds.close()
with open(_sfile, "w", encoding="utf-8") as _f:
    json.dump({"devices": {"R1": {"facts": {
        "interfaces": ["ether1", "ether2", "ether3", "ether4"]}}}}, _f)

_PORT = 8813
threading.Thread(target=_web.serve, kwargs=dict(
    metrics_db=os.path.join(_d, "m.db"), state_file=_sfile, auth_db=_adb,
    devices_db=_wdb, host="127.0.0.1", port=_PORT), daemon=True).start()
time.sleep(2.0)
_B = f"http://127.0.0.1:{_PORT}"
_cj = http.cookiejar.CookieJar()
_op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cj))
_op.open(urllib.request.Request(_B + "/login", data=urllib.parse.urlencode(
    {"email": "o@x.test", "password": "a-password-for-the-test"}).encode()),
    timeout=8)


def _tab():
    return _op.open(_B + "/device?name=R1&tab=departments",
                    timeout=10).read().decode("utf-8", "replace")


def _post(**kw):
    fields = {"csrf": _CSRF, "device": "R1", "action": "save"}
    fields.update(kw)
    try:
        r = _op.open(urllib.request.Request(
            _B + "/device/departments",
            data=urllib.parse.urlencode(fields).encode()), timeout=10)
        return getattr(r, "status", r.code)
    except urllib.error.HTTPError as exc:
        return exc.code


_page = _tab()
check("the tab actually SERVES, rather than drawing correctly in a test and "
      "doing nothing in the browser",
      "Add a department" in _page and "shares one network" in _page)
check("...offering the router's real port names from cached facts, with no "
      "connection to the router", "ether3" in _page)

_CSRF = _page.split('name="csrf" value="')[1].split('"')[0]

check("saving a department is accepted -- a device POST that is not on the "
      "write whitelist is a 404 however right the handler is",
      _post(name="Sales", vlan="20", subnet="10.20.20.0/24", ports="ether3",
            profile_id="p1", resolvers="2a07:a8c0::1") == 200)
check("...and a second one", _post(name="Support", vlan="30",
                                   subnet="10.20.30.0/24",
                                   ports="ether4") == 200)

_page = _html.unescape(_tab())
check("both appear on the tab afterwards",
      "Sales" in _page and "Support" in _page)
check("...with the plan showing each port stamped with its VLAN",
      "ether3 -> VLAN 20 (Sales)" in _page)
check("...the wall between departments",
      "drop department-to-department" in _page)
check("...and the one with no DNS of its own called out",
      "not filtered separately" in _page)

_post(name="Clashing", vlan="20", subnet="10.20.90.0/24")
_page = _tab()
check("a department clashing with one already saved is REFUSED rather than "
      "stored and left to break the push", "Clashing" not in _page)

_op.open(urllib.request.Request(_B + "/device/departments",
         data=urllib.parse.urlencode({"csrf": _CSRF, "device": "R1",
                                      "action": "delete",
                                      "name": "Support"}).encode()),
         timeout=10)
_page = _tab()
check("removing one takes its ROW off the tab and leaves the other -- "
      "checked by its delete form rather than by its name, which also "
      "appears in the tab's own explanation",
      'value="Support"' not in _page and 'value="Sales"' in _page)

print("\nAgainst what the router already has")

# check_set only compares departments with each other, which is half the
# question. The other half is everything that was on the router before
# anybody thought of departments: the office LAN on 192.168.88.0/24, a CCTV
# VLAN somebody made by hand two years ago, a routed port to another
# building. Pushing over any of those does not fail cleanly -- it half
# works, and a subnet that exists twice routes to whichever entry RouterOS
# matches first.

ROUTER = {
    "read": True, "error": "", "dhcp": [],
    "addresses": [
        {"address": "192.168.88.1/24", "interface": "bridge",
         "network": "192.168.88.0", "disabled": False, "comment": ""},
        {"address": "10.20.20.1/24", "interface": "vlan20-sales",
         "network": "10.20.20.0", "disabled": False,
         "comment": "mikromon: Sales gateway"},
        {"address": "172.16.5.1/30", "interface": "ether9",
         "network": "172.16.5.0", "disabled": False,
         "comment": "link to building B"}],
    "vlans": [
        {"name": "cctv", "vlan_id": "50", "interface": "bridge",
         "comment": "cameras - do not touch"},
        {"name": "vlan20-sales", "vlan_id": "20", "interface": "bridge",
         "comment": "mikromon: Sales"}],
    "ports": [
        {"interface": "ether2", "bridge": "bridge", "pvid": "1",
         "comment": ""},
        {"interface": "ether3", "bridge": "bridge", "pvid": "50",
         "comment": "camera nvr"},
        {"interface": "ether4", "bridge": "bridge", "pvid": "1",
         "comment": ""}],
}


def _against(dept):
    return D.check_against_router([dept], ROUTER)


check("a department on top of the existing office LAN is caught -- a range "
      "that exists twice routes to whichever entry RouterOS matches first, "
      "which is not a thing anybody can predict or debug",
      any("overlaps 192.168.88.0/24" in p for p in
          _against(D.make("Admin", 60, "192.168.88.0/24", ports="ether4"))))

check("a VLAN id somebody else already used is caught, and NAMED, so it is "
      "obvious what would have been trodden on",
      any("cctv" in p for p in
          _against(D.make("Admin", 50, "10.20.60.0/24", ports="ether4"))))

check("a port already carrying another VLAN is caught: moving it would take "
      "whatever is plugged into it off that network",
      any("already on VLAN 50" in p for p in
          _against(D.make("Admin", 60, "10.20.60.0/24", ports="ether3"))))

check("a port with an address directly on it is caught as routed rather "
      "than a bridge member -- claiming it would take that link down",
      any("routed port" in p for p in
          _against(D.make("Admin", 60, "10.20.60.0/24", ports="ether9"))))

check("a port on no bridge at all is caught, or the department gets a VLAN "
      "with nothing plugged into it",
      any("not a member of any bridge" in p for p in
          _against(D.make("Admin", 60, "10.20.60.0/24", ports="ether7"))))

check("a department that clashes with nothing passes",
      _against(D.make("Admin", 60, "10.20.60.0/24", ports="ether4")) == [])

# The one that would make the feature unusable if it were wrong.
check("re-pushing a department mikromon itself created is NOT a clash with "
      "its own last push -- otherwise the tab fills with conflicts the "
      "second time anybody opens it",
      _against(D.make("Sales", 20, "10.20.20.0/24", ports="ether2")) == [])

check("a disabled address is not treated as occupying its range",
      D.check_against_router(
          [D.make("Admin", 60, "10.9.9.0/24")],
          {"read": True, "addresses": [
              {"address": "10.9.9.1/24", "interface": "x", "disabled": True,
               "comment": ""}], "vlans": [], "ports": []}) == [])

check("a router that could not be read blocks nothing -- planning VLANs for "
      "a site that is down is a normal thing to be doing",
      D.check_against_router([D.make("Admin", 50, "192.168.88.0/24")],
                             {"read": False, "error": "unreachable"}) == [])

print("\nAnd the tab says which of those it is")

from mikromon.web import _existing_network_box  # noqa: E402

box = _existing_network_box(ROUTER)
check("every address the router has is shown, with the interface it is on",
      "192.168.88.1/24" in box and "ether9" in box)
check("...and every bridge port with the VLAN it currently carries, which "
      "is the answer to 'which port is free' and lives nowhere else",
      "ether3" in box and "VLAN 50" in box)
check("...and the VLANs that already exist", "cctv" in box)
check("anything mikromon put there is marked, so a second look does not "
      "read as a pile of conflicts with its own last push",
      box.count("mikromon") >= 2)

box = _existing_network_box({"read": False, "error": "connection refused"})
check("a router that could not be read says so plainly, and says the tab "
      "still works but cannot warn about clashes",
      "could not be read" in box and "connection refused" in box
      and "check before you push" in box)

# The live read is a convenience, and it must never be what makes the tab
# unusable. At the device's default sixty-second timeout an unreachable
# router hung the page for a minute -- which this test caught by timing out
# against a fake device on 10.10.0.2 that does not answer.
_t0 = time.monotonic()
_page = _tab()
_took = time.monotonic() - _t0
check("the tab still answers promptly when the router cannot be reached, "
      "because the address read is bounded -- at the default timeout an "
      "unreachable site hung this page for a minute",
      _took < 20 and "Add a department" in _page)
check("...and says the router could not be read, rather than silently "
      "showing no conflicts as though there were none",
      "could not be read" in _page)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DEPARTMENT TESTS PASSED")
