"""A WAN uplink on a static IP has to be detected and monitored like any
other, which it was not: with no DHCP client and no PPP session behind it,
every place that works out "which gateway belongs to this link" came back
empty, so the link showed no detected gateway on the WAN tab and was reported
permanently DOWN by the monitor while carrying traffic perfectly well.

The rule these tests pin down is that the gateway is READ BACK off the router,
never guessed from the subnet. Assuming the ISP sits on the first usable
address is right often enough to look fine in testing and wrong often enough
to blackhole a site.

Run:  ./.venv/Scripts/python.exe tests/static_wan_test.py
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.push.features import (_gateway_for_link, _static_gw_by_iface,
                                    _route_iface)
from mikromon.checks.wan import _matches_endpoint

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def link(iface, gw=""):
    return types.SimpleNamespace(interface=iface, gateway=gw)


# A site the ISP handed a /29 to: ether1 static, ether2 on DHCP as backup.
ADDRS = [
    {"interface": "ether1", "address": "41.72.140.34/29", "network": "41.72.140.32"},
    {"interface": "ether2", "address": "10.0.8.2/24", "network": "10.0.8.0",
     "dynamic": "true"},
    {"interface": "bridge", "address": "192.168.88.1/24", "network": "192.168.88.0"},
]
ROUTES = [
    {"dst-address": "0.0.0.0/0", "gateway": "41.72.140.33", "distance": "1",
     "active": "true", "gateway-status": "41.72.140.33 reachable"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.8.1", "distance": "2",
     "active": "true", "gateway-status": "10.0.8.1 reachable via ether2"},
]

print("\nWorking out the gateway of a statically-addressed uplink")

m = _static_gw_by_iface(ROUTES, ADDRS)
check("the static uplink's gateway is found even though its route never "
      "says 'via ether1' -- the gateway sits inside the subnet configured "
      "on that interface, so it is reachable through it and nowhere else",
      m.get("ether1") == "41.72.140.33")

check("...and it is the gateway the router actually has, not the first "
      "usable address of the subnet guessed at",
      "41.72.140.33" in m.values() and m.get("ether1") != "41.72.140.1")

check("a dynamic (DHCP/PPP-assigned) address is left to the branch that "
      "knows its gateway exactly, rather than being second-guessed here",
      "ether2" not in m)

check("a LAN interface with no default route through it is not mistaken "
      "for an uplink", "bridge" not in m)

print("\n_gateway_for_link end to end")

gw = _gateway_for_link(link("ether1"), {}, {}, None, None, m)
check("a static link now reports its gateway instead of nothing at all",
      gw == "41.72.140.33")

check("...and still reports nothing when there is genuinely no route to "
      "read it from, rather than inventing one",
      _gateway_for_link(link("ether9"), {}, {}, None, None, m) == "")

check("a gateway typed in by hand still wins over anything detected",
      _gateway_for_link(link("ether1", "1.2.3.4"), {}, {}, None, None, m)
      == "1.2.3.4")

check("DHCP still wins for a DHCP link, since its lease states the gateway "
      "exactly",
      _gateway_for_link(link("ether2"), {},
                        {"ether2": {"gateway": "10.0.8.1"}}, None, None, m)
      == "10.0.8.1")

# A DHCP client that exists but has not bound has no gateway to give. If the
# interface also carries a static address, that is better than nothing.
check("a DHCP client that is not bound falls through to the static address "
      "on the same interface instead of giving up",
      _gateway_for_link(link("ether1"), {}, {"ether1": {"gateway": ""}},
                        None, None, m) == "41.72.140.33")

print("\nRoutes mikromon wrote are not treated as evidence")

check("a failover route mikromon added is ignored, so one bad detection "
      "cannot feed itself back in and persist forever",
      _static_gw_by_iface(
          [{"dst-address": "0.0.0.0/0", "gateway": "41.72.140.99",
            "comment": "mikromon:failover:primary"}], ADDRS) == {})

print("\nThe monitor no longer calls a static uplink DOWN")

ep = link("ether1")
static_route = ROUTES[0]
check("before the fix this matched nothing and the link was reported DOWN; "
      "it now ties the route to the interface it leaves through",
      _matches_endpoint(static_route, ep, {}, ADDRS))

check("...without the address list it still cannot (which is exactly the "
      "bug that was reported)",
      not _matches_endpoint(static_route, ep, {}))

check("a route belonging to a different uplink is not claimed by this one",
      not _matches_endpoint(ROUTES[1], ep, {}, ADDRS))

check("a route whose gateway is an interface name rather than an IP does "
      "not raise", not _matches_endpoint(
          {"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1"}, ep, {}, ADDRS))

print("\nOdd shapes do not crash the poller")

check("a malformed address is skipped rather than taking the check down",
      _static_gw_by_iface(ROUTES, [{"interface": "ether1",
                                    "address": "not-an-ip"}]) == {})
check("empty inputs are fine", _static_gw_by_iface([], []) == {})
check("a route naming its interface directly is used as-is",
      _route_iface({"gateway-status": "41.72.140.33 reachable via ether1"})
      == "ether1")
check("...as is RouterOS's own <ip>%<iface> form",
      _route_iface({"immediate-gw": "41.72.140.33%ether1"}) == "ether1")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL STATIC WAN TESTS PASSED")
