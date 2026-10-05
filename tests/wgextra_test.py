"""Extra WireGuard: a second tunnel (e.g. AdGuard VPN) beside the management one.

Offline, against a fake router that already has what a real site has: the
management tunnel, a LAN, a WAN and a default route. The point of these
checks is the ways this could take a site down or leak the private key.

Run:  ./.venv/Scripts/python.exe tests/wgextra_test.py
"""
from __future__ import annotations

import base64
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.push import FEATURES, Pusher, TAB_SLUGS
from mikromon.push import wgextra as W
from mikromon.push.api import PlanRefused, PushError

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeApi:
    """Records executed ops and mutates an in-memory router state."""

    def __init__(self, state):
        self.state = state
        self.executed = []
        self._n = 100

    def fetch(self, path):
        return [dict(r) for r in self.state.get(tuple(path), [])]

    def execute(self, op):
        self.executed.append(op)
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self._n += 1
            nid = f"*{self._n}"
            row = {k: v for k, v in op.params.items() if k != "place-before"}
            row[".id"] = nid
            rows.append(row)
            return nid
        if op.action == "remove":
            self.state[tuple(op.path)] = [
                r for r in rows if r.get(".id") != op.params[".id"]]
            return None
        if op.action == "set":
            for r in rows:
                if r.get(".id") == op.params.get(".id"):
                    r.update({k: v for k, v in op.params.items() if k != ".id"})
            return None
        raise PushError("unsupported in fake")


class Cfg:
    name = "Site1"


class Audit:
    def __init__(self):
        self.rows = []

    def append(self, *args):
        self.rows.append(args)


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode()


PRIV = key(7)
PUB = key(9)
HUB = "102.36.140.219"
VPN_IP = "185.1.1.1"


def router():
    return {
        ("system", "resource"): [{"version": "7.14.3"}],
        ("interface",): [{"name": "ether1"}, {"name": "bridge"},
                         {"name": "mikromon"}],
        ("interface", "wireguard"): [
            {".id": "*1", "name": "mikromon", "listen-port": "13231",
             "comment": "mikromon:tunnel:if", "public-key": "HUBSIDE="}],
        ("interface", "wireguard", "peers"): [
            {".id": "*2", "interface": "mikromon", "public-key": key(1),
             "endpoint-address": HUB, "endpoint-port": "51820",
             "allowed-address": "10.10.0.0/16",
             "persistent-keepalive": "25s", "comment": "mikromon:tunnel:hub"}],
        ("ip", "address"): [
            {".id": "*3", "address": "10.10.4.7/16", "interface": "mikromon",
             "comment": "mikromon:tunnel:addr"},
            {".id": "*4", "address": "192.168.88.1/24", "interface": "bridge"},
            {".id": "*5", "address": "41.1.1.10/24", "interface": "ether1"}],
        ("ip", "route"): [
            {".id": "*6", "dst-address": "0.0.0.0/0", "gateway": "41.1.1.1"},
            {".id": "*7", "dst-address": "192.168.88.0/24",
             "gateway": "bridge", "dynamic": "true"}],
        ("ip", "firewall", "filter"): [
            {".id": "*a", "chain": "forward",
             "action": "passthrough", "dynamic": "true"},
            {".id": "*b", "chain": "input", "action": "accept",
             "connection-state": "established,related"}],
        ("ip", "firewall", "nat"): [
            {".id": "*c", "chain": "srcnat", "action": "masquerade",
             "out-interface-list": "WAN"}],
    }


def fake_resolve(host):
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        return {ipaddress.ip_address(VPN_IP)} if "adguard" in host else set()


W.resolve = fake_resolve


def new_flat(**over):
    flat = {"c0_name": "adguard", "c0_private_key": PRIV,
            "c0_address": "172.16.0.2/32", "c0_public_key": PUB,
            "c0_allowed": "94.140.14.14/32, 94.140.15.15/32",
            "c0_endpoint": "vpn.adguard.example:51820", "c0_keepalive": "25"}
    flat.update(over)
    return flat


def plan(api, flat):
    return W.wgextra_plan(Pusher(Cfg(), api), Cfg(), flat, {})


def refused(api, flat):
    try:
        plan(api, flat)
    except PlanRefused as exc:
        return str(exc)
    return ""


def all_text(p):
    out = [p.diff_text(), p.summary]
    for op in p.ops:
        out.append(op.desc)
        if op.inverse is not None:
            out.append(op.inverse.desc)
    return "\n".join(out)


print("registered as a Maintenance tab:")
check("the feature exists and writes", FEATURES["wgextra"]["write"] is True)
check("...with a tab label", TAB_SLUGS.get("Extra WireGuard") == "wgextra")

print("creating a connection:")
api = FakeApi(router())
p = plan(api, new_flat())
paths = [(op.action, op.path) for op in p.ops]
check("interface, address, peer, two drop rules, NAT, then two routes, in "
      "that order",
      paths == [("add", ("interface", "wireguard")),
                ("add", ("ip", "address")),
                ("add", ("interface", "wireguard", "peers")),
                ("add", ("ip", "firewall", "filter")),
                ("add", ("ip", "firewall", "filter")),
                ("add", ("ip", "firewall", "nat")),
                ("add", ("ip", "route")), ("add", ("ip", "route"))])
iface_op = p.ops[0]
check("the new interface listens next to the management one, not on it",
      iface_op.params["listen-port"] == "13232")
check("...and carries the private key to the router",
      iface_op.params["private-key"] == PRIV)
check("the private key is in no plan line, preview or undo text",
      PRIV not in all_text(p))
peer_op = p.ops[2]
check("the peer gets exactly what was typed, in RouterOS's own format",
      peer_op.params == {
          "interface": "adguard", "public-key": PUB,
          "endpoint-address": "vpn.adguard.example", "endpoint-port": "51820",
          "allowed-address": "94.140.14.14/32,94.140.15.15/32",
          "persistent-keepalive": "25s", "comment": "mikromon:wgx:adguard:peer"})
check("routes go to exactly the allowed addresses, via the new interface",
      sorted((o.params["dst-address"], o.params["gateway"])
             for o in p.ops if o.path == ("ip", "route"))
      == [("94.140.14.14/32", "adguard"), ("94.140.15.15/32", "adguard")])
fw = [o.params for o in p.ops if o.path == ("ip", "firewall", "filter")]
check("new connections from the tunnel are dropped, into the LAN and into "
      "the router",
      {(r["chain"], r["in-interface"], r["connection-state"], r["action"])
       for r in fw} == {("forward", "adguard", "new", "drop"),
                        ("input", "adguard", "new", "drop")})
check("...placed above the first real rule, skipping the dynamic one",
      all(r.get("place-before") == "*b" for r in fw))
nat = next(o.params for o in p.ops if o.path == ("ip", "firewall", "nat"))
check("LAN traffic into the tunnel is masqueraded",
      nat["out-interface"] == "adguard" and nat["action"] == "masquerade")
hub_ids = {"*1", "*2", "*3"}
check("nothing touches the management tunnel's rows",
      not any(o.params.get(".id") in hub_ids for o in p.ops))

print("the push itself, then pushing again:")
audit = Audit()
Pusher(Cfg(), api, dry_run=False, audit=audit).apply(p, feature="wgextra")
check("applied", len(api.executed) == 8)
check("the private key is not in the activity log",
      not any(PRIV in str(a) for a in audit.rows))
current = W.read_router(api)
check("the router now shows one extra connection",
      [c["name"] for c in current["conns"]] == ["adguard"])
same = {"c0_existing": "adguard", "c0_address": "172.16.0.2/32",
        "c0_public_key": PUB,
        "c0_allowed": "94.140.14.14/32,94.140.15.15/32",
        "c0_endpoint": "vpn.adguard.example:51820", "c0_keepalive": "25",
        "c0_action": "keep"}
check("previewing it unchanged changes nothing -- a blank key box keeps the "
      "router's key", plan(api, same).empty)

print("the tab itself:")
fields = W.wgextra_form(current, Cfg())
secrets = [f for f in fields if f["type"] == "secret"]
check("one private-key box per connection plus the add block, never "
      "pre-filled", len(secrets) == 2
      and not any(f.get("value") for f in secrets))
check("the existing connection is carried by name",
      any(f["type"] == "hidden" and f["value"] == "adguard" for f in fields))
check("its values are shown for editing",
      any(f.get("value") == "94.140.14.14/32,94.140.15.15/32"
          for f in fields))
lines = W.wgextra_summary(current, Cfg())
check("the summary says there is no handshake yet",
      len(lines) == 1 and "no handshake yet" in lines[0])
untouched = {"c1_name": "", "c1_keepalive": "25"}
check("an untouched add block (keepalive pre-filled) is not a new "
      "connection", plan(api, {**same, **untouched}).empty)

print("editing it:")
p = plan(api, {**same, "c0_allowed": "94.140.14.14/32"})
check("dropping an allowed address updates the peer and removes its route",
      [(o.action, o.path) for o in p.ops] ==
      [("set", ("interface", "wireguard", "peers")),
       ("remove", ("ip", "route"))])
p = plan(api, {**same, "c0_private_key": key(8)})
check("pasting a new key replaces it, without writing it anywhere readable",
      len(p.ops) == 1 and p.ops[0].params.get("private-key") == key(8)
      and key(8) not in all_text(p))

print("a second connection:")
second = {**same, "c1_name": "office", "c1_private_key": key(11),
          "c1_address": "172.20.0.2/32", "c1_public_key": key(12),
          "c1_allowed": "203.0.113.0/24", "c1_endpoint": "198.51.100.7",
          "c1_keepalive": ""}
p = plan(api, second)
check("gets the next free listen port and the default endpoint port",
      p.ops[0].params["listen-port"] == "13233"
      and p.ops[2].params["endpoint-port"] == "51820"
      and p.ops[2].params["persistent-keepalive"] == "25s")
msg = refused(api, {**second, "c1_allowed": "94.140.14.0/24"})
check("cannot claim addresses the first one already carries",
      "already goes through adguard" in msg)

print("refused before anything is sent:")
fresh = FakeApi(router())
cases = [
    ("0.0.0.0/0 (would take the management tunnel with it)",
     {"c0_allowed": "0.0.0.0/0"}, "0.0.0.0/0"),
    ("a range covering our management server",
     {"c0_allowed": "102.36.140.0/24"}, "management server"),
    ("a range covering the router's internet gateway",
     {"c0_allowed": "41.1.0.0/16"}, "internet gateway"),
    ("a range overlapping the LAN",
     {"c0_allowed": "192.168.0.0/16"}, "would be cut off"),
    ("a range overlapping the management tunnel's pool",
     {"c0_allowed": "10.0.0.0/8"}, "management tunnel"),
    ("a range covering the VPN server itself (a routing loop)",
     {"c0_allowed": "185.1.1.0/24"}, "never connect"),
    ("an address that overlaps the LAN",
     {"c0_address": "192.168.88.50/24"}, "overlaps 192.168.88.0/24"),
    ("an address inside the management pool",
     {"c0_address": "10.10.9.9/32"}, "management tunnel"),
    ("IPv6 in Allowed IPs", {"c0_allowed": "::/0"}, "IPv6"),
    ("a name another interface already has",
     {"c0_name": "ether1"}, "already exists"),
    ("the management tunnel's own name",
     {"c0_name": "mikromon"}, "already exists"),
    ("a missing endpoint", {"c0_endpoint": ""}, "endpoint is missing"),
]
for label, over, expect in cases:
    msg = refused(fresh, new_flat(**over))
    check(f"{label}", msg.startswith("Nothing was sent to the router.")
          and expect in msg)
check("...and none of those sent anything", fresh.executed == [])
bad = "not-a-real-key-but-secret-looking-0123456789="
msg = refused(fresh, new_flat(c0_private_key=bad))
check("a malformed private key is refused without quoting it back",
      "not a WireGuard key" in msg and bad not in msg)
taken = FakeApi(router())
taken.state[("ip", "route")].append(
    {".id": "*9", "dst-address": "94.140.14.14/32", "gateway": "41.1.1.1"})
check("an address already routed by a hand-made route",
      "already routed via 41.1.1.1" in refused(taken, new_flat()))
check("adding a connection that already exists",
      "already exists" in refused(api, {**same, "c1_name": "adguard",
                                        "c1_private_key": PRIV,
                                        "c1_address": "172.16.0.9/32",
                                        "c1_public_key": PUB,
                                        "c1_allowed": "1.1.1.1/32",
                                        "c1_endpoint": "1.2.3.4"}))
old = FakeApi(router())
old.state[("system", "resource")] = [{"version": "6.49.8"}]
check("a RouterOS 6 router, which has no WireGuard",
      "7.1 or later" in refused(old, new_flat()))
check("...and its tab says so instead of offering a form",
      W.wgextra_form(W.read_router(old), Cfg())[0]["type"] == "static")

print("removing it:")
p = plan(api, {**same, "c0_action": "remove"})
check("routes, NAT, firewall, peer, address, then the interface",
      [o.path for o in p.ops] ==
      [("ip", "route"), ("ip", "route"), ("ip", "firewall", "nat"),
       ("ip", "firewall", "filter"), ("ip", "firewall", "filter"),
       ("interface", "wireguard", "peers"), ("ip", "address"),
       ("interface", "wireguard")])
check("the removed interface could be restored with its key on rollback",
      p.ops[-1].inverse.params.get("private-key") == PRIV
      and PRIV not in all_text(p))
Pusher(Cfg(), api, dry_run=False).apply(p, feature="wgextra")
left = [r for rows in api.state.values() for r in rows
        if str(r.get("comment", "")).startswith(W.TAG)]
check("nothing of it is left on the router", left == [])
check("the management tunnel is exactly as it was",
      api.state[("interface", "wireguard")] == router()[("interface",
                                                         "wireguard")]
      and api.state[("interface", "wireguard", "peers")]
      == router()[("interface", "wireguard", "peers")])

print("the web side:")
import mikromon.web as web
from mikromon import guide_tabs

check("listed under Maintenance", ("Extra WireGuard", "wgextra")
      in web._MAINT_ITEMS and web._LIVE_TABS["Extra WireGuard"] == "wgextra")
check("previewed before it is applied, never on a flick of a switch",
      "wgextra" in web._INSTANT_TOGGLE_OFF)
check("has a guide entry for its '?'", "wgextra" in guide_tabs.BY_SLUG)
html = web._field_html({"type": "secret", "name": "k", "label": "Key",
                        "value": PRIV})
check("a secret box is a password field and never echoes a value",
      'type="password"' in html and PRIV not in html)
box = web._friendly_push_error("Nothing was sent to the router.\nfirst\n"
                               "second <b>")
check("a refusal reads as a list of reasons, not 'could not reach the "
      "router'", "<li>first</li>" in box and "&lt;b&gt;" in box
      and "reach" not in box)

print()
if FAILS:
    print(f"{len(FAILS)} FAILED")
    sys.exit(1)
print("all passed")
