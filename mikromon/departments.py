"""Departments: one company, several networks, each filtered differently.

Sales needs Facebook and Instagram because that is where the customers are.
Support does not, but wants YouTube for the guides. Accounts wants neither
and would rather nobody could reach the accounts machines from the guest
Wi-Fi at all. That is three networks and three filtering policies inside one
company, on one router, behind one internet line.

Two halves, and only one of them is a router problem.

THE NETWORK half is ordinary RouterOS: a VLAN per department, an address on
it, a DHCP pool that serves it, and firewall rules so the departments cannot
reach each other. Well-trodden, and this module builds it.

THE FILTERING half runs into a wall that is worth stating plainly, because
it drives the whole design. RouterOS's DNS client speaks DoH and nothing
else, and `use-doh-server` is a SINGLE GLOBAL SETTING -- so the router
itself can only ever be on one NextDNS profile. Pointing three departments
at the router gets three departments one filtering policy.

So the departments do not use the router's resolver. Each VLAN's DHCP hands
out its OWN profile's resolver addresses, and clients talk to NextDNS
directly. Which raises the only question this module refuses to guess at:
what those addresses are.

It does not guess. NextDNS publishes each profile's own endpoints on that
profile's setup page, and this asks for them there -- so it works whatever
NextDNS offers now or changes to later, rather than encoding an assumption
of mine about IPv4 linked-IP or per-profile IPv6 that would rot silently.
A department without resolver addresses is not pushed as filtered; it is
reported as unfinished.
"""
from __future__ import annotations

import ipaddress
import logging
import re

log = logging.getLogger(__name__)

# VLAN 1 is the native/untagged VLAN on essentially every switch, and 4095 is
# reserved. Using either is a way to make a department's traffic quietly leak
# onto the trunk.
VLAN_MIN = 2
VLAN_MAX = 4094

# A department is a LAN. A public range here would mean handing a company
# addresses that belong to somebody else and watching half the internet stop
# working from that VLAN.
_PRIVATE_ONLY = True

_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,38}$")


class DepartmentError(ValueError):
    """A department that cannot be used, with the reason a person needs."""


def slug(name: str) -> str:
    """A RouterOS-safe identifier from a department name.

    Interface and pool names end up in the router's config, where a space or
    a slash is a syntax error rather than a cosmetic problem.
    """
    out = re.sub(r"[^A-Za-z0-9]+", "-", (name or "").strip().lower())
    return out.strip("-") or "dept"


def parse_subnet(text: str) -> ipaddress.IPv4Network:
    """The department's network, or a refusal saying which part is wrong."""
    raw = (text or "").strip()
    if not raw:
        raise DepartmentError("A department needs its own IP range, e.g. "
                              "10.20.10.0/24.")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise DepartmentError(
            f"{raw!r} is not an IP range: {exc}. It should look like "
            f"10.20.10.0/24.") from None
    if net.version != 4:
        raise DepartmentError("Use an IPv4 range for the department LAN, "
                              "e.g. 10.20.10.0/24.")
    if _PRIVATE_ONLY and not net.is_private:
        raise DepartmentError(
            f"{net} is a public range. A department LAN has to be private "
            f"(10.x, 172.16-31.x or 192.168.x), or the company loses access "
            f"to whoever really owns those addresses.")
    if net.prefixlen > 30:
        raise DepartmentError(
            f"{net} has no room for clients. Use /24 unless you have a "
            f"reason not to.")
    return net


def parse_vlan(value) -> int:
    try:
        vid = int(str(value).strip())
    except (TypeError, ValueError):
        raise DepartmentError(
            f"{value!r} is not a VLAN id. Use a number between "
            f"{VLAN_MIN} and {VLAN_MAX}.") from None
    if not VLAN_MIN <= vid <= VLAN_MAX:
        raise DepartmentError(
            f"VLAN {vid} is outside {VLAN_MIN}-{VLAN_MAX}. VLAN 1 is the "
            f"untagged VLAN on nearly every switch and 4095 is reserved, so "
            f"using either is how a department's traffic ends up on the "
            f"trunk.")
    return vid


def parse_resolvers(text: str) -> list:
    """The DNS servers this department's clients are handed.

    Taken as given rather than derived. NextDNS publishes each profile's own
    endpoints on that profile's setup page, and which form they take -- IPv4,
    IPv6, linked or not -- is NextDNS's business and has changed before.
    Encoding a guess here would rot silently; asking for the addresses does
    not.
    """
    out = []
    for part in re.split(r"[\s,;]+", (text or "").strip()):
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_address(part)))
        except ValueError:
            raise DepartmentError(
                f"{part!r} is not an IP address. Copy this department's "
                f"resolver addresses from its NextDNS setup page.") from None
    return out


def parse_ports(text) -> list:
    """Which physical ports belong to this department.

    A VLAN with no ports is a network nothing can plug into. It is allowed --
    a trunk to a managed switch is a perfectly good way to run one, and the
    tagging happens there instead -- so this validates the names and leaves
    the judgement to whoever knows the cabling.
    """
    if isinstance(text, (list, tuple)):
        parts = list(text)
    else:
        parts = re.split(r"[\s,;]+", str(text or "").strip())
    out = []
    for p in parts:
        p = str(p).strip()
        if not p:
            continue
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}$", p):
            raise DepartmentError(
                f"{p!r} is not an interface name. Use the router's own "
                f"names, like ether3 or sfp-sfpplus1.")
        if p not in out:
            out.append(p)
    return out


def make(name: str, vlan: int, subnet: str, profile_id: str = "",
         resolvers: str = "", note: str = "", ports=None) -> dict:
    """One validated department. Raises DepartmentError with the reason."""
    clean = (name or "").strip()
    if not _NAME_OK.match(clean):
        raise DepartmentError(
            "A department name should be a short, plain name like 'Sales' "
            "or 'Support' -- letters, numbers, spaces, dots and dashes.")
    net = parse_subnet(subnet)
    return {
        "name": clean,
        "slug": slug(clean),
        "vlan": parse_vlan(vlan),
        "subnet": str(net),
        "gateway": str(next(net.hosts())),
        "prefixlen": net.prefixlen,
        "pool_from": str(list(net.hosts())[1]) if net.num_addresses > 3 else "",
        "pool_to": str(list(net.hosts())[-1]),
        "profile_id": (profile_id or "").strip(),
        "resolvers": parse_resolvers(resolvers),
        "note": (note or "").strip(),
        "ports": parse_ports(ports),
    }


def check_set(departments: list) -> list:
    """Problems across a whole set: clashing VLANs, names or ranges.

    Checked together rather than one at a time because every fault here is a
    relationship. A subnet is only wrong because another department already
    has it, and the symptom of missing that is two networks that half work.
    """
    problems = []
    seen_vlan, seen_name, seen_port, nets = {}, {}, {}, []
    for d in departments:
        vid, name = d["vlan"], d["name"].lower()
        if vid in seen_vlan:
            problems.append(
                f"{d['name']} and {seen_vlan[vid]} are both on VLAN {vid}. "
                f"Two departments on one VLAN are one department.")
        seen_vlan[vid] = d["name"]
        if name in seen_name:
            problems.append(f"There are two departments called {d['name']}.")
        seen_name[name] = d["name"]

        for port in d.get("ports") or []:
            if port in seen_port:
                problems.append(
                    f"{d['name']} and {seen_port[port]} both claim {port}. "
                    f"A port belongs to one department, because a cable "
                    f"goes to one place.")
            seen_port[port] = d["name"]

        net = ipaddress.ip_network(d["subnet"])
        for other_name, other in nets:
            if net.overlaps(other):
                problems.append(
                    f"{d['name']} ({net}) overlaps {other_name} ({other}). "
                    f"Overlapping ranges route unpredictably and fail in a "
                    f"way that looks intermittent.")
        nets.append((d["name"], net))
    return problems


def unfinished(departments: list) -> list:
    """Departments that will not actually be filtered, and why.

    A department with no resolver addresses still gets its network -- the
    VLAN, the addressing, the isolation are all real and useful. What it does
    not get is its own filtering, and that is worth saying out loud rather
    than leaving somebody to discover that Sales and Support are blocking
    exactly the same things.
    """
    out = []
    for d in departments:
        if not d.get("resolvers"):
            out.append({
                "name": d["name"],
                "why": ("No DNS servers set, so this department uses "
                        "whatever the router hands out and gets the same "
                        "filtering as everyone else. Its NextDNS profile "
                        "publishes the addresses on its setup page."),
            })
    return out


# ---------------------------------------------------------------------------
# What this looks like on the router
# ---------------------------------------------------------------------------
# Built as a list of operations rather than applied directly, so the same
# code produces the preview somebody reads before agreeing to it and the
# change that is then made. A plan nobody can read before it runs is how a
# company loses its network to a typo in a VLAN id.

_LIST_ALLOWED = "dept-allowed"


def _op(action, path, params, desc):
    from .push.plan import Operation

    return Operation(action=action, path=path, params=params, desc=desc)


def _iface(dept: dict) -> str:
    return f"vlan{dept['vlan']}-{dept['slug']}"


def vlan_ops(dept: dict, bridge: str = "bridge") -> list:
    """The VLAN interface a department's traffic actually arrives on."""
    return [_op("add", ("interface", "vlan"),
                {"name": _iface(dept), "vlan-id": str(dept["vlan"]),
                 "interface": bridge, "comment": f"mikromon: {dept['name']}"},
                f"VLAN {dept['vlan']} for {dept['name']} on {bridge}")]


def address_ops(dept: dict) -> list:
    """The router's own address on that VLAN -- the department's gateway."""
    return [_op("add", ("ip", "address"),
                {"address": f"{dept['gateway']}/{dept['prefixlen']}",
                 "interface": _iface(dept),
                 "comment": f"mikromon: {dept['name']} gateway"},
                f"{dept['gateway']}/{dept['prefixlen']} on {_iface(dept)}")]


def dhcp_ops(dept: dict) -> list:
    """Pool, server and network for the department.

    The network's dns-server is the whole point of the exercise: it is what
    sends this department's clients to THEIR NextDNS profile instead of the
    router's single global one. A department with no resolvers gets no
    dns-server rather than a wrong one -- its clients then fall back to the
    router and are filtered like everyone else, which is the honest outcome
    and is what unfinished() reports.
    """
    pool = f"pool-{dept['slug']}"
    ops = [
        _op("add", ("ip", "pool"),
            {"name": pool, "ranges": f"{dept['pool_from']}-{dept['pool_to']}",
             "comment": f"mikromon: {dept['name']}"},
            f"address pool {dept['pool_from']}-{dept['pool_to']}"),
        _op("add", ("ip", "dhcp-server"),
            {"name": f"dhcp-{dept['slug']}", "interface": _iface(dept),
             "address-pool": pool, "disabled": "no",
             "comment": f"mikromon: {dept['name']}"},
            f"DHCP server on {_iface(dept)}"),
    ]
    net = {"address": dept["subnet"], "gateway": dept["gateway"],
           "comment": f"mikromon: {dept['name']}"}
    if dept.get("resolvers"):
        net["dns-server"] = ",".join(dept["resolvers"])
        desc = (f"DHCP network {dept['subnet']} -> DNS "
                f"{', '.join(dept['resolvers'])}")
    else:
        desc = (f"DHCP network {dept['subnet']} (no DNS of its own -- this "
                f"department is NOT filtered separately)")
    ops.append(_op("add", ("ip", "dhcp-server", "network"), net, desc))
    return ops


def port_ops(departments: list, bridge: str = "bridge") -> list:
    """Put each department's ports on its VLAN, untagged.

    A device plugged into ether3 has no idea VLANs exist, so the port does
    the tagging for it: PVID stamps the department's VLAN onto everything
    arriving, and the bridge VLAN table lists that port as untagged so the
    tag comes off again on the way out.

    The bridge itself is tagged on every department VLAN, because the router
    is the gateway for all of them and its own traffic has to carry the tag.

    vlan-filtering is deliberately NOT set here. Turning it on is the moment
    a mis-tagged trunk port stops passing traffic, and doing that in the same
    unattended push that creates the VLANs is how somebody loses the link
    they are managing the router over. It is left to be switched on
    deliberately, once the ports read correctly.
    """
    if not departments:
        return []
    ops = []
    for d in departments:
        for port in d.get("ports") or []:
            ops.append(_op("set", ("interface", "bridge", "port"),
                           {"interface": port, "bridge": bridge,
                            "pvid": str(d["vlan"])},
                           f"{port} -> VLAN {d['vlan']} ({d['name']}), "
                           f"untagged"))
        ports = d.get("ports") or []
        entry = {"bridge": bridge, "vlan-ids": str(d["vlan"]),
                 "tagged": bridge,
                 "comment": f"mikromon: {d['name']}"}
        if ports:
            entry["untagged"] = ",".join(ports)
        ops.append(_op("add", ("interface", "bridge", "vlan"), entry,
                       f"bridge VLAN {d['vlan']}: tagged {bridge}"
                       + (f", untagged {', '.join(ports)}" if ports
                          else " (no ports yet -- trunk only)")))
    return ops


def isolation_ops(departments: list) -> list:
    """Stop departments reaching each other, while leaving the internet alone.

    Three kinds of rule rather than one per pair, because a pair-wise list
    for six departments is thirty rules nobody will ever audit:

      established/related FIRST, or the replies to the traffic that IS
      allowed get dropped and everything looks broken in a way that takes an
      afternoon to find;

      each department to its OWN gateway, so DHCP, DNS-to-the-router and
      management still work;

      then drop department-to-department, which leaves the internet
      reachable because the internet is not in the address list.

    Accounts being unreachable from the guest Wi-Fi is the reason anybody
    asks for departments in the first place, so it is not left as an
    exercise for the reader.
    """
    if len(departments) < 2:
        return []
    ops = [_op("add", ("ip", "firewall", "address-list"),
               {"list": _LIST_ALLOWED, "address": d["subnet"],
                "comment": f"mikromon: {d['name']}"},
               f"{d['name']} {d['subnet']} in {_LIST_ALLOWED}")
           for d in departments]
    ops.append(_op("add", ("ip", "firewall", "filter"),
                   {"chain": "forward",
                    "connection-state": "established,related",
                    "action": "accept",
                    "comment": "mikromon: replies first, or nothing works"},
                   "accept established/related"))
    for d in departments:
        ops.append(_op("add", ("ip", "firewall", "filter"),
                       {"chain": "forward", "src-address": d["subnet"],
                        "dst-address": f"{d['gateway']}/32",
                        "action": "accept",
                        "comment": f"mikromon: {d['name']} to its gateway"},
                       f"{d['name']} may reach its own gateway"))
    ops.append(_op("add", ("ip", "firewall", "filter"),
                   {"chain": "forward",
                    "src-address-list": _LIST_ALLOWED,
                    "dst-address-list": _LIST_ALLOWED,
                    "action": "drop",
                    "comment": "mikromon: departments stay apart"},
                   "drop department-to-department "
                   "(the internet is untouched)"))
    return ops


def needs_own_profiles(departments: list) -> bool:
    """Should each department get its own NextDNS profile?

    Only once there is more than one. A site with a single department has
    nothing to tell apart: the router's own profile already filters all of
    it, and creating a second profile to point one VLAN at would be an
    account to maintain, a bill to pay and a thing to keep in step, in
    exchange for nothing.

    The moment a second department exists that stops being true, because the
    whole point of the second one is that it is filtered differently.
    """
    return len([d for d in departments if d]) > 1


def profiles_to_create(departments: list) -> list:
    """Departments that should have a profile and do not yet.

    Empty for a single-department site, however long it stays that way.
    """
    if not needs_own_profiles(departments):
        return []
    return [d["name"] for d in departments if not d.get("profile_id")]


def build_plan(device_name: str, departments: list, bridge: str = "bridge"):
    """Everything one router needs for this set of departments.

    Refuses outright on a clash. A half-applied set of overlapping subnets is
    worse than no departments at all: it fails intermittently, which is the
    most expensive way for a network to be wrong.
    """
    from .push.plan import Plan

    if not departments:
        return Plan(device_name, [], summary="no departments")
    problems = check_set(departments)
    if problems:
        raise DepartmentError(" ".join(problems))

    ops = []
    for d in departments:
        ops += vlan_ops(d, bridge)
        ops += address_ops(d)
        ops += dhcp_ops(d)
    ops += port_ops(departments, bridge)
    ops += isolation_ops(departments)

    filtered = sum(1 for d in departments if d.get("resolvers"))
    return Plan(device_name, ops,
                summary=(f"{len(departments)} department(s), {filtered} with "
                         f"their own DNS filtering"))
