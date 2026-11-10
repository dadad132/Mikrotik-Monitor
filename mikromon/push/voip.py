"""VoIP priority: phone calls go first on a router's upload, so they do not
break up while someone else fills the line.

A line drops calls when its upload is full: the queue builds up in the ISP's
modem, behind somebody's cloud backup, and the router cannot reorder what is
already waiting there. So the router shapes its own upload to just below the
line's real speed -- the queue then forms on the router, where calls can be
sent first.

What a plan here puts on the router, every row tagged as the dashboard's:

  * a queue tree on the WAN egress (a PPPoE line's pppoe-out interface, not
    the port under it) capped at the shaping speed, with two children: calls
    at priority 1 with some bandwidth always kept for them, and everything
    else at priority 8 -- which keeps a floor of its own, so traffic wrongly
    taken for calls can never starve the router's tunnel to this dashboard
  * mangle rules that recognise a call -- SIP ports, the voice (RTP) port
    range, and anything the phones mark as voice (DSCP 46) -- and mark the
    whole connection, then every packet of a marked connection
  * FastTrack switched off: fast-tracked traffic goes around the queues,
    so with it on nothing above has any effect
  * optionally, the SIP helper (ALG) switched off, a common cause of
    one-way audio with hosted phone systems

FastTrack rules and the SIP helper are not the dashboard's: somebody else
set them up. What this changes about them is written into one disabled,
inert mangle row (STATE_TAG), in the same plan as the change itself, so a
rollback or a Safe mode restore keeps the record true -- and switching the
feature off turns back on exactly what it turned off, and nothing else.

Downloads are not shaped: by the time a download reaches the router it has
already crossed the slow line.
"""
from __future__ import annotations

import hashlib
import re

from ..util import as_bool, as_int, mbps_text, mbps_to_bps, rate_bps
from .api import PlanRefused
from .plan import Operation, Plan
from .vpnusers import IFACE_NAME as _USERS_IFACE

_RESOURCE = ("system", "resource")
_MANGLE = ("ip", "firewall", "mangle")
_FILTER = ("ip", "firewall", "filter")
_SERVICE_PORT = ("ip", "firewall", "service-port")
_TREE = ("queue", "tree")
_SIMPLE = ("queue", "simple")
_INTERFACE = ("interface",)
_PPPOE = ("interface", "pppoe-client")
_VLAN = ("interface", "vlan")
_ROUTE = ("ip", "route")

TAG = "mikromon:voip:"               # rows this feature owns
STATE_TAG = "mikromon:voip-state:"   # the inert row recording what it changed
CONN_MARK = "voip-conn"
PKT_MARK = "voip-packets"
Q_PARENT = "mm-voip-upload"
Q_VOICE = "mm-voip-voice"
Q_OTHER = "mm-voip-other"
RTP_PRESETS = {"asterisk": "10000-20000", "3cx": "9000-10999"}
DEFAULT_SIP = "5060,5061"
DEFAULT_GUAR_BPS = 5_000_000
_MIN_OTHER_BPS = 500_000
_SDWAN_POL = "mikromon:sdwan:pol:"
_TUNNEL_IFACES = ("mikromon", _USERS_IFACE)

# What a removed row is put back with if a rollback needs it. Counters and
# flags RouterOS reports but will not take (bytes, packets, dynamic,
# invalid...) are left out, or the put-back itself would fail.
_MANGLE_FIELDS = ("chain", "action", "protocol", "dst-port", "dscp",
                  "connection-mark", "new-connection-mark", "packet-mark",
                  "new-packet-mark", "passthrough", "comment", "disabled")
_TREE_FIELDS = ("name", "parent", "packet-mark", "limit-at", "max-limit",
                "priority", "queue", "comment", "disabled")
# A FastTrack rule is recognised by these if its .id has changed by the
# time the feature is switched off.
_SIG_FIELDS = ("chain", "connection-state", "connection-mark", "hw-offload",
               "in-interface", "out-interface", "in-interface-list",
               "out-interface-list", "src-address", "dst-address",
               "src-address-list", "dst-address-list", "comment")
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


def _text(v) -> str:
    """A value as the router holds it: librouteros hands yes/no back as
    True/False and numbers as ints."""
    if isinstance(v, bool):
        return "yes" if v else "no"
    return "" if v is None else str(v)


def _norm(s) -> str:
    return str(s or "").strip().lower()


def _fetch(api, path) -> list:
    """A read that must work: one that failed silently would look like
    "nothing set up yet", and the plan would add everything a second time."""
    return list(api.fetch(path))


def _safe(api, path) -> list:
    try:
        return list(api.fetch(path))
    except Exception:  # noqa: BLE001 -- a menu missing on this board
        return []


def _owned(rows, tag) -> tuple:
    """({key: row}, [duplicates]) for rows whose comment carries `tag`."""
    out, dupes = {}, []
    for r in rows:
        c = str(r.get("comment", "") or "")
        if not c.startswith(tag):
            continue
        key = c[len(tag):]
        if key in out:
            dupes.append(r)
        else:
            out[key] = r
    return out, dupes


def _ft_sig(row) -> str:
    """A FastTrack rule's fingerprint, from what it matches -- not from
    whether it is switched on, which is the very thing that changes."""
    parts = []
    for f in _SIG_FIELDS:
        v = row.get(f)
        if isinstance(v, bool) or _norm(v) in ("true", "false", "yes", "no"):
            v = "yes" if as_bool(v) else "no"
        parts.append(f"{f}={_text(v)}")
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:8]


def _state(marker) -> dict:
    """What the marker row says this feature changed. "lost": the record
    went missing at some point while the feature was on, so what it had
    switched off then is no longer known."""
    out = {"ft": [], "alg": False, "lost": False}
    if not marker:
        return out
    body = str(marker.get("comment", ""))[len(STATE_TAG):]
    for part in body.split(";"):
        key, _, val = part.partition("=")
        if key == "ft":
            for item in val.split(","):
                rid, _, sig = item.partition("/")
                if rid:
                    out["ft"].append((rid, sig))
        elif key == "alg":
            out["alg"] = val == "1"
        elif key == "lost":
            out["lost"] = val == "1"
    return out


def _state_comment(ft, alg, lost=False) -> str:
    return (STATE_TAG + "ft=" + ",".join(f"{rid}/{sig}" for rid, sig in ft)
            + f";alg={1 if alg else 0}" + (";lost=1" if lost else ""))


def _looks_ip(s) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(s).split("/")[0])
        return True
    except ValueError:
        return False


def _version(rows) -> tuple:
    ver = str(rows[0].get("version", "")) if rows else ""
    m = re.match(r"(\d+)\.(\d+)", ver)
    return ((int(m.group(1)), int(m.group(2)), ver) if m
            else (0, 0, ver or "unknown"))


def read(pusher, cfg) -> dict:
    """Everything the Queues tab needs to show VoIP priority and to plan it."""
    from .features import _route_iface, detect_isp_ifaces

    api = pusher.api
    res = _fetch(api, _RESOURCE)
    major, minor, ver = _version(res)
    out: dict = {"version": ver,
                 "unsupported": bool(major and (major, minor) < (7, 1)),
                 "cpu": as_int((res[0] if res else {}).get("cpu-load"), -1),
                 "board": str((res[0] if res else {}).get("board-name", ""))}
    if out["unsupported"]:
        return out
    mangle = _fetch(api, _MANGLE)
    tree = _fetch(api, _TREE)
    filters = _fetch(api, _FILTER)
    ifaces = _fetch(api, _INTERFACE)

    out["mangle"], out["mangle_dupes"] = _owned(mangle, TAG)
    out["tree"], out["tree_dupes"] = _owned(tree, TAG)
    markers = [r for r in mangle
               if str(r.get("comment", "")).startswith(STATE_TAG)]
    out["marker"] = markers[0] if markers else None
    out["marker_dupes"] = markers[1:]
    out["state"] = _state(out["marker"])
    out["on"] = bool(out["marker"] or out["mangle"] or out["tree"])
    out["fasttrack"] = [r for r in filters
                        if _text(r.get("action")) == "fasttrack-connection"
                        and not as_bool(r.get("dynamic"))]
    out["sip_alg"] = next((r for r in _safe(api, _SERVICE_PORT)
                           if _norm(r.get("name")) == "sip"), None)
    ours = (TAG, STATE_TAG)
    out["foreign_mangle"] = [r for r in mangle
                             if not str(r.get("comment", "")).startswith(ours)
                             and not as_bool(r.get("dynamic"))]
    out["foreign_tree"] = [r for r in tree
                           if not str(r.get("comment", "")).startswith(TAG)]
    out["simple"] = _safe(api, _SIMPLE)

    # Interfaces, and which PPPoE connection runs over which port: a PPPoE
    # line's traffic leaves through pppoe-out1, and a queue on the port
    # under it would see only PPPoE frames.
    out["ifaces"] = {_norm(i.get("name")): str(i.get("name"))
                     for i in ifaces if i.get("name")}
    pppoe = _safe(api, _PPPOE)
    out["pppoe"] = {_norm(p.get("name")): str(p.get("name"))
                    for p in pppoe if p.get("name")}
    vlans = {_norm(v.get("name")): _norm(v.get("interface"))
             for v in _safe(api, _VLAN) if v.get("name")}
    out["ppp_over"] = {}
    for p in pppoe:
        # Only a connection that is switched on carries the line: one left
        # over from an old ADSL line must not hide the port the new line
        # really uses.
        if (not (p.get("interface") and p.get("name"))
                or as_bool(p.get("disabled"))):
            continue
        under = _norm(p.get("interface"))
        out["ppp_over"][under] = str(p["name"])
        # PPPoE over a VLAN, for an ISP that wants tagged frames: the port
        # under the VLAN carries this line too.
        if vlans.get(under):
            out["ppp_over"].setdefault(vlans[under], str(p["name"]))

    def egress(name):
        n = _norm(name)
        if n in out["pppoe"]:
            return out["pppoe"][n]
        if n in out["ppp_over"]:
            return out["ppp_over"][n]
        return out["ifaces"].get(n, "")

    # Where the WAN tab sends some devices: by interface (resolved like the
    # line itself, so "ether1" under pppoe-out1 is the same line), or by a
    # gateway address, which says nothing certain about the line.
    out["policy_via"] = sorted({
        egress(via) or via
        for via in (str(r.get("comment", "")).partition("|")[2]
                    for r in mangle
                    if str(r.get("comment", "")).startswith(_SDWAN_POL))
        if via and not _looks_ip(via)})

    choices, seen = [], set()
    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])
    for i, link in enumerate(links):
        e = egress(getattr(link, "interface", ""))
        if e and _norm(e) not in seen:
            seen.add(_norm(e))
            role = "main line" if i == 0 else f"backup line {i}"
            choices.append((e, f"{e}: {link.label(i)} ({role})"))
    out["link_ifaces"] = [c[0] for c in choices]
    for name in sorted(detect_isp_ifaces(api)):
        e = egress(name)
        if e and _norm(e) not in seen:
            seen.add(_norm(e))
            choices.append((e, f"{e} (has internet now)"))
    parent = str((out["tree"].get("q-parent") or {}).get("parent", "") or "")
    if parent and _norm(parent) not in seen:
        choices.append((parent, f"{parent} (set now)"))
    out["choices"] = choices

    active = ""
    for r in _safe(api, _ROUTE):
        if (str(r.get("dst-address", "")).startswith("0.0.0.0/0")
                and as_bool(r.get("active", True))
                and _norm(r.get("routing-table") or "main") == "main"):
            active = _route_iface(r)
            if active:
                break
    out["active_iface"] = egress(active) or active
    out["default_iface"] = (parent or (choices[0][0] if choices else "")
                            or out["active_iface"])
    return out


# ---- what the owner asked for -------------------------------------------------
def _ports_ok(text: str, most: int) -> bool:
    toks = [t for t in text.split(",") if t]
    if not toks or len(toks) > most:
        return False
    for t in toks:
        if not _PORTS_RE.match(t):
            return False
        lo, _, hi = t.partition("-")
        if not 1 <= int(lo) <= 65535 or (hi and not int(lo) < int(hi) <= 65535):
            return False
    return True


def _settings(flat: dict, cur: dict) -> tuple:
    """(want, problems): the validated settings, or every reason they are
    not usable, all at once."""
    problems = []
    raw_iface = (flat.get("voip_iface") or cur.get("default_iface") or "").strip()
    n = _norm(raw_iface)
    iface = ""
    if not n:
        problems.append("Choose the line to give calls priority on.")
    elif n in _TUNNEL_IFACES:
        problems.append(f"{raw_iface} is a VPN tunnel, not an internet line.")
    elif n in cur.get("ppp_over", {}):
        problems.append(f"{raw_iface} carries the PPPoE connection "
                        f"{cur['ppp_over'][n]}: choose {cur['ppp_over'][n]}, "
                        f"which is where the traffic actually leaves.")
    elif n not in cur.get("ifaces", {}):
        problems.append(f"There is no interface called {raw_iface} on this "
                        f"router.")
    else:
        iface = cur["ifaces"][n]

    up = mbps_to_bps(flat.get("voip_up"))
    if not 1_000_000 <= up <= 10_000_000_000:
        problems.append("Shape the upload to: give a speed in Mbps between 1 "
                        "and 10000, about 90% of the line's real upload.")
        up = -1
    guar_text = (flat.get("voip_guar") or "").strip()
    guar = mbps_to_bps(guar_text) if guar_text else (
        min(DEFAULT_GUAR_BPS, up // 2) if up > 0 else -1)
    if guar_text and guar <= 0:
        problems.append("Kept free for calls: give a speed in Mbps, such as 5.")
    floor = max(up // 10, _MIN_OTHER_BPS) if up > 0 else 0
    if up > 0 and guar > 0 and guar + floor > up:
        problems.append(
            f"Keeping {mbps_text(guar)} Mbps for calls leaves too little for "
            f"everything else on a {mbps_text(up)} Mbps upload: keep at most "
            f"{mbps_text(up - floor)} Mbps for calls.")

    preset = (flat.get("voip_rtp") or "asterisk").strip()
    if preset in RTP_PRESETS:
        rtp = RTP_PRESETS[preset]
    else:
        rtp = re.sub(r"\s+", "", flat.get("voip_rtp_custom") or "")
        lo, _, hi = rtp.partition("-")
        if not (lo.isdigit() and hi.isdigit()
                and 1024 <= int(lo) < int(hi) <= 65535):
            problems.append("Voice ports: give the range your phone system "
                            "uses, like 16384-32767 (from 1024 to 65535).")
    sip = re.sub(r"\s+", "", flat.get("voip_sip") or DEFAULT_SIP)
    if not _ports_ok(sip, 15):
        problems.append("Call setup ports: give up to 15 ports or ranges, "
                        "separated by commas, like 5060,5061.")
    # "5060,5061," passes the check above but RouterOS refuses it.
    sip = ",".join(t for t in sip.split(",") if t)

    # Somebody's own setup on the same line or with the same marks would
    # fight this one -- they say so rather than get two half-working halves.
    for r in cur.get("foreign_tree", []):
        if (iface and _norm(r.get("parent")) == _norm(iface)
                and not as_bool(r.get("disabled"))):
            problems.append(f"The queue tree '{r.get('name')}' on {iface} "
                            f"looks set up by hand: remove it in Winbox → "
                            f"Queues → Queue Tree first.")
    marks = (CONN_MARK, PKT_MARK)
    for r in cur.get("foreign_mangle", []):
        if any(_text(r.get(f)) in marks for f in (
                "new-connection-mark", "connection-mark",
                "new-packet-mark", "packet-mark")):
            problems.append(f"A mangle rule set up by hand already uses the "
                            f"'{CONN_MARK}' or '{PKT_MARK}' mark (it looks "
                            f"like the VoIP script was run by hand): remove "
                            f"those rules in Winbox → IP → Firewall → Mangle "
                            f"first.")
            break
    for r in cur.get("foreign_tree", []) + cur.get("simple", []):
        if (str(r.get("name", "")).startswith("mm-voip-")
                and not str(r.get("comment", "")).startswith(TAG)):
            problems.append(f"A queue called '{r.get('name')}' already exists "
                            f"and is not the dashboard's: rename or remove it.")
            break
    want = {"iface": iface, "up": up, "guar": guar, "floor": floor,
            "rtp": rtp, "sip": sip, "dscp": flat.get("voip_dscp") == "1",
            "alg": flat.get("voip_alg") == "1"}
    return want, problems


def _desired_tree(w) -> list:
    return [
        ("q-parent", {"name": Q_PARENT, "parent": w["iface"],
                      "max-limit": str(w["up"])},
         f"shape all upload on {w['iface']} to {mbps_text(w['up'])} Mbps, so "
         f"the queue forms on the router, where calls can go first"),
        ("q-voice", {"name": Q_VOICE, "parent": Q_PARENT,
                     "packet-mark": PKT_MARK, "priority": "1",
                     "limit-at": str(w["guar"]), "max-limit": str(w["up"])},
         f"calls go first, with {mbps_text(w['guar'])} Mbps always kept for "
         f"them"),
        ("q-other", {"name": Q_OTHER, "parent": Q_PARENT,
                     "packet-mark": "no-mark", "priority": "8",
                     "limit-at": str(w["floor"]), "max-limit": str(w["up"])},
         f"everything else after calls, never below {mbps_text(w['floor'])} "
         f"Mbps (keeps the dashboard's connection to the router alive)"),
    ]


def _desired_mangle(w) -> list:
    conn = {"chain": "prerouting", "connection-mark": "no-mark",
            "action": "mark-connection", "new-connection-mark": CONN_MARK,
            "passthrough": "yes"}
    rows = [
        ("sip-udp", {**conn, "protocol": "udp", "dst-port": w["sip"]},
         f"recognise calls: call setup (SIP) on UDP {w['sip']}"),
        ("sip-tcp", {**conn, "protocol": "tcp", "dst-port": w["sip"]},
         f"recognise calls: call setup (SIP) on TCP {w['sip']}"),
        ("rtp", {**conn, "protocol": "udp", "dst-port": w["rtp"]},
         f"recognise calls: voice (RTP) on UDP {w['rtp']}"),
    ]
    if w["dscp"]:
        rows.append(("dscp", {**conn, "dscp": "46"},
                     "recognise calls: anything the phones mark as voice "
                     "(DSCP 46)"))
    # passthrough=yes so rules added after this one -- the WAN tab's policy
    # routing appends its rules -- still see call packets.
    rows.append(("pkt", {"chain": "prerouting", "connection-mark": CONN_MARK,
                         "action": "mark-packet", "new-packet-mark": PKT_MARK,
                         "passthrough": "yes"},
                 "label every packet of a call for the priority queue"))
    return rows


def _same(field: str, have, want) -> bool:
    if field in ("max-limit", "limit-at"):
        return rate_bps(have) == rate_bps(want)
    if field in ("passthrough", "disabled"):
        return as_bool(have) == as_bool(want)
    if field == "parent":
        return _norm(have) == _norm(want)
    if field == "dst-port":
        return (set(_text(have).replace(" ", "").split(","))
                == set(_text(want).split(",")))
    return _text(have) == _text(want)


def _restore(row, fields) -> dict:
    return {f: _text(row[f]) for f in fields
            if f in row and row[f] not in (None, "")}


def _remove(path, row, fields, desc, what) -> Operation:
    return Operation("remove", path, {".id": row[".id"]}, desc=desc,
                     inverse=Operation("add", path, _restore(row, fields),
                                       desc=f"put back {what}"))


def _row_ops(path, desired, owned, dupes, fields, what,
             place_before="") -> list:
    """Add, change or remove this feature's own rows so they match
    `desired` -- changing only what differs, so applying the same settings
    twice sends nothing."""
    ops = []
    for key, params, desc in desired:
        params = {**params, "comment": TAG + key}
        row = owned.get(key)
        if row is None:
            add = dict(params)
            if place_before:
                add["place-before"] = place_before
            ops.append(Operation("add", path, add, desc=desc,
                                 inverse=Operation("remove", path, {},
                                                   desc=f"remove {what} {key}")))
            continue
        changes = {f: v for f, v in params.items()
                   if not _same(f, row.get(f), v)}
        if as_bool(row.get("disabled")):
            changes["disabled"] = "no"
        if changes:
            old = {f: _text(row.get(f)) for f in changes if f in row}
            if "disabled" in changes:
                old["disabled"] = "yes"
            ops.append(Operation(
                "set", path, {".id": row[".id"], **changes},
                desc=f"{desc} (updating {what} {key})",
                inverse=Operation("set", path, {".id": row[".id"], **old},
                                  desc=f"put back {what} {key}")))
    keys = {k for k, _p, _d in desired}
    for key, row in owned.items():
        if key not in keys:
            ops.append(_remove(path, row, fields,
                               f"remove {what} {key} (no longer used)",
                               f"{what} {key}"))
    for row in dupes:
        ops.append(_remove(path, row, fields,
                           f"remove a duplicate {what} "
                           f"({str(row.get('comment', ''))[len(TAG):]})",
                           f"duplicate {what}"))
    return ops


def _on_ops(cur: dict, w: dict) -> list:
    ops = _row_ops(_TREE, _desired_tree(w), cur["tree"], cur["tree_dupes"],
                   _TREE_FIELDS, "queue")
    # A connection rule added after the packet-marking rule exists goes in
    # front of it, so the first packet of a newly recognised call is
    # labelled too.
    pkt = cur["mangle"].get("pkt")
    desired = _desired_mangle(w)
    ops += _row_ops(_MANGLE, [d for d in desired if d[0] != "pkt"],
                    {k: v for k, v in cur["mangle"].items() if k != "pkt"},
                    cur["mangle_dupes"], _MANGLE_FIELDS, "call rule",
                    place_before=str(pkt[".id"]) if pkt else "")
    ops += _row_ops(_MANGLE, [d for d in desired if d[0] == "pkt"],
                    {"pkt": pkt} if pkt else {}, [], _MANGLE_FIELDS,
                    "call rule")

    state = cur["state"]
    ft = list(state["ft"])
    recorded = {rid for rid, _sig in ft}
    ft_ops = []
    for r in cur["fasttrack"]:
        if as_bool(r.get("disabled")):
            continue
        rid = str(r[".id"])
        if rid not in recorded:
            ft.append((rid, _ft_sig(r)))
        name = str(r.get("comment") or rid)
        ft_ops.append(Operation(
            "set", _FILTER, {".id": rid, "disabled": "yes"},
            desc=f"switch off FastTrack rule {rid} ({name}): fast-tracked "
                 f"traffic skips the queues. It comes back on when VoIP "
                 f"priority is switched off",
            inverse=Operation("set", _FILTER, {".id": rid, "disabled": "no"},
                              desc=f"switch FastTrack rule {rid} back on")))
    alg = state["alg"]
    alg_ops = []
    svc = cur.get("sip_alg")
    if svc and svc.get(".id"):
        sid = str(svc[".id"])
        if w["alg"] and not as_bool(svc.get("disabled")):
            alg = True
            alg_ops.append(Operation(
                "set", _SERVICE_PORT, {".id": sid, "disabled": "yes"},
                desc="switch off the router's SIP helper (SIP ALG), a common "
                     "cause of one-way audio",
                inverse=Operation("set", _SERVICE_PORT,
                                  {".id": sid, "disabled": "no"},
                                  desc="switch the SIP helper back on")))
        elif not w["alg"] and alg and as_bool(svc.get("disabled")):
            alg = False
            alg_ops.append(Operation(
                "set", _SERVICE_PORT, {".id": sid, "disabled": "no"},
                desc="switch the router's SIP helper back on",
                inverse=Operation("set", _SERVICE_PORT,
                                  {".id": sid, "disabled": "yes"},
                                  desc="switch the SIP helper off again")))

    marker = cur.get("marker")
    # A record that vanished while the feature was on: what it had switched
    # off then is unknown, and stays flagged rather than being forgotten by
    # a fresh, empty record.
    lost = state["lost"] or (marker is None
                             and bool(cur["mangle"] or cur["tree"]))
    comment = _state_comment(ft, alg, lost)
    marker_ops = []
    if marker is None:
        marker_ops.append(Operation(
            "add", _MANGLE, {"chain": "prerouting", "action": "passthrough",
                             "disabled": "yes", "comment": comment},
            desc="record what this changes, so switching it off puts back "
                 "exactly that (a switched-off rule that does nothing)",
            inverse=Operation("remove", _MANGLE, {},
                              desc="remove the VoIP priority record")))
    elif str(marker.get("comment", "")) != comment:
        marker_ops.append(Operation(
            "set", _MANGLE, {".id": marker[".id"], "comment": comment},
            desc="update the record of what VoIP priority changed",
            inverse=Operation("set", _MANGLE,
                              {".id": marker[".id"],
                               "comment": str(marker.get("comment", ""))},
                              desc="put back the previous record")))
    for extra in cur.get("marker_dupes", []):
        marker_ops.append(_remove(_MANGLE, extra, _MANGLE_FIELDS,
                                  "remove a duplicate VoIP priority record",
                                  "duplicate record"))
    # The record goes in before FastTrack is touched, so a rollback that
    # gets as far as the record leaves it true.
    return ops + marker_ops + ft_ops + alg_ops


def _off_ops(cur: dict) -> list:
    """Everything this feature added, and what it switched off switched
    back on. FastTrack is only touched when the record says so."""
    ops = []
    state = cur["state"]
    marker = cur.get("marker")
    by_id = {str(r.get(".id")): r for r in cur.get("fasttrack", [])}
    unresolved = []
    for rid, sig in state["ft"]:
        row = by_id.get(rid)
        if row is None:
            same = [r for r in cur.get("fasttrack", [])
                    if as_bool(r.get("disabled")) and _ft_sig(r) == sig]
            row = same[0] if len(same) == 1 else None
        if row is None:
            unresolved.append(rid)
            continue
        if as_bool(row.get("disabled")):
            fid = str(row[".id"])
            ops.append(Operation(
                "set", _FILTER, {".id": fid, "disabled": "no"},
                desc=f"switch FastTrack rule {fid} "
                     f"({row.get('comment') or fid}) back on",
                inverse=Operation("set", _FILTER, {".id": fid,
                                                   "disabled": "yes"},
                                  desc=f"switch FastTrack rule {fid} off "
                                       f"again")))
    svc = cur.get("sip_alg")
    if state["alg"] and svc and svc.get(".id") and as_bool(svc.get("disabled")):
        ops.append(Operation(
            "set", _SERVICE_PORT, {".id": str(svc[".id"]), "disabled": "no"},
            desc="switch the router's SIP helper back on",
            inverse=Operation("set", _SERVICE_PORT,
                              {".id": str(svc[".id"]), "disabled": "yes"},
                              desc="switch the SIP helper off again")))
    mangle = cur["mangle"]
    for key in ["pkt"] + [k for k in mangle if k != "pkt"]:
        if key in mangle:
            ops.append(_remove(_MANGLE, mangle[key], _MANGLE_FIELDS,
                               f"remove call rule {key}", f"call rule {key}"))
    for row in cur.get("mangle_dupes", []):
        ops.append(_remove(_MANGLE, row, _MANGLE_FIELDS,
                           "remove a duplicate call rule", "call rule"))
    tree = cur["tree"]
    for key in [k for k in tree if k != "q-parent"] + ["q-parent"]:
        if key in tree:
            ops.append(_remove(_TREE, tree[key], _TREE_FIELDS,
                               f"remove queue {tree[key].get('name', key)}",
                               f"queue {key}"))
    for row in cur.get("tree_dupes", []):
        ops.append(_remove(_TREE, row, _TREE_FIELDS,
                           "remove a duplicate queue", "queue"))
    for m in ([marker] if marker else []) + cur.get("marker_dupes", []):
        note = ""
        if unresolved and m is marker:
            note = (f" -- FastTrack rule(s) {', '.join(unresolved)} could not "
                    f"be found to switch back on: check IP → Firewall → "
                    f"Filter Rules")
        ops.append(_remove(_MANGLE, m, _MANGLE_FIELDS,
                           "remove the VoIP priority record" + note,
                           "the VoIP priority record"))
    return ops


def plan(pusher, cfg, flat: dict, multi: dict) -> Plan:
    """Switch VoIP priority on (or change its settings), or off."""
    cur = read(pusher, cfg)
    if cur.get("unsupported"):
        raise PlanRefused("Nothing was sent to the router.\nVoIP priority "
                          "needs RouterOS 7.1 or newer; this router runs "
                          f"{cur.get('version')}. Update it on the Update "
                          f"tab first.")
    mode = (flat.get("voip_on") or "").strip()
    if mode == "off":
        return Plan(cfg.name, _off_ops(cur), summary="VoIP priority off")
    if mode != "on":
        # Never read a missing field as "off": a form that lost it would
        # quietly take the feature away.
        raise PlanRefused("Nothing was sent to the router.\nThe form did "
                          "not say whether to switch VoIP priority on or "
                          "off. Reload the Queues tab and try again.")
    want, problems = _settings(flat, cur)
    if problems:
        raise PlanRefused("Nothing was sent to the router.\n"
                          + "\n".join(problems))
    return Plan(cfg.name, _on_ops(cur, want), summary="VoIP priority")


# ---- what the tab shows -------------------------------------------------------
def _current(cur: dict) -> dict:
    """The settings as they are on the router, for the form."""
    tree, mangle = cur.get("tree", {}), cur.get("mangle", {})
    up = rate_bps((tree.get("q-parent") or {}).get("max-limit"))
    guar = rate_bps((tree.get("q-voice") or {}).get("limit-at"))
    rtp = _text((mangle.get("rtp") or {}).get("dst-port"))
    preset = next((k for k, v in RTP_PRESETS.items() if v == rtp),
                  "custom" if rtp else "asterisk")
    svc = cur.get("sip_alg")
    return {
        "iface": cur.get("default_iface", ""),
        "up": mbps_text(up) if up > 0 else "",
        "guar": mbps_text(guar) if guar > 0 else mbps_text(DEFAULT_GUAR_BPS),
        "rtp": preset, "rtp_custom": rtp if preset == "custom" else "",
        "sip": _text((mangle.get("sip-udp") or {}).get("dst-port"))
               or DEFAULT_SIP,
        "dscp": bool(mangle.get("dscp")) or not cur.get("on"),
        "alg": (as_bool(svc.get("disabled")) if svc and cur.get("on")
                else bool(svc)),
    }


def form(cur: dict, cfg) -> list:
    """The settings form, as field descriptions for the page."""
    c = _current(cur)
    choices = list(cur.get("choices") or [])
    if c["iface"] and all(_norm(v) != _norm(c["iface"]) for v, _l in choices):
        choices.append((c["iface"], c["iface"]))
    fields = [
        {"type": "select", "name": "voip_iface", "label": "Internet line",
         "options": choices or [("", "No internet line found")],
         "value": c["iface"]},
        {"type": "text", "name": "voip_up",
         "label": "Shape the upload to (Mbps) — about 90% of the line's "
                  "real upload speed",
         "value": c["up"], "placeholder": "e.g. 18 on a 20 Mbps upload"},
        {"type": "text", "name": "voip_guar",
         "label": "Kept free for calls (Mbps) — 1 Mbps carries about 10 "
                  "calls",
         "value": c["guar"], "placeholder": "5"},
        {"type": "select", "name": "voip_rtp",
         "label": "Phone system (voice ports)",
         "options": [("asterisk", "Asterisk, FreePBX and most hosted "
                                  "systems (10000–20000)"),
                     ("3cx", "3CX (9000–10999)"),
                     ("custom", "Other — type the range below")],
         "value": c["rtp"]},
        {"type": "text", "name": "voip_rtp_custom",
         "label": "Other voice port range (only for Other)",
         "value": c["rtp_custom"], "placeholder": "e.g. 16384-32767"},
        {"type": "text", "name": "voip_sip",
         "label": "Call setup (SIP) ports", "value": c["sip"],
         "placeholder": DEFAULT_SIP},
        {"type": "check", "name": "voip_dscp",
         "label": "Also treat anything the phones mark as voice (DSCP 46) "
                  "as a call", "on": c["dscp"]},
    ]
    if cur.get("sip_alg"):
        fields.append({"type": "check", "name": "voip_alg",
                       "label": "Switch off the router's SIP helper (often "
                                "the cause of one-way audio)",
                       "on": c["alg"]})
    return fields


def summary(cur: dict, cfg) -> list:
    """Plain-language state, then anything that stops it working fully
    (each starting with "⚠ ")."""
    if cur.get("unsupported"):
        return [f"Needs RouterOS 7.1 or newer; this router runs "
                f"{cur.get('version')}. Update it on the Update tab first."]
    tree, mangle = cur.get("tree", {}), cur.get("mangle", {})
    ft = cur.get("fasttrack", [])
    if not cur.get("on"):
        lines = ["Off. Calls share the upload with everything else."]
        live = [r for r in ft if not as_bool(r.get("disabled"))]
        if live:
            lines.append(f"Switching it on turns FastTrack off "
                         f"({len(live)} rule(s)) so the queues see every "
                         f"packet. Switching it off turns them back on.")
        return lines
    c = _current(cur)
    parent = str((tree.get("q-parent") or {}).get("parent", "") or "?")
    lines = [f"On: calls on {parent} go first. Upload shaped to "
             f"{c['up'] or '?'} Mbps, {c['guar']} Mbps always kept for "
             f"calls. Downloads are not changed."]
    rtp = _text((mangle.get("rtp") or {}).get("dst-port")) or "?"
    lines.append(f"Recognised as calls: call setup on ports {c['sip']}, "
                 f"voice on ports {rtp}"
                 + (", and anything the phones mark as voice."
                    if mangle.get("dscp") else "."))
    state = cur.get("state") or {}
    if state.get("ft"):
        lines.append(f"FastTrack: {len(state['ft'])} rule(s) switched off by "
                     f"the dashboard; they come back on when you switch "
                     f"this off.")
    if not cur.get("marker") or state.get("lost"):
        lines.append("⚠ The record of what this switched off went missing "
                     "at some point, so switching it off may not turn every "
                     "FastTrack rule back on: check Winbox → IP → Firewall → "
                     "Filter Rules afterwards.")
    if state.get("alg"):
        lines.append("The SIP helper was switched off by the dashboard and "
                     "comes back on when you switch this off.")
    lines += warnings(cur, cfg)
    return lines


def warnings(cur: dict, cfg) -> list:
    """What keeps calls from getting priority, while it is switched on."""
    out = []
    tree, mangle = cur.get("tree", {}), cur.get("mangle", {})
    parent_row = tree.get("q-parent") or {}
    parent = str(parent_row.get("parent", "") or "")
    up = rate_bps(parent_row.get("max-limit"))
    if any(not as_bool(r.get("disabled")) for r in cur.get("fasttrack", [])):
        out.append("⚠ A FastTrack rule is switched on again, so calls skip "
                   "the queues: preview and apply again to switch it off.")
    broken = [r for r in list(tree.values()) + list(mangle.values())
              if as_bool(r.get("disabled"))]
    if broken or as_bool(parent_row.get("invalid")):
        out.append("⚠ Part of this is switched off or not working on the "
                   "router: preview and apply again to repair it.")
    others = [i for i in cur.get("link_ifaces", [])
              if _norm(i) != _norm(parent)]
    if others:
        out.append(f"⚠ Only {parent} is shaped: while the router uses "
                   f"{', '.join(others)}, calls get no priority.")
    active = cur.get("active_iface", "")
    if active and parent and _norm(active) != _norm(parent):
        out.append(f"⚠ Internet traffic is going out through {active} right "
                   f"now, not {parent}: calls get no priority until it is "
                   f"back on {parent}.")
    vias = [v for v in cur.get("policy_via", []) if _norm(v) != _norm(parent)]
    if vias:
        out.append(f"⚠ The WAN tab sends some devices out through "
                   f"{', '.join(vias)}: their calls get no priority.")
    foreign = cur.get("foreign_mangle", [])
    if any(_text(r.get("action")) == "mark-connection"
           and not as_bool(r.get("disabled")) for r in foreign):
        out.append("⚠ This router has connection-marking rules of its own; "
                   "a connection they mark first is not recognised as a "
                   "call.")
    marks = sorted({_text(r.get("new-packet-mark")) for r in foreign
                    if _text(r.get("action")) == "mark-packet"
                    and not as_bool(r.get("disabled"))} - {""})
    if marks:
        out.append(f"⚠ Traffic the router's own rules mark as "
                   f"{', '.join(marks)} goes around the priority queues.")
    if up > 0:
        slow = []
        for q in cur.get("simple", []):
            if as_bool(q.get("disabled")) or as_bool(q.get("dynamic")):
                continue
            q_up = rate_bps(str(q.get("max-limit", "")).partition("/")[0])
            if 0 < q_up < up:
                slow.append(str(q.get("name", "?")))
        if slow:
            out.append(f"⚠ Speed limits {', '.join(slow[:3])}"
                       + (" and others" if len(slow) > 3 else "")
                       + ": a call from a device they cover waits in that "
                         "limit first. Keep phones out of them.")
    if cur.get("cpu", -1) >= 80:
        out.append(f"⚠ The processor is at {cur['cpu']}%: with FastTrack off "
                   f"it handles every packet itself. Check System → "
                   f"Resources at a busy time.")
    if _norm(cur.get("board")).startswith("crs"):
        out.append("⚠ This is a CRS switch: with FastTrack off its hardware "
                   "offloading stops, which costs more processor time.")
    return out
