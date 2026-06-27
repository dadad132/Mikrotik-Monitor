"""Web dashboard + JSON API + Prometheus endpoint, with multi-user auth.

Runs as a separate process from `mikromon run` (they share the metrics DB and
state.json). When an `auth_db` is configured, every page requires a login and
all data is filtered to the devices the logged-in user is allowed to see, so
users never see each other's routers. Admins manage users from /admin.

Endpoints:
  GET  /                 dashboard (scoped to the user's devices)
  GET  /login  POST      login form / authenticate
  GET  /logout           end session
  GET  /admin  POST .../ user management (admins only)
  GET  /api/devices      JSON, scoped
  GET  /api/series?...   JSON time-series (device must be permitted)
  GET  /metrics          Prometheus (admin session, or ?token=/Bearer metrics_token)
  GET  /health           "ok"
"""
from __future__ import annotations

import html
import json
import logging
import math
import os
import re
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from .auth import AuthStore
from .config import DEFAULT_CHECKS
from .metrics import MetricsStore
from .util import human_bps
from .web_shared import (
    esc, _BRAND, _REVERT_MINUTES, _PAGE_CSS,
    _nav, _who, _header, _page,
)
from .web_auth import (
    _render_login, _render_signup, _render_account,
    _render_admin, _device_chips, _ADMIN_JS,
)

_CLIENT_SOURCES = ["dhcp", "wireless", "arp", "hotspot"]

log = logging.getLogger(__name__)

_PROM_SAFE = re.compile(r"[^a-zA-Z0-9_]")
_COOKIE = "mikromon_session"
_SESSION_TTL = 12 * 3600


# ============================ data assembly ================================
def _load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"devices": {}}


def _problems(conditions: dict) -> list:
    out = []
    for key, cond in (conditions or {}).items():
        if cond.get("status") == "problem" or cond.get("level") in ("warn", "crit"):
            out.append({"key": key, "since": cond.get("since"),
                        "level": cond.get("level", "problem")})
    return out


def _device_view(store, state, name) -> dict:
    latest = store.latest(name)
    dnode = state.get("devices", {}).get(name, {})
    conditions = dnode.get("conditions", {})
    facts = dnode.get("facts", {})
    metrics, throughput = {}, {}
    for (metric, label), rec in latest.items():
        if metric in ("rx_bps", "tx_bps"):
            throughput.setdefault(label, {})[metric] = rec["value"]
        else:
            metrics[metric] = rec["value"]
    up = metrics.get("up")
    if up is None:
        rc = conditions.get("reachability", {})
        up = 0 if rc.get("status") == "problem" else 1
    problems = _problems(conditions)
    keys = {p["key"] for p in problems}
    if not up or "internet_down" in keys:
        wan_health = "down"
    elif "wan_failover" in keys:
        wan_health = "partial"
    else:
        wan_health = "full"
    return {"device": name, "up": int(up), "metrics": metrics,
            "throughput": throughput, "problems": problems,
            "facts": facts, "wan_health": wan_health}


def _known_devices(store, state) -> list:
    return sorted(set(store.devices()) | set(state.get("devices", {}).keys()))


def _visible_device_names(store, state, ds) -> set:
    """Which devices the dashboard / inventory / device pages may show.

    Web-managed mode (`devices_db` set, so `ds` is given): the devices DB is the
    single source of truth — show EXACTLY what's in the Devices tab, nothing
    more. A device deleted there vanishes immediately, even if stale samples or
    saved state linger (those get swept by the delete itself and by the engine's
    next poll). This is why a removed device no longer haunts the dashboard.

    YAML mode (no `devices_db`, `ds` is None): fall back to anything that has
    metrics or saved state, since there is no managed inventory to defer to."""
    if ds is not None:
        return set(ds.names())
    return set(_known_devices(store, state))


def _device_has_data(d) -> bool:
    """True if a device has anything real to show — telemetry, a recorded
    problem (e.g. offline), or inventory facts. Devices with NO data at all
    (added but never successfully polled) are hidden from the dashboard."""
    return bool(d.get("metrics") or d.get("problems") or d.get("facts"))


def _all_devices(store, state, allowed=None) -> list:
    names = _known_devices(store, state)
    if allowed is not None:
        names = [n for n in names if n in allowed]
    return [_device_view(store, state, n) for n in names]


# ============================ rendering ====================================
def _throughput_chart(rx_pts, tx_pts, width=284) -> str:
    """SVG throughput chart: RX (blue) + TX (orange) lines, time axis, peak marker."""
    all_vals = [v for _, v in rx_pts + tx_pts]
    if not all_vals:
        return ""
    plot_h = 52
    pad_t, pad_b = 14, 22
    total_h = plot_h + pad_t + pad_b
    now_t = time.time()
    win = 3600.0
    since_t = now_t - win
    hi = max(all_vals) or 1.0

    def xp(ts):
        return max(0.0, min(float(width), (ts - since_t) / win * width))

    def yp(v):
        return pad_t + plot_h - v / hi * plot_h

    def polyline(pts, color):
        visible = [(ts, v) for ts, v in pts if since_t - 120 <= ts <= now_t + 60]
        if len(visible) < 2:
            return ""
        coords = " ".join(f"{xp(ts):.1f},{yp(v):.1f}" for ts, v in visible)
        return (f'<polyline fill="none" stroke="{color}" stroke-width="1.5" '
                f'stroke-linejoin="round" stroke-linecap="round" points="{coords}"/>')

    # grid lines at 25 / 50 / 75 %
    grid = "".join(
        f'<line x1="0" y1="{yp(hi * f):.1f}" x2="{width}" y2="{yp(hi * f):.1f}" '
        f'stroke="#f1f5f9" stroke-width="1"/>'
        for f in (0.25, 0.5, 0.75, 1.0))

    # peak marker (RX only)
    peak_html = ""
    if rx_pts:
        peak_ts, peak_v = max(rx_pts, key=lambda p: p[1])
        if peak_v > 0 and since_t <= peak_ts <= now_t:
            px, py = xp(peak_ts), yp(peak_v)
            t_s = time.localtime(peak_ts)
            t_lbl = f"{t_s.tm_hour:02d}:{t_s.tm_min:02d}"
            v_lbl = human_bps(peak_v)
            # place label left-of-marker on right half, right-of-marker on left half
            if px >= width / 2:
                anch, label_x = "end", min(px - 4, float(width) - 2)
            else:
                anch, label_x = "start", max(px + 4, 2.0)
            peak_html = (
                f'<line x1="{px:.1f}" y1="{pad_t}" x2="{px:.1f}" y2="{pad_t + plot_h}" '
                f'stroke="#2563eb" stroke-width="0.8" stroke-dasharray="3,2" opacity="0.45"/>'
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="#2563eb"/>'
                f'<text x="{label_x:.1f}" y="{pad_t - 3}" text-anchor="{anch}" '
                f'font-size="9" fill="#2563eb" font-family="system-ui,sans-serif">'
                f'{t_lbl} {v_lbl}</text>')

    # x-axis
    axis = (f'<line x1="0" y1="{pad_t + plot_h + 1}" x2="{width}" '
            f'y2="{pad_t + plot_h + 1}" stroke="#e2e8f0" stroke-width="1"/>')
    for mins_ago, lbl in [(60, "-1h"), (45, "-45m"), (30, "-30m"), (15, "-15m"), (0, "now")]:
        lx = xp(now_t - mins_ago * 60)
        anch = "start" if mins_ago == 60 else ("end" if mins_ago == 0 else "middle")
        axis += (
            f'<line x1="{lx:.1f}" y1="{pad_t + plot_h}" x2="{lx:.1f}" '
            f'y2="{pad_t + plot_h + 3}" stroke="#cbd5e1" stroke-width="1"/>'
            f'<text x="{lx:.1f}" y="{pad_t + plot_h + 14}" text-anchor="{anch}" '
            f'font-size="9" fill="#94a3b8" font-family="system-ui,sans-serif">{lbl}</text>')

    return (
        f'<svg viewBox="0 0 {width} {total_h}" width="{width}" height="{total_h}" '
        f'style="display:block">'
        f'{grid}'
        f'{axis}'
        f'{polyline(rx_pts, "#2563eb")}'
        f'{polyline(tx_pts, "#f97316")}'
        f'{peak_html}'
        f'</svg>'
    )


# _PAGE_CSS, _nav, _who, _header, _page — imported from web_shared

def _severity(d) -> str:
    """Worst-first ordering key: offline = crit, any problem = warn, else ok."""
    if not d["up"]:
        return "crit"
    return "warn" if d["problems"] else "ok"


# How recent a config change must be to be blamed for a router going offline.
_CHANGE_BLAME_MINUTES = 10
# How many OTHER routers must be down at the same time to call it a wider outage.
_AREA_OUTAGE_MIN = 2


def _diagnose(up, internet_down, mins_since_change, others_down):
    """Best-effort verdict for WHY a device looks unhealthy, so the owner can
    tell a self-inflicted change from an ISP/area problem. Returns
    (kind, message) or None when there's nothing to flag.

      * "change"   — went down right after a config push (likely the push)
      * "internet" — router is up but its own WAN/uplink is down (ISP)
      * "area"     — several routers down at once (wider/regional outage)
      * "offline"  — down, but nothing points to a cause
    """
    if up and not internet_down:
        return None
    if not up:
        if others_down >= _AREA_OUTAGE_MIN:
            return ("area",
                    f"{others_down} other routers are offline at the same time — "
                    "this looks like a wider network or ISP outage in the area, "
                    "not a change you made. Wait for the upstream to recover.")
        if mins_since_change is not None \
                and mins_since_change <= _CHANGE_BLAME_MINUTES:
            return ("change",
                    f"This router went unreachable about {mins_since_change} min "
                    "after a configuration change was pushed to it — that change "
                    "is the most likely cause. If Safe mode was on it auto-reverts "
                    f"within {_REVERT_MINUTES} minutes; otherwise restore the latest backup from "
                    "Maintenance → Backups.")
        return ("offline",
                "The router isn't responding and nothing points to a recent "
                "change or a wider outage — most likely its power, the device "
                "itself, or its internet uplink being down.")
    return ("internet",
            "The router itself is reachable, but its internet / WAN link is down "
            "— that's an upstream (ISP) problem, not a configuration change.")


def _diagnosis_box(diag) -> str:
    if not diag:
        return ""
    kind, msg = diag
    color = {"change": "#dc2626", "internet": "#0369a1", "area": "#7c3aed",
             "offline": "#b45309"}.get(kind, "#475569")
    return (f'<div class="box" style="border-left:4px solid {color}">'
            f'<h2>What\'s likely wrong</h2><p>{esc(msg)}</p></div>')


def _wan_unhealthy(d) -> bool:
    keys = {p["key"] for p in d["problems"]}
    return (not d["up"]) or any("wan" in k or "internet" in k for k in keys)


def _fleet_summary(devs) -> dict:
    """At-a-glance NOC counters derived from the live device views."""
    total = len(devs)
    online = sum(1 for d in devs if d["up"])
    alerts = sum(len(d["problems"]) for d in devs)
    wan_bad = sum(1 for d in devs if _wan_unhealthy(d))
    lat = [d["metrics"]["latency_ms"] for d in devs if "latency_ms" in d["metrics"]]
    vpns = [d["metrics"]["vpn_up"] for d in devs if "vpn_up" in d["metrics"]]
    return {
        "total": total, "online": online, "offline": total - online,
        "alerts": alerts, "wan_ok": total - wan_bad, "wan_bad": wan_bad,
        "latency": (sum(lat) / len(lat)) if lat else None,
        "vpns": int(sum(vpns)) if vpns else None,
    }


def _tile(num, lbl, cls="", filt=None) -> str:
    click = ' click" onclick="setf(\'%s\')' % filt if filt else ""
    return (f'<div class="tile {cls}{click}"><div class="num">{num}</div>'
            f'<div class="lbl">{lbl}</div></div>')


# ----- SVG charts (pure-stdlib, no JS libraries) ---------------------------
def _donut(title, segments, size=128) -> str:
    """A donut chart. `segments` = list of (label, value, color)."""
    total = sum(v for _, v, _ in segments)
    r, sw = size / 2 - 12, 13
    cx = cy = size / 2
    circ = 2 * math.pi * r
    arcs, offset = [], 0.0
    track = (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
             f'stroke="#e5e7eb" stroke-width="{sw}"/>')
    for _label, val, color in segments:
        if val <= 0:
            continue
        dash = (val / total) * circ if total else 0
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{sw}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>')
        offset += dash
    center = (f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" '
              f'font-size="26" font-weight="700" fill="#0f172a">{total}</text>'
              f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="10" '
              f'fill="#64748b">total</text>')
    legend = "".join(
        f'<div class="lg"><span class="sw" style="background:{color}"></span>'
        f'{esc(lbl)} <b>{val}</b></div>' for lbl, val, color in segments)
    return (f'<div class="chart"><div class="ct">{esc(title)}</div>'
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            f'{track}{"".join(arcs)}{center}</svg>'
            f'<div class="legend">{legend}</div></div>')


def _gauge(label, pct, unit="%", good_high=False) -> str:
    """A horizontal gauge bar, colored by how alarming the value is."""
    pct = max(0, min(100, pct))
    bad = (pct < 20) if good_high else (pct > 85)
    warn = (pct < 40) if good_high else (pct > 65)
    color = "#dc2626" if bad else ("#d97706" if warn else "#16a34a")
    return (f'<div class="gauge"><div class="gl">{esc(label)}'
            f'<span>{pct:.0f}{unit}</span></div>'
            f'<div class="gbar"><i style="width:{pct:.0f}%;background:{color}"></i>'
            f'</div></div>')


def _version_panel(devs) -> str:
    counts = {}
    for d in devs:
        ver = d["facts"].get("version") or "unknown"
        counts[ver] = counts.get(ver, 0) + 1
    total = sum(counts.values()) or 1
    rows = []
    for ver, n in sorted(counts.items(), key=lambda kv: kv[0], reverse=True):
        old = ver[:1] in ("5", "6")  # pre-v7 → prompt upgrade
        color = "#d97706" if old else "#2563eb"
        tag = ' <span class="up">upgrade</span>' if old else ""
        rows.append(
            f'<div class="vrow"><div class="vlabel">RouterOS {esc(ver)}{tag}</div>'
            f'<div class="vbar"><i style="width:{n / total * 100:.0f}%;'
            f'background:{color}"></i></div><div class="vn">{n}</div></div>')
    return (f'<div class="chart wide"><div class="ct">RouterOS versions</div>'
            f'<div class="vlist">{"".join(rows) or "<p class=muted>No data yet</p>"}'
            f'</div></div>')


def _render_noc_charts(devs) -> str:
    online = sum(1 for d in devs if d["up"])
    status = [("Online", online, "#16a34a"), ("Offline", len(devs) - online, "#dc2626")]
    sev = {"ok": 0, "warn": 0, "crit": 0}
    wan = {"full": 0, "partial": 0, "down": 0}
    for d in devs:
        sev[_severity(d)] += 1
        wan[d["wan_health"]] += 1
    health = [("Normal", sev["ok"], "#16a34a"), ("Warning", sev["warn"], "#d97706"),
              ("Error", sev["crit"], "#dc2626")]
    failover = [("Full WAN", wan["full"], "#16a34a"),
                ("On backup", wan["partial"], "#d97706"),
                ("No WAN", wan["down"], "#dc2626")]
    return (f'<div class="charts">{_donut("Device status", status)}'
            f'{_donut("Device health", health)}'
            f'{_donut("Failover health", failover)}'
            f'{_version_panel(devs)}</div>')


def _render_noc_bar(s) -> str:
    health = "green" if s["wan_bad"] == 0 else ("red" if s["offline"] else "amber")
    lat = f'{s["latency"]:.0f} ms' if s["latency"] is not None else "—"
    vpns = s["vpns"] if s["vpns"] is not None else "—"
    return (
        '<div class="noc">'
        + _tile(s["total"], "Devices", filt="all")
        + _tile(s["online"], "Online", "green", filt="all")
        + _tile(s["offline"], "Offline", "red" if s["offline"] else "", filt="offline")
        + _tile(s["alerts"], "Active alerts",
                "amber" if s["alerts"] else "", filt="problems")
        + _tile(f'{s["wan_ok"]}/{s["total"]}', "WAN healthy", health)
        + _tile(lat, "Avg latency",
                "" if s["latency"] is not None else "planned")
        + _tile(vpns, "VPN tunnels",
                "green" if s["vpns"] else "planned")
        + "</div>")


_DASH_JS = """
<script>
 var q=document.getElementById('q');
 function apply(){
   var t=(q&&q.value||'').toLowerCase();
   var f=document.body.getAttribute('data-filter')||'all';
   var n=0;
   document.querySelectorAll('.card').forEach(function(c){
     var nm=c.getAttribute('data-name'), sv=c.getAttribute('data-sev');
     var show=!t||nm.indexOf(t)>=0;
     if(show&&f==='problems') show=sv!=='ok';
     if(show&&f==='offline') show=sv==='crit';
     c.style.display=show?'':'none'; if(show)n++;
   });
   var e=document.getElementById('empty'); if(e)e.style.display=n?'none':'';
 }
 function setf(f){
   document.body.setAttribute('data-filter',f);
   try{sessionStorage.setItem('flt',f);}catch(e){}
   document.querySelectorAll('.fbtn').forEach(function(b){
     b.classList.toggle('on',b.getAttribute('data-f')===f);});
   apply();
 }
 if(q) q.addEventListener('input',apply);
 var saved='all'; try{saved=sessionStorage.getItem('flt')||'all';}catch(e){}
 setf(saved);
</script>"""


def _render_dashboard(store, state, user=None, allowed=None) -> str:
    devs = sorted((d for d in _all_devices(store, state, allowed)
                   if _device_has_data(d)),
                  key=lambda d: ({"crit": 0, "warn": 1, "ok": 2}[_severity(d)],
                                 d["device"].lower()))
    summary = _fleet_summary(devs)
    cards = []
    for d in devs:
        up = d["up"]
        sev = _severity(d)
        dot = "#16a34a" if up else "#dc2626"
        # Compact dashboard: just the device name + an online/offline dot. The
        # full telemetry (CPU/RAM/throughput/problems) lives on the device page.
        cls = "card name-only" + ("" if sev == "ok" else f" {sev}")
        link = f'/device?name={quote(d["device"])}'
        cards.append(f'<div class="{cls}" data-name="{html.escape(d["device"].lower())}"'
                     f' data-sev="{sev}"><h2><span class="dot" style="background:'
                     f'{dot}"></span><a href="{link}">{html.escape(d["device"])}</a>'
                     f'<span class="state">'
                     f'{"ONLINE" if up else "OFFLINE"}</span></h2></div>')
    grid = "".join(cards) or "<p style='padding:20px'>No devices to show.</p>"
    fbar = ('<div class="fbar"><input id="q" placeholder="Filter devices by name…">'
            '<button class="fbtn" data-f="all" onclick="setf(\'all\')">All</button>'
            '<button class="fbtn" data-f="problems" onclick="setf(\'problems\')">'
            'Problems</button>'
            '<button class="fbtn" data-f="offline" onclick="setf(\'offline\')">'
            'Offline</button></div>') if devs else ""
    empty = ('<p id="empty" class="muted" style="padding:0 20px;display:none">'
             'No devices match this filter.</p>')
    charts = _render_noc_charts(devs) if devs else ""
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="10"><title>{esc(_BRAND)}</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'{_render_noc_bar(summary)}{charts}{fbar}'
            f'<div class="grid">{grid}</div>{empty}{_DASH_JS}</body></html>')


# Flat tabs on the device bar.
_DEVICE_TABS = ["Overview", "Provision", "WAN", "Security",
                "DNS", "Queues", "Port forwarding",
                "Tunnel", "Scripts"]
_MAINT_ITEMS = [("Update", "update"), ("Backups", "backups")]
# label -> url slug (all tabs are wired to the engine now)
_LIVE_TABS = {"Overview": "", "Provision": "provision",
              "WAN": "sdwan",
              "Security": "security", "Restrict access": "harden",
              "DNS": "nextdns", "Queues": "qos", "QoS": "qos", "Port forwarding": "portfwd",
              "Interfaces": "interfaces", "Remote access": "remote",
              "Tunnel": "tunnel", "Scripts": "scripts",
              "Update": "update", "Backups": "backups"}
# tabs that WRITE to the router (admins only); Overview is read-only
_ADMIN_TABS = {"provision", "sdwan", "security", "harden", "nextdns",
               "qos", "portfwd", "remote", "tunnel", "scripts",
               "update", "backups", "interfaces"}


def _device_tabbar(name, active, is_admin=True, csrf="") -> str:
    q = quote(name)
    out = []
    for t in _DEVICE_TABS:
        slug = _LIVE_TABS.get(t)
        live = slug is not None and not (slug in _ADMIN_TABS and not is_admin)
        if live:
            href = f"/device?name={q}" + (f"&tab={slug}" if slug else "")
            cls = "on" if (slug or "overview") == active else ""
            out.append(f'<a class="{cls}" href="{href}">{esc(t)}</a>')
        else:
            out.append(f'<a class="soon">{esc(t)}</a>')
    if is_admin:
        out.append(_maintenance_menu(name, active, csrf))
    return f'<div class="tabs">{"".join(out)}</div>'


def _maintenance_menu(name, active, csrf) -> str:
    q = quote(name)
    on = active in {slug for _l, slug in _MAINT_ITEMS}
    items = "".join(
        f'<a class="{"on" if slug == active else ""}" '
        f'href="/device?name={q}&tab={slug}">{esc(label)}</a>'
        for label, slug in _MAINT_ITEMS)
    reboot = (
        f'<form method="POST" action="/device/reboot" onsubmit="return confirm('
        f"'Reboot {esc(name)} now? It will go offline for ~1–2 minutes.')\">"
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="hidden" name="device" value="{esc(name)}">'
        f'<button type="submit" class="reboot">Reboot</button></form>'
    ) if csrf else ""
    return (f'<div class="tabdrop"><a class="dropbtn{" on" if on else ""}">'
            f'Maintenance</a><div class="tabmenu">{items}{reboot}</div></div>')


def _facts_strip(f) -> str:
    items = [("Model", f.get("model", "—")), ("RouterOS", f.get("version", "—")),
             ("Identity", f.get("identity", "—")), ("Serial", f.get("serial", "—")),
             ("Host / IP", f.get("host", "—")), ("Uptime", f.get("uptime", "—"))]
    cells = "".join(f'<div class="fact"><div class="k">{esc(k)}</div>'
                    f'<div class="val">{esc(str(v))}</div></div>' for k, v in items)
    return f'<div class="box"><div class="factgrid">{cells}</div></div>'


def _render_inventory(store, state, user, allowed) -> str:
    devs = sorted(_all_devices(store, state, allowed),
                  key=lambda d: d["device"].lower())
    rows = []
    for d in devs:
        f = d["facts"]
        sev = _severity(d)
        dot = {"ok": "#16a34a", "warn": "#d97706", "crit": "#dc2626"}[sev]
        ver = f.get("version", "—")
        old = ver[:1] in ("5", "6")
        ver_html = (esc(ver) + (
            f' <a class="up" href="/device?name={quote(d["device"])}&tab=update">'
            f'upgrade</a>' if old else ""))
        wl = f.get("wan_links") or []
        links = ", ".join(esc(x) for x in wl) if wl else '<span class="muted">—</span>'
        link = f'/device?name={quote(d["device"])}'
        rows.append(
            f'<tr><td><span class="dot" style="background:{dot}"></span> '
            f'<a href="{link}"><b>{esc(d["device"])}</b></a></td>'
            f'<td>{esc(f.get("model", "—"))}</td><td>{ver_html}</td>'
            f'<td class="muted">{esc(f.get("serial", "—"))}</td>'
            f'<td class="muted">{esc(f.get("host", "—"))}</td>'
            f'<td>{links}</td>'
            f'<td><span class="badge {sev}">{"online" if d["up"] else "offline"}'
            f'</span></td></tr>')
    body = "".join(rows) or ('<tr><td colspan="7" class="muted">No devices to '
                             'show yet.</td></tr>')
    inner = (
        f'<div class="wrap" style="max-width:1100px"><h1>Device inventory</h1>'
        f'<div class="box">'
        f'<input id="iq" placeholder="Search by name, model, version, serial…" '
        f'style="width:100%;margin-bottom:12px" '
        f'onkeyup="invFilter()"><table id="invt">'
        f'<tr><th>Name</th><th>Model</th><th>RouterOS</th><th>Serial</th>'
        f'<th>Host / IP</th><th>WAN uplinks</th><th>Status</th></tr>{body}'
        f'</table></div></div>'
        '<script>function invFilter(){var t=document.getElementById("iq")'
        '.value.toLowerCase();document.querySelectorAll("#invt tr").forEach('
        'function(r,i){if(i===0)return;r.style.display='
        'r.textContent.toLowerCase().indexOf(t)>=0?"":"none";});}</script>')
    return _page("Inventory", _header(user, "/inventory") + inner)


def _render_device(store, state, name, user, csrf="",
                   last_change=None, others_down=0) -> str:
    d = _device_view(store, state, name)
    f = d["facts"]
    sev = _severity(d)
    badge = {"ok": ("ok", "Healthy"), "warn": ("warn", "Warning"),
             "crit": ("crit", "Offline / Error")}[sev]
    m = d["metrics"]
    q = quote(name)

    tabbar = _device_tabbar(name, "overview", AuthStore.is_admin(user or {}), csrf)

    # ── speedometer gauge (220° arc, 0% at lower-left, 100% at lower-right) ──
    def gauge_card(label, val_str, pct, color):
        p = max(0.0, min(0.999, pct))
        cx, cy = 56, 60      # SVG circle centre
        r, sw = 42, 11       # radius, track stroke width

        # Angles in standard math convention (CCW from east, y-up).
        # Arc spans 220° symmetrically: starts at 200° (lower-left ≈ 7:40 on a
        # clock), sweeps CW over the top (90°), ends at 340° (lower-right ≈ 4:20).
        # 50% lands exactly at 90° = the top.  CW = decreasing standard angle.
        a_start = math.radians(200)
        a_end   = math.radians(340)
        span    = math.radians(220)

        def pt(a):
            return cx + r * math.cos(a), cy - r * math.sin(a)

        sx, sy = pt(a_start)
        ex, ey = pt(a_end)

        # Background track: one large CW arc (220° > 180° → large-arc=1, sweep=1)
        bg_d = f"M {sx:.2f} {sy:.2f} A {r} {r} 0 1 1 {ex:.2f} {ey:.2f}"

        # Rounded end-cap discs so the butt-capped track has tidy terminations
        dot = sw // 2
        caps = (f'<circle cx="{sx:.2f}" cy="{sy:.2f}" r="{dot}" fill="#e8edf5"/>'
                f'<circle cx="{ex:.2f}" cy="{ey:.2f}" r="{dot}" fill="#e8edf5"/>')

        # Fill arc: CW from start, spanning p × 220°
        fg = ""
        if p > 0:
            a_tip = a_start - p * span          # CW = decreasing angle
            tx, ty = pt(a_tip)
            large = 1 if p * span > math.pi else 0   # > 180° needs large-arc=1
            fg = (f'<path d="M {sx:.2f} {sy:.2f} '
                  f'A {r} {r} 0 {large} 1 {tx:.2f} {ty:.2f}" '
                  f'stroke="{color}" stroke-width="{sw}" fill="none" '
                  f'stroke-linecap="round"/>')

        # ViewBox: full width, just tall enough to show arc bottom + a sliver
        vb_w = cx * 2                        # 112
        vb_h = int(sy + dot + 6)             # ≈ 85

        return (
            f'<div class="box" style="padding:16px 12px 14px;text-align:center">'
            f'<div style="font-size:10px;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:.08em;color:#94a3b8;margin-bottom:8px">{label}</div>'
            f'<svg viewBox="0 0 {vb_w} {vb_h}" width="{vb_w}" height="{vb_h}" '
            f'style="display:block;margin:0 auto">'
            f'<path d="{bg_d}" stroke="#e8edf5" stroke-width="{sw}" fill="none" '
            f'stroke-linecap="butt"/>'
            f'{caps}'
            f'{fg}'
            # Value sits at the arc centre — like a speedometer readout
            f'<text x="{cx}" y="{cy}" text-anchor="middle" '
            f'dominant-baseline="middle" font-size="20" font-weight="700" '
            f'fill="{color}" font-family="system-ui,sans-serif">{val_str}</text>'
            f'</svg></div>'
        )

    # ── top facts bar ──────────────────────────────────────────────────────────
    fi = []
    if f.get("uptime"):   fi.append(("Uptime",       f["uptime"]))
    if f.get("model"):    fi.append(("Model",         f["model"]))
    if f.get("serial"):   fi.append(("Serial",        f["serial"]))
    if f.get("host"):     fi.append(("Management IP", f["host"]))
    if f.get("version"):  fi.append(("RouterOS",      f["version"]))
    if "temp_c" in m:     fi.append(("Temperature",   f'{m["temp_c"]:.0f}°C'))
    fact_cells = "".join(
        f'<div style="flex:1;min-width:130px;padding:11px 16px;'
        f'border-right:1px solid #f0f4f8">'
        f'<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;'
        f'letter-spacing:.06em;margin-bottom:3px">{esc(k)}</div>'
        f'<div style="font-size:13px;font-weight:600;color:#0f172a">{esc(v)}</div>'
        f'</div>'
        for k, v in fi)
    facts_bar = (f'<div style="display:flex;flex-wrap:wrap;background:#fff;'
                 f'border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08);'
                 f'margin-bottom:16px;overflow:hidden">{fact_cells}</div>')

    # ── left column: gauges ────────────────────────────────────────────────────
    left_col = ""
    if "cpu" in m:
        cpu = m["cpu"]
        cc = "#dc2626" if cpu > 80 else "#f97316"
        left_col += gauge_card("CPU Usage", f"{cpu:.0f}%", cpu / 100, cc)
    if "mem_free_pct" in m:
        mu = 100 - m["mem_free_pct"]
        mc = "#dc2626" if mu > 85 else "#3b82f6"
        left_col += gauge_card("Memory", f"{mu:.0f}%", mu / 100, mc)
    if f.get("disk_used_pct") is not None:
        du = f["disk_used_pct"]
        dc = "#dc2626" if du > 85 else "#8b5cf6"
        left_col += gauge_card("Disk", f"{du:.0f}%", du / 100, dc)
    if "temp_c" in m:
        t = m["temp_c"]
        tc = "#dc2626" if t > 70 else "#f97316" if t > 50 else "#16a34a"
        left_col += (f'<div class="box" style="padding:18px 14px;text-align:center">'
                     f'<div style="font-size:11px;font-weight:600;text-transform:uppercase;'
                     f'letter-spacing:.06em;color:#94a3b8;margin-bottom:12px">'
                     f'Temperature</div>'
                     f'<div style="font-size:38px;font-weight:700;color:{tc};'
                     f'padding:8px 0">{t:.0f}°C</div></div>')
    if "client_count" in m:
        left_col += (f'<div class="box" style="padding:18px 14px;text-align:center">'
                     f'<div style="font-size:11px;font-weight:600;text-transform:uppercase;'
                     f'letter-spacing:.06em;color:#94a3b8;margin-bottom:12px">'
                     f'Connected</div>'
                     f'<div style="font-size:38px;font-weight:700;color:#2563eb;'
                     f'padding:8px 0">{m["client_count"]:.0f}</div>'
                     f'<div style="font-size:12px;color:#94a3b8;margin-top:4px">'
                     f'devices</div></div>')
    if not left_col:
        left_col = '<div class="box"><p class="muted">No telemetry yet.</p></div>'

    # ── center: WAN status circles ─────────────────────────────────────────────
    wl = f.get("wan_links") or []
    circles_html = ""
    for i, wname in enumerate(wl):
        if not d["up"]:
            cc = "#dc2626"
            label = "Offline"
        elif d["wan_health"] == "partial" and i == 0:
            cc = "#f97316"
            label = "Failover"
        else:
            cc = "#16a34a"
            label = "Online"
        circles_html += (
            f'<div style="display:flex;flex-direction:column;align-items:center;gap:8px">'
            f'<div style="width:52px;height:52px;border-radius:50%;'
            f'border:3px solid {cc};background:{cc}18;display:flex;'
            f'align-items:center;justify-content:center;font-size:20px;'
            f'font-weight:700;color:{cc}">{i + 1}</div>'
            f'<div style="font-size:12px;color:#334155;font-weight:500;text-align:center;'
            f'max-width:80px;word-break:break-all">{esc(wname)}</div>'
            f'<div style="font-size:11px;color:{cc};font-weight:600">{label}</div>'
            f'</div>')
    if circles_html:
        center_wan = (f'<div class="box"><h2 style="margin-bottom:14px">WAN Status</h2>'
                      f'<div style="display:flex;gap:24px;flex-wrap:wrap">'
                      f'{circles_html}</div></div>')
    else:
        center_wan = (f'<div class="box"><h2>WAN Status</h2>'
                      f'<p class="muted">No WAN uplinks configured.</p></div>')

    # ── center: throughput sparklines ──────────────────────────────────────────
    spark_rows = ""
    _since = time.time() - 3600
    for iface, t in sorted(d["throughput"].items()):
        rx_pts = store.series(name, "rx_bps", label=iface, since=_since)
        tx_pts = store.series(name, "tx_bps", label=iface, since=_since)
        sp = _throughput_chart(rx_pts, tx_pts)
        # find peak across the same series we just fetched
        peak_rx = max((v for _, v in rx_pts), default=0)
        spark_rows += (
            f'<div style="margin-bottom:14px;padding-bottom:14px;'
            f'border-bottom:1px solid #f1f5f9">'
            f'<div style="display:flex;justify-content:space-between;'
            f'align-items:center;margin-bottom:6px">'
            f'<b style="font-size:13px;color:#334155">{esc(iface)}</b>'
            f'<span style="font-size:12px">'
            f'<span style="color:#2563eb">&darr;&nbsp;{human_bps(t.get("rx_bps", 0))}</span>'
            f'&nbsp;&nbsp;'
            f'<span style="color:#f97316">&uarr;&nbsp;{human_bps(t.get("tx_bps", 0))}</span>'
            f'&nbsp;&nbsp;'
            f'<span style="color:#94a3b8">peak&nbsp;{human_bps(peak_rx)}</span>'
            f'</span></div>'
            f'{sp}</div>')
    center_throughput = (
        f'<div class="box"><h2 style="margin-bottom:14px">Network Throughput '
        f'<span style="font-size:12px;color:#94a3b8;font-weight:400">'
        f'(last hour)</span></h2>'
        f'{spark_rows or "<p class=muted>No throughput data yet.</p>"}'
        f'</div>')

    # ── right: online availability (24 h bar chart) ────────────────────────────
    avail_box = ""
    up_series = store.series(name, "up", since=time.time() - 86400)
    if up_series:
        n = len(up_series)
        up_n = sum(1 for _, v in up_series if v > 0)
        avail = (up_n / n * 100) if n else 100.0
        acol = "#16a34a" if avail >= 99 else "#d97706" if avail >= 90 else "#dc2626"
        now_t = time.time()
        buckets: list = [[] for _ in range(24)]
        for ts, v in up_series:
            h = int((now_t - ts) / 3600)
            if 0 <= h < 24:
                buckets[23 - h].append(v)
        bars_h = "".join(
            '<div style="flex:1;height:28px;background:'
            + ("#e2e8f0" if not b
               else "#16a34a" if (sum(b) / len(b)) >= 0.9
               else "#dc2626" if (sum(b) / len(b)) < 0.1
               else "#f97316")
            + ';border-radius:2px;min-width:2px"></div>'
            for b in buckets)
        avail_box = (
            f'<div class="box"><h2 style="margin-bottom:12px">Online Availability</h2>'
            f'<div style="display:flex;gap:2px;margin-bottom:8px">{bars_h}</div>'
            f'<div style="display:flex;justify-content:space-between;'
            f'font-size:12px;color:#64748b">'
            f'<span>24h ago</span>'
            f'<span style="font-weight:700;color:{acol}">{avail:.1f}% uptime</span>'
            f'<span>now</span></div></div>')

    # ── right: active problems ─────────────────────────────────────────────────
    _lc = {"warn": "#d97706", "crit": "#dc2626"}
    if d["problems"]:
        phtml = "".join(
            f'<div style="padding:8px 10px;margin:4px 0;border-radius:6px;'
            f'border-left:3px solid {_lc.get(str(p["level"]), "#dc2626")};'
            f'background:{_lc.get(str(p["level"]), "#dc2626")}15">'
            f'<span style="font-weight:600;font-size:13px;'
            f'color:{_lc.get(str(p["level"]), "#dc2626")}">'
            f'{esc(p["key"])}</span></div>'
            for p in d["problems"])
    else:
        phtml = ('<p style="color:#16a34a;font-weight:600;padding:4px 0">'
                 'No active problems</p>')
    probs_box = (f'<div class="box"><h2 style="margin-bottom:12px">'
                 f'Active Problems</h2>{phtml}</div>')

    # ── right: diagnosis ───────────────────────────────────────────────────────
    internet_down = any(p["key"] in ("internet_down", "wan_failover")
                        for p in d["problems"])
    mins = (max(0, int((time.time() - last_change) / 60)) if last_change else None)
    diag_html = _diagnosis_box(_diagnose(d["up"], internet_down, mins, others_down))

    iface_card = (f'<div class="box"><h2>Interfaces</h2>'
                  f'<p class="muted">Port list, VLANs, bridges and IP addresses.</p>'
                  f'<a class="btn ghost" href="/device?name={q}&tab=interfaces">'
                  f'View interfaces</a></div>')

    # ── assemble ───────────────────────────────────────────────────────────────
    inner = (
        f'<div class="wrap" style="max-width:1300px">'
        f'<h1 style="display:flex;align-items:center;gap:12px">{esc(name)}'
        f'<span class="badge {badge[0]}">{badge[1]}</span></h1>'
        f'{tabbar}{facts_bar}'
        f'<div style="display:grid;grid-template-columns:220px 1fr 280px;'
        f'gap:16px;align-items:start">'
        f'<div style="display:flex;flex-direction:column;gap:16px">{left_col}</div>'
        f'<div style="display:flex;flex-direction:column;gap:16px">'
        f'{center_wan}{center_throughput}</div>'
        f'<div style="display:flex;flex-direction:column;gap:16px">'
        f'{avail_box}{probs_box}{diag_html or ""}{iface_card}</div>'
        f'</div>'
        f'<p style="margin-top:16px"><a href="/">&larr; dashboard</a></p>'
        f'</div>')
    return _page(esc(name), _header(user, "/") + inner)


def _access_box(name, csrf, hub_host, tunnel_ip, creds, grants) -> str:
    """On-demand remote access through the hub. `grants` maps kind -> active
    grant dict (or None). Each kind shows either an Open button or the live
    connection details + a countdown + Close while a grant is active."""
    if not csrf:
        return ""
    q = esc(name)
    if not hub_host:
        return ""
    if not tunnel_ip:
        return (f'<div class="box"><h2>Remote access</h2>'
                f'<p class="muted">This device has no hub tunnel yet. Provision it '
                f'(Maintenance &rarr; Provision) so it dials home, then you can '
                f'open WebFig / Winbox here.</p></div>')
    u, pw = esc(creds.get("user", "")), esc(creds.get("pwd", ""))

    def row(kind, label, how):
        g = grants.get(kind)
        if g:
            port = g["port"]
            exp = int(g["expires"])
            if kind == "webfig":
                target = (f'<a href="https://{esc(hub_host)}:{port}" '
                          f'target="_blank" rel="noopener">'
                          f'https://{esc(hub_host)}:{port}</a>')
            else:
                target = (f'<code>{esc(hub_host)}:{port}</code> '
                          f'<span class="muted">(enter in the Winbox client)</span>')
            close = (f'<form method="POST" action="/device/access" '
                     f'style="display:inline">'
                     f'<input type="hidden" name="csrf" value="{csrf}">'
                     f'<input type="hidden" name="device" value="{q}">'
                     f'<input type="hidden" name="kind" value="{kind}">'
                     f'<input type="hidden" name="action" value="close">'
                     f'<button class="btn ghost" type="submit">Close</button></form>')
            return (f'<div class="linkrow" style="display:block">'
                    f'<b>{label}</b> &nbsp;{target} &nbsp;'
                    f'<span class="muted" data-expires="{exp}">'
                    f'expires in …</span> &nbsp;{close}<br>'
                    f'<span class="muted">{how} &middot; sign in with '
                    f'<b>{u}</b> / <b>{pw}</b></span></div>')
        return (f'<div class="linkrow" style="display:block">'
                f'<form method="POST" action="/device/access" '
                f'style="display:inline">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="device" value="{q}">'
                f'<input type="hidden" name="kind" value="{kind}">'
                f'<input type="hidden" name="action" value="open">'
                f'<button class="btn" type="submit">Open {label}</button></form> '
                f'<span class="muted">{how}</span></div>')

    return (f'<div class="box"><h2>Remote access <span class="muted" '
            f'style="font-weight:400;font-size:13px">(through the hub — no public '
            f'IP on the router)</span></h2>'
            f'{row("webfig", "WebFig", "Browser management over HTTPS")}'
            f'{row("winbox", "Winbox", "Desktop Winbox client (raw TCP)")}'
            f'<p class="muted" style="margin:10px 0 0">Access opens for a few '
            f'minutes then closes itself, so the router is never left exposed.</p>'
            f'{_ACCESS_JS}</div>')


_ACCESS_JS = """
<script>
 // Live "expires in mm:ss" countdown for any open access grant.
 function mmTickAccess(){
   document.querySelectorAll('[data-expires]').forEach(function(el){
     var left=Math.max(0, (+el.getAttribute('data-expires'))*1000 - Date.now());
     var s=Math.floor(left/1000), m=Math.floor(s/60);
     el.textContent = left ? ('expires in '+m+':'+('0'+(s%60)).slice(-2))
                           : 'expired — refresh';
   });
 }
 mmTickAccess(); setInterval(mmTickAccess, 1000);
</script>"""


def _device_forget_box(name, csrf) -> str:
    """Admin-only: remove this device from the dashboard entirely — deletes it
    from the devices DB (if managed) and purges its metrics + saved state, so a
    stale/orphan device that's stuck on the dashboard can be cleared from here."""
    if not csrf:
        return ""
    q = esc(name)
    return (f'<div class="box" style="border-left:4px solid #dc2626">'
            f'<h2>Remove from dashboard</h2>'
            f'<p class="muted">Deletes <b>{q}</b> from the device list and purges '
            f'its metrics history and saved state.</p>'
            f'<p class="muted">Before deleting, mikromon will attempt to connect '
            f'to the router and <b>remove the WireGuard hub tunnel and monitoring '
            f'user</b> so it stops dialling home. This requires the push/admin '
            f'credentials to be set on the Devices page.</p>'
            f'<form method="POST" action="/device/forget" '
            f'onsubmit="return confirm(\'Remove {q} from the dashboard and '
            f'decommission its router config?\')">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="device" value="{q}">'
            f'<div class="actions"><button class="btn red" type="submit">'
            f'Decommission &amp; remove</button></div></form></div>')


def _render_offboard_page(name, result, back_url, user) -> str:
    """Summary page shown after a device is deleted, describing what was cleaned
    up on the router (or why cleanup could not run)."""
    q = esc(name)
    steps = result.get("steps", [])
    conn_err = result.get("error")
    _icon = {"ok": "✓", "warn": "⚠", "error": "✗", "fixed": "✓"}
    _col = {"ok": "#16a34a", "warn": "#d97706", "error": "#dc2626",
            "fixed": "#16a34a"}
    if conn_err:
        router_box = (
            f'<div class="box" style="border-left:4px solid #d97706;margin-top:16px">'
            f'<b style="color:#d97706">Router could not be reached</b>'
            f'<p class="muted" style="margin-top:6px">{esc(conn_err)}</p>'
            f'<p class="muted">The device has been removed from the dashboard. '
            f'You will need to manually log in to the router and:<br>'
            f'&nbsp;• Remove the <code>mikromon</code> WireGuard interface<br>'
            f'&nbsp;• Delete the <code>{esc(result.get("username","mkmonitor"))}'
            f'</code> user</p></div>')
    elif steps:
        rows = "".join(
            f'<div style="padding:3px 0;color:{_col.get(s["level"],"#374151")}">'
            f'<b>{_icon.get(s["level"], "·")}</b>&nbsp;{esc(s["msg"])}</div>'
            for s in steps)
        has_err = any(s["level"] == "error" for s in steps)
        border = "#dc2626" if has_err else "#16a34a"
        router_box = (
            f'<div class="box" style="border-left:4px solid {border};margin-top:16px">'
            f'<b>Router cleanup</b>'
            f'<div style="margin-top:8px;font-size:14px">{rows}</div>'
            + (f'<p class="muted" style="margin-top:8px">Some steps failed — '
               f'check the router manually if the tunnel or user persists.</p>'
               if has_err else "")
            + f'</div>')
    else:
        router_box = ""
    body = (
        f'<div class="wrap">'
        f'<h1 style="margin-bottom:6px">{q} removed</h1>'
        f'<p class="muted">Removed from the dashboard and its metrics history '
        f'cleared.</p>'
        f'{router_box}'
        f'<div class="actions" style="margin-top:20px">'
        f'<a class="btn" href="{esc(back_url)}">Done</a>'
        f'</div></div>')
    return _page(f"{q} · Removed", _header(user, "/") + body)


_PWALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
# Special characters that are safe inside a RouterOS double-quoted string and
# paste cleanly into a terminal script. Deliberately EXCLUDES " \ $ (string
# terminator, escape char, and RouterOS variable-expansion trigger) plus spaces.
_PW_SPECIALS = "!#%*+-=?@^_.:~"


def _gen_password(n=20) -> str:
    """A strong password (letters, digits and script-safe specials) that pastes
    cleanly into a RouterOS terminal script. Ambiguous characters (0/O/1/l) are
    omitted; the result always contains lower, upper, a digit and a special."""
    pool = _PWALPHABET + _PW_SPECIALS
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in _PW_SPECIALS for c in pw)):
            return pw


def _user_slug(s) -> str:
    out = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(s or "").strip()).strip("-")
    return out[:32] or "mikromon"


# --- hub (WireGuard server) settings + per-device peer registry -------------
# The dashboard runs ON the Ubuntu server, so it can auto-detect the server's
# own IP, generate each device's WireGuard keypair, and write the device's peer
# into a peers file that the hub's wg0 reads (set up by deploy/install.sh). That
# way the provisioning script is filled with the SERVER's real details and the
# hub already accepts the peer — no manual entry, no mismatch.
_HUB_SUBNET_DEFAULT = "10.10.0.0/24"
_WG_PEERS_DEFAULT = "/etc/wireguard/wg-peers.conf"
_WG_PORT_DEFAULT = "51820"


def _detect_server_ip() -> str:
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa: BLE001
        return ""


def _hub_path(devices_db) -> str:
    d = (os.path.dirname(devices_db) if devices_db else "") or "."
    return os.path.join(d, "hub.json")


def _access_grants_path(devices_db) -> str:
    d = (os.path.dirname(devices_db) if devices_db else "") or "."
    return os.path.join(d, "access-grants.json")


def _hub_tunnel_ip(hub) -> str:
    """The hub's own address inside the tunnel (the .1 of the WG subnet) — what
    a router pings to prove it still has management connectivity."""
    subnet = (hub or {}).get("subnet", _HUB_SUBNET_DEFAULT)
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return f"{base}.1"


def _device_tunnel_ip(name, devices_db) -> str:
    """The device's tunnel IP (10.10.0.x) — from its saved host if that's
    already a tunnel address, else from the hub lease table in hub.json."""
    hub = _hub_load(_hub_path(devices_db))
    meta = (hub.get("leases_meta") or {}).get(name) or {}
    if meta.get("ip"):
        return meta["ip"]
    lease = (hub.get("leases") or {}).get(name)
    if lease:
        return lease
    return ""


def _hub_load(path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001 — missing/invalid -> fresh
        return {}


def _hub_save(path, data) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:  # noqa: BLE001 — best effort
        log.warning("could not save hub settings to %s", path)


def _alloc_tunnel_ip(hub, name) -> str:
    """Random stable per-device tunnel IP across the 10.10.x.y /16 space.

    Third octet (0-254) and fourth octet (2-254) are both chosen randomly so
    sequential device registration produces no detectable pattern.  The pool
    has ~64k addresses; if random probing keeps hitting collisions (dense
    allocation) it falls back to a shuffled exhaustive scan.
    """
    import random
    leases = hub.setdefault("leases", {})
    if name in leases:
        return leases[name]
    subnet = hub.get("subnet", _HUB_SUBNET_DEFAULT)
    base = ".".join(subnet.split("/")[0].split(".")[:2])   # "10.10"
    hub_ip = f"{base}.0.1"
    used = set(leases.values()) | {hub_ip}
    # Fast path: random probing succeeds almost instantly when allocation is sparse
    for _ in range(500):
        ip = f"{base}.{random.randint(0, 254)}.{random.randint(2, 254)}"
        if ip not in used:
            leases[name] = ip
            return ip
    # Fallback: shuffled exhaustive scan for dense allocations
    thirds = list(range(0, 255))
    random.shuffle(thirds)
    for third in thirds:
        fourths = list(range(2, 255))
        random.shuffle(fourths)
        for fourth in fourths:
            ip = f"{base}.{third}.{fourth}"
            if ip not in used:
                leases[name] = ip
                return ip
    return f"{base}.0.2"


def _wg_keypair():
    """Generate a WireGuard keypair via the `wg` CLI (wireguard-tools on the
    Ubuntu hub). Returns (private, public) or (None, error)."""
    import subprocess
    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True,
                              check=True).stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                             text=True, check=True).stdout.strip()
        return priv, pub
    except Exception as exc:  # noqa: BLE001 — wg missing / failed
        return None, str(exc)


def _write_wg_peers(path, leases):
    """Rebuild the hub's WireGuard peers file from every device lease
    ({name: {ip, pubkey}}). The hub's wg0 includes this file. Returns (ok, err)."""
    blocks = []
    for nm, lease in sorted(leases.items()):
        pub, ip = lease.get("pubkey"), lease.get("ip")
        if pub and ip:
            blocks.append(f"[Peer]\n# {nm}\nPublicKey = {pub}\n"
                          f"AllowedIPs = {ip}/32")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n\n".join(blocks) + ("\n" if blocks else ""))
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _provision_script(name, raw, pwuser, pwd, *,
                      hub_ip="", hub_port="51820", hub_pubkey="", wg_priv="",
                      tunnel_ip="", subnet="", harden=True, enable_api=True,
                      lock_api=True) -> str:
    """A one-paste RouterOS bootstrap script that is SAFE on an already-configured
    router: every step is guarded so it only ADDS what is missing and never
    resets existing config. The WireGuard dial-home tunnel needs RouterOS 7.1+."""
    u = pwuser
    L = []

    def a(s=""):
        L.append(s)

    def user_block(uname, upwd, group):
        # create if missing, else just (re)set password + group — idempotent
        a(":if ([:len [/user find name=" + uname + "]] = 0) do={")
        a('  /user add name=' + uname + ' password="' + upwd + '" group=' + group
          + ' comment="mikromon-managed"')
        a("} else={")
        a('  /user set [/user find name=' + uname + '] password="' + upwd
          + '" group=' + group)
        a("}")

    a(f"# === mikromon provisioning for {name} ===")
    a("# Safe to paste on a NEW *or* an already-configured router: it only ADDS")
    a("# what is missing and never resets your existing config. The WireGuard")
    a("# tunnel block needs RouterOS 7.1+.")
    a("")
    a("# 1) the mikromon management user (full access - used for both monitoring")
    a("#    and config-push; one login keeps things simple)")
    user_block(u, pwd, "full")
    if enable_api:
        a("")
        a("# 2) make sure the API is reachable for mikromon (idempotent)")
        a("/ip service set api disabled=no")
    a("")
    a("# 3) baseline defaults - ONLY on an unconfigured (factory) unit")
    a(':if ([/system identity get name] = "MikroTik") do={')
    a('  /system identity set name="' + name + '"')
    a("  # add any other fresh-unit defaults you want here (NTP, DNS, etc.)")
    a("}")
    if harden:
        a("")
        a("# 4) hardening - turn off legacy plaintext services (idempotent)")
        a("/ip service set telnet disabled=yes")
        a("/ip service set ftp disabled=yes")
    if hub_ip and hub_pubkey and wg_priv and tunnel_ip:
        port = hub_port or "51820"
        _sn_base = ".".join((subnet or _HUB_SUBNET_DEFAULT).split("/")[0].split(".")[:2])
        net = f"{_sn_base}.0.0/16"   # cover all sub-/24 ranges so hub is reachable
        a("")
        a("# 5) WireGuard dial-home tunnel (RouterOS 7.1+) - add only if absent")
        a(":if ([:len [/interface wireguard find name=mikromon]] = 0) do={")
        a('  /interface wireguard add name=mikromon listen-port=13231 '
          'private-key="' + wg_priv + '" comment="mikromon:tunnel:if"')
        a("}")
        a(":if ([:len [/ip address find interface=mikromon]] = 0) do={")
        a("  /ip address add address=" + tunnel_ip + "/16 interface=mikromon "
          'comment="mikromon:tunnel:addr"')
        a("}")
        a(":if ([:len [/interface wireguard peers find "
          "interface=mikromon]] = 0) do={")
        a('  /interface wireguard peers add interface=mikromon public-key="'
          + hub_pubkey + '" endpoint-address=' + hub_ip + " endpoint-port="
          + port + " allowed-address=" + net
          + ' persistent-keepalive=25s comment="mikromon:tunnel:hub"')
        a("}")
        a(":if ([:len [/ip firewall filter find "
          'comment="mikromon:tunnel:fw"]] = 0) do={')
        a('  /ip firewall filter add chain=input in-interface=mikromon '
          'action=accept comment="mikromon:tunnel:fw"')
        a("  # put it FIRST so a default input drop can't block tunnel access")
        a('  /ip firewall filter move [find comment="mikromon:tunnel:fw"] '
          "destination=0")
        a("}")
        a("")
        a("# 5b) make sure WebFig + Winbox are on, so you can manage this router")
        a("#     remotely over the tunnel (from the dashboard's Remote access)")
        a("/ip service set www disabled=no")
        a("/ip service set winbox disabled=no")
        if lock_api:
            a("")
            a("# 6) Lock the API to the VPN tunnel - no public exposure. WireGuard")
            a("#    already encrypts the tunnel, so binding the API services to the")
            a("#    tunnel subnet removes them from the internet entirely (no")
            a("#    API-SSL/cert needed - the tunnel is the encryption). Runs LAST")
            a("#    so you don't lock yourself out mid-script: you reach mikromon")
            a("#    over the tunnel afterwards, on plain API (8728).")
            a("/ip service set api address=" + net)
            a("/ip service set api-ssl address=" + net)
    a("")
    a('/log info "mikromon provisioning done"')
    return "\n".join(L)


_REVEAL_JS = ("<script>function mmReveal(b,id){var i=document.getElementById(id);"
              "if(i.type==='password'){i.type='text';b.textContent='Hide';}"
              "else{i.type='password';b.textContent='Show';}}</script>")


def _plain_field(lbl, val):
    return (f'<div class="f"><label class="f">{esc(lbl)}</label>'
            f'<input readonly value="{esc(val or "")}" onclick="this.select()" '
            f'style="width:100%;font-family:ui-monospace,monospace"></div>')


def _secret_field(lbl, val, fid):
    """A read-only credential field that is masked until you click Show."""
    return (f'<div class="f"><label class="f">{esc(lbl)}</label>'
            f'<div style="display:flex;gap:6px">'
            f'<input id="{fid}" type="password" readonly value="{esc(val or "")}" '
            f'onclick="this.select()" '
            f'style="flex:1;font-family:ui-monospace,monospace">'
            f'<button type="button" class="btn ghost" '
            f'onclick="mmReveal(this,\'{fid}\')">Show</button></div></div>')


def _render_device_provision(name, user, raw, csrf, *, hub_ip="", script=None,
                             creds=None, msg="", error="") -> str:
    tabbar = _device_tabbar(name, "provision", True, csrf)
    q = quote(name)
    banner = (f'<div class="box" style="border-left:4px solid #16a34a">{esc(msg)}'
              f'</div>' if msg else "")
    err = (f'<div class="box" style="border-left:4px solid #dc2626">{esc(error)}'
           f'</div>' if error else "")
    pwuser = ((raw or {}).get("push_username") or (raw or {}).get("username")
              or "mkmonitor")
    intro = ('<p class="muted" style="margin:-6px 0 14px">Generate a one-paste '
             'script for a new router. It creates a management user with a strong '
             'password (saved here), optionally enables the API, and adds a '
             '<b>WireGuard</b> dial-home tunnel. The hub IP + keys are filled from '
             '<b>this</b> server, and the device is registered as a WireGuard peer '
             'on the hub automatically — no manual entry. (WireGuard tunnel needs '
             'RouterOS 7.1+.)</p>')
    form = (
        f'<div class="box"><h2>Generate provisioning script</h2>'
        f'<form method="POST" action="/device/provision">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="device" value="{esc(name)}">'
        f'<div class="fields">'
        f'<input type="hidden" name="pwuser" value="{esc(pwuser)}">'
        f'<div class="f"><label class="f">Username <span class="muted">'
        f'(the {esc(_BRAND)} management login)</span></label>'
        f'<div class="muted" style="padding:7px 0"><code>{esc(pwuser)}</code> '
        f'<span style="font-size:11px">— fixed, not editable</span></div></div>'
        f'<div class="f"><label class="f">Dial-home tunnel</label>'
        f'<select name="transport">'
        f'<option value="wg" selected>WireGuard (RouterOS 7.1+)</option>'
        f'<option value="">None (just user + API)</option></select></div>'
        f'<div class="f"><label class="f">Hub address (this server\'s IP)</label>'
        f'<input type="hidden" name="hub" value="{esc(hub_ip)}">'
        f'<div class="muted" style="padding:7px 0">'
        f'<code>{esc(hub_ip) or "(auto-detected)"}</code> '
        f'<span style="font-size:11px">— set by the server, not editable</span>'
        f'</div></div>'
        f'<div class="f full"><div class="chkrow">'
        f'<label class="chk"><input type="checkbox" '
        f'name="enable_api" value="1" class="switch" checked> Enable the API '
        f'service (needed for {esc(_BRAND)} to connect over the API)</label>'
        f'<label class="chk"><input type="checkbox" '
        f'name="lock_api" value="1" class="switch" checked> Lock the API to the '
        f'VPN tunnel (no public exposure — WireGuard encrypts it, so no API-SSL '
        f'needed; needs the tunnel above)</label>'
        f'</div></div>'
        f'</div>'
        f'<div class="actions" style="margin-top:12px">'
        f'<button class="btn ghost" type="submit" name="auto" value="0">Generate '
        f'script instead</button> '
        f'<button class="btn" type="submit" name="auto" value="1">Provision now '
        f'(connect &amp; apply)</button></div></form>'
        f'<p class="muted"><b>Provision now</b> connects to the router over its '
        f'API (using the Host + login from the Devices page) and sets everything '
        f'up automatically — no terminal, nothing to paste. Use it for a router '
        f'you can reach now (e.g. on the LAN with its default login). <b>Generate '
        f'script</b> is the fallback when you can\'t reach it directly. Either way '
        f'a NEW key + password is created and the peer registered on the '
        f'server.</p></div>')
    out = ""
    c = creds or {}
    if script is not None or c.get("applied"):
        ip = c.get("ip", "")
        if ip and c.get("reg_ok"):
            srv = (f'<p class="ok">✓ Registered as a WireGuard peer on this server '
                   f'— the router connects to <code>{esc(c.get("hub", ""))}</code> '
                   f'and gets tunnel IP <code>{esc(ip)}</code>. The device Host was '
                   f'set to <code>{esc(ip)}</code>.</p>')
        elif c.get("no_hub_key"):
            srv = ('<p style="color:#b91c1c">⚠ The WireGuard hub isn\'t set up on '
                   'this server yet (no hub key). Run <code>sudo bash '
                   'deploy/install.sh</code> on the server, then re-run.</p>')
        elif ip:
            srv = (f'<p style="color:#b91c1c">⚠ Could not write the hub peers file '
                   f'(<code>{esc(c.get("peers_path", ""))}</code>: '
                   f'{esc(c.get("reg_err", ""))}). Add this peer on the server:</p>'
                   f'<pre style="{_PRE}">[Peer]\n# {esc(name)}\nPublicKey = '
                   f'{esc(c.get("pubkey", ""))}\nAllowedIPs = {esc(ip)}/32</pre>')
        else:
            srv = ""
        if c.get("applied"):
            head = ('<h2>Provisioned over the API ✓</h2>'
                    f'<p class="muted">{esc(_BRAND)} connected to the router and applied '
                    'everything — nothing to paste. The saved login is below.</p>')
            body = srv
        else:
            head = ('<h2>Provisioning script — paste into the new router</h2>'
                    '<p class="muted">Open the router in WinBox/WebFig → <b>New '
                    'Terminal</b>, paste this, press Enter.</p>')
            body = (f'<pre style="{_PRE}">{esc(script)}</pre>{srv}'
                    f'<p class="muted">The script sets the password in plain text — '
                    f'paste it, then clear your clipboard.</p>')
        out = (f'<div class="box" style="border-left:4px solid #16a34a">{head}{body}'
               f'<div class="fields">'
               f'{_secret_field("Username", c.get("user", ""), "su")}'
               f'{_secret_field("Password", c.get("pwd", ""), "sp")}'
               f'</div></div>')
    inner = (f'<div class="wrap" style="max-width:1100px">'
             f'<h1>{esc(name)} &middot; Provision &amp; connect</h1>{tabbar}{intro}'
             f'{banner}{err}{form}{out}'
             f'<p><a href="/device?name={q}">&larr; overview</a></p></div>'
             f'{_REVEAL_JS}')
    return _page(esc(name) + " · Provision", _header(user, "/") + inner)


def _fmt_backup_date(bname, ctime) -> str:
    """A human-friendly created date. mikromon backups embed a YYYYMMDD-HHMMSS
    stamp in the name (reliable, server-time), so prefer that; otherwise fall
    back to the router's own creation-time (which depends on the router clock)."""
    m = re.search(r"(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", bname or "")
    if m:
        y, mo, d, hh, mm, _ss = m.groups()
        return f"{y}-{mo}-{d} {hh}:{mm}"
    return str(ctime or "—")


def _render_device_backups(name, user, facts, csrf, *, backups=None,
                           error="", msg="", dry_plan=None) -> str:
    """The Backups tab — wired to the real config-push engine (admin-only)."""
    tabbar = _device_tabbar(name, "backups", True, csrf)
    q = quote(name)
    banner = (f'<div class="box" style="border-left:4px solid #16a34a">{esc(msg)}'
              f'</div>' if msg else "")
    err = (f'<div class="box" style="border-left:4px solid #dc2626">'
           f'<b>Could not reach the router:</b> {esc(error)}<br>'
           f'<span class="muted">Check the host, that the API service is '
           f'enabled, and the read-write push user/password on the Devices '
           f'page.</span></div>' if error else "")

    if dry_plan is not None:
        # Step 2: show the dry-run plan and a confirm button.
        resolved = dry_plan.ops[0].params.get("name", "") if dry_plan.ops else ""
        action = (f'<div class="box"><h2>Dry run — nothing has been written yet</h2>'
                  f'<pre style="background:#f8fafc;padding:12px;border-radius:8px;'
                  f'white-space:pre-wrap">{esc(dry_plan.diff_text())}</pre>'
                  f'<form method="POST" action="/device/backup" class="actions">'
                  f'<input type="hidden" name="csrf" value="{csrf}">'
                  f'<input type="hidden" name="device" value="{esc(name)}">'
                  f'<input type="hidden" name="bkname" value="{esc(resolved)}">'
                  f'<input type="hidden" name="apply" value="1">'
                  f'<button class="btn" type="submit">Confirm &amp; create on the '
                  f'router</button>'
                  f'<a class="btn ghost" href="/device?name={q}&tab=backups">Cancel'
                  f'</a></form></div>')
    else:
        # Step 1: list existing backups + a create form (which previews first).
        def _bk_btn(bname, action, label, cls, confirm):
            return (f'<form method="POST" action="/device/backup" class="inline" '
                    f'onsubmit="return confirm(\'{confirm}\')">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="device" value="{esc(name)}">'
                    f'<input type="hidden" name="bkname" value="{esc(bname)}">'
                    f'<input type="hidden" name="backup_action" value="{action}">'
                    f'<button class="btn {cls}" type="submit">{label}</button>'
                    f'</form>')
        rows = ""
        for b in (backups or []):
            bn = b["name"]
            acts = (_bk_btn(bn, "restore", "Restore", "",
                            f"Restore {bn}? This REBOOTS the router and replaces "
                            f"its config with this snapshot.")
                    + " " + _bk_btn(bn, "delete", "Delete", "ghost",
                                    f"Delete {bn} from the router?"))
            rows += (f'<tr><td><b>{esc(bn)}</b></td>'
                     f'<td class="muted">{esc(str(b.get("size", "")))}</td>'
                     f'<td class="muted">'
                     f'{esc(_fmt_backup_date(bn, b.get("time")))}</td>'
                     f'<td>{acts}</td></tr>')
        if not rows and not error:
            rows = '<tr><td colspan="4" class="muted">No backup files on the router yet.</td></tr>'
        table = (f'<div class="box"><h2>Restore points on the router</h2>'
                 f'<p class="muted">A backup is taken automatically before every '
                 f'change you push (named <code>before-&lt;feature&gt;-&lt;time&gt;'
                 f'</code>). If a change broke something, <b>Restore</b> the '
                 f'matching snapshot (reboots the router); once you\'ve confirmed a '
                 f'change is good, <b>Delete</b> its snapshot to keep this tidy.</p>'
                 f'<table><tr><th>File</th><th>Size</th><th>Created</th>'
                 f'<th>Actions</th></tr>{rows}</table></div>') if not error else ""
        create = (f'<div class="box"><h2>Create a backup</h2>'
                  f'<p class="muted">Creates a <code>.backup</code> file on the '
                  f'router — a safe, additive write. You will see a dry-run '
                  f'preview before anything is applied.</p>'
                  f'<form method="POST" action="/device/backup" class="actions">'
                  f'<input type="hidden" name="csrf" value="{csrf}">'
                  f'<input type="hidden" name="device" value="{esc(name)}">'
                  f'<input name="bkname" placeholder="backup name (optional)">'
                  f'<button class="btn" type="submit">Preview backup (dry-run)'
                  f'</button></form></div>')
        action = table + create

    inner = (f'<div class="wrap" style="max-width:1100px">'
             f'<h1>{esc(name)} &middot; Backups</h1>{tabbar}'
             f'{_facts_strip(facts)}{banner}{err}{action}'
             f'<p><a href="/device?name={q}">&larr; overview</a></p></div>')
    return _page(esc(name) + " · Backups", _header(user, "/") + inner)


# ---- generic feature tabs (SD-WAN / Security / NextDNS / QoS / …) ----------
_FEATURE_JS = """
<script>
 function pushAddRow(name){
   var t=document.getElementById('tmpl-'+name);
   var host=document.querySelector('#rows-'+name+' tbody')
            || document.getElementById('rows-'+name);
   host.appendChild(t.content.cloneNode(true));
 }
 // Move a table row up (dir<0) or down (dir>0). The form submits its inputs in
 // DOM order, so reordering rows here changes the saved priority order.
 function pushMoveRow(btn, dir){
   var tr=btn.closest('tr'), p=tr.parentNode;
   if(dir<0){ var prev=tr.previousElementSibling; if(prev) p.insertBefore(tr,prev); }
   else { var next=tr.nextElementSibling; if(next) p.insertBefore(next,tr); }
 }
 // Drag-and-drop reordering via the ⠿ handle. Delegated so dynamically-added
 // rows work too. Reordering the rows reorders the submitted inputs = priority.
 function mmInitDrag(){
   document.querySelectorAll('table.rowtbl tbody').forEach(function(tb){
     if(tb._dnd) return; tb._dnd=1;
     tb.addEventListener('dragstart', function(e){
       var h=e.target.closest('.draghandle'); if(!h) return;
       tb._drag=h.closest('tr'); if(tb._drag) tb._drag.style.opacity='0.4';
     });
     tb.addEventListener('dragend', function(){
       if(tb._drag){ tb._drag.style.opacity=''; tb._drag=null; }
     });
     tb.addEventListener('dragover', function(e){
       if(!tb._drag) return; e.preventDefault();
       var tr=e.target.closest('tr'); if(!tr || tr===tb._drag) return;
       var r=tr.getBoundingClientRect();
       tb.insertBefore(tb._drag,
         (e.clientY-r.top)/r.height > 0.5 ? tr.nextElementSibling : tr);
     });
   });
 }
 // Toggles sharing a data-exclusive group behave like radio buttons: switching
 // one ON turns the others in the same group OFF (e.g. only one DNS provider at
 // a time). Leaving them all off falls back to the manual field.
 function mmExclusive(){
   document.querySelectorAll('input[data-exclusive]').forEach(function(cb){
     if(cb._excl) return; cb._excl=1;
     cb.addEventListener('change', function(){
       if(!cb.checked) return;
       var g=cb.getAttribute('data-exclusive');
       document.querySelectorAll('input[data-exclusive="'+g+'"]').forEach(
         function(o){ if(o!==cb) o.checked=false; });
     });
   });
 }
 document.addEventListener('DOMContentLoaded', mmInitDrag);
 document.addEventListener('DOMContentLoaded', mmExclusive);
</script>"""


def _field_html(desc) -> str:
    t = desc.get("type")
    label = desc.get("label", "")
    hint = (f'<div class="muted" style="margin-top:3px">{desc["hint"]}</div>'
            if desc.get("hint") else "")
    if t == "toggle":
        ck = " checked" if desc.get("on") else ""
        d = (f'<div class="muted">{esc(desc["desc"])}</div>'
             if desc.get("desc") else "")
        # toggles sharing an "exclusive" group act like radios (only one on) — JS
        # mmExclusive() turns the others off when one is switched on.
        excl = (f' data-exclusive="{esc(desc["exclusive"])}"'
                if desc.get("exclusive") else "")
        return (f'<div class="f"><label class="chk"><input type="checkbox" '
                f'class="switch" name="{desc["name"]}" '
                f'value="{esc(desc["value"])}"{ck}{excl}> '
                f'<b>{esc(label)}</b></label>{d}</div>')
    if t == "text":
        return (f'<div class="f"><label class="f">{esc(label)}</label>'
                f'<input name="{desc["name"]}" value="{esc(desc.get("value",""))}" '
                f'placeholder="{esc(desc.get("placeholder",""))}" '
                f'style="width:100%">{hint}</div>')
    if t == "textarea":
        return (f'<div class="f full"><label class="f">{esc(label)}</label>'
                f'<textarea name="{desc["name"]}" rows="4" style="width:100%">'
                f'{esc(desc.get("value",""))}</textarea>{hint}</div>')
    if t == "select":
        opts = "".join(
            f'<option value="{esc(v)}"{" selected" if v == desc.get("value") else ""}>'
            f'{esc(lbl)}</option>' for v, lbl in desc["options"])
        return (f'<div class="f"><label class="f">{esc(label)}</label>'
                f'<select name="{desc["name"]}">{opts}</select>{hint}</div>')
    if t == "static":
        return (f'<div class="f full"><label class="f">{esc(label)}</label>'
                f'<div>{esc(desc.get("value",""))}</div>{hint}</div>')
    if t == "rows":
        cols = desc["cols"]
        name = desc["name"]
        ths = "".join(f"<th>{esc(lbl)}</th>" for _c, lbl, _ph in cols) + "<th></th>"

        def row_html(r):
            tds = "".join(
                f'<td><input name="{name}__{c}" placeholder="{esc(ph)}" '
                f'value="{esc((r or {}).get(c, ""))}" style="width:100%"></td>'
                for c, _lbl, ph in cols)
            return (f'<tr>{tds}<td><button type="button" class="btn ghost" '
                    f'title="remove row" onclick="this.closest(\'tr\').remove()">'
                    f'&times;</button></td></tr>')
        body = "".join(row_html(r) for r in desc.get("rows", [])) + row_html({})
        return (f'<div class="f full"><label class="f">{esc(label)}</label>'
                f'<table class="rowtbl" id="rows-{name}"><thead><tr>{ths}</tr>'
                f'</thead><tbody>{body}</tbody></table>'
                f'<button type="button" class="btn ghost" '
                f'onclick="pushAddRow(\'{name}\')" style="margin-top:6px">'
                f'+ Add row</button>{hint}'
                f'<template id="tmpl-{name}">{row_html({})}</template></div>')
    return ""


def _hidden_from_multi(multi, skip=("csrf", "apply")) -> str:
    out = []
    for k, vals in multi.items():
        if k in skip:
            continue
        for v in vals:
            out.append(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">')
    return "".join(out)


def _log_status_badge(status) -> str:
    cls = {"ok": "ok", "error": "crit", "preview": "warn",
           "rolled-back": "warn"}.get(status, "warn")
    return f'<span class="badge {cls}">{esc(status)}</span>'


def _recent_log_box(recent, device=None) -> str:
    if not recent:
        return ('<div class="box"><h2>Recent activity</h2>'
                '<p class="muted">No push activity logged yet.</p></div>')
    rows = ""
    for r in recent:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        dev = f'<td>{esc(r["device"])}</td>' if device is None else ""
        rows += (f'<tr><td class="muted">{when}</td>{dev}'
                 f'<td>{esc(r["feature"])}</td><td>{esc(r["mode"])}</td>'
                 f'<td>{_log_status_badge(r["status"])}</td>'
                 f'<td>{esc(r["summary"])}'
                 f'<details><summary class="muted">detail</summary>'
                 f'<pre style="white-space:pre-wrap;background:#f8fafc;padding:8px;'
                 f'border-radius:6px">{esc(r["detail"])}</pre></details></td></tr>')
    devh = "<th>Device</th>" if device is None else ""
    return (f'<div class="box"><h2>Recent activity</h2><table>'
            f'<tr><th>When</th>{devh}<th>Feature</th><th>Mode</th><th>Status</th>'
            f'<th>Summary</th></tr>{rows}</table></div>')


def _adopt_box(name, slug, feature, csrf, unmanaged) -> str:
    """List existing (unmanaged) rows on the router, with Adopt buttons."""
    if not unmanaged:
        return ""
    can_adopt = bool(feature.get("adopt"))
    rows = ""
    for u in unmanaged:
        if can_adopt:
            action = (f'<form method="POST" action="/device/adopt" class="inline">'
                      f'<input type="hidden" name="csrf" value="{csrf}">'
                      f'<input type="hidden" name="device" value="{esc(name)}">'
                      f'<input type="hidden" name="feature" value="{esc(slug)}">'
                      f'<input type="hidden" name="adopt_id" value="{esc(u["id"])}">'
                      f'<button class="btn ghost" type="submit">Adopt</button></form>')
        else:
            action = '<span class="muted">read-only</span>'
        rows += f'<tr><td>{esc(u["text"])}</td><td>{action}</td></tr>'
    note = (f"Adopt = bring a rule under {_BRAND} management (stamps a "
            "<code>mikromon:…</code> comment) so it appears in the editor above. "
            "Previewed and reversible." if can_adopt else
            "Shown for reference. Adopting these into an editable policy is coming "
            "next.")
    return (f'<div class="box"><h2>Existing on the router (unmanaged)</h2>'
            f'<p class="muted">{note}</p><table><tr><th>Rule</th><th></th></tr>'
            f'{rows}</table></div>')


_QUEUE_BUILDER_JS = '''<script>
function qbGen(){
  var from=parseInt(document.getElementById('qb-from').value)||40;
  var to=parseInt(document.getElementById('qb-to').value)||60;
  var pfx=document.getElementById('qb-pfx').value||'User';
  var dl=document.getElementById('qb-dl').value||'3';
  var ul=document.getElementById('qb-ul').value||'3';
  var base=document.getElementById('qb-base').value.trim();
  if(to<from)to=from;
  var lim=dl+'M/'+ul+'M';
  var L=['# Queue setup: '+pfx+'-'+from+' to '+pfx+'-'+to+', '+lim,
         '# Generated by MikroMon — review before applying',''];
  if(base){
    L.push('/queue simple');
    L.push(':for i from='+from+' to='+to+' do={');
    L.push('    add name=("'+pfx+'-$i") target=("'+base+'.$i") max-limit='+lim);
    L.push('    }');
  }else{
    L.push('# Auto-detect LAN subnet from bridge interface');
    L.push(':local subnet ""');
    L.push(':foreach a in=[/ip address find where interface~"bridge"] do={');
    L.push('  :if ($subnet="") do={');
    L.push('    :local addr [/ip address get $a address]');
    L.push('    :local ip [:pick $addr 0 [:find $addr "/"]]');
    L.push('    :local d1 [:find $ip "."]');
    L.push('    :local d2 [:find $ip "." ($d1+1)]');
    L.push('    :local d3 [:find $ip "." ($d2+1)]');
    L.push('    :set subnet [:pick $ip 0 $d3]');
    L.push('  }');
    L.push('}');
    L.push(':if ($subnet="") do={ :error "Could not detect bridge subnet" }');
    L.push('');
    L.push('/queue simple');
    L.push(':for i from='+from+' to='+to+' do={');
    L.push('    add name=("'+pfx+'-$i") target=($subnet . ".$i") max-limit='+lim);
    L.push('    }');
  }
  document.getElementById('qb-out').value=L.join('\n');
}
window.addEventListener('DOMContentLoaded',qbGen);
</script>'''


def _queue_script_box(name, csrf, facts=None) -> str:
    """Interactive queue setup builder shown on the Queues tab.
    Generates a RouterOS :for-loop script from form fields; submits via scripts pipeline."""
    qn = esc(name)
    base_attr = 'placeholder="leave blank to auto-detect"'
    return (
        f'<div class="box"><h2>Queue Setup Builder</h2>'
        f'<p class="muted">Set the IP range, name prefix, and speeds — the '
        f'RouterOS script is generated live below. Leave the LAN subnet blank '
        f'to auto-detect from the router\'s bridge interface at run time.</p>'
        f'<div class="fields">'
        f'<div class="f"><label class="f">Range from (host #)</label>'
        f'<input id="qb-from" type="number" min="1" max="254" value="40" oninput="qbGen()"></div>'
        f'<div class="f"><label class="f">Range to (host #)</label>'
        f'<input id="qb-to" type="number" min="1" max="254" value="60" oninput="qbGen()"></div>'
        f'<div class="f"><label class="f">Name prefix (e.g. User)</label>'
        f'<input id="qb-pfx" type="text" value="User" oninput="qbGen()"></div>'
        f'<div class="f"><label class="f">Download limit (Mbps)</label>'
        f'<input id="qb-dl" type="number" min="1" value="3" oninput="qbGen()"></div>'
        f'<div class="f"><label class="f">Upload limit (Mbps)</label>'
        f'<input id="qb-ul" type="number" min="1" value="3" oninput="qbGen()"></div>'
        f'<div class="f"><label class="f">LAN subnet (first 3 octets)</label>'
        f'<input id="qb-base" type="text" {base_attr} oninput="qbGen()"></div>'
        f'</div>'
        f'<hr style="margin:14px 0;border:none;border-top:1px solid #e2e8f0">'
        f'<form method="POST" action="/device/push">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="device" value="{qn}">'
        f'<input type="hidden" name="feature" value="scripts">'
        f'<div class="fields">'
        f'<div class="f"><label class="f">Script name</label>'
        f'<input name="new_name" value="queue-setup" placeholder="queue-setup"></div>'
        f'<div class="f full"><label class="f">'
        f'Generated RouterOS script (review before submitting)</label>'
        f'<textarea id="qb-out" name="new_source" rows="10"'
        f' style="width:100%;font-family:ui-monospace,Consolas,monospace;'
        f'font-size:13px;padding:8px;border:1px solid #cbd5e1;border-radius:7px"'
        f'></textarea></div>'
        f'</div>'
        f'<div class="actions" style="margin-top:12px">'
        f'<button class="btn" type="submit">Preview &amp; save script</button>'
        f'</div></form>'
        + _QUEUE_BUILDER_JS + '</div>'
    )


def _scripts_box(name, csrf, scripts) -> str:
    """List mikromon-managed /system scripts with Run and Remove buttons.

    Both actions POST to /device/push (so they get the dry-run -> confirm ->
    apply -> log pipeline) with a script_action + script_name."""
    q = esc(name)
    rows = ""
    for s in scripts:
        sn = esc(s.get("name", ""))
        src = s.get("source", "") or ""
        last = s.get("last-started", "")
        meta = (f'<span class="muted"> · last run {esc(last)}</span>' if last else "")

        def act(action, label, cls):
            return (f'<form method="POST" action="/device/push" class="inline">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="device" value="{q}">'
                    f'<input type="hidden" name="feature" value="scripts">'
                    f'<input type="hidden" name="script_action" value="{action}">'
                    f'<input type="hidden" name="script_name" value="{sn}">'
                    f'<button class="btn {cls}" type="submit">{label}</button></form>')
        rows += (f'<tr><td><b>{sn}</b>{meta}'
                 f'<details><summary class="muted">source</summary>'
                 f'<pre style="white-space:pre-wrap;background:#f8fafc;padding:8px;'
                 f'border-radius:6px">{esc(src)}</pre></details></td>'
                 f'<td style="white-space:nowrap">{act("run", "Run", "ghost")} '
                 f'{act("remove", "Remove", "ghost")}</td></tr>')
    if not rows:
        return ""
    return (f'<div class="box"><h2>Saved scripts on the router</h2>'
            f'<p class="muted">Run executes the script now; Remove deletes the '
            f'script entry. Both are previewed before anything happens. Note: '
            f'removing a script does not undo changes it already made — add an '
            f'undo script for that, or use the typed tabs for reversible rules.'
            f'</p><table><tr><th>Script</th><th></th></tr>{rows}</table></div>')


_PRE = ('white-space:pre-wrap;background:#f8fafc;padding:10px;border-radius:6px;'
        'font-family:ui-monospace,Consolas,monospace')


_WG_REPORT_STYLE = {
    "healthy":   ("#16a34a", "✓ Tunnel healthy"),
    "repaired":  ("#16a34a", "✓ Tunnel repaired"),
    "attention": ("#d97706", "⚠ Tunnel needs attention"),
    "failed":    ("#dc2626", "✗ Tunnel repair failed"),
}
_WG_STEP = {"ok": ("✓", "#16a34a"), "fixed": ("🔧", "#2563eb"),
            "warn": ("⚠", "#d97706"), "error": ("✗", "#dc2626")}


def _wg_repair_report_html(report) -> str:
    """Render a WireGuard self-repair report: overall status + every check, with
    what was auto-fixed and a clear message for anything that needs a human."""
    color, title = _WG_REPORT_STYLE.get(report.get("status"),
                                        ("#334155", "Tunnel report"))
    items = []
    for s in report.get("steps", []):
        icon, c = _WG_STEP.get(s.get("level"), ("•", "#334155"))
        items.append(f'<li style="margin:6px 0"><span style="color:{c};'
                     f'font-weight:bold">{icon}</span> {esc(s.get("msg", ""))}</li>')
    applied = report.get("applied", [])
    applied_html = (f'<p class="muted" style="margin:8px 0 0">Applied '
                    f'{len(applied)} automatic fix(es): {esc(", ".join(applied))}'
                    f'.</p>' if applied else "")
    return (f'<div class="box" style="border-left:4px solid {color}">'
            f'<h2 style="margin-top:0;color:{color}">{esc(title)}</h2>'
            f'<p class="muted" style="margin:0 0 8px">RouterOS '
            f'{esc(report.get("version", "?"))} — diagnosed the WireGuard '
            f'dial-home tunnel and applied any safe fixes.</p>'
            f'<ul style="list-style:none;padding:0;margin:0">{"".join(items)}</ul>'
            f'{applied_html}</div>')


def _hubtunnel_box(name, current, csrf="") -> str:
    """Hub-side (Ubuntu WireGuard server) setup help. deploy/install.sh sets this
    up automatically; the Provision tab registers each device as a peer."""
    wg = ("# Ubuntu hub - WireGuard server (deploy/install.sh does this for you):\n"
          "sudo apt install wireguard wireguard-tools\n"
          "# /etc/wireguard/wg0.conf — NO PostUp; peers are applied by\n"
          "#   mikromon-wg-reload.service (a separate systemd unit that runs\n"
          "#   outside wg-quick's AppArmor confinement):\n"
          "[Interface]\nPrivateKey = <hub private key>\nAddress = 10.10.0.1/24\n"
          "ListenPort = 51820")
    return (f'<div class="box"><h2>Hub (Ubuntu WireGuard server) setup</h2>'
            f'<p class="muted">Every device dials home with <b>WireGuard</b> '
            f'(needs RouterOS 7.1+). Run <code>sudo bash deploy/install.sh</code> '
            f"on your Ubuntu host — it installs WireGuard, makes the hub key, and "
            f'writes the hub\'s public key + IP where mikromon reads them. The '
            f'<b>Provision</b> tab then generates each router\'s keypair, registers '
            f'it as a peer on the hub, and fills the script automatically — no '
            f'manual steps. For reference, the hub interface looks like:</p>'
            f'<pre style="{_PRE}">{esc(wg)}</pre>'
            f'<p class="muted">After a device is up, set its <b>Host</b> (Devices '
            f'page) to its tunnel IP and use <b>Restrict access</b> to lock the API '
            f'to <code>10.10.0.0/24</code> and close the public port.</p></div>'
            + _wg_repair_box(name, csrf))


def _wg_repair_box(name, csrf) -> str:
    """A button that diagnoses the WireGuard tunnel on the router and self-repairs
    what it safely can, then shows a full report of what it found and fixed."""
    if not csrf:
        return ""
    q = esc(name)
    return (f'<div class="box"><h2>Diagnose &amp; self-repair the tunnel</h2>'
            f'<p class="muted">Checks the WireGuard dial-home tunnel on this '
            f'router — firmware support, the interface, the hub peer, keepalive '
            f'and the last handshake — fixes what it safely can (re-enables a '
            f'disabled interface, restores the keepalive), and reports clearly on '
            f'anything that needs you. The run is recorded in the activity log.</p>'
            f'<form method="POST" action="/device/wg-repair">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="device" value="{q}">'
            f'<div class="actions"><button class="btn" type="submit">'
            f'Diagnose &amp; repair now</button></div></form></div>')


def _update_box(name, csrf, current):
    """Returns (extra_html, extra_actions) for the update feature tab.
    extra_actions are injected into the top form's actions row.
    extra_html holds the reboot box shown below."""
    from .push.features import firmware_available, update_available

    q = esc(name)

    def act(action, label, cls, confirm=""):
        oc = (f' onclick="return confirm(\'{confirm}\')"' if confirm else "")
        return (f'<form method="POST" action="/device/push" class="inline">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="device" value="{q}">'
                f'<input type="hidden" name="feature" value="update">'
                f'<input type="hidden" name="update_action" value="{action}">'
                f'<button class="btn {cls}" type="submit"{oc}>{label}</button>'
                f'</form>')

    avail = update_available(current)

    # Buttons that live in the top form's actions row
    actions = ""
    if firmware_available(current):
        actions += " " + act("firmware", "Upgrade RouterBOOT firmware", "ghost",
                              confirm="Schedules a firmware upgrade. Continue?")

    avail_line = ('<p><span class="badge warn">update available</span></p>'
                  if avail else "")
    note = ('<p class="muted" style="border-left:3px solid #d97706;'
            'padding-left:8px;margin-top:12px">'
            '⚠ <b>Download &amp; install + reboot</b> checks for the latest '
            'version, downloads and installs it, then <b>reboots</b> (~1–2 min '
            'offline). If the router is already current, nothing happens. '
            'You get a dry-run preview and confirm step first.</p>')

    reboot = ('<div class="box"><h2>Reboot</h2><p class="muted">Manually reboot '
              'this router now — it will be offline ~1–2 minutes. Previewed and '
              'confirmed first.</p><div class="actions">'
              + act("reboot", "Reboot router now", "ghost",
                    confirm="Reboot the router now? It will go offline ~1–2 min.")
              + '</div></div>')

    extra_html = avail_line + note + reboot
    return extra_html, actions


def _interfaces_table(current) -> str:
    """A detailed read-only table: each interface's type, status, MAC, MTU, the
    IP(s) on it and its comment — so you can see what every port is and doing."""
    if not isinstance(current, dict):
        current = {"ifaces": current or [], "addrs": []}
    ifaces = current.get("ifaces", [])
    if not ifaces:
        return ('<div class="box"><h2>Interfaces</h2>'
                '<p class="muted">No interfaces read from the router.</p></div>')
    # map interface name -> list of IP addresses configured on it
    ips = {}
    for a in current.get("addrs", []):
        ifc = a.get("interface") or a.get("actual-interface")
        if ifc:
            ips.setdefault(ifc, []).append(a.get("address", ""))
    rows = ""
    for r in ifaces:
        nm = r.get("name", "?")
        disabled = _norm_html(r.get("disabled", "")) == "true"
        running = _norm_html(r.get("running", "")) == "true"
        if disabled:
            state = '<span class="badge warn">disabled</span>'
        elif running:
            state = '<span class="badge ok">up</span>'
        else:
            state = '<span class="badge crit">down</span>'
        addr = ", ".join(x for x in ips.get(nm, []) if x) or "—"
        rows += (f'<tr><td><b>{esc(nm)}</b></td>'
                 f'<td>{esc(str(r.get("type", "?")))}</td>'
                 f'<td>{state}</td>'
                 f'<td class="muted">{esc(str(r.get("mac-address", "—")))}</td>'
                 f'<td class="muted">{esc(str(r.get("mtu", "—")))}</td>'
                 f'<td>{esc(addr)}</td>'
                 f'<td class="muted">{esc(str(r.get("comment", "")))}</td></tr>')
    return (f'<div class="box"><h2>Interfaces ({len(ifaces)})</h2>'
            f'<table><tr><th>Name</th><th>Type</th><th>Status</th><th>MAC</th>'
            f'<th>MTU</th><th>IP address</th><th>Comment</th></tr>{rows}</table>'
            f'<p class="muted">Read-only inventory: physical ports, VLANs, '
            f'bridges, tunnels, etc. — their type, link state and the IPs they '
            f'carry.</p></div>')


def _norm_html(v) -> str:
    return "true" if v in (True, "true") else str(v)


def _wan_uplink_editor(name, cfg, csrf) -> str:
    """Editable WAN uplink list (saved to the device record, not pushed)."""
    def row(link):
        return (f'<tr>'
                f'<td><input name="link_name" placeholder="ISP name (Vodacom)" '
                f'value="{esc(link.name if link else "")}" style="width:100%"></td>'
                f'<td><input name="link_iface" placeholder="ether1 / lte1" '
                f'value="{esc(link.interface if link else "")}" style="width:100%">'
                f'</td>'
                f'<td><input name="link_gw" placeholder="gateway IP (optional)" '
                f'value="{esc(link.gateway if link else "")}" style="width:100%">'
                f'</td><td style="white-space:nowrap">'
                f'<span class="draghandle" draggable="true" title="drag to '
                f'reorder priority" style="cursor:grab;padding:0 6px">&#9776;</span>'
                f'<button type="button" class="btn ghost" title="move up (higher '
                f'priority)" onclick="pushMoveRow(this,-1)">&uarr;</button>'
                f'<button type="button" class="btn ghost" title="move down" '
                f'onclick="pushMoveRow(this,1)">&darr;</button>'
                f'<button type="button" class="btn ghost" title="remove" '
                f'onclick="this.closest(\'tr\').remove()">&times;</button></td></tr>')
    links = list(getattr(cfg.wan, "links", [])) if cfg else []
    body = "".join(row(link) for link in links) + row(None)
    return (f'<div class="box"><h2>WAN uplinks</h2>'
            f'<p class="muted">List your internet links in <b>priority order</b> — '
            f'<b>top = primary</b>, 2nd = first backup, and so on. <b>Drag the '
            f'&#9776; handle</b> (or use the &uarr;/&darr; buttons) to reorder; '
            f'failover/load-balancing below uses this order. Saved on the device '
            f'— no router change.</p>'
            f'<form method="POST" action="/device/wan">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="device" value="{esc(name)}">'
            f'<table class="rowtbl" id="rows-wl"><thead><tr><th>Name</th>'
            f'<th>Interface</th><th>Gateway</th><th>Order</th></tr></thead>'
            f'<tbody>{body}</tbody></table>'
            f'<button type="button" class="btn ghost" onclick="pushAddRow(\'wl\')" '
            f'style="margin-top:6px">+ Add uplink</button>'
            f'<div class="actions" style="margin-top:12px">'
            f'<button class="btn" type="submit">Save WAN uplinks</button></div>'
            f'</form><template id="tmpl-wl">{row(None)}</template></div>')


_TAB_INTRO = {
    "sdwan": "Add your internet links, set failover or load-balancing priority, "
             "and choose which LANs go out which WAN.",
    "security": "Toggle common firewall protections. Existing rules below can be "
                "viewed; easymikrotik only manages the ones it creates.",
    "harden": "Stop brute-force attacks: lock API/Winbox/SSH to your trusted IPs, "
              "disable insecure services, and block attacker IPs. ⚠ Include this "
              "server's IP in the allowed list so you don't lock easymikrotik out.",
    "nextdns": "Point DNS at a filtering service and list any IPs that bypass it.",
    "qos": "Cap upload/download speed for a subnet or interface (simple queues). "
           "Add a row, then Preview.",
    "portfwd": "Forward an external port to an internal device, or adopt forwards "
               "the router already has.",
    "interfaces": "A read-only view of the router's ports, VLANs and bridges.",
    "remote": "Grant a temporary firewall opening for Winbox/SSH/WebFig.",
    "tunnel": ("Manage WireGuard VPN interfaces and peers. "
               "Requires RouterOS 7.1+; shows a compatibility notice on older firmware."),
    "scripts": "Paste any RouterOS script for things the other tabs don't cover. "
               "Save adds it (tagged), Run executes it, Remove deletes it — all "
               "previewed first and logged.",
    "update": "Check for and install RouterOS upgrades. ⚠ Installing reboots the "
              "router (1–2 min offline) — it's previewed and you must confirm.",
}


def _render_confirm_page(name, user, slug, minutes, backup, hub_ip, csrf) -> str:
    """Shown right after a safe-mode change is applied. The router itself
    verifies, in `minutes`, that it can still reach the hub — and auto-reverts
    if it can't. The human doesn't have to judge whether it'll break; the
    'Keep now' button is only an early opt-out of that self-check."""
    q = quote(name)
    secs = int(minutes) * 60
    inner = (
        f'<div class="wrap" style="max-width:760px">'
        f'<div class="box" style="border-left:4px solid #16a34a">'
        f'<h1 style="margin-top:0">Change applied to {esc(name)} — safety net armed'
        f'</h1>'
        f'<p>You don\'t need to do anything. In about <b>{minutes} minutes</b> the '
        f'router will check whether it can still reach the hub '
        f'(<code>{esc(hub_ip)}</code>):</p>'
        f'<ul><li>If it <b>can</b> — the change is safe and is kept.</li>'
        f'<li>If it <b>can\'t</b> — the change cut it off, so it automatically '
        f'restores the pre-change backup (<code>{esc(backup)}</code>) and reboots, '
        f'and comes back on the old config. No site visit.</li></ul>'
        f'<p class="muted">The check runs <b>on the router</b>, so it works even '
        f'if the change made the box unreachable from here. Because it waits the '
        f'full window and tests real connectivity, a change that only breaks a '
        f'minute later is still caught.</p>'
        f'<p style="font-size:24px;font-weight:700;margin:6px 0" '
        f'data-countdown="{secs}">self-check in {minutes}:00</p>'
        f'<p class="muted">Already verified it\'s fine and don\'t want to wait? '
        f'You can keep it now (this skips the self-check):</p>'
        f'<form method="POST" action="/device/confirm" class="actions">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="device" value="{esc(name)}">'
        f'<input type="hidden" name="feature" value="{esc(slug)}">'
        f'<button class="btn" type="submit">Confirm (skip the self-check)</button>'
        f'<a class="btn ghost" href="/device?name={q}&tab={slug}">Go to the tab</a>'
        f'</form></div></div>'
        f'{_CONFIRM_JS}')
    return _page(esc(name) + " · Change armed", _header(user, "/") + inner)


_CONFIRM_JS = """
<script>
 (function(){
   var el=document.querySelector('[data-countdown]'); if(!el) return;
   var end=Date.now()+ (+el.getAttribute('data-countdown'))*1000;
   function tick(){
     var s=Math.max(0,Math.round((end-Date.now())/1000));
     var m=Math.floor(s/60);
     if(s<=0){el.textContent='running the self-check…';
       el.parentNode.insertAdjacentHTML('beforeend',
         '<p style=\"color:#475569\">The router is now testing hub connectivity. '+
         'If it lost contact it is reverting + rebooting; reload in a minute.</p>');
       return;}
     el.textContent='self-check in '+m+':' + ('0'+(s%60)).slice(-2);
     setTimeout(tick,1000);
   }
   tick();
 })();
</script>"""


def _render_feature_tab(name, user, slug, feature, csrf, *, summary_lines=None,
                        fields=None, preview=None, submitted=None, error="",
                        msg="", recent=None, facts=None, unmanaged=None,
                        confirm_action="/device/push", cfg=None,
                        extra_html="", extra_actions="", report_html="") -> str:
    tabbar = _device_tabbar(name, slug, AuthStore.is_admin(user or {}), csrf)
    q = quote(name)
    banner = (f'<div class="box" style="border-left:4px solid #16a34a">{esc(msg)}'
              f'</div>' if msg else "")
    err = (f'<div class="box" style="border-left:4px solid #dc2626">'
           f'<b>Could not reach the router:</b> {esc(error)}<br>'
           f'<span class="muted">See the activity log below for the full error. '
           f'Check the host and the read-write push user on the Devices page.'
           f'</span></div>' if error else "")

    if preview is not None:
        # Safe mode (commit-confirm): offered for changes that could lock you
        # out. Not for 'update' (its reboot is intentional and would fight the
        # revert).
        safe = ("" if slug == "update" else
                f'<label class="chk" style="display:block;margin:10px 0">'
                f'<input type="checkbox" name="safe_revert" value="1" checked> '
                f'<b>Safe mode</b> — {_REVERT_MINUTES} min after applying, the '
                f'router checks it can still reach the hub and <b>auto-reverts to '
                f'the backup if it can\'t</b>. The router decides from real '
                f'connectivity (not a guess), so a change that only breaks a '
                f'minute later is still caught. Protects against locking yourself '
                f'out.</label>')
        body = (f'<div class="box"><h2>Dry run — nothing has been written yet</h2>'
                f'<pre style="background:#f8fafc;padding:12px;border-radius:8px;'
                f'white-space:pre-wrap">{esc(preview.diff_text())}</pre>'
                f'<form method="POST" action="{confirm_action}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="apply" value="1">'
                f'{_hidden_from_multi(submitted or {})}'
                f'{safe}'
                f'<div class="actions">'
                f'<button class="btn" type="submit">Confirm &amp; apply to the '
                f'router</button>'
                f'<a class="btn ghost" href="/device?name={q}&tab={slug}">Cancel'
                f'</a></div></form></div>')
    elif error:
        body = ""
    else:
        sm = "".join(f'<li>{esc(s)}</li>' for s in (summary_lines or []))
        state = (f'<div class="box"><h2>Current (managed by {esc(_BRAND)})</h2>'
                 f'<ul style="margin:0 0 0 18px">{sm}</ul></div>')
        if fields is not None:
            ff = "".join(_field_html(d) for d in fields)
            preview_btn = ('<button class="btn" type="submit">Preview changes '
                           '(dry-run)</button>')
            form = (f'<div class="box"><h2>{esc(feature["title"])}</h2>'
                    f'<form method="POST" action="/device/push">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="device" value="{esc(name)}">'
                    f'<input type="hidden" name="feature" value="{esc(slug)}">'
                    f'<div class="fields">{ff}</div>'
                    f'<div class="actions" style="margin-top:14px">{preview_btn}'
                    f'{extra_actions}</div></form></div>')
        else:
            form = ""  # read-only feature (e.g. Interfaces)
        body = (state + form + extra_html
                + _adopt_box(name, slug, feature, csrf, unmanaged))

    # The SD-WAN tab gets an inline WAN-uplink editor (device metadata, so it
    # works even when the router is unreachable). Hidden during the confirm step.
    wan_editor = (_wan_uplink_editor(name, cfg, csrf)
                  if slug == "sdwan" and preview is None else "")
    logbox = _recent_log_box(recent or [], device=name)
    intro = (f'<p class="muted" style="margin:-6px 0 14px">{_TAB_INTRO[slug]}</p>'
             if slug in _TAB_INTRO else "")
    inner = (f'<div class="wrap" style="max-width:1100px">'
             f'<h1>{esc(name)} &middot; {esc(feature["title"])}</h1>{tabbar}{intro}'
             f'{_facts_strip(facts or {})}{banner}{err}{report_html}'
             f'{wan_editor}{body}{logbox}'
             f'<p class="muted">These engines are experimental — every push is '
             f'dry-run-first and logged above so you can see exactly what the '
             f'router accepted or rejected.</p>'
             f'<p><a href="/device?name={q}">&larr; overview</a></p></div>')
    return _page(esc(name) + " · " + feature["title"],
                 _header(user, "/") + inner + _FEATURE_JS)


def _render_logs(user, rows) -> str:
    inner = (f'<div class="wrap" style="max-width:1100px"><h1>Push activity log</h1>'
             f'<p class="muted">Every config-push (preview, apply, success and '
             f'failure) across all devices. Expand a row for the full diff and '
             f'any error.</p>{_recent_log_box(rows, device=None)}</div>')
    return _page("Activity log", _header(user, "/logs") + inner)


_FREE_PLAN_DEVICE_LIMIT = 1


def _render_upgrade_wall(user, current_count: int = 0) -> str:
    inner = (
        '<div class="wrap"><h1>Upgrade required</h1>'
        '<div class="box" style="text-align:center;padding:40px 24px">'
        '<div style="font-size:48px;margin-bottom:16px">&#128274;</div>'
        '<h2 style="margin-top:0">Free plan: 1 device included</h2>'
        f'<p class="muted">Your account has {current_count} device'
        f'{"s" if current_count != 1 else ""} — the free plan allows '
        f'{_FREE_PLAN_DEVICE_LIMIT}. Cloud and Enterprise plans '
        f'(coming soon) remove this limit and unlock additional features.</p>'
        '<p style="margin-top:24px">'
        '<a class="btn ghost" href="/devices">Back to devices</a>'
        '</p></div></div>')
    return _page("Upgrade required", _header(user, "/devices") + inner)


def _render_devices(store, csrf, user, edit_name=None, msg="",
                    all_devs=None, org_count: int = 0, org_plan: str = "free") -> str:
    if store is None:
        return _page("Devices", _header(user, "/devices") + '<div class="wrap">'
                     '<h1>Devices</h1><div class="box">Device management is not '
                     'enabled. Set <code>devices_db:</code> in the config.</div></div>')
    pre = (store.raw(edit_name) or {}) if edit_name else {}
    wan = pre.get("wan") or {}

    # Build inventory-style rows with live state merged in
    devs_by_name = {d["device"]: d for d in (all_devs or [])}
    all_names = sorted(set(store.names()) | set(devs_by_name.keys()),
                       key=lambda x: x.lower())
    trows = ""
    for n in all_names:
        d = devs_by_name.get(n, {})
        f = d.get("facts") or {}
        sev = _severity(d) if d else "crit"
        dot = {"ok": "#16a34a", "warn": "#d97706", "crit": "#dc2626"}[sev]
        ver = f.get("version", "—")
        old = ver[:1] in ("5", "6")
        ver_html = (esc(ver) + (
            f' <a class="up" href="/device?name={quote(n)}&tab=update">'
            f'upgrade</a>' if old else ""))
        host = f.get("host") or (store.raw(n) or {}).get("host", "—")
        badge_lbl = "online" if d.get("up") else "offline"
        upd = f.get("update_available")
        if upd is True:
            upd_html = '<span class="badge warn">Yes</span>'
        elif upd is False:
            upd_html = '<span class="muted">No</span>'
        else:
            upd_html = '<span class="muted">—</span>'
        trows += (
            f'<tr>'
            f'<td><span class="dot" style="background:{dot}"></span> '
            f'<a href="/device?name={quote(n)}"><b>{esc(n)}</b></a></td>'
            f'<td>{esc(f.get("model", "—"))}</td>'
            f'<td>{ver_html}</td>'
            f'<td class="muted">{esc(f.get("serial", "—"))}</td>'
            f'<td class="muted">{esc(host)}</td>'
            f'<td>{upd_html}</td>'
            f'<td><span class="badge {sev}">{badge_lbl}</span></td>'
            f'<td><div class="actions">'
            f'<a class="btn ghost" href="/device?name={quote(n)}">Open</a>'
            f'<a class="btn ghost" href="/devices?edit={quote(n)}" '
            f'onclick="event.preventDefault();'
            f'fetch(\'/devices?edit={quote(n)}\').then(r=>r.text()).then(function(h){{'
            f'var p=new DOMParser().parseFromString(h,\'text/html\');'
            f'var src=p.getElementById(\'edit-modal\');'
            f'var dst=document.getElementById(\'edit-modal\');'
            f'if(src&&dst){{dst.innerHTML=src.innerHTML;}}'
            f'document.getElementById(\'edit-modal\').classList.add(\'open\');}})">Edit</a>'
            f'{_mini_form("/devices/test", csrf, n, "Test", "btn ghost")}'
            f'{_mini_form("/devices/delete", csrf, n, "Delete", "btn red", n)}'
            f'</div></td>'
            f'</tr>')
    if not trows:
        trows = ('<tr><td colspan="8" class="muted" style="padding:16px">No devices '
                 'yet — click <b>Add device</b> to get started.</td></tr>')

    sources_sel = set(pre.get("client_count_sources") or ["dhcp", "wireless"])
    src_boxes = "".join(
        f'<label><input type="checkbox" name="sources" value="{s}"'
        f'{" checked" if s in sources_sel else ""}> {s}</label>'
        for s in _CLIENT_SOURCES)
    checks_pre = pre.get("checks") or {}
    chk_boxes = "".join(
        f'<label><input type="checkbox" name="checks" value="{k}"'
        f'{" checked" if checks_pre.get(k, DEFAULT_CHECKS[k]) else ""}> {k}</label>'
        for k in DEFAULT_CHECKS)

    def v(key, d=""):
        return esc(pre.get(key, d))

    def field(label, inner_html, full=False):
        cls = "f full" if full else "f"
        return f'<div class="{cls}"><label class="f">{label}</label>{inner_html}</div>'

    fields = (
        field("Name", f'<input name="name" value="{v("name")}">')
        + field("Host / IP <span class='muted'>(leave BLANK to provision over "
                "the tunnel — no public IP; you'll get a script to paste and the "
                "device syncs itself. Only fill this for a directly-reachable "
                "router.)</span>",
                f'<input name="host" placeholder="leave blank to provision" '
                f'value="{v("host")}">')
        + field(f"API port <span class='muted'>(how {esc(_BRAND)} connects to monitor "
                "this router — blank = 8728, or 8729 with API-SSL)</span>",
                f'<input name="api_port" placeholder="8728" '
                f'value="{esc(str(pre.get("api_port", 8728)))}">')
        + field("API timeout <span class='muted'>(seconds; raise for slow boxes "
                "/ long scripts)</span>", f'<input name="timeout" '
                f'value="{esc(str(pre.get("timeout", 60)))}">')
        # No username/password here — the provisioning script creates the login
        # for you. (Existing creds are preserved untouched when you edit.)
        + field("Security",
                f'<div class="chkrow">'
                f'<label class="chk"><input type="checkbox" name="use_ssl"'
                f'{" checked" if pre.get("use_ssl") else ""}> API-SSL</label>'
                f'<label class="chk"><input type="checkbox" name="verify_ssl"'
                f'{" checked" if pre.get("verify_ssl") else ""}> verify cert</label>'
                f'</div>')
        + field("WAN uplinks <span class='muted'>(top = highest priority; "
                "add as many as the router has)</span>",
                _wan_editor(wan.get("links") or []), full=True)
        + field("LAN subnets <span class='muted'>(comma-separated)</span>",
                f'<input name="lan_subnets" '
                f'value="{esc(",".join(pre.get("lan_subnets") or []))}">', full=True)
        + field("Monitor interfaces <span class='muted'>(comma; blank = auto)</span>",
                f'<input name="monitor_interfaces" '
                f'value="{esc(",".join(pre.get("monitor_interfaces") or []))}">',
                full=True)
        + field("Client-count sources",
                f'<div class="chips">{src_boxes}</div>', full=True)
        + field("Enabled checks", f'<div class="chips">{chk_boxes}</div>', full=True))

    msg_html = f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else ""

    def _device_modal(modal_id, title, form_action, original_name, submit_lbl,
                      form_fields, intro=""):
        close_js = f"document.getElementById('{modal_id}').classList.remove('open')"
        return (
            f'<div id="{modal_id}" class="modal-backdrop">'
            f'<div class="modal">'
            f'<button class="modal-close" type="button" '
            f'onclick="{close_js}">&times;</button>'
            f'<h2>{title}</h2>'
            f'{intro}'
            f'<form method="POST" action="{form_action}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="original_name" value="{esc(original_name)}">'
            f'<div class="fields">{form_fields}</div>'
            f'<div class="actions" style="margin-top:16px">'
            f'<button class="btn" type="submit">{submit_lbl}</button>'
            f'<button type="button" class="btn ghost" onclick="{close_js}">Cancel</button>'
            f'</div></form></div></div>')

    add_intro = ('<p class="muted" style="margin-top:0">Enter a <b>name</b> and click '
                 '<b>Add device</b> — you\'ll be taken to the Provision tab to generate '
                 'a script or connect directly.</p>')

    # Separate fields without pre-filled values for Add modal
    pre_add = {}
    wan_add = {}
    sources_add = set(["dhcp", "wireless"])
    src_add = "".join(
        f'<label><input type="checkbox" name="sources" value="{s}"'
        f'{" checked" if s in sources_add else ""}> {s}</label>'
        for s in _CLIENT_SOURCES)
    chk_add = "".join(
        f'<label><input type="checkbox" name="checks" value="{k}"'
        f'{" checked" if DEFAULT_CHECKS[k] else ""}> {k}</label>'
        for k in DEFAULT_CHECKS)

    def vv(key, d="", p=None):
        return esc((p or {}).get(key, d))

    def field_add(label, inner_html, full=False):
        cls = "f full" if full else "f"
        return f'<div class="{cls}"><label class="f">{label}</label>{inner_html}</div>'

    add_fields = (
        field_add("Name", '<input name="name" value="">')
        + field_add("Host / IP <span class='muted'>(leave BLANK to provision over the tunnel)</span>",
                    '<input name="host" placeholder="leave blank to provision" value="">')
        + field_add(f"API port <span class='muted'>(blank = 8728)</span>",
                    '<input name="api_port" placeholder="8728" value="8728">')
        + field_add("API timeout <span class='muted'>(seconds)</span>",
                    '<input name="timeout" value="60">')
        + field_add("Security",
                    '<div class="chkrow"><label class="chk"><input type="checkbox" '
                    'name="use_ssl"> API-SSL</label><label class="chk"><input type="checkbox" '
                    'name="verify_ssl"> verify cert</label></div>')
        + field_add("WAN uplinks", _wan_editor([]), full=True)
        + field_add("LAN subnets <span class='muted'>(comma-separated)</span>",
                    '<input name="lan_subnets" value="">', full=True)
        + field_add("Monitor interfaces <span class='muted'>(comma; blank = auto)</span>",
                    '<input name="monitor_interfaces" value="">', full=True)
        + field_add("Client-count sources", f'<div class="chips">{src_add}</div>', full=True)
        + field_add("Enabled checks", f'<div class="chips">{chk_add}</div>', full=True))

    add_modal = _device_modal("add-modal", "Add a device", "/devices/save", "",
                              "Add device", add_fields, add_intro)
    edit_modal = _device_modal("edit-modal",
                               f"Edit: {esc(edit_name)}" if edit_name else "Edit device",
                               "/devices/save", edit_name or "",
                               "Save changes", fields)

    inv_table = (
        f'<div class="box">'
        f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">'
        f'<input id="iq" placeholder="Search by name, model, version, serial…" '
        f'style="flex:1" onkeyup="invFilter()">'
        f'<button class="btn" type="button" '
        f'onclick="document.getElementById(\'add-modal\').classList.add(\'open\')">'
        f'Add device</button></div>'
        f'<table id="invt" style="width:100%">'
        f'<tr><th>Name</th><th>Model</th><th>RouterOS</th><th>Serial</th>'
        f'<th>Host / IP</th><th>Update available</th><th>Status</th><th>Actions</th></tr>'
        f'{trows}</table></div>')

    auto_open = (f'<script>document.getElementById("edit-modal")'
                 f'.classList.add("open");</script>') if edit_name else ""

    inv_js = ('<script>'
              'function invFilter(){var t=document.getElementById("iq")'
              '.value.toLowerCase();document.querySelectorAll("#invt tr").forEach('
              'function(r,i){if(i===0)return;r.style.display='
              'r.textContent.toLowerCase().indexOf(t)>=0?"":"none";});}'
              'document.addEventListener("click",function(e){'
              '["add-modal","edit-modal"].forEach(function(id){'
              'var m=document.getElementById(id);'
              'if(m&&e.target===m)m.classList.remove("open");});});'
              '</script>')

    plan_banner = ""
    # TODO: re-enable after testing
    # if org_plan == "free": ...

    inner = (f'<div class="wrap" style="max-width:1200px"><h1>Devices</h1>'
             f'{msg_html}{plan_banner}{inv_table}</div>'
             f'{add_modal}{edit_modal}{auto_open}')
    return _page("Devices", _header(user, "/devices") + inner + _WAN_JS + inv_js)


def _wan_link_row(idx, ep=None) -> str:
    ep = ep or {}
    return (f'<div class="wanrow"><span class="prio">{idx + 1}</span>'
            f'<input name="link_name" placeholder="ISP name (e.g. Vodacom)" '
            f'value="{esc(ep.get("name", ""))}">'
            f'<input name="link_iface" placeholder="interface (ether1, lte1…)" '
            f'value="{esc(ep.get("interface", ""))}">'
            f'<input name="link_gw" placeholder="gateway IP (optional)" '
            f'value="{esc(ep.get("gateway", ""))}">'
            f'<button type="button" class="btn ghost wandel" '
            f'onclick="this.parentNode.remove();wanReindex()">&times;</button></div>')


def _wan_editor(links) -> str:
    rows = list(links) or [{}, {}]  # start with two rows for a new device
    body = "".join(_wan_link_row(i, ep) for i, ep in enumerate(rows))
    return (f'<div id="wanlinks">{body}</div>'
            f'<button type="button" class="btn ghost" onclick="wanAdd()" '
            f'style="margin-top:4px">+ Add WAN link</button>'
            f'<template id="wantmpl">{_wan_link_row(0, {})}</template>')


_WAN_JS = """
<script>
 function wanReindex(){
   var i=1; document.querySelectorAll('#wanlinks .wanrow .prio')
     .forEach(function(p){p.textContent=i++;});
 }
 function wanAdd(){
   var t=document.getElementById('wantmpl');
   document.getElementById('wanlinks').appendChild(t.content.cloneNode(true));
   wanReindex();
 }
</script>"""


def _mini_form(action, csrf, name, label, cls, confirm=None) -> str:
    onsub = (f' onsubmit="return confirm(\'Delete {esc(confirm)}?\')"'
             if confirm else "")
    return (f'<form class="inline" method="POST" action="{action}"{onsub}>'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="name" value="{esc(name)}">'
            f'<button class="{cls}" type="submit">{label}</button></form>')


def _render_test_result(name, ok, detail, user) -> str:
    color = "#16a34a" if ok else "#dc2626"
    inner = (f'<div class="wrap"><h1>Connection test: {esc(name)}</h1>'
             f'<div class="box"><p style="color:{color};font-weight:700">'
             f'{"SUCCESS" if ok else "FAILED"}</p><pre>{esc(detail)}</pre></div>'
             f'<p><a href="/devices">&larr; back to devices</a></p></div>')
    return _page("Test", _header(user, "/devices") + inner)


def _render_prometheus(store, allowed=None) -> str:
    lines = []
    for device, metric, label, value, _ts in store.all_latest():
        if allowed is not None and device not in allowed:
            continue
        name = "mikromon_" + _PROM_SAFE.sub("_", metric)
        labels = f'device="{device}"' + (f',name="{label}"' if label else "")
        lines.append(f"{name}{{{labels}}} {value}")
    return "\n".join(lines) + "\n"


# ============================ sessions =====================================
class SessionManager:
    def __init__(self):
        self._s: dict[str, dict] = {}

    def create(self, login: str) -> str:
        token = secrets.token_urlsafe(32)
        self._s[token] = {"login": login, "expires": time.time() + _SESSION_TTL,
                          "csrf": secrets.token_urlsafe(16)}
        return token

    def get(self, token: str):
        s = self._s.get(token or "")
        if not s:
            return None
        if s["expires"] < time.time():
            self._s.pop(token, None)
            return None
        s["expires"] = time.time() + _SESSION_TTL  # sliding window
        return s

    def destroy(self, token: str) -> None:
        self._s.pop(token or "", None)


# ============================ HTTP handler =================================
def make_handler(metrics_db, state_file, auth: AuthStore | None,
                 sessions: SessionManager, secure_cookies=False,
                 metrics_token=None, devices_db=None, defaults=None,
                 push_log_db=None, access_cfg=None):
    defaults = defaults or {}
    access_cfg = access_cfg or {}

    class Handler(BaseHTTPRequestHandler):
        server_version = "mikromon"

        def log_message(self, *_):
            pass

        # ---- low-level helpers ----
        def _send(self, code, body, ctype="text/plain; charset=utf-8", headers=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _redirect(self, location, headers=None):
            self.send_response(303)
            self.send_header("Location", location)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _cookie_header(self, token, clear=False):
            attrs = f"{_COOKIE}={'' if clear else token}; HttpOnly; SameSite=Lax; Path=/"
            attrs += "; Max-Age=0" if clear else ""
            if secure_cookies:
                attrs += "; Secure"
            return {"Set-Cookie": attrs}

        def _token(self):
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            try:
                return SimpleCookie(raw)[_COOKIE].value
            except KeyError:
                return None

        def _session(self):
            return sessions.get(self._token())

        def _user(self):
            s = self._session()
            if not s:
                return None
            user = auth.get_user(s["login"])
            if user:
                user["org_name"] = auth.org_name(user.get("org_id"))
            return user

        def _form(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8") if length else ""
            return {k: v[-1] for k, v in parse_qs(body, keep_blank_values=True).items()}, \
                   parse_qs(body, keep_blank_values=True)

        def _store(self):
            return MetricsStore(metrics_db)

        # ---- GET ----
        def do_GET(self):
            url = urlparse(self.path)
            path = url.path
            if path == "/health":
                return self._send(200, "ok")

            # Preview the landing page without wiring it to /.
            if path == "/landing":
                from .web_landing import render_landing
                return self._send(200, render_landing(), "text/html; charset=utf-8")

            # No auth configured -> open dashboard (back-compat / demo without auth).
            if auth is None:
                store = self._store()
                ds = self._devstore()
                managed = ds is not None
                known = _visible_device_names(store, _load_state(state_file), ds)
                if ds:
                    ds.close()
                store.close()
                # Even with auth off, the devices DB stays authoritative in
                # web-managed mode so orphans never leak onto the open dashboard.
                allowed = sorted(known) if managed else None
                return self._serve_data(path, url, user=None, allowed=allowed)

            # Open self-signup: anyone can create a company account.
            if path == "/signup":
                if self._session():
                    return self._redirect("/")
                err = parse_qs(url.query).get("error", [""])[0]
                return self._send(200, _render_signup(err),
                                  "text/html; charset=utf-8")
            # With no accounts yet, send first-time visitors to sign up.
            if auth.count_users() == 0 and path not in ("/login",):
                return self._redirect("/signup")

            if path == "/login":
                if self._session():
                    return self._redirect("/")
                err = {"1": "Invalid email or password."}.get(
                    parse_qs(url.query).get("error", [""])[0], "")
                return self._send(200, _render_login(err), "text/html; charset=utf-8")
            if path == "/logout":
                sessions.destroy(self._token())
                return self._redirect("/login", self._cookie_header("", clear=True))
            if path == "/metrics":
                return self._serve_metrics(url)

            user = self._user()
            if not user:
                if path.startswith("/api/"):
                    return self._send(401, '{"error":"unauthorized"}',
                                      "application/json")
                return self._redirect("/login")
            if path == "/account":
                q = parse_qs(url.query)
                return self._send(200, _render_account(
                    user, self._session()["csrf"],
                    msg=q.get("ok", [""])[0], error=q.get("error", [""])[0]),
                    "text/html; charset=utf-8")
            if path == "/admin":
                return self._serve_admin(user)
            if path == "/devices":
                return self._serve_devices(url, user)
            if path == "/logs":
                return self._serve_logs(user)

            store = self._store()
            ds = self._devstore()
            # In web-managed mode show only devices still in the DB (hide
            # orphans left in metrics/state); fall back to known in YAML mode.
            known = _visible_device_names(store, _load_state(state_file), ds)
            # Scope to the user's company: only devices their org owns.
            org_names = (set(ds.names_for_org(user["org_id"]))
                         if ds is not None else None)
            if ds:
                ds.close()
            store.close()
            scope = sorted(known & org_names) if org_names is not None \
                else sorted(known)
            allowed = AuthStore.allowed_devices(user, scope)
            return self._serve_data(path, url, user=user, allowed=allowed)

        def _serve_data(self, path, url, user, allowed):
            store = self._store()
            try:
                state = _load_state(state_file)
                if path == "/":
                    return self._send(200, _render_dashboard(store, state, user,
                                      allowed), "text/html; charset=utf-8")
                # if path == "/inventory":
                #     return self._send(200, _render_inventory(store, state, user,
                #                       allowed), "text/html; charset=utf-8")
                if path == "/device":
                    q = parse_qs(url.query)
                    dev = q.get("name", [""])[0]
                    ds = self._devstore()
                    known = _visible_device_names(store, state, ds)
                    if ds:
                        ds.close()
                    if dev not in known:
                        return self._send(404, "no such device")
                    if allowed is not None and dev not in allowed:
                        return self._send(403, "forbidden")
                    tab = q.get("tab", [""])[0]
                    if tab == "backups":
                        if user is not None and not AuthStore.is_admin(user):
                            return self._send(403, "forbidden")
                        return self._device_backups_page(
                            dev, user, msg=q.get("msg", [""])[0])
                    if tab == "provision":
                        if user is not None and not AuthStore.is_admin(user):
                            return self._send(403, "forbidden")
                        return self._device_provision_page(
                            dev, user, msg=q.get("msg", [""])[0])
                    if tab:
                        from .push import FEATURES
                        if tab in FEATURES:
                            return self._feature_tab_page(
                                dev, user, tab, msg=q.get("msg", [""])[0])
                    sess = self._session()
                    csrf = sess["csrf"] if sess else ""
                    # Diagnosis inputs: when did this device last change, and how
                    # many OTHER devices are down right now (wider-outage signal).
                    last_change = None
                    al = self._auditlog()
                    if al is not None:
                        last_change = al.last_change(dev)[0]
                    others_down = sum(
                        1 for dd in _all_devices(store, state, allowed)
                        if dd.get("device") != dev and not dd.get("up", True))
                    return self._send(200, _render_device(store, state, dev, user,
                                      csrf, last_change=last_change,
                                      others_down=others_down),
                                      "text/html; charset=utf-8")
                if path == "/api/devices":
                    return self._send(200, json.dumps(
                        _all_devices(store, state, allowed), indent=2),
                        "application/json")
                if path == "/api/series":
                    q = parse_qs(url.query)
                    dev = q.get("device", [""])[0]
                    if allowed is not None and dev not in allowed:
                        return self._send(403, '{"error":"forbidden"}',
                                          "application/json")
                    rows = store.series(dev, q.get("metric", [""])[0],
                                        label=q.get("label", [""])[0],
                                        since=float(q.get("since",
                                                    [time.time() - 3600])[0]))
                    return self._send(200, json.dumps(
                        [{"ts": t, "value": v} for t, v in rows]),
                        "application/json")
                if path == "/metrics":  # only reached when auth is None
                    return self._send(200, _render_prometheus(store, allowed))
                return self._send(404, "not found")
            finally:
                store.close()

        def _serve_metrics(self, url):
            token = (parse_qs(url.query).get("token", [""])[0]
                     or self.headers.get("Authorization", "").removeprefix("Bearer "))
            ok = metrics_token and secrets.compare_digest(token, metrics_token)
            if not ok:
                user = self._user()
                if not AuthStore.is_admin(user or {}):
                    return self._send(401, "unauthorized\n",
                                      headers={"WWW-Authenticate": "Bearer"})
            store = self._store()
            try:
                return self._send(200, _render_prometheus(store, None))
            finally:
                store.close()

        def _serve_admin(self, user):
            if not AuthStore.is_admin(user):
                return self._send(403, "forbidden")
            ds = self._devstore()
            if ds is not None:
                known = ds.names_for_org(user["org_id"])
                ds.close()
            else:
                store = self._store()
                known = _known_devices(store, _load_state(state_file))
                store.close()
            return self._send(200, _render_admin(
                auth, known, self._session()["csrf"], user),
                "text/html; charset=utf-8")

        # ---- device management (admin only) ----
        def _serve_devices(self, url, user):
            if not AuthStore.is_admin(user):
                return self._send(403, "forbidden")
            edit = parse_qs(url.query).get("edit", [None])[0]
            store = self._devstore()
            main_store = self._store()
            try:
                state = _load_state(state_file)
                org_names = (set(store.names_for_org(user["org_id"])) if store else None)
                scope = sorted(org_names) if org_names is not None else []
                all_devs = _all_devices(main_store, state, scope if scope else None)
                org_count = store.count_for_org(user["org_id"]) if store else 0
                org_plan = (auth.org(user["org_id"]) or {}).get("plan", "free") if auth else "free"
                page = _render_devices(store, self._session()["csrf"], user,
                                       edit_name=edit,
                                       all_devs=all_devs,
                                       org_count=org_count, org_plan=org_plan)
            finally:
                if store:
                    store.close()
                if main_store:
                    main_store.close()
            return self._send(200, page, "text/html; charset=utf-8")

        def _devstore(self):
            if not devices_db:
                return None
            from .devices_store import DevicesStore
            return DevicesStore(devices_db)

        def _access_store(self):
            """The on-demand access grant store, or None when the feature is
            not configured (no `access.hub_host`)."""
            if not access_cfg.get("hub_host"):
                return None
            from .access import AccessStore
            path = access_cfg.get("grants_file") or _access_grants_path(devices_db)
            return AccessStore(path)

        def _access_ttl(self):
            return int(access_cfg.get("ttl_minutes", 15)) * 60

        def _access_box_html(self, name, csrf):
            store = self._access_store()
            if store is None:
                return ""
            ds = self._devstore()
            raw = ds.raw(name) if ds else None
            if ds:
                ds.close()
            raw = raw or {}
            creds = {"user": raw.get("username", ""),
                     "pwd": raw.get("password", "")}
            grants = {k: store.grant_for(name, k) for k in ("webfig", "winbox")}
            return _access_box(name, csrf, access_cfg.get("hub_host", ""),
                               _device_tunnel_ip(name, devices_db), creds, grants)

        @staticmethod
        def _purge_device_data(name):
            """Remove a deleted device's leftover data: its time-series samples
            and its saved monitoring state, so it stops appearing on the
            dashboard. Best-effort — a failure here must not break the delete."""
            if not name:
                return
            if metrics_db:
                try:
                    ms = MetricsStore(metrics_db)
                    try:
                        ms.delete_device(name)
                    finally:
                        ms.close()
                except Exception:  # noqa: BLE001 — never fail the delete on this
                    log.exception("could not purge metrics for %s", name)
            if state_file:
                try:
                    from .state import StateStore
                    st = StateStore(state_file).load()
                    st.forget_device(name)
                    st.save()
                except Exception:  # noqa: BLE001
                    log.exception("could not purge state for %s", name)

        def _try_offboard(self, raw, name, uname):
            """Best-effort: connect to the router and run device_offboard().

            Always returns a result dict — never raises. If the router cannot
            be reached the dict carries an "error" string so the caller can
            tell the user to clean up manually."""
            if not raw:
                return {"steps": [], "error": "device config not found",
                        "username": ""}
            from .config import build_device
            from .device import DeviceError
            from .push import PushError, device_offboard, rw_device
            from .push.api import PushApi
            username = raw.get("username", "")
            try:
                cfg = build_device(raw, defaults)
                dev = rw_device(cfg)
                api = PushApi(dev)
                try:
                    api.connect()
                    steps = device_offboard(api, cfg)
                finally:
                    dev.close()
            except (DeviceError, PushError) as exc:
                return {"steps": [], "error": str(exc), "username": username}
            except Exception as exc:  # noqa: BLE001
                return {"steps": [], "error": f"Unexpected error: {exc}",
                        "username": username}
            audit = self._auditlog()
            if audit:
                has_err = any(s["level"] == "error" for s in steps)
                detail = "; ".join(s["msg"] for s in steps) or "no changes"
                audit.append(name, uname, "device", "offboard",
                             "error" if has_err else "ok",
                             f"offboard on delete", detail)
                audit.close()
            return {"steps": steps, "error": None, "username": username}

        # ---- Backups tab (config-push engine, admin only) ----
        def _device_raw(self, name):
            store = self._devstore()
            if store is None:
                return None
            try:
                return store.raw(name)
            finally:
                store.close()

        def _device_backups_page(self, name, user, dry_plan=None, error="",
                                 msg=""):
            raw = self._device_raw(name)
            if raw is None:
                return self._send(400, "This device is not managed in the "
                                       "dashboard (set devices_db / add it on "
                                       "the Devices page).")
            facts = (_load_state(state_file).get("devices", {})
                     .get(name, {}).get("facts", {}))
            sess = self._session()
            csrf = sess["csrf"] if sess else ""
            backups = []
            if dry_plan is None:  # live-read the router's restore points
                from .config import build_device
                from .device import DeviceError
                from .push import Pusher, PushError, rw_device
                from .push.api import PushApi

                cfg = build_device(raw, defaults)
                dev = rw_device(cfg)
                api = PushApi(dev)
                try:
                    api.connect()
                    backups = Pusher(cfg, api).list_backups()
                except (DeviceError, PushError) as exc:
                    error = error or str(exc)
                finally:
                    dev.close()
            page = _render_device_backups(name, user, facts, csrf,
                                          backups=backups, error=error, msg=msg,
                                          dry_plan=dry_plan)
            return self._send(200, page, "text/html; charset=utf-8")

        def _device_provision_page(self, name, user, msg="", script=None,
                                   creds=None, error=""):
            raw = self._device_raw(name)
            if raw is None:
                return self._send(400, "This device is not managed in the "
                                       "dashboard (add it on the Devices page).")
            sess = self._session()
            csrf = sess["csrf"] if sess else ""
            hub = _hub_load(_hub_path(devices_db))
            hub_ip = hub.get("hub_ip") or _detect_server_ip()
            page = _render_device_provision(name, user, raw, csrf, hub_ip=hub_ip,
                                            script=script, creds=creds, msg=msg,
                                            error=error)
            return self._send(200, page, "text/html; charset=utf-8")

        def _device_provision_post(self, flat, user):
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            if flat.get("auto") == "1":
                return self._device_provision_apply(flat, user)
            name = flat.get("device", "")
            store = self._devstore()
            if store is None:
                return self._send(400, "device management not enabled")
            raw = store.raw(name)
            if raw is None:
                store.close()
                return self._send(404, "no such device")
            # hub (WireGuard server) details — auto-detected, overridable in form
            hub_file = _hub_path(devices_db)
            hub = _hub_load(hub_file)
            hub_ip = (flat.get("hub", "").strip() or hub.get("hub_ip")
                      or _detect_server_ip())
            hub["hub_ip"] = hub_ip
            hub.setdefault("subnet", _HUB_SUBNET_DEFAULT)
            hub_pubkey = hub.get("hub_pubkey", "")
            hub_port = hub.get("listen_port", _WG_PORT_DEFAULT)
            peers_path = hub.get("wg_peers") or _WG_PEERS_DEFAULT
            uname = flat.get("pwuser", "").strip() or "mkmonitor"
            pwd = _gen_password()
            want_tunnel = flat.get("transport", "wg").strip() == "wg"
            lock_api = flat.get("lock_api") == "1"
            tunnel_ip = dev_pub = wg_priv = ""
            reg_ok, reg_err = True, ""
            if want_tunnel and hub_pubkey:
                wg_priv, dev_pub = _wg_keypair()
                if wg_priv is None:
                    reg_ok, reg_err = False, f"wg keygen failed: {dev_pub}"
                    dev_pub = ""
                else:
                    tunnel_ip = _alloc_tunnel_ip(hub, name)
                    hub.setdefault("leases_meta", {})[name] = {
                        "ip": tunnel_ip, "pubkey": dev_pub}
                    # rebuild the hub peers file from every device's pubkey+ip
                    leases = {n: {"ip": hub["leases"].get(n),
                                  "pubkey": m.get("pubkey")}
                              for n, m in hub["leases_meta"].items()}
                    reg_ok, reg_err = _write_wg_peers(peers_path, leases)
            _hub_save(hub_file, hub)
            # one full-access user, used for both polling and config-push
            raw["username"] = uname
            raw["password"] = pwd
            raw["push_username"] = ""   # no separate push user; falls back above
            raw["push_password"] = ""
            if tunnel_ip:
                raw["host"] = tunnel_ip
                # Reach the router over the tunnel on plain API (8728). WireGuard
                # encrypts the tunnel, so no API-SSL is needed — locking the API
                # to the tunnel subnet is what removes it from the internet.
                if lock_api:
                    raw["use_ssl"] = False
                    raw["api_port"] = 8728
            try:
                store.upsert(raw, defaults, original_name=name)
            except Exception as exc:  # noqa: BLE001 — surface validation errors
                store.close()
                return self._send(400, f"Error: {exc}")
            store.close()
            script = _provision_script(
                name, raw, uname, pwd,
                hub_ip=hub_ip, hub_port=hub_port,
                hub_pubkey=hub_pubkey if tunnel_ip else "", wg_priv=wg_priv,
                tunnel_ip=tunnel_ip, subnet=hub.get("subnet"),
                harden=True,
                enable_api=flat.get("enable_api") == "1", lock_api=lock_api)
            creds = {"user": uname, "pwd": pwd, "ip": tunnel_ip, "hub": hub_ip,
                     "pubkey": dev_pub, "reg_ok": reg_ok, "reg_err": reg_err,
                     "peers_path": peers_path,
                     "no_hub_key": want_tunnel and not hub_pubkey}
            if tunnel_ip and reg_ok:
                msg = (f"Generated keys, registered the WireGuard peer on this "
                       f"server, and filled the script with the server's IP "
                       f"({hub_ip}). The device will be reachable at {tunnel_ip}.")
            elif want_tunnel and not hub_pubkey:
                msg = ("Generated the user + API script, but the WireGuard HUB "
                       "isn't set up yet — run deploy/install.sh on the server "
                       "(it creates the hub key). Then regenerate.")
            elif tunnel_ip:
                msg = ("Generated the script, but could NOT write the hub peers "
                       "file — add the peer shown below on the server.")
            else:
                msg = "Generated a strong password and script for this device."
            return self._device_provision_page(name, user, script=script,
                                                creds=creds, msg=msg)

        def _device_provision_apply(self, flat, user):
            """Zero-touch: connect to the router over the API and apply everything
            (user, API, WireGuard tunnel) — no script to paste."""
            from .config import build_device
            from .device import DeviceError
            from .push import Pusher, PushError, provision_apply, rw_device
            from .push.api import PushApi

            name = flat.get("device", "")
            store = self._devstore()
            if store is None:
                return self._send(400, "device management not enabled")
            raw = store.raw(name)
            if raw is None:
                store.close()
                return self._send(404, "no such device")
            hub_file = _hub_path(devices_db)
            hub = _hub_load(hub_file)
            hub_ip = (flat.get("hub", "").strip() or hub.get("hub_ip")
                      or _detect_server_ip())
            hub["hub_ip"] = hub_ip
            hub.setdefault("subnet", _HUB_SUBNET_DEFAULT)
            hub_pubkey = hub.get("hub_pubkey", "")
            hub_port = hub.get("listen_port", _WG_PORT_DEFAULT)
            peers_path = hub.get("wg_peers") or _WG_PEERS_DEFAULT
            uname = flat.get("pwuser", "").strip() or "mkmonitor"
            pwd = _gen_password()
            want_tunnel = flat.get("transport", "wg").strip() == "wg"
            lock_api = flat.get("lock_api") == "1"
            tunnel_ip = _alloc_tunnel_ip(hub, name) if (want_tunnel and hub_pubkey) \
                else ""
            cfg = build_device(raw, defaults)
            audit = self._auditlog()
            actor = (user or {}).get("login", "")
            dev = rw_device(cfg)
            api = PushApi(dev)
            result, err = None, None
            try:
                api.connect()
                result = provision_apply(
                    api, name, uname, pwd,
                    harden=True,
                    enable_api=flat.get("enable_api") == "1",
                    lock_api=lock_api,
                    hub_pubkey=hub_pubkey,
                    hub_ip=hub_ip, port=hub_port, subnet=hub.get("subnet"),
                    tunnel_ip=tunnel_ip)
            except (DeviceError, PushError) as exc:
                err = str(exc)
            finally:
                dev.close()
            if err is not None:
                if audit:
                    audit.append(name, actor, "provision", "apply", "error",
                                 f"could not provision over the API: {err}", err)
                    audit.close()
                store.close()
                return self._device_provision_page(
                    name, user, error=f"Could not connect to the router to "
                    f"provision it ({err}). Check the device's Host and login on "
                    f"the Devices page, or use the paste-script fallback below.")
            if audit:
                audit.append(name, actor, "provision", "apply", "ok",
                             f"provisioned {uname}"
                             + (f" + WG tunnel {tunnel_ip}" if tunnel_ip else ""),
                             "\n".join(result.get("steps", [])))
                audit.close()
            # register the router's WireGuard peer on the hub
            reg_ok, reg_err, router_pub = True, "", result.get("router_pubkey", "")
            if tunnel_ip and router_pub:
                hub.setdefault("leases_meta", {})[name] = {
                    "ip": tunnel_ip, "pubkey": router_pub}
                leases = {n: {"ip": hub["leases"].get(n), "pubkey": m.get("pubkey")}
                          for n, m in hub["leases_meta"].items()}
                reg_ok, reg_err = _write_wg_peers(peers_path, leases)
            _hub_save(hub_file, hub)
            # save the new creds; reach the device at the tunnel IP from now on.
            # one full-access user does both polling and config-push.
            raw["username"] = uname
            raw["password"] = pwd
            raw["push_username"] = ""   # no separate push user; falls back
            raw["push_password"] = ""
            if tunnel_ip and router_pub:
                raw["host"] = tunnel_ip
                # plain API (8728) over the encrypted tunnel — no API-SSL
                if lock_api:
                    raw["use_ssl"] = False
                    raw["api_port"] = 8728
            try:
                store.upsert(raw, defaults, original_name=name)
            finally:
                store.close()
            creds = {"user": uname, "pwd": pwd,
                     "ip": tunnel_ip if router_pub else "",
                     "hub": hub_ip, "pubkey": router_pub, "reg_ok": reg_ok,
                     "reg_err": reg_err, "peers_path": peers_path,
                     "no_hub_key": want_tunnel and not hub_pubkey, "applied": True}
            if tunnel_ip and router_pub and reg_ok:
                msg = (f"✓ Provisioned over the API and registered the WireGuard "
                       f"peer. The device is reachable at {tunnel_ip}.")
            elif want_tunnel and not hub_pubkey:
                msg = ("Created the user + API over the API, but the WireGuard hub "
                       "isn't set up — run deploy/install.sh on the server, then "
                       "re-run Provision now.")
            else:
                msg = "Provisioned the user + API over the API."
            return self._device_provision_page(name, user, creds=creds, msg=msg)

        def _device_backup_post(self, flat, user):
            name = flat.get("device", "")
            raw = self._device_raw(name)
            if raw is None:
                return self._send(400, "device not managed in the dashboard")
            from .config import build_device
            from .device import DeviceError
            from .push import Pusher, PushError, rw_device
            from .push.api import PushApi

            cfg = build_device(raw, defaults)
            bkname = (flat.get("bkname") or "").strip() or None
            action = flat.get("backup_action", "")
            if action not in ("restore", "delete") and flat.get("apply") != "1":
                # Step 1: dry-run preview — connects to nothing.
                plan = Pusher(cfg, None, dry_run=True).plan_backup(bkname)
                return self._device_backups_page(name, user, dry_plan=plan)
            # Restore / delete / create — actually talk to the router.
            uname = (user or {}).get("login", "")
            audit = self._auditlog()
            dev = rw_device(cfg)
            api = PushApi(dev)
            pusher = Pusher(cfg, api, dry_run=False, audit=audit, user=uname)
            try:
                api.connect()
                if action == "restore":
                    pusher.apply(pusher.plan_restore(bkname or ""),
                                 feature="backup:restore")
                    msg = (f"Restoring '{bkname}' — the router is rebooting and "
                           f"will be back in 1–2 minutes with that configuration.")
                elif action == "delete":
                    pusher.apply(pusher.plan_delete_backup(bkname or ""),
                                 feature="backup:delete")
                    msg = f"Deleted backup '{bkname}'."
                else:
                    pusher.apply(pusher.plan_backup(bkname), feature="backup")
                    msg = "Backup created on the router."
                return self._redirect(
                    f"/device?name={quote(name)}&tab=backups&msg=" + quote(msg))
            except (DeviceError, PushError) as exc:
                return self._device_backups_page(name, user, error=str(exc))
            finally:
                dev.close()
                if audit:
                    audit.close()

        # ---- generic feature tabs (SD-WAN/Security/NextDNS/QoS/…) ----
        def _auditlog(self):
            if not push_log_db:
                return None
            from .push import AuditLog
            return AuditLog(push_log_db)

        def _feature_tab_page(self, name, user, slug, preview=None,
                              submitted=None, error="", msg="",
                              confirm_action="/device/push", report_html=""):
            from .push import FEATURES

            feature = FEATURES.get(slug)
            if feature is None:
                return self._send(404, "no such feature")
            raw = self._device_raw(name)
            if raw is None:
                return self._send(400, "device not managed in the dashboard")
            if feature.get("write") and not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            facts = (_load_state(state_file).get("devices", {})
                     .get(name, {}).get("facts", {}))
            sess = self._session()
            csrf = sess["csrf"] if sess else ""
            audit = self._auditlog()
            recent = audit.recent(device=name, limit=8) if audit else []
            if audit:
                audit.close()
            from .config import build_device

            cfg = build_device(raw, defaults)  # device metadata (no router needed)
            summary_lines = fields = unmanaged = None
            extra_html = extra_actions = ""
            if preview is None and not error:
                from .device import DeviceError
                from .push import Pusher, PushError, rw_device
                from .push.api import PushApi

                dev = rw_device(cfg)
                api = PushApi(dev)
                try:
                    api.connect()
                    pusher = Pusher(cfg, api)
                    current = feature["read"](pusher, cfg)
                    summary_lines = feature["summary"](current, cfg)
                    if "form" in feature:
                        fields = feature["form"](current, cfg)
                    if "unmanaged" in feature:
                        unmanaged = feature["unmanaged"](pusher, cfg)
                    if slug == "scripts":
                        extra_html = _scripts_box(name, csrf, current)
                    elif slug == "qos":
                        extra_html = _queue_script_box(name, csrf, facts)
                    elif slug == "hubtunnel":
                        extra_html = _hubtunnel_box(name, current, csrf)
                    elif slug == "update":
                        extra_html, extra_actions = _update_box(name, csrf, current)
                    elif slug == "interfaces":
                        extra_html = _interfaces_table(current)
                except (DeviceError, PushError) as exc:
                    error = str(exc)
                finally:
                    dev.close()
            page = _render_feature_tab(
                name, user, slug, feature, csrf, summary_lines=summary_lines,
                fields=fields, preview=preview, submitted=submitted, error=error,
                msg=msg, recent=recent, facts=facts, unmanaged=unmanaged,
                confirm_action=confirm_action, cfg=cfg, extra_html=extra_html,
                extra_actions=extra_actions, report_html=report_html)
            return self._send(200, page, "text/html; charset=utf-8")

        def _device_wan_post(self, flat, multi, user):
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            name = flat.get("device", "")
            store = self._devstore()
            if store is None:
                return self._send(400, "device management not enabled")
            raw = store.raw(name)
            if raw is None:
                store.close()
                return self._send(404, "no such device")
            links = []
            for nm, ifc, gw in zip(multi.get("link_name", []),
                                   multi.get("link_iface", []),
                                   multi.get("link_gw", [])):
                nm, ifc, gw = nm.strip(), ifc.strip(), gw.strip()
                if nm or ifc or gw:
                    links.append({"name": nm, "interface": ifc, "gateway": gw})
            raw["wan"] = {"links": links,
                          "ping_targets": (raw.get("wan") or {}).get("ping_targets", [])}
            try:
                store.upsert(raw, defaults, original_name=name)
            except Exception as exc:  # noqa: BLE001 — surface validation errors
                store.close()
                return self._send(400, f"Error: {exc}")
            store.close()
            return self._redirect(f"/device?name={quote(name)}&tab=sdwan&msg=" +
                                  quote("WAN uplinks saved."))

        def _device_adopt_post(self, flat, user):
            from .config import build_device
            from .device import DeviceError
            from .push import (FEATURES, Pusher, PushError, adopt_plan,
                               rw_device)
            from .push.api import PushApi

            slug = flat.get("feature", "")
            name = flat.get("device", "")
            rid = flat.get("adopt_id", "")
            feature = FEATURES.get(slug)
            raw = self._device_raw(name)
            if feature is None or raw is None or not feature.get("adopt"):
                return self._send(404, "not found")
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            cfg = build_device(raw, defaults)
            commit = flat.get("apply") == "1"
            uname = (user or {}).get("login", "")
            audit = self._auditlog()
            dev = rw_device(cfg)
            api = PushApi(dev)
            pusher = Pusher(cfg, api, dry_run=not commit, audit=audit, user=uname)
            try:
                try:
                    api.connect()
                    plan = adopt_plan(pusher, cfg, feature, rid)
                except (DeviceError, PushError) as exc:
                    if audit:
                        audit.append(name, uname, slug + ":adopt",
                                     "apply" if commit else "dry-run", "error",
                                     f"could not read the router: {exc}", str(exc))
                    return self._feature_tab_page(name, user, slug, error=str(exc))
                try:
                    pusher.apply(plan, feature=slug + ":adopt")
                except PushError as exc:
                    return self._feature_tab_page(name, user, slug, error=str(exc))
                if not commit:
                    return self._feature_tab_page(
                        name, user, slug, preview=plan,
                        submitted={"feature": [slug], "adopt_id": [rid]},
                        confirm_action="/device/adopt")
                return self._redirect(
                    f"/device?name={quote(name)}&tab={slug}&msg=" +
                    quote("Rule adopted — it's now under management above."))
            finally:
                dev.close()
                if audit:
                    audit.close()

        def _device_push_post(self, flat, multi, user):
            from .config import build_device
            from .device import DeviceError
            from .push import FEATURES, Pusher, PushError, rw_device
            from .push.api import PushApi

            slug = flat.get("feature", "")
            name = flat.get("device", "")
            feature = FEATURES.get(slug)
            raw = self._device_raw(name)
            if feature is None or raw is None:
                return self._send(404, "not found")
            if feature.get("write") and not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            cfg = build_device(raw, defaults)
            commit = flat.get("apply") == "1"
            uname = (user or {}).get("login", "")
            audit = self._auditlog()
            dev = rw_device(cfg)
            api = PushApi(dev)
            pusher = Pusher(cfg, api, dry_run=not commit, audit=audit, user=uname)
            try:
                # Reading the router (connect + diff) — log failures here so a
                # bad host/credential shows up in the activity log too.
                try:
                    api.connect()
                    plan = feature["plan"](pusher, cfg, flat, multi)
                except (DeviceError, PushError) as exc:
                    if audit:
                        audit.append(name, uname, slug,
                                     "apply" if commit else "dry-run", "error",
                                     f"could not read the router: {exc}", str(exc))
                    return self._feature_tab_page(name, user, slug, error=str(exc))
                # Safety net: snapshot the whole config to a named backup BEFORE
                # committing a real change, so you can restore it from the
                # Backups tab if the change breaks something. Skipped on dry-run
                # previews and no-op plans. If the snapshot can't be made we do
                # NOT proceed — better to fail safe than change without a backup.
                bkname = ""
                if commit and not plan.empty:
                    bkname = f"before-{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
                    try:
                        pusher.apply(pusher.plan_backup(bkname),
                                     feature=slug + ":backup")
                    except PushError as exc:
                        return self._feature_tab_page(
                            name, user, slug,
                            error=f"Could not create the safety backup before "
                                  f"applying ({exc}). Nothing was changed — free "
                                  f"up flash space or check the router, then retry.")
                try:
                    pusher.apply(plan, feature=slug)  # logs its own outcome
                except PushError as exc:
                    return self._feature_tab_page(name, user, slug, error=str(exc))
                if not commit:
                    return self._feature_tab_page(name, user, slug, preview=plan,
                                                  submitted=multi)
                # After applying the hub-tunnel feature, register the router's
                # WireGuard public key as a peer on this server automatically.
                if slug == "hubtunnel" and devices_db:
                    _register_hub_peer(name, pusher.api, flat, devices_db)
                # Safe mode (commit-confirm): arm a local auto-revert so a change
                # that locks us out heals itself. Best-effort — if arming fails
                # the change still stands (just without the safety net).
                if (bkname and flat.get("safe_revert") == "1"
                        and slug != "update"):
                    hub_ip = _hub_tunnel_ip(_hub_load(_hub_path(devices_db)))
                    try:
                        pusher.apply(
                            pusher.plan_arm_revert(bkname, _REVERT_MINUTES,
                                                   hub_ip=hub_ip),
                            feature=slug + ":arm-revert")
                        sess = self._session()
                        return self._send(200, _render_confirm_page(
                            name, user, slug, _REVERT_MINUTES, bkname, hub_ip,
                            sess["csrf"] if sess else ""),
                            "text/html; charset=utf-8")
                    except PushError:
                        pass  # couldn't arm; fall through to the normal result
                return self._redirect(
                    f"/device?name={quote(name)}&tab={slug}&msg=" +
                    quote("Changes applied to the router."))
            finally:
                dev.close()
                if audit:
                    audit.close()

        def _device_reboot_post(self, flat, user):
            """Reboot the router now (/system reboot). Detached run — the API
            session drops as the box restarts, which counts as submitted. We do
            NOT re-read the (now offline) router; just confirm the command went."""
            from .config import build_device
            from .device import DeviceError
            from .push import Pusher, PushError, rw_device
            from .push.api import PushApi
            from .push.plan import Operation, Plan

            name = flat.get("device", "")
            raw = self._device_raw(name)
            if raw is None:
                return self._send(404, "no such device")
            cfg = build_device(raw, defaults)
            audit = self._auditlog()
            uname = (user or {}).get("login", "")
            dev = rw_device(cfg)
            api = PushApi(dev)
            pusher = Pusher(cfg, api, dry_run=False, audit=audit, user=uname)
            err = None
            try:
                api.connect()
                op = Operation("run", ("system",), {"_cmd": "reboot"},
                               desc="reboot the router now (/system reboot)",
                               detach=True)
                pusher.apply(Plan(cfg.name, [op], summary="reboot"),
                             feature="reboot")
            except (DeviceError, PushError) as exc:
                err = str(exc)
            finally:
                dev.close()
                if audit:
                    audit.close()
            q = quote(name)
            if err is not None:
                box = (f'<div class="box" style="border-left:4px solid #dc2626">'
                       f'<h2>Reboot failed</h2><p>{esc(err)}</p>'
                       f'<a class="btn" href="/device?name={q}">Back</a></div>')
            else:
                box = (f'<div class="box" style="border-left:4px solid #16a34a">'
                       f'<h2>Reboot sent to {esc(name)}</h2><p>The router is '
                       f'restarting and will be offline for ~1–2 minutes.</p>'
                       f'<a class="btn" href="/device?name={q}">Back to {esc(name)}'
                       f'</a></div>')
            return self._send(200, _page(esc(name) + " · Reboot",
                              _header(user, "/") + f'<div class="wrap">{box}</div>'),
                              "text/html; charset=utf-8")

        def _device_access_post(self, flat, user):
            """Open or close an on-demand WebFig/Winbox grant for a device. The
            grant is written to the access-grants file; the hub's reload unit
            turns it into (or removes it from) the nginx proxy config."""
            store = self._access_store()
            if store is None:
                return self._send(400, "remote access not configured "
                                       "(set access.hub_host in config)")
            name = flat.get("device", "")
            kind = flat.get("kind", "")
            action = flat.get("action", "")
            from .access import KINDS
            if kind not in KINDS:
                return self._send(400, "unknown access kind")
            q = quote(name)
            if action == "close":
                store.close(name, kind)
                return self._redirect(f"/device?name={q}")
            tunnel_ip = _device_tunnel_ip(name, devices_db)
            if not tunnel_ip:
                return self._send(400, "this device has no hub tunnel yet")
            try:
                store.open(name, kind, tunnel_ip, ttl=self._access_ttl())
            except (ValueError, RuntimeError) as exc:
                return self._send(400, f"Error: {exc}")
            return self._redirect(f"/device?name={q}")

        def _device_confirm_post(self, flat, user):
            """Approve a safe-mode change: connect and cancel the pending
            auto-revert scheduler. If the router can't be reached, the change
            evidently broke connectivity — so we leave the revert armed and tell
            the user it will roll back on its own."""
            from .config import build_device
            from .device import DeviceError
            from .push import Pusher, PushError, rw_device
            from .push.api import PushApi

            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            name = flat.get("device", "")
            slug = flat.get("feature", "")
            raw = self._device_raw(name)
            if raw is None:
                return self._send(404, "no such device")
            cfg = build_device(raw, defaults)
            audit = self._auditlog()
            dev = rw_device(cfg)
            api = PushApi(dev)
            err = None
            try:
                api.connect()
                pusher = Pusher(cfg, api, dry_run=False, audit=audit,
                                user=(user or {}).get("login", ""))
                pusher.apply(pusher.plan_disarm_revert(), feature=slug + ":confirm")
            except (DeviceError, PushError) as exc:
                err = str(exc)
            finally:
                dev.close()
                if audit:
                    audit.close()
            if err is None:
                return self._redirect(
                    f"/device?name={quote(name)}&tab={quote(slug)}&msg=" +
                    quote("Change kept — auto-revert cancelled."))
            q = quote(name)
            box = (f'<div class="box" style="border-left:4px solid #dc2626">'
                   f'<h2>Could not reach {esc(name)} to confirm</h2>'
                   f'<p>{esc(err)}</p><p>If the change broke the router\'s '
                   f'connectivity, <b>leave it</b> — the safety net will revert it '
                   f'to the pre-change backup and reboot within the timer, and it '
                   f'should come back on the old config. Try the dashboard again in '
                   f'a couple of minutes.</p>'
                   f'<a class="btn" href="/device?name={q}">Back to {esc(name)}</a>'
                   f'</div>')
            return self._send(200, _page(esc(name) + " · Confirm",
                              _header(user, "/") + f'<div class="wrap">{box}</div>'),
                              "text/html; charset=utf-8")

        def _device_forget_post(self, flat, user):
            """Remove a device from the dashboard entirely: delete it from the
            devices DB (if managed) and purge its metrics + saved state. Works
            for orphan devices that are no longer in the DB too (just purges).
            Also attempts to decommission the router (remove WG tunnel + monitor user)."""
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            name = flat.get("device", "")
            if not name:
                return self._redirect("/")
            uname = (user or {}).get("login", "system")
            raw = None
            store = self._devstore()
            if store is not None:
                try:
                    raw = store.raw(name)
                    store.delete(name)
                finally:
                    store.close()
            result = self._try_offboard(raw, name, uname)
            self._purge_device_data(name)
            page = _render_offboard_page(name, result, "/", user)
            return self._send(200, page, "text/html; charset=utf-8")

        def _device_wg_repair_post(self, flat, user):
            """Connect to the router, diagnose + self-repair the WireGuard tunnel,
            log the outcome, and render the Hub tunnel tab with a full report. A
            connection/read failure is itself reported as a failed repair (with
            the error) rather than 500-ing."""
            from .config import build_device
            from .device import DeviceError
            from .push import PushError, rw_device, wireguard_repair
            from .push.api import PushApi

            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            name = flat.get("device", "")
            raw = self._device_raw(name)
            if raw is None:
                return self._send(404, "no such device")
            cfg = build_device(raw, defaults)
            actor = (user or {}).get("login", "")
            dev = rw_device(cfg)
            api = PushApi(dev)
            report, err = None, None
            try:
                api.connect()
                report = wireguard_repair(api)
            except (DeviceError, PushError) as exc:
                err = str(exc)
            finally:
                dev.close()
            if err is not None:
                report = {"status": "failed", "version": "?", "supported": True,
                          "applied": [],
                          "steps": [{"level": "error",
                                     "msg": f"Could not connect to the router to "
                                            f"check the tunnel: {err}. Verify the "
                                            f"Host and the read-write push user on "
                                            f"the Devices page."}]}
            audit = self._auditlog()
            if audit:
                summary = "; ".join(s["msg"] for s in report["steps"])
                ok = report["status"] not in ("failed",)
                audit.append(name, actor, "hubtunnel", "wg-repair",
                             "ok" if ok else "error",
                             f"tunnel self-repair: {report['status']} "
                             f"({len(report['applied'])} fix(es))", summary)
                audit.close()
            return self._feature_tab_page(
                name, user, "hubtunnel",
                report_html=_wg_repair_report_html(report))

        def _serve_logs(self, user):
            if not AuthStore.is_admin(user):
                return self._send(403, "forbidden")
            audit = self._auditlog()
            rows = audit.recent(limit=200) if audit else []
            if audit:
                audit.close()
            return self._send(200, _render_logs(user, rows),
                              "text/html; charset=utf-8")

        def _devices_post(self, path, flat, multi, user):
            store = self._devstore()
            if store is None:
                return self._send(400, "device management not enabled "
                                       "(set devices_db in config)")
            try:
                if path == "/devices/delete":
                    name = flat.get("name", "")
                    raw = store.raw(name)
                    uname = (user or {}).get("login", "system")
                    result = self._try_offboard(raw, name, uname)
                    store.delete(name)
                    self._purge_device_data(name)
                    page = _render_offboard_page(name, result, "/devices", user)
                    return self._send(200, page, "text/html; charset=utf-8")
                if path == "/devices/test":
                    return self._device_test(store, flat.get("name", ""), user)
                if path == "/devices/save":
                    raw = self._device_form_to_raw(store, flat, multi)
                    orig = flat.get("original_name") or None
                    # TODO: re-enable after testing
                    # if not orig and auth:
                    #     org_count = store.count_for_org(user["org_id"])
                    #     org_plan = (auth.org(user["org_id"]) or {}).get("plan", "free")
                    #     if org_plan == "free" and org_count >= _FREE_PLAN_DEVICE_LIMIT:
                    #         return self._send(200,
                    #             _render_upgrade_wall(user, org_count),
                    #             "text/html; charset=utf-8")
                    # Script-first add: no public IP entered -> provision over
                    # the tunnel. Pre-assign a stable tunnel IP now so the record
                    # is valid; the router dials home when the generated script
                    # is pasted, then the device syncs on the next poll.
                    provision_mode = not raw.get("host") and not orig
                    if provision_mode:
                        if not raw.get("name"):
                            return self._send(400, "Error: a device name is "
                                                   "required")
                        hub_file = _hub_path(devices_db)
                        hub = _hub_load(hub_file)
                        hub.setdefault("subnet", _HUB_SUBNET_DEFAULT)
                        raw["host"] = _alloc_tunnel_ip(hub, raw["name"])
                        _hub_save(hub_file, hub)
                        raw["use_ssl"] = False
                        raw["api_port"] = 8728
                    store.upsert(raw, defaults, original_name=orig,
                                 org_id=user["org_id"])
                    if provision_mode:
                        # Straight to the provisioning script to paste & sync.
                        return self._redirect(
                            f"/device?name={quote(raw['name'])}&tab=provision")
                    return self._redirect("/devices")
                return self._send(404, "not found")
            except Exception as exc:  # noqa: BLE001 — surface validation errors
                return self._send(400, f"Error: {exc}")
            finally:
                store.close()

        @staticmethod
        def _device_form_to_raw(store, flat, multi):
            def csv(s):
                return [x.strip() for x in (s or "").split(",") if x.strip()]
            orig = flat.get("original_name") or None
            orig_raw = (store.raw(orig) or {}) if orig else {}
            # The add/edit form no longer has username/password fields — the
            # provisioning script creates the login. Keep whatever the device
            # already has (so editing never wipes its credentials); provisioning
            # overwrites them with the generated user afterwards.
            uname = flat.get("username", "").strip() or orig_raw.get("username", "")
            pwd = flat.get("password", "") or orig_raw.get("password", "")
            # The form no longer has separate push-user fields — one full-access
            # login does both monitoring and config-push. Preserve any push creds
            # an older device still has (so editing it doesn't break pushing);
            # new devices have none and fall back to username/password.
            push_user = (flat.get("push_username", "").strip()
                         or orig_raw.get("push_username", ""))
            push_pwd = (flat.get("push_password", "")
                        or orig_raw.get("push_password", ""))
            checks_sel = set(multi.get("checks", []))
            # WAN uplinks come as parallel arrays, one entry per editor row,
            # in priority order (top row = highest priority).
            names = multi.get("link_name", [])
            ifaces = multi.get("link_iface", [])
            gws = multi.get("link_gw", [])
            links = []
            for nm, ifc, gw in zip(names, ifaces, gws):
                nm, ifc, gw = nm.strip(), ifc.strip(), gw.strip()
                if nm or ifc or gw:
                    links.append({"name": nm, "interface": ifc, "gateway": gw})
            # API port is required to connect, but you can leave it blank: it
            # defaults to 8729 when API-SSL is ticked, else 8728.
            api_port = (flat.get("api_port") or "").strip()
            if not api_port:
                api_port = "8729" if "use_ssl" in flat else "8728"
            return {
                "name": flat.get("name", "").strip(),
                "host": flat.get("host", "").strip(),
                "api_port": int(api_port),
                "username": uname,
                "password": pwd,
                "push_username": push_user,
                "push_password": push_pwd,
                "use_ssl": "use_ssl" in flat,
                "verify_ssl": "verify_ssl" in flat,
                "timeout": int(flat.get("timeout") or 60),
                "lan_subnets": csv(flat.get("lan_subnets")),
                "wan": {"links": links},
                "monitor_interfaces": csv(flat.get("monitor_interfaces")),
                "client_count_sources": multi.get("sources") or ["dhcp", "wireless"],
                "checks": {k: (k in checks_sel) for k in DEFAULT_CHECKS},
            }

        def _device_test(self, store, name, user):
            raw = store.raw(name)
            if not raw:
                return self._send(404, "no such device")
            from .config import build_device
            from .device import Device, DeviceError

            cfg = build_device(raw, defaults)
            dev = Device(cfg)
            try:
                if not dev.reachable():
                    return self._send(200, _render_test_result(
                        name, False, f"UNREACHABLE: no TCP response from "
                        f"{cfg.host}:{cfg.api_port}", user),
                        "text/html; charset=utf-8")
                dev.connect()
                res = dev.fetch(["resource"]).resource
                detail = (f"board={res.get('board-name', '?')}  "
                          f"version={res.get('version', '?')}  "
                          f"uptime={res.get('uptime', '?')}  "
                          f"cpu={res.get('cpu-load', '?')}%")
                return self._send(200, _render_test_result(name, True, detail, user),
                                  "text/html; charset=utf-8")
            except DeviceError as exc:
                return self._send(200, _render_test_result(name, False, str(exc),
                                  user), "text/html; charset=utf-8")
            finally:
                dev.close()

        # ---- POST ----
        def do_POST(self):
            if auth is None:
                return self._send(404, "not found")
            path = urlparse(self.path).path
            if path == "/signup":
                return self._post_signup()
            if path == "/login":
                return self._post_login()
            if path == "/logout":
                sessions.destroy(self._token())
                return self._redirect("/login", self._cookie_header("", clear=True))
            # /account: any logged-in user edits their own email/password.
            if path == "/account":
                return self._post_account()
            # Everything below requires an owner + a valid CSRF token.
            user = self._user()
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            flat, multi = self._form()
            if flat.get("csrf") != self._session()["csrf"]:
                return self._send(400, "bad csrf token")
            # Org isolation: an owner may only touch devices their company owns.
            if not self._owns_target(flat, user):
                return self._send(403, "forbidden")
            if path.startswith("/devices/"):
                return self._devices_post(path, flat, multi, user)
            if path == "/device/backup":
                return self._device_backup_post(flat, user)
            if path == "/device/provision":
                return self._device_provision_post(flat, user)
            if path == "/device/push":
                return self._device_push_post(flat, multi, user)
            if path == "/device/forget":
                return self._device_forget_post(flat, user)
            if path == "/device/wg-repair":
                return self._device_wg_repair_post(flat, user)
            if path == "/device/adopt":
                return self._device_adopt_post(flat, user)
            if path == "/device/wan":
                return self._device_wan_post(flat, multi, user)
            if path == "/device/reboot":
                return self._device_reboot_post(flat, user)
            if path == "/device/access":
                return self._device_access_post(flat, user)
            if path == "/device/confirm":
                return self._device_confirm_post(flat, user)
            try:
                if path == "/admin/add":
                    auth.add_member(user["org_id"], flat.get("email", ""),
                                    flat.get("password", ""),
                                    role=flat.get("role", "member"),
                                    devices=self._devices(flat, multi))
                elif path == "/admin/update":
                    acct = flat.get("account", "")
                    if not self._same_org(acct, user):
                        return self._send(403, "forbidden")
                    auth.set_role(acct, flat.get("role", "member"))
                    auth.set_devices(acct, self._devices(flat, multi))
                elif path == "/admin/delete":
                    acct = flat.get("account", "")
                    if not self._same_org(acct, user):
                        return self._send(403, "forbidden")
                    if acct == user["login"]:
                        return self._send(400, "cannot delete yourself")
                    auth.delete_user(acct)
                else:
                    return self._send(404, "not found")
            except Exception as exc:  # noqa: BLE001 — surface as a simple message
                return self._send(400, f"Error: {exc}")
            return self._redirect("/admin")

        def _same_org(self, identifier, user) -> bool:
            """True if `identifier` (email or username) is a user in the acting
            owner's company."""
            target = auth.get_user(identifier) if identifier else None
            return bool(target) and target.get("org_id") == user.get("org_id")

        def _owns_target(self, flat, user) -> bool:
            """For device-targeted POSTs, every *existing* device the request
            names must belong to the owner's company. New (not-yet-stored)
            names pass through — they'll be stamped with the owner's org.
            Non-device actions (admin/*) carry no device field and pass; they
            are scoped separately by _same_org."""
            if not devices_db:
                return True
            names = {flat.get(k, "") for k in
                     ("device", "name", "original_name")} - {""}
            if not names:
                return True
            ds = self._devstore()
            try:
                for n in names:
                    org = ds.org_of(n) if ds else None
                    if org is not None and org != user.get("org_id"):
                        return False
            finally:
                if ds:
                    ds.close()
            return True

        @staticmethod
        def _devices(flat, multi):
            if flat.get("all"):
                return "*"
            return multi.get("devices", [])

        def _post_signup(self):
            flat, _ = self._form()
            email = flat.get("email", "").strip().lower()
            phone = flat.get("phone", "").strip()
            import re as _re
            if len(_re.sub(r"\D", "", phone)) < 7:
                return self._redirect("/signup?error=" + quote(
                    "A valid mobile number is required (at least 7 digits)."))
            try:
                auth.signup(email, flat.get("password", ""),
                            flat.get("company", ""), phone=phone)
            except Exception as exc:  # noqa: BLE001 — show the reason on the form
                return self._redirect("/signup?error=" + quote(str(exc)))
            token = sessions.create(email)
            return self._redirect("/", self._cookie_header(token))

        def _post_login(self):
            flat, _ = self._form()
            # Accept either an email or a (legacy) username as the identifier.
            ident = flat.get("email", "") or flat.get("username", "")
            user = auth.verify(ident, flat.get("password", ""))
            if not user:
                time.sleep(0.5)  # mild brute-force friction
                return self._redirect("/login?error=1")
            token = sessions.create(user["login"])
            return self._redirect("/", self._cookie_header(token))

        def _post_account(self):
            user = self._user()
            if not user:
                return self._redirect("/login")
            flat, _ = self._form()
            if flat.get("csrf") != self._session()["csrf"]:
                return self._send(400, "bad csrf token")
            new_email = flat.get("email", "").strip().lower()
            new_pw = flat.get("password", "")
            ident = user["login"]
            try:
                if new_pw:
                    auth.set_password(ident, new_pw)
                if new_email and new_email != (user.get("email") or ""):
                    auth.set_email(ident, new_email)
                    # The session is keyed by login id. If they signed in with
                    # the email they just changed, repoint it so they stay
                    # logged in (signing in with a username keeps working as-is).
                    sess = self._session()
                    if sess and sess.get("login") == user.get("email"):
                        sess["login"] = new_email
            except Exception as exc:  # noqa: BLE001
                return self._redirect("/account?error=" + quote(str(exc)))
            return self._redirect("/account?ok=" + quote("Saved."))

    return Handler


def _register_hub_peer(device_name: str, api, flat: dict, devices_db: str) -> None:
    """After a successful hubtunnel apply, read the router's WireGuard public key
    and add it as a peer in hub.json + wg-peers.conf so the server side is in sync.
    Best-effort: any failure is silently swallowed so it never blocks the response."""
    try:
        from .push.features import _HUB_WG, _HUB_NAME
        tunnel_ip = flat.get("tunnel_ip", "").strip().split("/")[0]
        if not tunnel_ip:
            return
        ifaces = api.fetch(_HUB_WG)
        router_pub = next(
            (w.get("public-key", "") for w in ifaces if w.get("name") == _HUB_NAME),
            "")
        if not router_pub:
            return  # keypair still generating — Provision tab handles the async case
        hub_file = _hub_path(devices_db)
        hub = _hub_load(hub_file)
        peers_path = hub.get("wg_peers") or _WG_PEERS_DEFAULT
        hub.setdefault("leases", {})[device_name] = tunnel_ip
        hub.setdefault("leases_meta", {})[device_name] = {
            "ip": tunnel_ip, "pubkey": router_pub}
        leases = {n: {"ip": m.get("ip"), "pubkey": m.get("pubkey")}
                  for n, m in hub.get("leases_meta", {}).items()}
        _write_wg_peers(peers_path, leases)
        _hub_save(hub_file, hub)
    except Exception:  # noqa: BLE001
        pass


def serve(metrics_db, state_file, host="127.0.0.1", port=8080, auth_db=None,
          secure_cookies=False, metrics_token=None, devices_db=None,
          defaults=None, push_log_db=None, access_cfg=None):
    if metrics_db and not os.path.exists(metrics_db):
        log.warning("metrics DB %s not found yet — start the monitor first",
                    metrics_db)
    auth = AuthStore(auth_db) if auth_db else None
    if auth and not auth.count_users():
        log.info("No accounts yet — open the dashboard and create a company "
                 "account at /signup.")
    sessions = SessionManager()
    httpd = ThreadingHTTPServer(
        (host, port), make_handler(metrics_db, state_file, auth, sessions,
                                   secure_cookies, metrics_token, devices_db,
                                   defaults, push_log_db, access_cfg))
    scheme = "auth ON" if auth else "auth OFF (open)"
    log.info("Dashboard at http://%s:%d  [%s]  Prometheus: /metrics",
             host, port, scheme)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if auth:
            auth.close()
