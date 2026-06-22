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

_CLIENT_SOURCES = ["dhcp", "wireless", "arp", "hotspot"]
esc = html.escape

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


def _all_devices(store, state, allowed=None) -> list:
    names = _known_devices(store, state)
    if allowed is not None:
        names = [n for n in names if n in allowed]
    return [_device_view(store, state, n) for n in names]


# ============================ rendering ====================================
def _sparkline(points, width=160, height=36) -> str:
    vals = [v for _, v in points]
    if len(vals) < 2:
        return f'<svg width="{width}" height="{height}"></svg>'
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1.0
    step = width / (len(vals) - 1)
    coords = " ".join(
        f"{i * step:.1f},{height - 2 - (v - lo) / rng * (height - 4):.1f}"
        for i, v in enumerate(vals))
    return (f'<svg width="{width}" height="{height}" style="vertical-align:middle">'
            f'<polyline fill="none" stroke="#2563eb" stroke-width="1.5" '
            f'points="{coords}"/></svg>')


_PAGE_CSS = """
 *{box-sizing:border-box}
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
 a{color:#2563eb}
 h1{font-size:22px;margin:0 0 16px}
 /* top nav */
 header{background:#0f172a;color:#fff;padding:0 20px;display:flex;align-items:center;
   gap:6px;height:54px;box-shadow:0 1px 4px rgba(0,0,0,.2)}
 .brand{font-weight:700;font-size:17px;display:flex;align-items:center;gap:8px}
 .brand .logo{color:#38bdf8;font-size:18px}
 nav{display:flex;gap:4px;margin-left:20px}
 nav a{color:#cbd5e1;text-decoration:none;padding:8px 13px;border-radius:7px;
   font-size:14px}
 nav a:hover{background:#1e293b;color:#fff}
 nav a.on{background:#2563eb;color:#fff}
 header .right{margin-left:auto;display:flex;align-items:center;gap:14px;font-size:13px}
 .who{display:flex;flex-direction:column;line-height:1.15;text-align:right}
 .who small{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
 .logout{color:#93c5fd;text-decoration:none}.logout:hover{text-decoration:underline}
 /* device card grid */
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
   gap:16px;padding:18px 20px}
 .card{background:#fff;border-radius:10px;padding:14px 18px;
   box-shadow:0 1px 3px rgba(0,0,0,.1);border-left:4px solid #16a34a}
 .card h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
 .card.warn{border-left-color:#d97706}.card.crit{border-left-color:#dc2626}
 .dot{width:11px;height:11px;border-radius:50%;display:inline-block}
 .state{margin-left:auto;font-size:11px;color:#64748b;font-weight:600}
 /* NOC summary bar */
 .noc{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));
   gap:12px;padding:18px 20px 0}
 .tile{background:#fff;border-radius:10px;padding:12px 14px;
   box-shadow:0 1px 3px rgba(0,0,0,.1);border-top:3px solid #94a3b8;cursor:default}
 .tile.click{cursor:pointer}.tile.click:hover{box-shadow:0 2px 8px rgba(0,0,0,.18)}
 .tile .num{font-size:28px;font-weight:700;line-height:1}
 .tile .lbl{font-size:11px;color:#64748b;text-transform:uppercase;
   letter-spacing:.04em;margin-top:6px}
 .tile.green{border-top-color:#16a34a}.tile.green .num{color:#16a34a}
 .tile.red{border-top-color:#dc2626}.tile.red .num{color:#dc2626}
 .tile.amber{border-top-color:#d97706}.tile.amber .num{color:#d97706}
 .tile.planned{border-top-color:#cbd5e1}.tile.planned .num{color:#94a3b8;font-size:20px}
 .tile.planned .lbl::after{content:" · soon";color:#94a3b8}
 /* filter / search bar */
 .fbar{display:flex;gap:8px;align-items:center;padding:16px 20px 0;flex-wrap:wrap}
 .fbar input{flex:1;min-width:200px}
 .fbtn{background:#e2e8f0;border:0;padding:7px 13px;border-radius:7px;cursor:pointer;
   font-size:13px;color:#0f172a}.fbtn:hover{background:#cbd5e1}
 .fbtn.on{background:#2563eb;color:#fff}
 .muted{color:#64748b;font-size:12px}
 /* tables */
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;
   border-bottom:2px solid #e2e8f0}
 td,th{padding:8px 8px;border-bottom:1px solid #eef2f6;text-align:left;
   vertical-align:middle}
 tr:last-child td{border-bottom:0}
 .probs{margin-top:8px;color:#b91c1c;font-size:13px}.probs ul{margin:4px 0 0 18px}
 .ok{margin-top:8px;color:#16a34a;font-size:13px}
 /* layout + forms */
 .wrap{max-width:960px;margin:26px auto;padding:0 20px}
 .box{background:#fff;border-radius:10px;padding:20px;margin:16px 0;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
 .box h2{font-size:16px;margin:0 0 14px}
 form.inline{display:inline}
 input,select{font:inherit;padding:7px 9px;border:1px solid #cbd5e1;border-radius:7px;
   background:#fff;color:#0f172a}
 input:focus,select:focus{outline:2px solid #bfdbfe;border-color:#2563eb}
 .fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
   gap:14px 16px}
 .fields label.f{display:block;font-size:12px;color:#475569;font-weight:600;
   margin-bottom:4px}
 .fields .f input,.fields .f select{width:100%}
 .full{grid-column:1/-1}
 .chips{display:flex;flex-wrap:wrap;gap:6px;margin:2px 0}
 .chips label{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;
   padding:4px 11px;font-size:12px;cursor:pointer;user-select:none}
 .chips label:hover{background:#e2e8f0}
 .chips input{margin:0 5px 0 0;vertical-align:middle}
 .chk{margin-right:12px;font-size:13px}
 input.switch{appearance:none;-webkit-appearance:none;width:38px;height:20px;
   background:#cbd5e1;border-radius:999px;position:relative;cursor:pointer;
   vertical-align:middle;transition:.15s;flex:none}
 input.switch:checked{background:#2563eb}
 input.switch::after{content:"";position:absolute;top:2px;left:2px;width:16px;
   height:16px;background:#fff;border-radius:50%;transition:.15s}
 input.switch:checked::after{left:20px}
 .chk:has(.switch){display:inline-flex;align-items:center;gap:8px}
 .wanrow{display:flex;gap:8px;align-items:center;margin-bottom:7px}
 .wanrow .prio{width:24px;height:24px;border-radius:50%;background:#2563eb;color:#fff;
   display:flex;align-items:center;justify-content:center;font-size:12px;
   font-weight:700;flex-shrink:0}
 .wanrow input{flex:1;min-width:90px}
 .wanrow .wandel{padding:4px 10px;line-height:1}
 .rowtbl{width:100%;margin-top:6px}
 .rowtbl th{font-size:11px;color:#64748b;text-transform:uppercase;
   letter-spacing:.03em;padding:4px 6px;border-bottom:1px solid #e2e8f0}
 .rowtbl td{padding:4px 6px;border-bottom:1px solid #f1f5f9}
 .rowtbl input{padding:6px 8px}
 .btn{background:#2563eb;color:#fff;border:0;padding:8px 15px;border-radius:7px;
   cursor:pointer;font:inherit;font-weight:600}.btn:hover{background:#1d4ed8}
 .btn.red{background:#dc2626}.btn.red:hover{background:#b91c1c}
 .btn.ghost{background:#e2e8f0;color:#0f172a}.btn.ghost:hover{background:#cbd5e1}
 .actions{display:flex;gap:8px;align-items:center}
 .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;
   font-weight:700;text-transform:uppercase;letter-spacing:.03em}
 .pill.admin{background:#ede9fe;color:#6d28d9}.pill.user{background:#e0f2fe;color:#0369a1}
 /* NOC charts */
 .charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
   gap:14px;padding:14px 20px 0}
 .chart{background:#fff;border-radius:10px;padding:14px;box-shadow:0 1px 3px
   rgba(0,0,0,.1);display:flex;flex-direction:column;align-items:center}
 .chart.wide{align-items:stretch}
 .chart .ct{font-size:12px;font-weight:700;color:#475569;text-transform:uppercase;
   letter-spacing:.04em;margin-bottom:8px;align-self:flex-start}
 .legend{margin-top:8px;width:100%}
 .lg{display:flex;align-items:center;gap:6px;font-size:12px;color:#334155;
   margin:2px 0}
 .sw{width:10px;height:10px;border-radius:2px;display:inline-block}
 .lg b{margin-left:auto}
 .vlist{display:flex;flex-direction:column;gap:8px}
 .vrow{display:flex;align-items:center;gap:10px;font-size:13px}
 .vlabel{width:150px;flex-shrink:0}
 .vbar{flex:1;height:10px;background:#eef2f6;border-radius:6px;overflow:hidden}
 .vbar i{display:block;height:100%}
 .vn{width:24px;text-align:right;font-weight:700}
 .up{background:#fef3c7;color:#92400e;font-size:10px;font-weight:700;padding:1px 6px;
   border-radius:999px;text-transform:uppercase}
 /* gauges + device overview */
 .gauge{margin:8px 0}
 .gl{display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px}
 .gl span{font-weight:700}
 .gbar{height:12px;background:#eef2f6;border-radius:7px;overflow:hidden}
 .gbar i{display:block;height:100%}
 .factgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
   gap:12px}
 .fact .k{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.03em}
 .fact .val{font-size:15px;font-weight:600;margin-top:2px}
 .tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:2px solid #e2e8f0;
   margin-bottom:16px}
 .tabs a{padding:8px 13px;font-size:14px;color:#475569;text-decoration:none;
   border-bottom:2px solid transparent;margin-bottom:-2px}
 .tabs a.on{color:#2563eb;border-bottom-color:#2563eb;font-weight:600}
 .tabs a.soon{color:#cbd5e1;cursor:not-allowed}
 .tabs a.soon::after{content:" · soon";font-size:10px}
 .cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
 .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;
   font-weight:700}
 .badge.ok{background:#dcfce7;color:#166534}.badge.warn{background:#fef3c7;color:#92400e}
 .badge.crit{background:#fee2e2;color:#991b1b}
 .linkrow{display:flex;align-items:center;gap:10px;padding:8px 0;
   border-bottom:1px solid #eef2f6}
 .linkrow .prio{width:22px;height:22px;border-radius:50%;background:#1e293b;
   color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;
   font-weight:700;flex-shrink:0}
"""


def _nav(user, active) -> str:
    if not user:
        return ""
    items = [("/", "Dashboard"), ("/inventory", "Inventory")]
    if user.get("role") == "admin":
        items += [("/devices", "Devices"), ("/logs", "Activity"),
                  ("/admin", "Users")]
    links = "".join(
        f'<a href="{href}" class="{"on" if href == active else ""}">{label}</a>'
        for href, label in items)
    return f"<nav>{links}</nav>"


def _header(user, active="/") -> str:
    brand = '<div class="brand"><span class="logo">&#9670;</span>mikromon</div>'
    if not user:
        return f"<header>{brand}</header>"
    chip = (f'<span class="who">{esc(user["username"])}'
            f'<small>{esc(user["role"])}</small></span>')
    return (f"<header>{brand}{_nav(user, active)}"
            f'<div class="right">{chip}<a class="logout" href="/logout">Log out</a>'
            f"</div></header>")


def _severity(d) -> str:
    """Worst-first ordering key: offline = crit, any problem = warn, else ok."""
    if not d["up"]:
        return "crit"
    return "warn" if d["problems"] else "ok"


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


def _zt_setup_banner(csrf: str) -> str:
    return (
        '<div style="background:#fffbeb;border-left:4px solid #d97706;padding:14px 20px;'
        'margin:16px auto;max-width:1100px;border-radius:6px">'
        '<b>ZeroTier not configured</b> — set up your dial-home tunnel so routers '
        'behind NAT can connect back to this server.<br>'
        '<small style="color:#92400e">Create a free network at '
        '<a href="https://my.zerotier.com" target="_blank">my.zerotier.com</a>, '
        'then paste the Network ID below.</small>'
        f'<form method="POST" action="/admin/zerotier" '
        f'style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<input name="zt_network_id" placeholder="ZeroTier Network ID (e.g. 1a2b3c4d5e6f7890)" '
        'style="flex:1;min-width:260px">'
        '<button class="btn" type="submit">Save &amp; activate</button>'
        '</form></div>')


def _render_dashboard(store, state, user=None, allowed=None, zt_banner="") -> str:
    devs = sorted(_all_devices(store, state, allowed),
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
            f'<meta http-equiv="refresh" content="10"><title>mikromon</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'{zt_banner}'
            f'{_render_noc_bar(summary)}{charts}{fbar}'
            f'<div class="grid">{grid}</div>{empty}{_DASH_JS}</body></html>')


_DEVICE_TABS = ["Overview", "Provision", "SD-WAN", "Security", "Restrict access",
                "NextDNS", "QoS", "Port forwarding", "Interfaces", "Remote access",
                "Tunnel", "Hub tunnel", "Scripts", "Update", "Backups"]
# label -> url slug (all tabs are wired to the engine now)
_LIVE_TABS = {"Overview": "", "Provision": "provision", "SD-WAN": "sdwan",
              "Security": "security", "Restrict access": "harden",
              "NextDNS": "nextdns", "QoS": "qos", "Port forwarding": "portfwd",
              "Interfaces": "interfaces", "Remote access": "remote",
              "Tunnel": "tunnel", "Hub tunnel": "hubtunnel", "Scripts": "scripts",
              "Update": "update", "Backups": "backups"}
# tabs that WRITE to the router (admins only); Overview + Interfaces are read-only
_ADMIN_TABS = {"provision", "sdwan", "security", "harden", "nextdns", "qos",
               "portfwd", "remote", "tunnel", "hubtunnel", "scripts", "update",
               "backups"}


def _device_tabbar(name, active, is_admin=True) -> str:
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
    return f'<div class="tabs">{"".join(out)}</div>'


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


def _render_device(store, state, name, user) -> str:
    d = _device_view(store, state, name)
    f = d["facts"]
    sev = _severity(d)
    badge = {"ok": ("ok", "Healthy"), "warn": ("warn", "Warning"),
             "crit": ("crit", "Offline / Error")}[sev]
    m = d["metrics"]

    tabbar = _device_tabbar(name, "overview", AuthStore.is_admin(user or {}))
    facts_html = _facts_strip(f)

    # gauges (live latest values)
    gauges = ""
    if "cpu" in m:
        gauges += _gauge("CPU load", m["cpu"])
    if "mem_free_pct" in m:
        gauges += _gauge("Memory used", 100 - m["mem_free_pct"])
    if "temp_c" in m:
        gauges += _gauge("Temperature", m["temp_c"], unit="°C")
    if "client_count" in m:
        gauges += (f'<div class="gauge"><div class="gl">Connected devices'
                   f'<span>{m["client_count"]:.0f}</span></div></div>')
    gauges = gauges or '<p class="muted">No telemetry collected yet.</p>'

    # WAN uplinks with live throughput + role
    wl = f.get("wan_links") or []
    cur_link = next((p for p in d["problems"] if p["key"] == "wan_failover"), None)
    link_rows = ""
    for i, name_lbl in enumerate(wl):
        role = "primary" if i == 0 else "backup"
        tp = ""
        # match throughput by interface label if present
        for iface, t in d["throughput"].items():
            if iface and (iface == name_lbl):
                tp = (f' &nbsp;&darr;{human_bps(t.get("rx_bps", 0))} '
                      f'&uarr;{human_bps(t.get("tx_bps", 0))}')
        link_rows += (f'<div class="linkrow"><span class="prio">{i + 1}</span>'
                      f'<b>{esc(name_lbl)}</b> <span class="muted">{role}</span>'
                      f'{tp}</div>')
    if not link_rows:
        link_rows = '<p class="muted">No WAN uplinks configured for this device.</p>'
    wan_note = ('<p class="muted" style="margin-top:10px">Per-link latency / jitter / '
                'packet-loss graphs arrive with the SLA-probing phase.</p>')

    # throughput sparklines
    spark = ""
    for iface, t in sorted(d["throughput"].items()):
        sp = _sparkline(store.series(name, "rx_bps", label=iface,
                                     since=time.time() - 3600), width=240, height=44)
        spark += (f'<div style="margin:6px 0"><b>{esc(iface)}</b> '
                  f'&darr;{human_bps(t.get("rx_bps", 0))} '
                  f'&uarr;{human_bps(t.get("tx_bps", 0))}<br>{sp}</div>')

    # active problems
    if d["problems"]:
        probs = "".join(f'<li><b>{esc(p["key"])}</b> ({esc(str(p["level"]))})</li>'
                        for p in d["problems"])
        probs_html = f'<ul style="margin:6px 0 0 18px;color:#b91c1c">{probs}</ul>'
    else:
        probs_html = '<p class="ok">No active problems.</p>'

    inner = (
        f'<div class="wrap" style="max-width:1100px">'
        f'<h1 style="display:flex;align-items:center;gap:12px">{esc(name)}'
        f'<span class="badge {badge[0]}">{badge[1]}</span></h1>{tabbar}'
        f'{facts_html}'
        f'<div class="cols">'
        f'<div class="box"><h2>System</h2>{gauges}</div>'
        f'<div class="box"><h2>WAN uplinks</h2>{link_rows}{wan_note}</div>'
        f'</div>'
        f'<div class="cols">'
        f'<div class="box"><h2>Throughput (last hour)</h2>'
        f'{spark or "<p class=muted>No throughput data yet.</p>"}</div>'
        f'<div class="box"><h2>Active problems</h2>{probs_html}</div>'
        f'</div>'
        f'<p><a href="/">&larr; dashboard</a> &nbsp; '
        f'<a href="/inventory">inventory</a></p></div>')
    return _page(esc(name), _header(user, "/") + inner)


_PWALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _gen_password(n=20) -> str:
    """A strong password using only RouterOS-script-safe characters (no quotes,
    spaces or backslashes, so it pastes cleanly into a terminal script)."""
    return "".join(secrets.choice(_PWALPHABET) for _ in range(n))


def _user_slug(s) -> str:
    out = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(s or "").strip()).strip("-")
    return out[:32] or "mikromon"


# --- hub (ZeroTier) settings — loaded from hub.json written by install.sh ----
# The dashboard reads the ZeroTier Network ID and fills each router's provision
# script with the join command automatically. No key management needed.


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




def _provision_script(name, raw, pwuser, pwd, *, zt_network_id="",
                      harden=True) -> str:
    """A one-paste RouterOS bootstrap script that is SAFE on an already-configured
    router: every step is guarded so it only ADDS what is missing and never
    resets existing config. The ZeroTier tunnel block needs RouterOS 7.1+."""
    u = pwuser
    L = []

    def a(s=""):
        L.append(s)

    a(f"# === mikromon provisioning for {name} ===")
    a("# Safe to paste on a NEW *or* an already-configured router: it only ADDS")
    a("# what is missing and never resets your existing config. The ZeroTier")
    a("# tunnel block needs RouterOS 7.1+.")
    a("")
    a("# 1) management user - create if missing, else just (re)set its password")
    a(":if ([:len [/user find name=" + u + "]] = 0) do={")
    a('  /user add name=' + u + ' password="' + pwd + '" group=full '
      'comment="mikromon-managed"')
    a("} else={")
    a('  /user set [/user find name=' + u + '] password="' + pwd + '" group=full')
    a("}")
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
    if zt_network_id:
        a("")
        a("# 5) ZeroTier dial-home tunnel (RouterOS 7.1+) - add only if absent")
        a(":if ([:len [/zerotier find name=zt1]] = 0) do={")
        a('  /zerotier add name=zt1')
        a("}")
        a(':if ([:len [/zerotier interface find network="'
          + zt_network_id + '"]] = 0) do={')
        a('  /zerotier interface add instance=zt1 network="' + zt_network_id
          + '" name=ztmikromon comment="mikromon:tunnel:if"')
        a("}")
        a(":if ([:len [/ip firewall filter find "
          'comment="mikromon:tunnel:fw"]] = 0) do={')
        a('  /ip firewall filter add chain=input in-interface=ztmikromon '
          'action=accept comment="mikromon:tunnel:fw"')
        a("}")
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


def _connect_box(name, raw) -> str:
    """WinBox connect helper: a winbox:// launch link + the saved credentials.
    Username and password are HIDDEN until Show is clicked. Admin-only."""
    if not raw:
        return ""
    host = raw.get("host", "")
    user = raw.get("push_username") or raw.get("username", "")
    pwd = raw.get("push_password") or raw.get("password", "")
    if not host:
        return ""
    wb = f"winbox://{esc(host)}"
    creds = (_plain_field("Host", host) + _plain_field("WinBox port", "8291")
             + _secret_field("Username", user, "cu")
             + _secret_field("Password", pwd, "cp"))
    return (f'<div class="box"><h2>Connect (WinBox)</h2>'
            f'<p><a class="btn" href="{wb}">Open in WinBox</a> '
            f'<span class="muted">launches WinBox at this router (needs WinBox '
            f'installed with the <code>winbox://</code> handler)</span></p>'
            f'<div class="fields">{creds}</div>'
            f'<p class="muted">Username and password are hidden — click <b>Show</b> '
            f'to reveal, then click the field to select and copy. WinBox can\'t be '
            f'auto-filled with the password from a browser link, so paste it after '
            f'WinBox opens.</p></div>')


def _render_device_provision(name, user, raw, csrf, *, hub_ip="", script=None,
                             creds=None, msg="", error="") -> str:
    tabbar = _device_tabbar(name, "provision", True)
    q = quote(name)
    banner = (f'<div class="box" style="border-left:4px solid #16a34a">{esc(msg)}'
              f'</div>' if msg else "")
    err = (f'<div class="box" style="border-left:4px solid #dc2626">{esc(error)}'
           f'</div>' if error else "")
    pwuser = (raw or {}).get("push_username") or _user_slug(name)
    intro = ('<p class="muted" style="margin:-6px 0 14px">Generate a one-paste '
             'script for a new router. It creates a management user with a strong '
             'password (saved here), enables the API, and adds a <b>ZeroTier</b> '
             'dial-home tunnel. The Network ID is filled from <b>this</b> server '
             'automatically. (ZeroTier tunnel needs RouterOS 7.1+.)</p>')
    form = (
        f'<div class="box"><h2>Generate provisioning script</h2>'
        f'<form method="POST" action="/device/provision">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="device" value="{esc(name)}">'
        f'<div class="fields">'
        f'<div class="f"><label class="f">Management username (unique per '
        f'device)</label><input name="pwuser" value="{esc(pwuser)}"></div>'
        f'<div class="f"><label class="f">Dial-home tunnel</label>'
        f'<select name="transport">'
        f'<option value="zt" selected>ZeroTier (RouterOS 7.1+)</option>'
        f'<option value="">None (just user + API)</option></select></div>'
        f'<div class="f"><label class="chk"><input type="checkbox" name="harden" '
        f'value="1" class="switch" checked> Disable Telnet/FTP (basic hardening)'
        f'</label></div>'
        f'</div>'
        f'<div class="actions" style="margin-top:12px">'
        f'<button class="btn" type="submit" name="auto" value="1">Provision now '
        f'(connect &amp; apply)</button> '
        f'<button class="btn ghost" type="submit" name="auto" value="0">Generate '
        f'script instead</button></div></form>'
        f'<p class="muted"><b>Provision now</b> connects to the router over its '
        f'API (using the Host + login from the Devices page) and sets everything '
        f'up automatically — no terminal, nothing to paste. Use it for a router '
        f'you can reach now (e.g. on the LAN with its default login). <b>Generate '
        f'script</b> is the fallback when you can\'t reach it directly.</p></div>')
    out = ""
    c = creds or {}
    if script is not None or c.get("applied"):
        if c.get("zt_network_id"):
            srv = ('<p class="ok">✓ ZeroTier join command included in script. '
                   'After pasting, authorize the router at '
                   '<a href="https://my.zerotier.com" target="_blank">my.zerotier.com</a> '
                   'then update the <b>Host</b> on the Devices page to its '
                   'ZeroTier IP.</p>')
        elif c.get("no_zt_network"):
            srv = ('<p style="color:#b91c1c">⚠ ZeroTier Network ID not configured. '
                   'Add it to <code>config.yaml</code> under '
                   '<code>zerotier: network_id:</code> and re-run '
                   '<code>sudo bash deploy/install.sh</code>.</p>')
        else:
            srv = ""
        if c.get("applied"):
            head = ('<h2>Provisioned over the API ✓</h2>'
                    '<p class="muted">mikromon connected to the router and applied '
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
               f'{_secret_field("Saved username", c.get("user", ""), "su")}'
               f'{_secret_field("Saved password", c.get("pwd", ""), "sp")}'
               f'</div></div>')
    connect = _connect_box(name, raw)
    inner = (f'<div class="wrap" style="max-width:1100px">'
             f'<h1>{esc(name)} &middot; Provision &amp; connect</h1>{tabbar}{intro}'
             f'{banner}{err}{connect}{form}{out}'
             f'<p><a href="/device?name={q}">&larr; overview</a></p></div>'
             f'{_REVEAL_JS}')
    return _page(esc(name) + " · Provision", _header(user, "/") + inner)


def _render_device_backups(name, user, facts, csrf, *, backups=None,
                           error="", msg="", dry_plan=None) -> str:
    """The Backups tab — wired to the real config-push engine (admin-only)."""
    tabbar = _device_tabbar(name, "backups", True)
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
        rows = ""
        for b in (backups or []):
            rows += (f'<tr><td><b>{esc(b["name"])}</b></td>'
                     f'<td class="muted">{esc(str(b.get("size", "")))}</td>'
                     f'<td class="muted">{esc(str(b.get("time", "")))}</td></tr>')
        if not rows and not error:
            rows = '<tr><td colspan="3" class="muted">No backup files on the router yet.</td></tr>'
        table = (f'<div class="box"><h2>Restore points on the router</h2>'
                 f'<table><tr><th>File</th><th>Size</th><th>Created</th></tr>'
                 f'{rows}</table></div>') if not error else ""
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
        return (f'<div class="f"><label class="chk"><input type="checkbox" '
                f'class="switch" name="{desc["name"]}" '
                f'value="{esc(desc["value"])}"{ck}> '
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
    note = ("Adopt = bring a rule under mikromon management (stamps a "
            "<code>mikromon:…</code> comment) so it appears in the editor above. "
            "Previewed and reversible." if can_adopt else
            "Shown for reference. Adopting these into an editable policy is coming "
            "next.")
    return (f'<div class="box"><h2>Existing on the router (unmanaged)</h2>'
            f'<p class="muted">{note}</p><table><tr><th>Rule</th><th></th></tr>'
            f'{rows}</table></div>')


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


def _hubtunnel_box(name, current) -> str:
    """Hub-side (ZeroTier) setup help. deploy/install.sh sets this up."""
    steps = ("# deploy/install.sh does all of this for you:\n"
             "curl -fsSL https://install.zerotier.com | bash\n"
             "zerotier-cli join <your-network-id>\n"
             "# Then authorize this server in my.zerotier.com")
    return (f'<div class="box"><h2>Hub (ZeroTier) setup</h2>'
            f'<p class="muted">Every device dials home with <b>ZeroTier</b> '
            f'(needs RouterOS 7.1+). '
            f'<b>Step 1:</b> Create a free network at '
            f'<a href="https://my.zerotier.com" target="_blank">my.zerotier.com</a>. '
            f'<b>Step 2:</b> Add the Network ID to '
            f'<code>config.yaml</code> under <code>zerotier: network_id:</code>. '
            f'<b>Step 3:</b> Run <code>sudo bash deploy/install.sh</code> on the '
            f'Ubuntu server — it installs ZeroTier, joins the network, and saves '
            f'the Network ID so the Provision tab fills scripts automatically.</p>'
            f'<pre style="{_PRE}">{esc(steps)}</pre>'
            f'<p class="muted">After a device joins, authorize it in ZeroTier '
            f'Central, then update its <b>Host</b> (Devices page) to the ZeroTier '
            f'IP shown in my.zerotier.com. Use <b>Restrict access</b> to lock the '
            f'API to the ZeroTier subnet and close the public port.</p></div>')


def _update_box(name, csrf, current) -> str:
    """Check-for-updates / Install (+reboot) / RouterBOOT firmware buttons."""
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
    install_cls = "" if avail else "ghost"
    note = ('<p class="muted" style="border-left:3px solid #d97706;padding-left:8px">'
            '⚠ <b>Install</b> downloads the new RouterOS and <b>reboots</b> to apply '
            'it — the router goes offline ~1–2 min and briefly shows as down. '
            '<b>Install only reboots when an update is actually available</b>; if the '
            "box is already current it does nothing. Run <b>Check for updates</b> "
            'first to be sure. You get a dry-run preview and a confirm step before '
            'anything happens.</p>')
    buttons = (act("check", "Check for updates", "ghost") + " "
               + act("install", "Download &amp; install + reboot", install_cls,
                     confirm="This reboots the router now. Continue?"))
    if firmware_available(current):
        buttons += " " + act("firmware", "Upgrade RouterBOOT firmware", "ghost",
                             confirm="Schedules a firmware upgrade. Continue?")
    avail_line = ('<p><span class="badge warn">update available</span></p>'
                  if avail else "")
    reboot = ('<div class="box"><h2>Reboot</h2><p class="muted">Manually reboot '
              'this router now — it will be offline ~1–2 minutes. Previewed and '
              'confirmed first.</p><div class="actions">'
              + act("reboot", "Reboot router now", "ghost",
                    confirm="Reboot the router now? It will go offline ~1–2 min.")
              + '</div></div>')
    return (f'<div class="box"><h2>Run an update</h2>{avail_line}{note}'
            f'<div class="actions">{buttons}</div></div>{reboot}')


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
            f'<b>top = primary</b>, 2nd = first backup, and so on. Use the '
            f'&uarr;/&darr; buttons to reorder; failover/load-balancing below uses '
            f'this order. Saved on the device — no router change.</p>'
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
                "viewed; mikromon only manages the ones it creates.",
    "harden": "Stop brute-force attacks: lock API/Winbox/SSH to your trusted IPs, "
              "disable insecure services, and block attacker IPs. ⚠ Include this "
              "server's IP in the allowed list so you don't lock mikromon out.",
    "nextdns": "Point DNS at a filtering service and list any IPs that bypass it.",
    "qos": "Cap upload/download speed for a subnet or interface (simple queues). "
           "Add a row, then Preview.",
    "portfwd": "Forward an external port to an internal device, or adopt forwards "
               "the router already has.",
    "interfaces": "A read-only view of the router's ports, VLANs and bridges.",
    "remote": "Grant a temporary firewall opening for Winbox/SSH/WebFig.",
    "tunnel": ("Manage WireGuard VPN interfaces and peers. "
               "Requires RouterOS 7.1+; shows a compatibility notice on older firmware."),
    "hubtunnel": "Connect a router with no public / a changing IP. It dials out to "
                 "your monitoring server over WireGuard and is reachable at a "
                 "constant private IP — works through CGNAT. Requires RouterOS "
                 "7.1+. Provisioning sets up the hub side automatically.",
    "scripts": "Paste any RouterOS script for things the other tabs don't cover. "
               "Save adds it (tagged), Run executes it, Remove deletes it — all "
               "previewed first and logged.",
    "update": "Check for and install RouterOS upgrades. ⚠ Installing reboots the "
              "router (1–2 min offline) — it's previewed and you must confirm.",
}


def _render_feature_tab(name, user, slug, feature, csrf, *, summary_lines=None,
                        fields=None, preview=None, submitted=None, error="",
                        msg="", recent=None, facts=None, unmanaged=None,
                        confirm_action="/device/push", cfg=None,
                        extra_html="") -> str:
    tabbar = _device_tabbar(name, slug, AuthStore.is_admin(user or {}))
    q = quote(name)
    banner = (f'<div class="box" style="border-left:4px solid #16a34a">{esc(msg)}'
              f'</div>' if msg else "")
    err = (f'<div class="box" style="border-left:4px solid #dc2626">'
           f'<b>Could not reach the router:</b> {esc(error)}<br>'
           f'<span class="muted">See the activity log below for the full error. '
           f'Check the host and the read-write push user on the Devices page.'
           f'</span></div>' if error else "")

    if preview is not None:
        body = (f'<div class="box"><h2>Dry run — nothing has been written yet</h2>'
                f'<pre style="background:#f8fafc;padding:12px;border-radius:8px;'
                f'white-space:pre-wrap">{esc(preview.diff_text())}</pre>'
                f'<form method="POST" action="{confirm_action}" class="actions">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="apply" value="1">'
                f'{_hidden_from_multi(submitted or {})}'
                f'<button class="btn" type="submit">Confirm &amp; apply to the '
                f'router</button>'
                f'<a class="btn ghost" href="/device?name={q}&tab={slug}">Cancel'
                f'</a></form></div>')
    elif error:
        body = ""
    else:
        sm = "".join(f'<li>{esc(s)}</li>' for s in (summary_lines or []))
        state = (f'<div class="box"><h2>Current (managed by mikromon)</h2>'
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
                    f'</div></form></div>')
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
             f'{_facts_strip(facts or {})}{banner}{err}{wan_editor}{body}{logbox}'
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


_AUTH_BRAND = ('<div class="brand" style="justify-content:center;color:#0f172a;'
               'font-size:22px;margin-bottom:6px">'
               '<span class="logo" style="color:#2563eb">&#9670;</span>mikromon</div>')


def _auth_page(title, body) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{esc(title)}'
            f'</title><style>{_PAGE_CSS}</style></head><body>'
            f'<div class="wrap" style="max-width:400px;margin-top:9vh">'
            f'{_AUTH_BRAND}<div class="box">{body}</div></div></body></html>')


def _render_login(error: str = "") -> str:
    msg = (f'<p style="color:#dc2626;margin-top:0">{esc(error)}</p>'
           if error else "")
    return _auth_page("Sign in",
            f'<h2 style="margin-top:0">Sign in</h2>{msg}'
            f'<form method="POST" action="/login">'
            f'<p><input name="username" placeholder="Username" autofocus '
            f'style="width:100%"></p>'
            f'<p><input name="password" type="password" placeholder="Password" '
            f'style="width:100%"></p>'
            f'<button class="btn" type="submit" style="width:100%">Sign in</button>'
            f'</form>')


def _render_setup(error: str = "") -> str:
    msg = (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    return _auth_page("First-run setup",
            f'<h2 style="margin-top:0">Welcome</h2>'
            f'<p>Create the first <b>administrator</b> account to get started. '
            f'You can add more users (and limit which devices they see) from the '
            f'Users page afterwards.</p>{msg}'
            f'<form method="POST" action="/setup">'
            f'<p><input name="username" placeholder="Admin username" autofocus '
            f'style="width:100%"></p>'
            f'<p><input name="password" type="password" '
            f'placeholder="Password (min 6 characters)" style="width:100%"></p>'
            f'<button class="btn" type="submit" style="width:100%">'
            f'Create admin account</button></form>')


_ADMIN_JS = """
<script>
 // When "All devices" is ticked, grey out + ignore the individual chips.
 // Exclude .allbox itself so name="all" is still submitted with the form.
 function syncAll(box){
   var grp=box.closest('.devsel');
   grp.querySelectorAll('.chips input:not(.allbox)').forEach(function(c){
     c.disabled=box.checked; c.closest('label').style.opacity=box.checked?.45:1;});
 }
 document.querySelectorAll('.allbox').forEach(function(b){
   syncAll(b); b.addEventListener('change',function(){syncAll(b);});});
</script>"""


def _device_chips(known_devices, selected, all_on) -> str:
    """A wrapped set of device toggles + an 'All devices' master toggle."""
    chips = "".join(
        f'<label><input type="checkbox" name="devices" value="{esc(d)}"'
        f'{" checked" if all_on or d in selected else ""}> {esc(d)}</label>'
        for d in known_devices) or '<span class="muted">no devices yet</span>'
    return (f'<div class="devsel"><div class="chips">'
            f'<label style="background:#eef2ff"><input type="checkbox" name="all" '
            f'class="allbox"{" checked" if all_on else ""}> <b>All devices</b></label>'
            f'{chips}</div></div>')


def _render_admin(auth: AuthStore, known_devices, csrf: str, user, hub=None) -> str:
    hub = hub or {}
    zt_net = hub.get("zt_network_id", "")
    zt_node = hub.get("zt_node_id", "")
    zt_status = ('<span style="color:#16a34a">&#10003; Configured</span>'
                 if zt_net else
                 '<span style="color:#d97706">&#9888; Not configured</span>')
    zt_box = (
        f'<div class="box" id="zerotier"><h2>ZeroTier tunnel settings</h2>'
        f'<p class="muted">Routers join this ZeroTier network to dial home to '
        f'this server through NAT/CGNAT. Create a free network at '
        f'<a href="https://my.zerotier.com" target="_blank">my.zerotier.com</a> '
        f'and enable <b>Auto-Approve Members</b> in the network settings.</p>'
        f'<p>Status: {zt_status}</p>'
        f'<form method="POST" action="/admin/zerotier">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<div class="actions" style="flex-wrap:wrap;margin-bottom:8px">'
        f'<input name="zt_network_id" value="{esc(zt_net)}" '
        f'placeholder="Network ID (e.g. 1a2b3c4d5e6f7890)" style="flex:1;min-width:220px">'
        f'<button class="btn" type="submit">Save</button>'
        f'</div>'
        + (f'<p class="muted" style="margin:0">Server ZeroTier node ID: '
           f'<code>{esc(zt_node)}</code> — authorize this in ZeroTier Central.</p>'
           if zt_node else '')
        + f'</form></div>')
    rows = []
    for u in auth.list_users():
        is_all = u["devices"] == "*"
        selected = set() if is_all else set(u["devices"])
        rows.append(f"""<tr>
          <td><b>{esc(u['username'])}</b></td>
          <td><span class="pill {esc(u['role'])}">{esc(u['role'])}</span></td>
          <td>
            <form method="POST" action="/admin/update">
              <input type="hidden" name="csrf" value="{csrf}">
              <input type="hidden" name="username" value="{esc(u['username'])}">
              <div class="actions" style="margin-bottom:8px">
                <select name="role">
                  <option{' selected' if u['role']=='user' else ''}>user</option>
                  <option{' selected' if u['role']=='admin' else ''}>admin</option>
                </select>
                <button class="btn" type="submit">Save changes</button>
              </div>
              {_device_chips(known_devices, selected, is_all)}
            </form>
          </td>
          <td>
            <form method="POST" action="/admin/delete"
              onsubmit="return confirm('Delete user {esc(u['username'])}?')">
              <input type="hidden" name="csrf" value="{csrf}">
              <input type="hidden" name="username" value="{esc(u['username'])}">
              <button class="btn red" type="submit">Delete</button>
            </form>
          </td></tr>""")
    inner = (
        f'<div class="wrap"><h1>Admin</h1>'
        f'{zt_box}'
        f'<div class="box"><h2>User management</h2><table>'
        f'<tr><th>User</th><th>Role</th><th>Allowed devices</th><th></th></tr>'
        f'{"".join(rows)}</table></div>'
        f'<div class="box"><h2>Add a user</h2>'
        f'<form method="POST" action="/admin/add">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<div class="actions" style="margin-bottom:12px;flex-wrap:wrap">'
        f'<input name="username" placeholder="username">'
        f'<input name="password" type="password" placeholder="password (min 6)">'
        f'<select name="role"><option>user</option><option>admin</option></select>'
        f'</div>'
        f'<p class="muted" style="margin:0 0 6px">Which devices may this user see?</p>'
        f'{_device_chips(known_devices, set(), False)}'
        f'<div style="margin-top:14px">'
        f'<button class="btn" type="submit">Create user</button></div>'
        f'</form></div></div>')
    return _page("Admin", _header(user, "/admin") + inner + _ADMIN_JS)


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>{esc(title)}</title><style>{_PAGE_CSS}</style></head>'
            f'<body>{body}</body></html>')


def _render_devices(store, csrf, user, edit_name=None, msg="") -> str:
    if store is None:
        return _page("Devices", _header(user, "/devices") + '<div class="wrap">'
                     '<h1>Devices</h1><div class="box">Device management is not '
                     'enabled. Set <code>devices_db:</code> in the config.</div></div>')
    pre = (store.raw(edit_name) or {}) if edit_name else {}
    wan = pre.get("wan") or {}

    trows = ""
    for n in store.names():
        host = (store.raw(n) or {}).get("host", "")
        trows += (
            f'<tr><td><b>{esc(n)}</b></td><td class="muted">{esc(host)}</td>'
            f'<td><div class="actions">'
            f'<a class="btn ghost" href="/device?name={quote(n)}">Open</a>'
            f'<a class="btn ghost" href="/devices?edit={quote(n)}">Edit</a>'
            f'{_mini_form("/devices/test", csrf, n, "Test", "btn ghost")}'
            f'{_mini_form("/devices/delete", csrf, n, "Delete", "btn red", n)}'
            f'</div></td></tr>')
    if not trows:
        trows = ('<tr><td colspan="3" class="muted">No devices yet — '
                 'add your first one below.</td></tr>')

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
        + field("Host / DDNS", f'<input name="host" value="{v("host")}">')
        + field("API port", f'<input name="api_port" '
                f'value="{esc(str(pre.get("api_port", 8728)))}">')
        + field("API timeout <span class='muted'>(seconds; raise for slow boxes "
                "/ long scripts)</span>", f'<input name="timeout" '
                f'value="{esc(str(pre.get("timeout", 10)))}">')
        + field("Username", f'<input name="username" value="{v("username")}">')
        + field("Password", f'<input name="password" type="password" '
                f'placeholder="{"(unchanged)" if edit_name else ""}">')
        + field("Security",
                f'<label class="chk"><input type="checkbox" name="use_ssl"'
                f'{" checked" if pre.get("use_ssl") else ""}> API-SSL</label> '
                f'<label class="chk"><input type="checkbox" name="verify_ssl"'
                f'{" checked" if pre.get("verify_ssl") else ""}> verify cert</label>')
        + field("Push user <span class='muted'>(read-write, for config-push; "
                "optional)</span>",
                f'<input name="push_username" value="{v("push_username")}">')
        + field("Push password",
                f'<input name="push_password" type="password" '
                f'placeholder="{"(unchanged)" if edit_name else ""}">')
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

    save_lbl = "Save changes" if edit_name else "Add device"
    cancel = ('<a class="btn ghost" href="/devices">Cancel</a>' if edit_name else "")
    form = (f'<form method="POST" action="/devices/save">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="original_name" value="{esc(edit_name or "")}">'
            f'<div class="fields">{fields}</div>'
            f'<div class="actions" style="margin-top:16px">'
            f'<button class="btn" type="submit">{save_lbl}</button>{cancel}</div>'
            f'</form>')
    msg_html = f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else ""
    inner = (f'<div class="wrap"><h1>Devices</h1>{msg_html}'
             f'<div class="box"><table><tr><th>Name</th><th>Host</th>'
             f'<th>Actions</th></tr>{trows}</table></div>'
             f'<div class="box"><h2>{"Edit device" if edit_name else "Add a device"}'
             f'</h2>{form}</div></div>')
    return _page("Devices", _header(user, "/devices") + inner + _WAN_JS)


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

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._s[token] = {"username": username, "expires": time.time() + _SESSION_TTL,
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
                 push_log_db=None):
    defaults = defaults or {}

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
            return auth.get_user(s["username"]) if s else None

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

            # No auth configured -> open dashboard (back-compat / demo without auth).
            if auth is None:
                return self._serve_data(path, url, user=None, allowed=None)

            # First-run bootstrap: with no admin yet, force creating one.
            needs_setup = auth.count_admins() == 0
            if path == "/setup":
                if not needs_setup:
                    return self._redirect("/login")
                err = parse_qs(url.query).get("error", [""])[0]
                return self._send(200, _render_setup(err),
                                  "text/html; charset=utf-8")
            if needs_setup:
                return self._redirect("/setup")

            if path == "/login":
                if self._session():
                    return self._redirect("/")
                err = {"1": "Invalid username or password."}.get(
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
            if path == "/admin":
                return self._serve_admin(user)
            if path == "/devices":
                return self._serve_devices(url, user)
            if path == "/logs":
                return self._serve_logs(user)

            store = self._store()
            known = set(_known_devices(store, _load_state(state_file)))
            store.close()
            ds = self._devstore()  # include web-managed devices not yet polled
            if ds:
                known |= set(ds.names())
                ds.close()
            allowed = AuthStore.allowed_devices(user, sorted(known))
            return self._serve_data(path, url, user=user, allowed=allowed)

        def _serve_data(self, path, url, user, allowed):
            store = self._store()
            try:
                state = _load_state(state_file)
                if path == "/":
                    zt_banner = ""
                    if AuthStore.is_admin(user) and devices_db:
                        hub = _hub_load(_hub_path(devices_db))
                        if not hub.get("zt_network_id"):
                            zt_banner = _zt_setup_banner(self._session()["csrf"])
                    return self._send(200, _render_dashboard(store, state, user,
                                      allowed, zt_banner=zt_banner),
                                      "text/html; charset=utf-8")
                if path == "/inventory":
                    return self._send(200, _render_inventory(store, state, user,
                                      allowed), "text/html; charset=utf-8")
                if path == "/device":
                    q = parse_qs(url.query)
                    dev = q.get("name", [""])[0]
                    known = set(_known_devices(store, state))
                    ds = self._devstore()
                    if ds:
                        known |= set(ds.names())
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
                    return self._send(200, _render_device(store, state, dev, user),
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
            store = self._store()
            known = _known_devices(store, _load_state(state_file))
            store.close()
            hub = _hub_load(_hub_path(devices_db)) if devices_db else {}
            return self._send(200, _render_admin(
                auth, known, self._session()["csrf"], user, hub=hub),
                "text/html; charset=utf-8")

        # ---- device management (admin only) ----
        def _serve_devices(self, url, user):
            if not AuthStore.is_admin(user):
                return self._send(403, "forbidden")
            edit = parse_qs(url.query).get("edit", [None])[0]
            store = self._devstore()
            try:
                page = _render_devices(store, self._session()["csrf"], user,
                                       edit_name=edit)
            finally:
                if store:
                    store.close()
            return self._send(200, page, "text/html; charset=utf-8")

        def _devstore(self):
            if not devices_db:
                return None
            from .devices_store import DevicesStore
            return DevicesStore(devices_db)

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
            # hub (ZeroTier) details from hub.json written by install.sh
            hub_file = _hub_path(devices_db)
            hub = _hub_load(hub_file)
            zt_network_id = hub.get("zt_network_id", "")
            uname = flat.get("pwuser", "").strip() or _user_slug(name)
            pwd = _gen_password()
            want_tunnel = flat.get("transport", "zt").strip() == "zt"
            _hub_save(hub_file, hub)
            raw["push_username"] = uname
            raw["push_password"] = pwd
            try:
                store.upsert(raw, defaults, original_name=name)
            except Exception as exc:  # noqa: BLE001 — surface validation errors
                store.close()
                return self._send(400, f"Error: {exc}")
            store.close()
            script = _provision_script(
                name, raw, uname, pwd,
                zt_network_id=zt_network_id if want_tunnel else "",
                harden=flat.get("harden") == "1")
            creds = {"user": uname, "pwd": pwd,
                     "zt_network_id": zt_network_id if want_tunnel else "",
                     "no_zt_network": want_tunnel and not zt_network_id}
            if want_tunnel and zt_network_id:
                msg = ("Script generated with ZeroTier join command. Paste into "
                       "the router, then authorize it at my.zerotier.com and "
                       "update the Host to its ZeroTier IP.")
            elif want_tunnel and not zt_network_id:
                msg = ("Generated user + API script, but the ZeroTier Network ID "
                       "isn't configured. Add it to config.yaml under "
                       "zerotier: network_id: and re-run deploy/install.sh.")
            else:
                msg = "Generated a strong password and script for this device."
            return self._device_provision_page(name, user, script=script,
                                                creds=creds, msg=msg)

        def _device_provision_apply(self, flat, user):
            """Zero-touch: connect to the router over the API and apply everything
            (user, API, ZeroTier tunnel) — no script to paste."""
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
            zt_network_id = hub.get("zt_network_id", "")
            uname = flat.get("pwuser", "").strip() or _user_slug(name)
            pwd = _gen_password()
            want_tunnel = flat.get("transport", "zt").strip() == "zt"
            cfg = build_device(raw, defaults)
            audit = self._auditlog()
            actor = (user or {}).get("username", "")
            dev = rw_device(cfg)
            api = PushApi(dev)
            result, err = None, None
            try:
                api.connect()
                result = provision_apply(
                    api, name, uname, pwd,
                    harden=flat.get("harden") == "1",
                    zt_network_id=zt_network_id if want_tunnel else "")
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
                             + (" + ZeroTier tunnel" if want_tunnel and zt_network_id
                                else ""),
                             "\n".join(result.get("steps", [])))
                audit.close()
            _hub_save(hub_file, hub)
            raw["push_username"] = uname
            raw["push_password"] = pwd
            try:
                store.upsert(raw, defaults, original_name=name)
            finally:
                store.close()
            creds = {"user": uname, "pwd": pwd,
                     "zt_network_id": zt_network_id if want_tunnel else "",
                     "no_zt_network": want_tunnel and not zt_network_id,
                     "applied": True}
            if want_tunnel and zt_network_id:
                msg = ("✓ Provisioned over the API. Router joined ZeroTier network. "
                       "Authorize it at my.zerotier.com then update the Host to its "
                       "ZeroTier IP.")
            elif want_tunnel and not zt_network_id:
                msg = ("Created the user + API, but the ZeroTier Network ID isn't "
                       "configured — add it to config.yaml and re-run install.sh.")
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
            if flat.get("apply") != "1":
                # Step 1: dry-run preview — connects to nothing.
                plan = Pusher(cfg, None, dry_run=True).plan_backup(bkname)
                return self._device_backups_page(name, user, dry_plan=plan)
            # Step 2: actually create it on the router.
            dev = rw_device(cfg)
            api = PushApi(dev)
            pusher = Pusher(cfg, api, dry_run=False)
            try:
                api.connect()
                pusher.apply(pusher.plan_backup(bkname))
                return self._redirect(
                    f"/device?name={quote(name)}&tab=backups&msg=" +
                    quote("Backup created on the router."))
            except (DeviceError, PushError) as exc:
                return self._device_backups_page(name, user, error=str(exc))
            finally:
                dev.close()

        # ---- generic feature tabs (SD-WAN/Security/NextDNS/QoS/…) ----
        def _auditlog(self):
            if not push_log_db:
                return None
            from .push import AuditLog
            return AuditLog(push_log_db)

        def _feature_tab_page(self, name, user, slug, preview=None,
                              submitted=None, error="", msg="",
                              confirm_action="/device/push"):
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
            extra_html = ""
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
                    elif slug == "hubtunnel":
                        extra_html = _hubtunnel_box(name, current)
                    elif slug == "update":
                        extra_html = _update_box(name, csrf, current)
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
                confirm_action=confirm_action, cfg=cfg, extra_html=extra_html)
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
            uname = (user or {}).get("username", "")
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
            uname = (user or {}).get("username", "")
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
                try:
                    pusher.apply(plan, feature=slug)  # logs its own outcome
                except PushError as exc:
                    return self._feature_tab_page(name, user, slug, error=str(exc))
                if not commit:
                    return self._feature_tab_page(name, user, slug, preview=plan,
                                                  submitted=multi)
                return self._redirect(
                    f"/device?name={quote(name)}&tab={slug}&msg=" +
                    quote("Changes applied to the router."))
            finally:
                dev.close()
                if audit:
                    audit.close()

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
                    store.delete(flat.get("name", ""))
                    return self._redirect("/devices")
                if path == "/devices/test":
                    return self._device_test(store, flat.get("name", ""), user)
                if path == "/devices/save":
                    raw = self._device_form_to_raw(store, flat, multi)
                    store.upsert(raw, defaults,
                                 original_name=flat.get("original_name") or None)
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
            pwd = flat.get("password", "")
            orig = flat.get("original_name") or None
            if not pwd and orig:  # keep existing password when left blank on edit
                pwd = (store.raw(orig) or {}).get("password", "")
            push_pwd = flat.get("push_password", "")
            if not push_pwd and orig:  # likewise keep the push password
                push_pwd = (store.raw(orig) or {}).get("push_password", "")
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
            return {
                "name": flat.get("name", "").strip(),
                "host": flat.get("host", "").strip(),
                "api_port": int(flat.get("api_port") or 8728),
                "username": flat.get("username", ""),
                "password": pwd,
                "push_username": flat.get("push_username", "").strip(),
                "push_password": push_pwd,
                "use_ssl": "use_ssl" in flat,
                "verify_ssl": "verify_ssl" in flat,
                "timeout": int(flat.get("timeout") or 10),
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
            if path == "/setup":
                return self._post_setup()
            if path == "/login":
                return self._post_login()
            if path == "/logout":
                sessions.destroy(self._token())
                return self._redirect("/login", self._cookie_header("", clear=True))
            # Everything below requires an admin + a valid CSRF token.
            user = self._user()
            if not AuthStore.is_admin(user or {}):
                return self._send(403, "forbidden")
            flat, multi = self._form()
            if flat.get("csrf") != self._session()["csrf"]:
                return self._send(400, "bad csrf token")
            if path.startswith("/devices/"):
                return self._devices_post(path, flat, multi, user)
            if path == "/device/backup":
                return self._device_backup_post(flat, user)
            if path == "/device/provision":
                return self._device_provision_post(flat, user)
            if path == "/device/push":
                return self._device_push_post(flat, multi, user)
            if path == "/device/adopt":
                return self._device_adopt_post(flat, user)
            if path == "/device/wan":
                return self._device_wan_post(flat, multi, user)
            if path == "/admin/zerotier":
                if not AuthStore.is_admin(user):
                    return self._send(403, "forbidden")
                zt_net = flat.get("zt_network_id", "").strip()
                if devices_db:
                    hub_file = _hub_path(devices_db)
                    hub = _hub_load(hub_file)
                    hub["zt_network_id"] = zt_net
                    _hub_save(hub_file, hub)
                return self._redirect("/admin#zerotier")
            try:
                if path == "/admin/add":
                    auth.add_user(flat.get("username", ""), flat.get("password", ""),
                                  role=flat.get("role", "user"),
                                  devices=self._devices(flat, multi))
                elif path == "/admin/update":
                    auth.set_role(flat["username"], flat.get("role", "user"))
                    auth.set_devices(flat["username"], self._devices(flat, multi))
                elif path == "/admin/delete":
                    if flat["username"] == user["username"]:
                        return self._send(400, "cannot delete yourself")
                    auth.delete_user(flat["username"])
                else:
                    return self._send(404, "not found")
            except Exception as exc:  # noqa: BLE001 — surface as a simple message
                return self._send(400, f"Error: {exc}")
            return self._redirect("/admin")

        @staticmethod
        def _devices(flat, multi):
            if flat.get("all"):
                return "*"
            return multi.get("devices", [])

        def _post_setup(self):
            # Only valid while no admin exists (prevents abuse after setup).
            if auth.count_admins() > 0:
                return self._redirect("/login")
            flat, _ = self._form()
            try:
                auth.add_user(flat.get("username", ""), flat.get("password", ""),
                              role="admin", devices="*")
            except Exception as exc:  # noqa: BLE001 — show the reason on the form
                return self._redirect("/setup?error=" + quote(str(exc)))
            token = sessions.create(flat["username"].strip())
            return self._redirect("/", self._cookie_header(token))

        def _post_login(self):
            flat, _ = self._form()
            user = auth.verify(flat.get("username", ""), flat.get("password", ""))
            if not user:
                time.sleep(0.5)  # mild brute-force friction
                return self._redirect("/login?error=1")
            token = sessions.create(user["username"])
            return self._redirect("/", self._cookie_header(token))

    return Handler



def serve(metrics_db, state_file, host="127.0.0.1", port=8080, auth_db=None,
          secure_cookies=False, metrics_token=None, devices_db=None,
          defaults=None, push_log_db=None):
    if metrics_db and not os.path.exists(metrics_db):
        log.warning("metrics DB %s not found yet — start the monitor first",
                    metrics_db)
    auth = AuthStore(auth_db) if auth_db else None
    if auth and not auth.count_admins():
        log.info("No admin yet — open the dashboard to create the first admin "
                 "at /setup.")
    sessions = SessionManager()
    httpd = ThreadingHTTPServer(
        (host, port), make_handler(metrics_db, state_file, auth, sessions,
                                   secure_cookies, metrics_token, devices_db,
                                   defaults, push_log_db))
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
