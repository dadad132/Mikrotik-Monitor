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
    conditions = state.get("devices", {}).get(name, {}).get("conditions", {})
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
    return {"device": name, "up": int(up), "metrics": metrics,
            "throughput": throughput, "problems": _problems(conditions)}


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
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f4f6;color:#111}
 header{background:#111827;color:#fff;padding:12px 20px;display:flex;
   justify-content:space-between;align-items:center}
 header a{color:#93c5fd;text-decoration:none;margin-left:14px}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
   gap:16px;padding:20px}
 .card{background:#fff;border-radius:10px;padding:14px 18px;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
 .card h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
 .card{border-left:4px solid #16a34a}
 .card.warn{border-left-color:#d97706}.card.crit{border-left-color:#dc2626}
 .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
 .state{margin-left:auto;font-size:11px;color:#6b7280}
 /* NOC summary bar */
 .noc{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));
   gap:12px;padding:18px 20px 0}
 .tile{background:#fff;border-radius:10px;padding:12px 14px;
   box-shadow:0 1px 3px rgba(0,0,0,.1);border-top:3px solid #6b7280;cursor:default}
 .tile.click{cursor:pointer}.tile.click:hover{box-shadow:0 2px 8px rgba(0,0,0,.18)}
 .tile .num{font-size:28px;font-weight:700;line-height:1}
 .tile .lbl{font-size:11px;color:#6b7280;text-transform:uppercase;
   letter-spacing:.04em;margin-top:6px}
 .tile.green{border-top-color:#16a34a}.tile.green .num{color:#16a34a}
 .tile.red{border-top-color:#dc2626}.tile.red .num{color:#dc2626}
 .tile.amber{border-top-color:#d97706}.tile.amber .num{color:#d97706}
 .tile.planned{border-top-color:#cbd5e1}.tile.planned .num{color:#9ca3af;font-size:20px}
 .tile.planned .lbl::after{content:" · soon";color:#9ca3af}
 /* filter / search bar */
 .fbar{display:flex;gap:8px;align-items:center;padding:16px 20px 0;flex-wrap:wrap}
 .fbar input{flex:1;min-width:200px;padding:7px 10px;border:1px solid #d1d5db;
   border-radius:6px}
 .fbtn{background:#e5e7eb;border:0;padding:6px 12px;border-radius:6px;cursor:pointer;
   font-size:13px}.fbtn.on{background:#2563eb;color:#fff}
 .muted{color:#6b7280;font-size:12px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{padding:4px 6px;border-bottom:1px solid #f0f0f0;text-align:left}
 .probs{margin-top:8px;color:#b91c1c;font-size:13px}.probs ul{margin:4px 0 0 18px}
 .ok{margin-top:8px;color:#16a34a;font-size:13px}
 .wrap{max-width:900px;margin:30px auto;padding:0 20px}
 form.inline{display:inline} input,select{padding:5px;margin:2px 0}
 .btn{background:#2563eb;color:#fff;border:0;padding:6px 12px;border-radius:6px;
   cursor:pointer}.btn.red{background:#dc2626}
 .box{background:#fff;border-radius:10px;padding:18px;margin:16px 0;
   box-shadow:0 1px 3px rgba(0,0,0,.1)}
"""


def _header(user) -> str:
    right = '<div style="font-size:12px">auto-refresh 10s</div>'
    if user:
        links = (' <a href="/devices">Devices</a> <a href="/admin">Admin</a>'
                 if user.get("role") == "admin" else "")
        right = (f'<div style="font-size:12px">{html.escape(user["username"])}'
                 f' ({html.escape(user["role"])}){links} '
                 f'<a href="/logout">Log out</a></div>')
    return (f'<header><div><b>mikromon</b> &middot; MikroTik fleet dashboard</div>'
            f'{right}</header>')


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
    devs = sorted(_all_devices(store, state, allowed),
                  key=lambda d: ({"crit": 0, "warn": 1, "ok": 2}[_severity(d)],
                                 d["device"].lower()))
    summary = _fleet_summary(devs)
    cards = []
    for d in devs:
        up = d["up"]
        sev = _severity(d)
        dot = "#16a34a" if up else "#dc2626"
        m = d["metrics"]
        rows = []
        if "cpu" in m:
            sp = _sparkline(store.series(d["device"], "cpu", since=time.time() - 3600))
            rows.append(f"<tr><td>CPU</td><td>{m['cpu']:.0f}%</td><td>{sp}</td></tr>")
        if "mem_free_pct" in m:
            rows.append(f"<tr><td>Free RAM</td><td>{m['mem_free_pct']:.0f}%</td>"
                        f"<td></td></tr>")
        if "client_count" in m:
            sp = _sparkline(store.series(d["device"], "client_count",
                                         since=time.time() - 3600))
            rows.append(f"<tr><td>Devices</td><td>{m['client_count']:.0f}</td>"
                        f"<td>{sp}</td></tr>")
        for iface, t in sorted(d["throughput"].items()):
            sp = _sparkline(store.series(d["device"], "rx_bps", label=iface,
                                         since=time.time() - 3600))
            rows.append(f"<tr><td>{html.escape(iface)}</td><td>"
                        f"&darr;{human_bps(t.get('rx_bps', 0))} "
                        f"&uarr;{human_bps(t.get('tx_bps', 0))}</td><td>{sp}</td></tr>")
        probs = "".join(f'<li><b>{html.escape(p["key"])}</b> '
                        f'({html.escape(str(p["level"]))})</li>' for p in d["problems"])
        probs_html = (f'<div class="probs"><b>Active problems:</b><ul>{probs}</ul>'
                      f'</div>' if probs else '<div class="ok">No active problems</div>')
        cls = "card" + ("" if sev == "ok" else f" {sev}")
        cards.append(f'<div class="{cls}" data-name="{html.escape(d["device"].lower())}"'
                     f' data-sev="{sev}"><h2><span class="dot" style="background:'
                     f'{dot}"></span>{html.escape(d["device"])}<span class="state">'
                     f'{"ONLINE" if up else "OFFLINE"}</span></h2><table>'
                     f'{"".join(rows)}</table>{probs_html}</div>')
    grid = "".join(cards) or "<p style='padding:20px'>No devices to show.</p>"
    fbar = ('<div class="fbar"><input id="q" placeholder="Filter devices by name…">'
            '<button class="fbtn" data-f="all" onclick="setf(\'all\')">All</button>'
            '<button class="fbtn" data-f="problems" onclick="setf(\'problems\')">'
            'Problems</button>'
            '<button class="fbtn" data-f="offline" onclick="setf(\'offline\')">'
            'Offline</button></div>') if devs else ""
    empty = ('<p id="empty" class="muted" style="padding:0 20px;display:none">'
             'No devices match this filter.</p>')
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="10"><title>mikromon</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'{_render_noc_bar(summary)}{fbar}'
            f'<div class="grid">{grid}</div>{empty}{_DASH_JS}</body></html>')


def _render_login(error: str = "") -> str:
    msg = f'<p style="color:#dc2626">{html.escape(error)}</p>' if error else ""
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>'
            f'<style>{_PAGE_CSS}</style></head><body><div class="wrap">'
            f'<div class="box" style="max-width:360px;margin:80px auto">'
            f'<h2>mikromon — sign in</h2>{msg}'
            f'<form method="POST" action="/login">'
            f'<p><input name="username" placeholder="Username" autofocus '
            f'style="width:100%"></p>'
            f'<p><input name="password" type="password" placeholder="Password" '
            f'style="width:100%"></p>'
            f'<button class="btn" type="submit">Sign in</button>'
            f'</form></div></div></body></html>')


def _render_setup(error: str = "") -> str:
    msg = f'<p style="color:#dc2626">{html.escape(error)}</p>' if error else ""
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>First-run setup</title><style>{_PAGE_CSS}</style></head><body>'
            f'<div class="wrap"><div class="box" style="max-width:420px;'
            f'margin:70px auto"><h2>Welcome to mikromon</h2>'
            f'<p>Create the first <b>administrator</b> account to get started. '
            f'You can add more users (and limit which devices they see) from the '
            f'Admin page afterwards.</p>{msg}'
            f'<form method="POST" action="/setup">'
            f'<p><input name="username" placeholder="Admin username" autofocus '
            f'style="width:100%"></p>'
            f'<p><input name="password" type="password" '
            f'placeholder="Password (min 6 characters)" style="width:100%"></p>'
            f'<button class="btn" type="submit">Create admin account</button>'
            f'</form></div></div></body></html>')


def _render_admin(auth: AuthStore, known_devices, csrf: str, user) -> str:
    rows = []
    for u in auth.list_users():
        devs = "*" if u["devices"] == "*" else ", ".join(u["devices"]) or "(none)"
        checks = "".join(
            f'<label><input type="checkbox" name="devices" value="{html.escape(d)}"'
            f'{" checked" if u["devices"] == "*" or d in u["devices"] else ""}> '
            f'{html.escape(d)}</label> ' for d in known_devices)
        rows.append(f"""<tr><td><b>{html.escape(u['username'])}</b></td>
          <td>{html.escape(u['role'])}</td><td>{html.escape(devs)}</td>
          <td><form class="inline" method="POST" action="/admin/update">
            <input type="hidden" name="csrf" value="{csrf}">
            <input type="hidden" name="username" value="{html.escape(u['username'])}">
            <select name="role"><option{' selected' if u['role']=='user' else ''}>user</option>
            <option{' selected' if u['role']=='admin' else ''}>admin</option></select>
            <label><input type="checkbox" name="all"{' checked' if u['devices']=='*' else ''}> all</label>
            {checks}
            <button class="btn" type="submit">Save</button></form>
            <form class="inline" method="POST" action="/admin/delete"
              onsubmit="return confirm('Delete {html.escape(u['username'])}?')">
            <input type="hidden" name="csrf" value="{csrf}">
            <input type="hidden" name="username" value="{html.escape(u['username'])}">
            <button class="btn red" type="submit">Delete</button></form></td></tr>""")
    add_checks = "".join(
        f'<label><input type="checkbox" name="devices" value="{html.escape(d)}"> '
        f'{html.escape(d)}</label> ' for d in known_devices)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>Users</title>'
            f'<style>{_PAGE_CSS}</style></head><body>{_header(user)}'
            f'<div class="wrap"><h1>User management</h1>'
            f'<div class="box"><table><tr><th>User</th><th>Role</th>'
            f'<th>Devices</th><th>Actions</th></tr>{"".join(rows)}</table></div>'
            f'<div class="box"><h2>Add user</h2>'
            f'<form method="POST" action="/admin/add">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input name="username" placeholder="username"> '
            f'<input name="password" type="password" placeholder="password (min 6)"> '
            f'<select name="role"><option>user</option><option>admin</option></select>'
            f'<br><label><input type="checkbox" name="all"> all devices</label> '
            f'{add_checks}<br><button class="btn" type="submit">Create user</button>'
            f'</form></div>'
            f'<p><a href="/">&larr; back to dashboard</a></p></div></body></html>')


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>{esc(title)}</title><style>{_PAGE_CSS}</style></head>'
            f'<body>{body}</body></html>')


def _render_devices(store, csrf, user, edit_name=None, msg="") -> str:
    if store is None:
        return _page("Devices", _header(user) + '<div class="wrap"><h1>Devices'
                     '</h1><div class="box">Device management is not enabled. '
                     'Set <code>devices_db:</code> in the config.</div></div>')
    pre = (store.raw(edit_name) or {}) if edit_name else {}
    wan = pre.get("wan") or {}

    trows = ""
    for n in store.names():
        host = (store.raw(n) or {}).get("host", "")
        trows += (
            f'<tr><td><b>{esc(n)}</b></td><td>{esc(host)}</td>'
            f'<td><a href="/devices?edit={quote(n)}">edit</a></td>'
            f'<td>{_mini_form("/devices/test", csrf, n, "test", "btn")}</td>'
            f'<td>{_mini_form("/devices/delete", csrf, n, "delete", "btn red", n)}'
            f'</td></tr>')
    if not trows:
        trows = '<tr><td colspan="5">No devices yet — add one below.</td></tr>'

    sources_sel = set(pre.get("client_count_sources") or ["dhcp", "wireless"])
    src_boxes = "".join(
        f'<label><input type="checkbox" name="sources" value="{s}"'
        f'{" checked" if s in sources_sel else ""}> {s}</label> '
        for s in _CLIENT_SOURCES)
    checks_pre = pre.get("checks") or {}
    chk_boxes = "".join(
        f'<label><input type="checkbox" name="checks" value="{k}"'
        f'{" checked" if checks_pre.get(k, DEFAULT_CHECKS[k]) else ""}> {k}</label> '
        for k in DEFAULT_CHECKS)

    def v(key, d=""):
        return esc(pre.get(key, d))

    form = f"""<form method="POST" action="/devices/save">
      <input type="hidden" name="csrf" value="{csrf}">
      <input type="hidden" name="original_name" value="{esc(edit_name or '')}">
      <p>Name <input name="name" value="{v('name')}">
         Host / DDNS <input name="host" value="{v('host')}">
         API port <input name="api_port" size="6" value="{esc(str(pre.get('api_port', 8728)))}"></p>
      <p>Username <input name="username" value="{v('username')}">
         Password <input name="password" type="password"
           placeholder="{'(unchanged)' if edit_name else ''}">
         <label><input type="checkbox" name="use_ssl"
           {' checked' if pre.get('use_ssl') else ''}> API-SSL</label>
         <label><input type="checkbox" name="verify_ssl"
           {' checked' if pre.get('verify_ssl') else ''}> verify cert</label></p>
      <p>LAN subnets <input name="lan_subnets" size="34"
         value="{esc(','.join(pre.get('lan_subnets') or []))}"> (comma-separated)</p>
      <p>WAN primary iface <input name="wan_primary"
           value="{esc((wan.get('primary') or {}).get('interface', ''))}">
         backup iface <input name="wan_backup"
           value="{esc((wan.get('backup') or {}).get('interface', ''))}"></p>
      <p>Monitor interfaces <input name="monitor_interfaces" size="34"
         value="{esc(','.join(pre.get('monitor_interfaces') or []))}">
         (comma; blank = auto)</p>
      <p>Client-count sources: {src_boxes}</p>
      <p>Checks: {chk_boxes}</p>
      <button class="btn" type="submit">{'Save changes' if edit_name else 'Add device'}</button>
      {'<a href="/devices" style="margin-left:8px">cancel</a>' if edit_name else ''}
    </form>"""
    msg_html = f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else ""
    inner = (f'<div class="wrap"><h1>Devices</h1>{msg_html}'
             f'<div class="box"><table><tr><th>Name</th><th>Host</th><th></th>'
             f'<th></th><th></th></tr>{trows}</table></div>'
             f'<div class="box"><h2>{"Edit device" if edit_name else "Add a device"}'
             f'</h2>{form}</div><p><a href="/">&larr; dashboard</a></p></div>')
    return _page("Devices", _header(user) + inner)


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
    return _page("Test", _header(user) + inner)


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
                 metrics_token=None, devices_db=None, defaults=None):
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

            store = self._store()
            allowed = AuthStore.allowed_devices(user, _known_devices(
                store, _load_state(state_file)))
            store.close()
            return self._serve_data(path, url, user=user, allowed=allowed)

        def _serve_data(self, path, url, user, allowed):
            store = self._store()
            try:
                state = _load_state(state_file)
                if path == "/":
                    return self._send(200, _render_dashboard(store, state, user,
                                      allowed), "text/html; charset=utf-8")
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
            return self._send(200, _render_admin(
                auth, known, self._session()["csrf"], user),
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
            checks_sel = set(multi.get("checks", []))
            return {
                "name": flat.get("name", "").strip(),
                "host": flat.get("host", "").strip(),
                "api_port": int(flat.get("api_port") or 8728),
                "username": flat.get("username", ""),
                "password": pwd,
                "use_ssl": "use_ssl" in flat,
                "verify_ssl": "verify_ssl" in flat,
                "timeout": int(flat.get("timeout") or 10),
                "lan_subnets": csv(flat.get("lan_subnets")),
                "wan": {"primary": {"interface": flat.get("wan_primary", "").strip()},
                        "backup": {"interface": flat.get("wan_backup", "").strip()}},
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
          defaults=None):
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
                                   defaults))
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
