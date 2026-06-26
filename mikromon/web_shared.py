"""Shared constants, CSS, and lightweight HTML helpers for the web dashboard.

Imported by web.py and web_auth.py so neither needs to duplicate these.
"""
from __future__ import annotations

import html

esc = html.escape

_BRAND = "easymikrotik"

# How long the router waits after a config push to self-verify hub connectivity
# before auto-reverting. Max 300 s per design; 5 min gives slow links enough
# time without letting a broken change sit too long.
_REVERT_MINUTES = 5

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
 .fields .f input:not([type=checkbox]):not([type=radio]),
 .fields .f select{width:100%}
 .full{grid-column:1/-1}
 .chkrow{display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;
   min-height:38px}
 .chips{display:flex;flex-wrap:wrap;gap:6px;margin:2px 0}
 .chips label{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;
   padding:4px 11px;font-size:12px;cursor:pointer;user-select:none}
 .chips label:hover{background:#e2e8f0}
 .chips input{margin:0 5px 0 0;vertical-align:middle}
 .chk{display:inline-flex;align-items:center;gap:6px;margin-right:12px;font-size:13px}
 input.switch{appearance:none;-webkit-appearance:none;width:38px;height:20px;
   background:#dc2626;border-radius:999px;position:relative;cursor:pointer;
   vertical-align:middle;transition:.15s;flex:none}
 input.switch:checked{background:#16a34a}
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
 .pill.owner{background:#ede9fe;color:#6d28d9}.pill.member{background:#e0f2fe;color:#0369a1}
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
 .tabdrop{position:relative}
 .tabdrop>.dropbtn{cursor:pointer}
 .tabdrop:hover>.tabmenu,.tabdrop:focus-within>.tabmenu{display:block}
 .tabmenu{display:none;position:absolute;top:100%;left:0;z-index:30;background:#fff;
   border:1px solid #e2e8f0;border-radius:8px;box-shadow:0 6px 18px rgba(15,23,42,.12);
   min-width:175px;padding:5px}
 .tabmenu a,.tabmenu button{display:block;width:100%;box-sizing:border-box;
   text-align:left;padding:8px 12px;font-size:14px;color:#475569;text-decoration:none;
   background:none;border:0;border-radius:6px;cursor:pointer;margin:0}
 .tabmenu a:hover,.tabmenu button:hover{background:#f1f5f9;color:#0f172a}
 .tabmenu a.on{color:#2563eb;font-weight:600}
 .tabmenu form{margin:0}
 .tabmenu button.reboot{color:#dc2626}
 .tabmenu button.reboot:hover{background:#fef2f2}
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
    if user.get("role") == "owner":
        items += [("/devices", "Devices"), ("/logs", "Activity"),
                  ("/admin", "Users")]
    items += [("/account", "Account")]
    links = "".join(
        f'<a href="{href}" class="{"on" if href == active else ""}">{label}</a>'
        for href, label in items)
    return f"<nav>{links}</nav>"


def _who(user) -> str:
    """The account's display/login name — its email, or a legacy username."""
    return (user.get("email") or user.get("username")
            or user.get("login") or "")


def _header(user, active="/") -> str:
    brand = (f'<div class="brand"><span class="logo">&#9670;</span>'
             f'{esc(_BRAND)}</div>')
    if not user:
        return f"<header>{brand}</header>"
    org = user.get("org_name", "")
    sub = f'{esc(org)} &middot; {esc(user["role"])}' if org else esc(user["role"])
    chip = (f'<span class="who">{esc(_who(user))}'
            f'<small>{sub}</small></span>')
    return (f"<header>{brand}{_nav(user, active)}"
            f'<div class="right">{chip}<a class="logout" href="/logout">Log out</a>'
            f"</div></header>")


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>{esc(title)}</title><style>{_PAGE_CSS}</style></head>'
            f'<body>{body}</body></html>')
