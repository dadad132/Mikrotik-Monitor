"""Shared constants, CSS, and lightweight HTML helpers for the web dashboard.

Imported by web.py and web_auth.py so neither needs to duplicate these.
"""
from __future__ import annotations

import html
import re

esc = html.escape

_MULTIPART_BOUNDARY_RE = re.compile(r'boundary="?([^";]+)"?')
_MULTIPART_NAME_RE = re.compile(r'name="([^"]*)"')


def parse_multipart_form(content_type: str, body: bytes) -> dict:
    """Minimal multipart/form-data parser: returns {field_name: bytes}.

    Only what's needed for a small admin form (a CSRF token + one uploaded
    file) — not a general MIME parser. Returns {} if `content_type` isn't
    multipart/form-data or has no boundary."""
    m = _MULTIPART_BOUNDARY_RE.search(content_type or "")
    if not m:
        return {}
    boundary = ("--" + m.group(1)).encode()
    fields: dict = {}
    for part in body.split(boundary)[1:-1]:
        part = part.strip(b"\r\n")
        if not part:
            continue
        header_blob, sep, content = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        name_m = _MULTIPART_NAME_RE.search(header_blob.decode("latin-1"))
        if not name_m:
            continue
        if content.endswith(b"\r\n"):
            content = content[:-2]
        fields[name_m.group(1)] = content
    return fields

_BRAND = "easymikrotik"

# How long the router waits after a config push to self-verify hub connectivity
# before auto-reverting. Max 300 s per design; 5 min gives slow links enough
# time without letting a broken change sit too long.
_REVERT_MINUTES = 5

_PAGE_CSS = """
 *{box-sizing:border-box}
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);
   color:var(--text)}
 a{color:var(--accent)}
 h1{font-size:22px;margin:0 0 16px}
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
 .tabdrop{position:relative;display:flex;align-items:stretch}
 .tabdrop>.dropbtn{padding:8px 13px;font-size:14px;color:#475569;text-decoration:none;
   border-bottom:2px solid transparent;margin-bottom:-2px;cursor:pointer;
   user-select:none;display:flex;align-items:center}
 .tabdrop>.dropbtn.on{color:#2563eb;border-bottom-color:#2563eb;font-weight:600}
 .tabdrop>.dropbtn:hover{color:#0f172a}
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
 /* modal overlay */
 .modal-backdrop{display:none;position:fixed;inset:0;background:rgba(15,23,42,.45);
   z-index:200;align-items:flex-start;justify-content:center;padding:60px 20px 20px;
   overflow-y:auto}
 .modal-backdrop.open{display:flex}
 .modal{background:#fff;border-radius:12px;padding:28px 28px 22px;width:100%;
   max-width:720px;box-shadow:0 12px 40px rgba(0,0,0,.25);position:relative}
 .modal h2{font-size:17px;margin:0 0 18px}
 .modal-close{position:absolute;top:14px;right:16px;background:none;border:0;
   font-size:20px;cursor:pointer;color:#64748b;line-height:1;padding:2px 6px}
 .modal-close:hover{color:#0f172a}
"""


# ---------------------------------------------------------------------------
# Light/dark theme: CSS custom properties + a persisted toggle. Opt-in per
# page (the dashboard and the landing page use this; _PAGE_CSS above is the
# older light-only stylesheet the rest of the app still uses, unchanged).
# ---------------------------------------------------------------------------
_THEME_VARS = """
:root{
  --bg:#f1f5f9;--surface:#ffffff;--surface-2:#f8fafc;--border:#e2e8f0;
  --text:#0f172a;--text-muted:#475569;--text-faint:#94a3b8;
  --accent:#2563eb;--accent-hover:#1d4ed8;--accent-soft:#eff6ff;
  --success:#16a34a;--success-bg:#dcfce7;
  --warning:#d97706;--warning-bg:#fef3c7;
  --danger:#dc2626;--danger-bg:#fee2e2;
  --shadow:0 1px 3px rgba(15,23,42,.08);
  --shadow-md:0 8px 28px rgba(15,23,42,.10);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0b1220;--surface:#111827;--surface-2:#0d1526;--border:#1f2937;
    --text:#e5e7eb;--text-muted:#94a3b8;--text-faint:#64748b;
    --accent:#3b82f6;--accent-hover:#60a5fa;--accent-soft:#13213b;
    --success:#22c55e;--success-bg:#052e16;
    --warning:#f59e0b;--warning-bg:#3a2a06;
    --danger:#ef4444;--danger-bg:#3a0d0d;
    --shadow:0 1px 3px rgba(0,0,0,.5);
    --shadow-md:0 8px 28px rgba(0,0,0,.5);
  }
}
:root[data-theme="dark"]{
  --bg:#0b1220;--surface:#111827;--surface-2:#0d1526;--border:#1f2937;
  --text:#e5e7eb;--text-muted:#94a3b8;--text-faint:#64748b;
  --accent:#3b82f6;--accent-hover:#60a5fa;--accent-soft:#13213b;
  --success:#22c55e;--success-bg:#052e16;
  --warning:#f59e0b;--warning-bg:#3a2a06;
  --danger:#ef4444;--danger-bg:#3a0d0d;
  --shadow:0 1px 3px rgba(0,0,0,.5);
  --shadow-md:0 8px 28px rgba(0,0,0,.5);
}
.theme-toggle{background:var(--surface-2);border:1px solid var(--border);
  color:var(--text-muted);width:34px;height:34px;border-radius:9px;cursor:pointer;
  font-size:15px;display:inline-flex;align-items:center;justify-content:center;
  transition:.12s;flex-shrink:0}
.theme-toggle:hover{color:var(--text);border-color:var(--accent)}
"""

# ---------------------------------------------------------------------------
# The persistent left sidebar (_header, below) — same chrome on every
# authenticated page, not just the dashboard, so navigating between them
# never swaps the look out from under you. Fixed-position + a body margin
# (rather than a flex row) because the page content after it isn't
# consistently a single wrapped element across every page in this app.
# ---------------------------------------------------------------------------
_SHELL_CSS = """
.dash-side{position:fixed;top:0;left:0;bottom:0;width:230px;overflow-y:auto;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;padding:18px 14px;z-index:50}
.dash-logo{display:flex;align-items:center;gap:8px;font-weight:700;
  font-size:16px;color:var(--text);padding:4px 8px 20px;text-decoration:none}
.dash-logo .dot{color:var(--accent);font-size:17px}
.dash-nav{display:flex;flex-direction:column;gap:2px;flex:1}
.dash-nav a{display:flex;align-items:center;gap:10px;color:var(--text-muted);
  padding:9px 10px;border-radius:8px;font-size:14px;font-weight:500;
  text-decoration:none}
.dash-nav a .ic{flex-shrink:0}
.dash-nav a:hover{background:var(--surface-2);color:var(--text)}
.dash-nav a.on{background:var(--accent-soft);color:var(--accent)}
.dash-nav-sep{height:1px;background:var(--border);margin:10px 6px}
.dash-side-foot{border-top:1px solid var(--border);padding-top:12px;
  margin-top:12px;display:flex;flex-direction:column;gap:10px}
.dash-side-foot-row{display:flex;align-items:center;justify-content:space-between;
  gap:8px}
.dash-who{font-size:12px;color:var(--text);line-height:1.3;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.dash-who small{display:block;color:var(--text-faint);font-size:11px}
.dash-logout{font-size:12px;color:var(--text-faint);text-decoration:none;
  flex-shrink:0}
.dash-logout:hover{color:var(--accent)}
body.has-sidebar{margin-left:230px;min-height:100vh}
@media(max-width:820px){
  .dash-side{position:static;width:100%;height:auto;flex-direction:row;
    align-items:center;padding:10px 14px;gap:14px;border-right:0;
    border-bottom:1px solid var(--border)}
  .dash-logo{padding:0;flex-shrink:0}
  .dash-nav{flex-direction:row;flex-wrap:nowrap;overflow-x:auto;flex:1;gap:2px;
    -webkit-overflow-scrolling:touch;scrollbar-width:none}
  .dash-nav::-webkit-scrollbar{display:none}
  .dash-nav a{flex-shrink:0;padding:8px 10px;white-space:nowrap}
  .dash-nav-sep{display:none}
  .dash-side-foot{border-top:0;margin-top:0;padding-top:0;
    flex-direction:row;flex-shrink:0}
  .dash-side-foot .dash-who{display:none}
  body.has-sidebar{margin-left:0}
}
"""

# Inline SVG icon bodies for the sidebar, keyed by nav href — stroke=
# "currentColor" so each one follows the link's own text color (inactive/
# hover/active) in both themes, with no per-icon color logic. Plain
# primitives (rect/circle/line/polyline), not glyph characters — a font's
# Unicode dingbats render wildly inconsistently across OSes/browsers
# (confirmed live: looked like blurry noise on mobile), where a small
# hand-drawn SVG always renders crisp.
_SIDE_ICONS = {
    "/dashboard": '<rect x="2.5" y="2.5" width="6" height="6" rx="1.3"/>'
                  '<rect x="11.5" y="2.5" width="6" height="6" rx="1.3"/>'
                  '<rect x="2.5" y="11.5" width="6" height="6" rx="1.3"/>'
                  '<rect x="11.5" y="11.5" width="6" height="6" rx="1.3"/>',
    "/devices":   '<rect x="3" y="3" width="14" height="6" rx="1.5"/>'
                  '<rect x="3" y="11" width="14" height="6" rx="1.5"/>'
                  '<circle cx="6.3" cy="6" r=".9" fill="currentColor" stroke="none"/>'
                  '<circle cx="6.3" cy="14" r=".9" fill="currentColor" stroke="none"/>',
    "/logs":      '<polyline points="2.5,11 6,11 8,4.5 12,15.5 14,11 17.5,11"/>',
    "/admin":     '<circle cx="10" cy="6.3" r="3.1"/>'
                  '<path d="M3.7 17c0-3.9 2.9-6.3 6.3-6.3s6.3 2.4 6.3 6.3"/>',
    "/billing":   '<rect x="2.5" y="4.7" width="15" height="10.6" rx="1.7"/>'
                  '<line x1="2.5" y1="8.3" x2="17.5" y2="8.3"/>'
                  '<line x1="5" y1="12.3" x2="9" y2="12.3"/>',
    "/guide":     '<path d="M3 4.3c1.7-.9 3.8-.9 5.2 0v11.2c-1.4-.9-3.5-.9-5.2 0z"/>'
                  '<path d="M17 4.3c-1.7-.9-3.8-.9-5.2 0v11.2c1.4-.9 3.5-.9 5.2 0z"/>',
    "/account":   '<circle cx="10" cy="10" r="7.3"/>'
                  '<circle cx="10" cy="8" r="2.3"/>'
                  '<path d="M4.9 15.8c.9-2.5 2.8-3.8 5.1-3.8s4.2 1.3 5.1 3.8"/>',
    "/superadmin": '<path d="M10 2.7l5.8 2.2v4.5c0 3.9-2.5 6.6-5.8 7.6-'
                   '3.3-1-5.8-3.7-5.8-7.6V4.9z"/>',
}


def _dash_icon(href) -> str:
    body = _SIDE_ICONS.get(href)
    if not body:
        return ""
    return (f'<svg class="ic" width="18" height="18" viewBox="0 0 20 20" '
            f'fill="none" stroke="currentColor" stroke-width="1.6" '
            f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>')


# Nav items are grouped visually: Dashboard, then the owner-only fleet-
# management cluster, then a divider before the personal/settings items.
_SIDE_SEP_BEFORE = "/guide"

# Runs before first paint (placed right after <meta charset> in <head>) so a
# saved preference applies with no flash of the wrong theme.
_THEME_INIT_JS = """<script>(function(){try{
var t=localStorage.getItem('mm-theme');
if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);
}catch(e){}})();</script>"""

# The toggle itself + setting the button's icon on load. Safe to place
# anywhere in the page — onclick resolves mmToggleTheme() at click time.
_THEME_TOGGLE_JS = """<script>
function mmThemeIsDark(){
  var t=document.documentElement.getAttribute('data-theme');
  return t?t==='dark':matchMedia('(prefers-color-scheme:dark)').matches;
}
function mmSyncThemeBtn(){
  var b=document.getElementById('mm-theme-btn');
  if(b)b.textContent=mmThemeIsDark()?'\\u2600':'\\u263E';
}
function mmToggleTheme(){
  var next=mmThemeIsDark()?'light':'dark';
  document.documentElement.setAttribute('data-theme',next);
  try{localStorage.setItem('mm-theme',next);}catch(e){}
  mmSyncThemeBtn();
}
mmSyncThemeBtn();
</script>"""


def _theme_toggle_btn() -> str:
    return ('<button type="button" id="mm-theme-btn" class="theme-toggle" '
            'onclick="mmToggleTheme()" aria-label="Toggle dark mode" '
            'title="Toggle light/dark theme">&#9789;</button>')


def _nav_items(user) -> list:
    """The app's nav destinations for this user, in order. Shared by the old
    horizontal top-nav (_nav, below) and the dashboard's sidebar so the two
    never drift apart."""
    if not user:
        return []
    items = [("/dashboard", "Dashboard")]
    if user.get("role") == "owner":
        items += [("/devices", "Devices"), ("/logs", "Activity"),
                  ("/admin", "Users")]
        if user.get("_show_billing"):
            items.append(("/billing", "Billing"))
    items += [("/guide", "Guide"), ("/account", "Account")]
    if user.get("is_superadmin"):
        items.append(("/superadmin", "Platform"))
    return items


def _sidebar_nav(user, active) -> str:
    parts = []
    for href, label in _nav_items(user):
        if href == _SIDE_SEP_BEFORE:
            parts.append('<div class="dash-nav-sep"></div>')
        parts.append(
            f'<a class="{"on" if href == active else ""}" href="{href}">'
            f'{_dash_icon(href)}{esc(label)}</a>')
    return f'<nav class="dash-nav">{"".join(parts)}</nav>'


def _who(user) -> str:
    """The account's display/login name — its email, or a legacy username."""
    return (user.get("email") or user.get("username")
            or user.get("login") or "")


def _header(user, active="/dashboard") -> str:
    """The persistent left sidebar: logo, nav, and the account/theme footer.
    Same markup on every authenticated page (via _page) and on the
    dashboard itself, so the chrome never changes when you navigate."""
    brand = (f'<a class="dash-logo" href="/dashboard">'
             f'<span class="dot">&#9670;</span>{esc(_BRAND)}</a>')
    if not user:
        return f'<aside class="dash-side">{brand}</aside>'
    org = user.get("org_name", "")
    sub = f'{esc(org)} &middot; {esc(user["role"])}' if org else esc(user["role"])
    foot = (f'<div class="dash-side-foot">'
            f'<div class="dash-who">{esc(_who(user))}<small>{sub}</small></div>'
            f'<div class="dash-side-foot-row">{_theme_toggle_btn()}'
            f'<a class="dash-logout" href="/logout">Log out</a></div>'
            f'</div>')
    return (f'<aside class="dash-side">{brand}{_sidebar_nav(user, active)}'
            f'{foot}</aside>')


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'{_THEME_INIT_JS}'
            f'<title>{esc(title)}</title>'
            f'<style>{_THEME_VARS}{_SHELL_CSS}{_PAGE_CSS}</style></head>'
            f'<body class="has-sidebar">{body}{_THEME_TOGGLE_JS}</body></html>')
