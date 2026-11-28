"""Cockpit pages for the two Wi-Fi features.

The stores and planners live in guest_wifi.py and capsman.py. This module only
renders their state: it never decides what is allowed, and it never trusts a
value enough to put it into HTML without escaping it. Router reads can fail,
and a sync result deliberately carries the raw exception text, so every error
string is treated as hostile copy rather than as markup.
"""
from __future__ import annotations

import html

from . import guest_wifi
from .web_shared import _flash, _header, _page, confirm_attr


def esc(value) -> str:
    """html.escape, but store ids and signal numbers are not strings."""
    return html.escape(str(value if value is not None else ""), quote=True)

_WIFI_CSS = """
.wifi-grid{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);
  gap:16px;align-items:start;padding:0 20px 20px}
@media(max-width:980px){.wifi-grid{grid-template-columns:minmax(0,1fr)}}
.wifi-grid>.box{margin:0}
.wifi-pre{white-space:pre-wrap;word-break:break-word;background:var(--surface-2);
  border:1px solid var(--border);border-radius:8px;padding:10px 12px;
  font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  max-height:280px;overflow:auto}
.wifi-preview{border:1px solid var(--border);border-radius:12px;padding:16px;
  background:var(--surface-2)}
.wifi-preview .brand{font-weight:700;font-size:15px}
.wifi-preview h3{margin:10px 0 4px;font-size:17px}
.wifi-preview p{margin:0 0 10px;color:var(--text-muted);font-size:13px}
.wifi-swatch{display:inline-block;width:14px;height:14px;border-radius:4px;
  vertical-align:middle;margin-right:6px;border:1px solid var(--border)}
.wifi-tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
.wifi-tools form{margin:0}
.sig{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
  font-weight:700;background:var(--success-bg);color:var(--success-text)}
.sig.mid{background:var(--warning-bg);color:var(--warning-text)}
.sig.low{background:var(--danger-bg);color:var(--danger-text)}
.wifi-err{background:var(--danger-bg);color:var(--danger-text);border-radius:8px;
  padding:9px 12px;font-size:12px;margin:8px 0;word-break:break-word}
.wifi-empty{color:var(--text-faint);font-size:13px;margin:8px 0}
"""


def _kpi(value, label, kind=""):
    cls = f"tile {kind}".strip()
    return (f'<div class="{cls}"><div class="num">{esc(str(value))}</div>'
            f'<div class="lbl">{esc(label)}</div></div>')


def _device_names(devices) -> list[str]:
    out = []
    for item in devices or []:
        name = item.get("name", "") if isinstance(item, dict) else str(item)
        name = str(name or "").strip()
        if name and name not in out:
            out.append(name)
    return out


def _options(names, selected=""):
    opts = ['<option value="">Choose a router…</option>']
    for name in names:
        opts.append(f'<option value="{esc(name)}"'
                    f'{" selected" if name == selected else ""}>'
                    f'{esc(name)}</option>')
    return "".join(opts)


def _hidden(name, value):
    return f'<input type="hidden" name="{esc(name)}" value="{esc(value)}">'


def _field(label, name, value="", *, kind="text", extra=""):
    return (f'<label class="f">{esc(label)}<input type="{kind}" '
            f'name="{esc(name)}" value="{esc(str(value if value is not None else ""))}"'
            f'{extra}></label>')


def _checkbox(label, name, checked=False):
    # An unchecked browser checkbox is omitted entirely; the hidden zero is
    # the other half of the answer, and _form() keeps the last value (the
    # checkbox's "1" when it is ticked).
    return (f'<input type="hidden" name="{esc(name)}" value="0">'
            f'<label class="chk"><input type="checkbox" name="{esc(name)}" '
            f'value="1"{" checked" if checked else ""}> {esc(label)}</label>')


def _checked(portal, key, default=0):
    return bool(portal.get(key, default) if isinstance(portal, dict) else default)


def _portal_url(base_url, slug):
    # Escape the whole address once, here, so the caller can use the same
    # string in both href and text without either becoming an attribute.
    base = esc(str(base_url or "").rstrip("/"))
    return f"{base}/portal/{esc(slug)}" if base else f"/portal/{esc(slug)}"


def render_guest_wifi_page(user, csrf, portals, leads, stats, devices, *,
                           base_url="", flash="", search="", error="") -> str:
    """The owner's Guest Wi-Fi page: portal studio, KPIs and captured leads."""
    portals = list(portals or [])
    leads = list(leads or [])
    stats = dict(stats or {})
    devices = _device_names(devices)
    portal = portals[0] if portals else {}
    slug = str(portal.get("slug", "") or "")
    device = str(portal.get("device", "") or "")
    url = _portal_url(base_url, slug)
    try:
        snippet = guest_wifi.hotspot_login_html_snippet(url.replace("&amp;", "&"))
    except Exception:  # noqa: BLE001 - a preview must never break the page
        snippet = ""
    snippet = snippet.replace("&amp;", "&")
    search = str(search or "")

    kpis = (
        _kpi(len(portals), "Live portals", "green")
        + _kpi(stats.get("total", 0), "Leads captured")
        + _kpi(stats.get("last_24h", 0), "New in 24h", "green")
        + _kpi(f"{stats.get('optin_pct', 0)}%", "Marketing opt-in", "amber"))

    studio = [
        '<div class="box"><h2>Portal Studio</h2>',
        f'<form method="post" action="/guest-wifi/save">', _hidden("csrf", csrf)]
    if portal.get("id"):
        studio.append(_hidden("id", portal["id"]))
    studio += [
        '<div class="fields">',
        _field("Brand name", "brand_name", portal.get("brand_name", "Guest Wi-Fi")),
        _field("Portal slug", "slug", slug,
               extra=' placeholder="acme-guest" required'),
        _field("Headline", "headline", portal.get(
            "headline", guest_wifi.DEFAULTS["headline"]), extra=' class="full"'),
        _field("Sub-headline", "subheadline", portal.get(
            "subheadline", guest_wifi.DEFAULTS["subheadline"]), extra=' class="full"'),
        _field("Logo URL", "logo_url", portal.get("logo_url", "")),
        _field("Accent colour", "accent_color",
               portal.get("accent_color", "#2563eb"), kind="color"),
        _field("Background", "bg_color", portal.get("bg_color", "#0f172a"),
               kind="color"),
        _field("Redirect after login", "redirect_url",
               portal.get("redirect_url", "")),
        _field("Terms text", "terms_text",
               portal.get("terms_text", guest_wifi.DEFAULTS["terms_text"]),
               extra=' class="full"'),
        '</div><h3>Hotspot and guest account</h3><div class="fields">',
        '<label class="f">Router<select name="device">',
        _options(devices, device), '</select></label>',
        _field("Hotspot interface", "hotspot_iface",
               portal.get("hotspot_iface", "vlan-guest")),
        _field("Guest subnet", "subnet", portal.get("subnet", "10.99.0.0/24")),
        _field("VLAN ID", "vlan_id", portal.get("vlan_id", "")),
        _field("Download Mbps", "down_mbps", portal.get("down_mbps", 10),
               kind="number"),
        _field("Upload Mbps", "up_mbps", portal.get("up_mbps", 5), kind="number"),
        _field("Session minutes", "session_minutes",
               portal.get("session_minutes", 120), kind="number"),
        _field("Guest user", "guest_username",
               portal.get("guest_username", "guest")),
        _field("Guest password", "guest_password",
               portal.get("guest_password", ""), kind="password"),
        _field("RADIUS shared secret", "shared_secret",
               portal.get("shared_secret", ""), kind="password"),
        '</div><div class="chkrow">',
        _checkbox("Ask for name", "require_name", _checked(portal, "require_name", 1)),
        _checkbox("Ask for email", "require_email", _checked(portal, "require_email", 1)),
        _checkbox("Ask for phone", "require_phone", _checked(portal, "require_phone")),
        _checkbox("Ask for company", "require_company",
                  _checked(portal, "require_company")),
        _checkbox("Marketing opt-in", "show_marketing_optin",
                  _checked(portal, "show_marketing_optin", 1)),
        _checkbox("Portal enabled", "enabled", _checked(portal, "enabled", 1)),
        '</div><p><button class="btn" type="submit">Save portal</button></p></form>',
    ]
    if portal.get("id"):
        studio.append(
            '<form method="post" action="/guest-wifi/delete"'
            f' onsubmit="{confirm_attr("Delete this portal and stop capturing leads?")}">'
            + _hidden("csrf", csrf) + _hidden("id", portal["id"])
            + '<button type="submit">Delete portal</button></form>')
    studio.append('</div>')

    preview = [
        '<div class="box"><h2>Guest preview</h2>',
        '<div class="wifi-preview">',
        f'<div class="brand">{esc(portal.get("brand_name", "Your brand"))}</div>',
        f'<h3>{esc(portal.get("headline", guest_wifi.DEFAULTS["headline"]))}</h3>',
        f'<p>{esc(portal.get("subheadline", guest_wifi.DEFAULTS["subheadline"]))}</p>',
        '<p>Connect to Wi-Fi &rarr;</p></div>',
        f'<p class="muted" style="margin:12px 0 4px">Portal URL '
        f'<a href="{url}">{url}</a></p>',
        '<h3>Hotspot login.html override</h3><p class="muted">'
        'Paste this into Files &rarr; hotspot on the router so guests land here '
        'before being handed back to the hotspot.</p>',
        f'<pre class="wifi-pre">{esc(snippet)}</pre>',
    ]
    if portal.get("id"):
        preview += [
            '<form method="post" action="/guest-wifi/push">',
            _hidden("csrf", csrf), _hidden("portal_id", portal["id"]),
            '<label class="f">Router to provision<select name="device">',
            _options(devices, device), '</select></label>',
            '<p><button class="btn" type="submit">Push to hotspot</button></p></form>']
    preview.append('</div>')

    lead_rows = []
    for lead in leads:
        lead_rows.append(
            '<tr>'
            f'<td>{esc(lead.get("name", ""))}</td>'
            f'<td>{esc(lead.get("email", ""))}</td>'
            f'<td>{esc(lead.get("phone", ""))}</td>'
            f'<td>{esc(lead.get("company", ""))}</td>'
            f'<td>{esc(lead.get("client_mac", ""))}</td>'
            f'<td>{esc(lead.get("marketing_optin", ""))}</td></tr>')
    if not lead_rows:
        lead_rows = [
            '<tr><td colspan="6" class="wifi-empty">No leads captured yet. '
            'Share the portal URL with guests.</td></tr>']
    leads_box = [
        '<div class="box"><h2>Captured Leads</h2>',
        '<div class="wifi-tools"><form method="get" action="/guest-wifi">'
        f'<input type="search" name="search" value="{esc(search)}" '
        'placeholder="Search name, email, phone, company or MAC">'
        '<button type="submit">Search</button></form>',
        f'<a class="btn" href="/guest-wifi/leads.csv'
        f'{"?portal_id=" + esc(portal["id"]) if portal.get("id") else ""}">'
        'Export CSV</a></div>',
        '<div style="overflow-x:auto"><table><thead><tr>'
        '<th>Name</th><th>Email</th><th>Phone</th><th>Company</th>'
        '<th>MAC</th><th>Opt-in</th></tr></thead><tbody>',
        "".join(lead_rows), '</tbody></table></div></div>']

    body = (_header(user, "/guest-wifi") + _flash(flash, error)
            + '<div class="noc">' + kpis + '</div>'
            + '<div class="wifi-grid">' + "".join(studio + preview) + '</div>'
            + '<div style="padding:0 20px 20px">' + "".join(leads_box) + '</div>')
    return _page("Guest Wi-Fi", body)


def _signal_badge(client):
    dbm = client.get("signal_dbm")
    try:
        dbm = int(float(dbm))
    except (TypeError, ValueError):
        dbm = None
    pct = client.get("signal_pct")
    try:
        pct = int(float(pct))
    except (TypeError, ValueError):
        pct = 100 if dbm is None else 0
    if dbm is not None and pct == 100:
        pct = max(0, min(100, 2 * (dbm + 100)))
    cls = "" if pct >= 60 else "mid" if pct >= 35 else "low"
    text = f"{dbm} dBm" if dbm is not None else f"{pct}%"
    return f'<span class="sig {cls}">{esc(text)}</span>'


def render_capsman_page(user, csrf, controllers, ssids, blocked_macs,
                        fleet_live, devices, *, flash="", sync_results=None,
                        error="") -> str:
    """The owner's CAPsMAN page: controllers, SSIDs, live clients and ACL."""
    controllers = list(controllers or [])
    ssids = list(ssids or [])
    blocked = list(blocked_macs or [])
    live = list(fleet_live or [])
    results = list(sync_results or [])
    devices = _device_names(devices)
    aps = sum(len(view.get("aps", [])) for view in live)
    clients = sum(len(view.get("clients", [])) for view in live)

    kpis = (_kpi(len(controllers), "Controllers", "green")
            + _kpi(aps, "Access points")
            + _kpi(clients, "Live clients", "green")
            + _kpi(len(blocked), "Blocked MACs", "amber"))

    sync_html = ['<div class="box"><h2>Fleet sync</h2>'
                 '<p class="muted">Publish these SSIDs and the blocked-client '
                 'ACL to every enabled controller. A router that is offline is '
                 'recorded and skipped; the others still sync.</p>'
                 '<form method="post" action="/capsman/sync-all">',
                 _hidden("csrf", csrf),
                 '<button class="btn" type="submit">Sync All</button></form>']
    if results:
        sync_html.append('<table><thead><tr><th>Router</th><th>Status</th>'
                         '<th>Changes</th><th>Detail</th></tr></thead><tbody>')
        for result in results:
            status = str(result.get("status", ""))
            cls = "ok" if status in ("ok", "unchanged") else "crit"
            detail = str(result.get("summary", "") or "")
            error = str(result.get("error", "") or "")
            if error:
                detail = (detail + " — " + error).strip(" —")
            sync_html.append(
                f'<tr><td>{esc(result.get("device", ""))}</td>'
                f'<td><span class="badge {cls}">{esc(status)}</span></td>'
                f'<td>{esc(result.get("changes", 0))}</td>'
                f'<td>{esc(detail)}</td></tr>')
        sync_html.append('</tbody></table>')
    sync_html.append('</div>')

    controller_rows = []
    for row in controllers:
        status = str(row.get("last_sync_status", "") or "never")
        cls = "ok" if status == "ok" else "warn" if status == "unchanged" else "crit"
        summary = str(row.get("last_sync_summary", "") or "")
        controller_rows.append(
            '<tr>'
            f'<td>{esc(row.get("device", ""))}</td>'
            f'<td>{esc(row.get("driver", "auto"))}</td>'
            f'<td>{"enabled" if row.get("enabled", 1) else "paused"}</td>'
            f'<td><span class="badge {cls}">{esc(status)}</span>'
            f'{"<div class=wifi-err>" + esc(summary) + "</div>" if summary else ""}</td></tr>')
    if not controller_rows:
        controller_rows = ['<tr><td colspan="4" class="wifi-empty">'
                           'No controllers yet. Add one below.</td></tr>']
    ctrl_html = [
        '<div class="box"><h2>Controllers / APs</h2>',
        '<div style="overflow-x:auto"><table><thead><tr><th>Router</th>'
        '<th>Driver</th><th>State</th><th>Last sync</th></tr></thead><tbody>',
        "".join(controller_rows), '</tbody></table></div>',
        '<form method="post" action="/capsman/controller" class="fields">',
        _hidden("csrf", csrf),
        '<label class="f">Router<select name="device">',
        _options(devices), '</select></label>',
        '<label class="f">Driver<select name="driver">'
        '<option value="auto">Auto detect</option>'
        '<option value="wifi">RouterOS 7 wifi</option>'
        '<option value="legacy">Legacy caps-man</option></select></label>',
        '<div class="chkrow">', _checkbox("Enabled", "enabled", True), '</div>',
        '<p><button class="btn" type="submit">Add controller</button></p></form>',
        '</div>']

    selected = ssids[0] if ssids else {}
    ssid_rows = []
    for row in ssids:
        ssid_rows.append(
            '<tr>'
            f'<td>{esc(row.get("name", ""))}</td>'
            f'<td>{esc(row.get("ssid", ""))}</td>'
            f'<td>{esc(row.get("purpose", ""))}</td>'
            f'<td>{esc(row.get("vlan_id", "") or "—")}</td>'
            f'<td>{esc(row.get("security_mode", ""))}</td>'
            f'<td><form method="post" action="/capsman/ssid-delete"'
            f' onsubmit="{confirm_attr("Remove this SSID profile?")}">'
            + _hidden("csrf", csrf) + _hidden("id", row.get("id", ""))
            + '<button type="submit">Remove</button></form></td></tr>')
    if not ssid_rows:
        ssid_rows = ['<tr><td colspan="6" class="wifi-empty">'
                     'No SSID profiles saved yet.</td></tr>']
    ssid_form = [
        '<div class="box"><h2>SSIDs / VLANs</h2>',
        '<div style="overflow-x:auto"><table><thead><tr><th>Profile</th>'
        '<th>SSID</th><th>Purpose</th><th>VLAN</th><th>Security</th>'
        '<th></th></tr></thead><tbody>', "".join(ssid_rows),
        '</tbody></table></div>',
        '<h3>Save a profile</h3><form method="post" action="/capsman/ssid-save" '
        'class="fields">', _hidden("csrf", csrf)]
    if selected.get("id"):
        ssid_form.append(_hidden("id", selected["id"]))
    ssid_form += [
        _field("Profile name", "name", selected.get("name", ""),
               extra=' placeholder="staff" required'),
        _field("Network name (SSID)", "ssid", selected.get("ssid", ""),
               extra=' required maxlength="32"'),
        '<label class="f">Purpose<select name="purpose">']
    for purpose in ("staff", "guest", "iot"):
        ssid_form.append(f'<option value="{purpose}"'
                         f'{" selected" if selected.get("purpose") == purpose else ""}>'
                         f'{purpose}</option>')
    ssid_form += [
        '</select></label>',
        _field("VLAN ID", "vlan_id", selected.get("vlan_id", ""), kind="number"),
        '<label class="f">Security<select name="security_mode">']
    for mode in ("wpa2-psk", "wpa3-psk", "wpa2-wpa3", "open"):
        ssid_form.append(f'<option value="{mode}"'
                         f'{" selected" if selected.get("security_mode") == mode else ""}>'
                         f'{mode}</option>')
    ssid_form += [
        '</select></label>',
        _field("Passphrase", "passphrase", selected.get("passphrase", ""),
               kind="password"),
        _field("Bridge", "bridge", selected.get("bridge", "bridge")),
        _field("Band", "band", selected.get("band", "dual")),
        '<div class="chkrow">',
        _checkbox("Client isolation", "client_isolation",
                  bool(selected.get("client_isolation"))),
        _checkbox("Enabled", "enabled", selected.get("enabled", 1)),
        '</div><p><button class="btn" type="submit">Save SSID</button></p></form>',
        '</div>']

    ap_rows = []
    for view in live:
        device = str(view.get("device", ""))
        for ap in view.get("aps", []):
            ap_rows.append(
                '<tr>'
                f'<td>{esc(device)}</td>'
                f'<td>{esc(ap.get("name", ""))}</td>'
                f'<td>{esc(ap.get("identity", ""))}</td>'
                f'<td>{esc(ap.get("address", ""))}</td>'
                f'<td>{esc(ap.get("state", ""))}</td>'
                f'<td>{esc(ap.get("model", ""))}</td>'
                f'<td>{esc(ap.get("clients_count", 0))}</td></tr>')
    if not ap_rows:
        ap_rows = ['<tr><td colspan="7" class="wifi-empty">'
                   'No access points have checked in yet.</td></tr>']
    ap_html = [
        '<div class="box"><h2>Access points</h2>',
        '<div style="overflow-x:auto"><table><thead><tr><th>Router</th>'
        '<th>Name</th><th>Identity</th><th>Address</th><th>State</th>'
        '<th>Model</th><th>Clients</th></tr></thead><tbody>',
        "".join(ap_rows), '</tbody></table></div></div>']

    client_rows = []
    for view in live:
        device = str(view.get("device", ""))
        if view.get("error"):
            client_rows.append(
                f'<tr><td colspan="8"><div class="wifi-err">'
                f'{esc(device)}: {esc(view["error"])}</div></td></tr>')
        for client in view.get("clients", []):
            mac = str(client.get("mac", ""))
            client_id = str(client.get("id", ""))
            blocked_mac = any(str(b.get("mac", "")).lower() == mac.lower()
                              for b in blocked)
            action = ('<span class="badge warn">blocked</span>' if blocked_mac else
                      '<form method="post" action="/capsman/client-block"'
                      f' onsubmit="{confirm_attr("Block this client?")}">'
                      + _hidden("csrf", csrf) + _hidden("device", device)
                      + _hidden("mac", mac)
                      + '<button type="submit">Block</button></form>')
            client_rows.append(
                '<tr>'
                f'<td>{esc(device)}</td><td>{esc(mac)}</td>'
                f'<td>{esc(client.get("ip", ""))}</td>'
                f'<td>{esc(client.get("ssid", ""))}</td>'
                f'<td>{esc(client.get("ap", ""))}</td>'
                f'<td>{_signal_badge(client)}</td>'
                f'<td>{esc(client.get("uptime", ""))}</td>'
                f'<td><form method="post" action="/capsman/client-disconnect">'
                + _hidden("csrf", csrf) + _hidden("device", device)
                + _hidden("client_id", client_id) + _hidden("mac", mac)
                + '<button type="submit">Disconnect</button></form>'
                + action + '</td></tr>')
    if not client_rows:
        client_rows = ['<tr><td colspan="8" class="wifi-empty">'
                       'No clients are associated right now.</td></tr>']
    client_html = [
        '<div class="box"><h2>Live clients</h2>',
        '<div style="overflow-x:auto"><table><thead><tr><th>Router</th>'
        '<th>MAC</th><th>IP</th><th>SSID</th><th>AP</th><th>Signal</th>'
        '<th>Uptime</th><th>Actions</th></tr></thead><tbody>',
        "".join(client_rows), '</tbody></table></div></div>']

    block_rows = []
    for row in blocked:
        block_rows.append(
            '<tr>'
            f'<td>{esc(row.get("mac", ""))}</td>'
            f'<td>{esc(row.get("reason", ""))}</td>'
            f'<td>{esc(row.get("blocked_by", ""))}</td>'
            f'<td><form method="post" action="/capsman/client-unblock"'
            f' onsubmit="{confirm_attr("Allow this MAC back onto Wi-Fi?")}">'
            + _hidden("csrf", csrf) + _hidden("mac", row.get("mac", ""))
            + _hidden("device", row.get("device", ""))
            + '<button type="submit">Unblock</button></form></td></tr>')
    if not block_rows:
        block_rows = ['<tr><td colspan="4" class="wifi-empty">'
                      'No MAC addresses are blocked.</td></tr>']
    block_html = [
        '<div class="box"><h2>Blocked MACs</h2>',
        '<div style="overflow-x:auto"><table><thead><tr><th>MAC</th>'
        '<th>Reason</th><th>By</th><th></th></tr></thead><tbody>',
        "".join(block_rows), '</tbody></table></div></div>']

    body = (_header(user, "/capsman") + _flash(flash, error)
            + '<div class="noc">' + kpis + '</div>'
            + '<div style="padding:16px 20px 0">' + "".join(sync_html) + '</div>'
            + '<div class="wifi-grid">'
            + "".join(ctrl_html + ssid_form + ap_html + client_html + block_html)
            + '</div>')
    return _page("Wi-Fi / CAPsMAN", body)
