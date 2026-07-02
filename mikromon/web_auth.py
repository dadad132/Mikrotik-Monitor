"""Auth, account, team-admin, and billing page renders for the web dashboard.

Extracted from web.py to keep that file manageable. Imports shared constants
and helpers from web_shared; web.py imports the render functions from here.
"""
from __future__ import annotations

import time

from .auth import AuthStore
from .billing import PLANS, GRACE_DAYS, FREE_DEVICES
from .web_shared import _BRAND, _PAGE_CSS, esc, _header, _page, _who


_AUTH_BRAND = ('<div class="brand" style="justify-content:center;color:#0f172a;'
               'font-size:22px;margin-bottom:6px">'
               '<span class="logo" style="color:#2563eb">&#9670;</span>'
               + _BRAND + '</div>')


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
            f'<p><input name="email" placeholder="Email" autofocus '
            f'style="width:100%"></p>'
            f'<p class="muted" style="margin:-6px 0 8px;font-size:12px">'
            f'Existing account? You can sign in with your username too.</p>'
            f'<p><input name="password" type="password" placeholder="Password" '
            f'style="width:100%"></p>'
            f'<button class="btn" type="submit" style="width:100%">Sign in</button>'
            f'</form>'
            f'<p class="muted" style="margin:14px 0 0;text-align:center">'
            f'New here? <a href="/signup">Create a company account</a></p>')


def _render_signup(error: str = "", values=None) -> str:
    v = values or {}
    msg = (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    return _auth_page("Create account",
            f'<h2 style="margin-top:0">Create your company account</h2>'
            f'<p class="muted" style="margin-top:0">You\'ll be the owner: you can '
            f'invite team members and choose which devices each one can see.</p>{msg}'
            f'<form method="POST" action="/signup">'
            f'<p><input name="company" placeholder="Company name" autofocus '
            f'value="{esc(v.get("company", ""))}" style="width:100%"></p>'
            f'<p><input name="email" type="email" placeholder="Your email" '
            f'value="{esc(v.get("email", ""))}" style="width:100%"></p>'
            f'<p><input name="phone" type="tel" placeholder="Mobile number (e.g. +27 82 555 1234)" '
            f'value="{esc(v.get("phone", ""))}" style="width:100%"></p>'
            f'<p style="color:#64748b;font-size:12px;margin:-8px 0 4px">'
            f'We collect your mobile number to help prevent abuse. '
            f'We will never share it or use it for marketing.</p>'
            f'<p><input name="password" type="password" '
            f'placeholder="Password (min 6 characters)" style="width:100%"></p>'
            f'<p style="margin-top:16px"><b style="font-size:13px">WAN failover '
            f'alert recipients</b><br>'
            f'<span style="color:#64748b;font-size:12px">Who should receive an '
            f'email when a router switches to its backup WAN link? '
            f'Separate multiple addresses with commas.</span></p>'
            f'<p><input name="alert_emails" type="text" '
            f'placeholder="it@company.com, manager@company.com" '
            f'value="{esc(v.get("alert_emails", ""))}" style="width:100%"></p>'
            f'<button class="btn" type="submit" style="width:100%">'
            f'Create account</button></form>'
            f'<p class="muted" style="margin:14px 0 0;text-align:center">'
            f'Already have an account? <a href="/login">Sign in</a></p>')


def _render_account(user, csrf: str, msg: str = "", error: str = "",
                    org: dict | None = None) -> str:
    note = (f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else "") + \
           (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    org_name = user.get("org_name", "")
    uname_row = (f'<p>Username <span class="muted">(your existing login — you can '
                 f'keep using it)</span><br><input value="{esc(user["username"])}" '
                 f'disabled style="width:100%;max-width:360px;background:#f1f5f9">'
                 f'</p>') if user.get("username") else ""
    email_hint = ("Add an email to sign in with it too"
                  if user.get("username") and not user.get("email")
                  else "Used to sign in")
    personal_box = (
        f'<div class="box"><h2 style="margin-top:0">Personal details</h2>'
        f'<form method="POST" action="/account">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="action" value="personal">'
        f'{uname_row}'
        f'<p>Email <span class="muted">({email_hint})</span><br>'
        f'<input name="email" type="email" value="{esc(user.get("email") or "")}" '
        f'style="width:100%;max-width:360px"></p>'
        f'<p>New password <span class="muted">(leave blank to keep current)</span>'
        f'<br><input name="password" type="password" placeholder="min 6 characters" '
        f'style="width:100%;max-width:360px"></p>'
        f'<button class="btn" type="submit">Save changes</button>'
        f'</form></div>')
    company_box = ""
    if AuthStore.is_owner(user) and org is not None:
        o = org
        sched = o.get("report_schedule") or "none"
        def _sched_opt(val, label):
            sel = ' selected' if sched == val else ''
            return f'<option value="{val}"{sel}>{label}</option>'
        company_box = (
            f'<div class="box"><h2 style="margin-top:0">Company details</h2>'
            f'<form method="POST" action="/account">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="action" value="company">'
            f'<div class="fields">'
            f'<label class="f full">Company name <span style="color:#dc2626">*</span>'
            f'<input name="org_name" value="{esc(o.get("name", ""))}" '
            f'style="width:100%" required></label>'
            f'<label class="f">Primary contact'
            f'<input name="org_contact" value="{esc(o.get("contact", ""))}" '
            f'placeholder="Contact person name" style="width:100%"></label>'
            f'<label class="f">Company phone'
            f'<input name="org_phone" value="{esc(o.get("phone", ""))}" '
            f'placeholder="+27 11 555 0000" style="width:100%"></label>'
            f'<label class="f">VAT / Tax number'
            f'<input name="org_vat" value="{esc(o.get("vat_number", ""))}" '
            f'placeholder="VAT number" style="width:100%"></label>'
            f'<label class="f full">Physical address'
            f'<input name="org_address" value="{esc(o.get("address", ""))}" '
            f'placeholder="Street, City, Province, Postal code" style="width:100%"></label>'
            f'</div>'
            f'<h3 style="margin:20px 0 8px">Alert notifications</h3>'
            f'<div class="fields">'
            f'<label class="f full">WAN alert recipients'
            f'<span style="color:#64748b;font-size:12px;font-weight:normal;margin-left:6px">'
            f'Comma-separated — notified when any WAN uplink changes state</span>'
            f'<div style="display:flex;gap:8px;align-items:center">'
            f'<input name="alert_emails" type="text" id="alert_emails_input" '
            f'value="{esc(", ".join(o.get("alert_emails") or []))}" '
            f'placeholder="it@company.com, manager@company.com" '
            f'style="flex:1;min-width:0"></div></label>'
            f'<label class="f full">Status report emails'
            f'<span style="color:#64748b;font-size:12px;font-weight:normal;margin-left:6px">'
            f'Send a device status summary to alert recipients</span>'
            f'<select name="report_schedule" style="width:auto">'
            + _sched_opt("none", "Disabled")
            + _sched_opt("weekly", "Weekly (every 7 days)")
            + _sched_opt("biweekly", "Bi-weekly (every 14 days)")
            + _sched_opt("monthly", "Monthly (every 30 days)")
            + f'</select></label>'
            f'</div>'
            f'<div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">'
            f'<button class="btn" type="submit">Save company details</button>'
            f'</div></form>'
            f'<form method="POST" action="/account/send-test-email" '
            f'style="margin-top:8px">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<button class="btn" type="submit" '
            f'style="background:#0f766e;border-color:#0f766e" '
            f'onclick="this.textContent=\'Sending…\';this.disabled=true">'
            f'&#9993; Send test email</button>'
            f'<span style="color:#64748b;font-size:12px;margin-left:8px">'
            f'Sends a test notification to the alert recipients above</span>'
            f'</form></div>')
    inner = (
        f'<div class="wrap"><h1>My account</h1>'
        f'<p class="muted" style="margin-top:-8px">'
        f'Company: <b>{esc(org_name)}</b> &middot; Role: <b>{esc(user["role"])}</b></p>'
        f'{note}'
        f'{personal_box}'
        f'{company_box}'
        f'</div>')
    return _page("My account", _header(user, "/account") + inner)


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


def _render_admin(auth: AuthStore, known_devices, csrf: str, user,
                  msg: str = "", error: str = "") -> str:
    rows = []
    for u in auth.list_users(user["org_id"]):
        is_all = u["devices"] == "*"
        selected = set() if is_all else set(u["devices"])
        acct = u["login"]
        is_self = acct == user["login"]
        rows.append(f"""<tr>
          <td><b>{esc(_who(u))}</b></td>
          <td><span class="pill {esc(u['role'])}">{esc(u['role'])}</span></td>
          <td>
            <form method="POST" action="/admin/update">
              <input type="hidden" name="csrf" value="{csrf}">
              <input type="hidden" name="account" value="{esc(acct)}">
              <div class="actions" style="margin-bottom:8px">
                <select name="role">
                  <option value="member"{' selected' if u['role']=='member' else ''}>member</option>
                  <option value="owner"{' selected' if u['role']=='owner' else ''}>owner</option>
                </select>
                <button class="btn" type="submit">Save changes</button>
              </div>
              {_device_chips(known_devices, selected, is_all)}
            </form>
          </td>
          <td>{'' if is_self else f'''
            <form method="POST" action="/admin/delete"
              onsubmit="return confirm('Delete user {esc(_who(u))}?')">
              <input type="hidden" name="csrf" value="{csrf}">
              <input type="hidden" name="account" value="{esc(acct)}">
              <button class="btn red" type="submit">Delete</button>
            </form>'''}
          </td></tr>""")
    note = (f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else "") + \
           (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    inner = (
        f'<div class="wrap"><h1>Team &mdash; {esc(user.get("org_name", ""))}</h1>'
        f'{note}'
        f'<p class="muted" style="margin-top:-8px">'
        f'Company details and alert settings are in '
        f'<a href="/account">Account</a>.</p>'
        f'<div class="box"><table>'
        f'<tr><th>Email</th><th>Role</th><th>Allowed devices</th><th></th></tr>'
        f'{"".join(rows)}</table></div>'
        f'<div class="box"><h2>Add a team member</h2>'
        f'<form method="POST" action="/admin/add">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<div class="actions" style="margin-bottom:12px;flex-wrap:wrap">'
        f'<input name="email" type="email" placeholder="email">'
        f'<input name="password" type="password" placeholder="password (min 6)">'
        f'<select name="role"><option value="member">member</option>'
        f'<option value="owner">owner</option></select>'
        f'</div>'
        f'<p class="muted" style="margin:0 0 6px">Which devices may this member see?</p>'
        f'{_device_chips(known_devices, set(), False)}'
        f'<div style="margin-top:14px">'
        f'<button class="btn" type="submit">Add member</button></div>'
        f'</form></div>'
        f'</div>')
    return _page("Team", _header(user, "/admin") + inner + _ADMIN_JS)


def _grace_banner_html(days_left: float) -> str:
    days = max(1, int(days_left) + 1)
    plural = "day" if days == 1 else "days"
    return (f'<div style="background:#fef3c7;border-bottom:2px solid #d97706;'
            f'padding:10px 20px;text-align:center;font-size:13px;color:#92400e">'
            f'<b>Subscription lapsed.</b> You have {days} {plural} before your '
            f'account is locked. '
            f'<a href="/billing" style="color:#92400e;font-weight:700">Upgrade now</a>'
            f'</div>')


def _render_billing(user, bill: dict | None, pf_enabled: bool, csrf: str,
                    msg: str = "", error: str = "") -> str:
    """Billing page: current subscription status + PayFast plan subscribe buttons."""
    status = (bill or {}).get("status", "none")
    plan_name = (bill or {}).get("plan") or ""
    device_limit = int((bill or {}).get("device_limit") or FREE_DEVICES)
    trial_end = (bill or {}).get("trial_end")
    grace_end = (bill or {}).get("grace_period_end")
    pf_token = (bill or {}).get("pf_token") or ""

    # --- status summary box ---
    if status in ("active", "trialing"):
        limit_label = (f"{device_limit} device{'s' if device_limit != 1 else ''}"
                       if device_limit else "unlimited devices")
        status_html = (f'<p style="margin:0"><span style="color:#16a34a;font-weight:700">'
                       f'Active</span> &middot; {esc(plan_name or "Subscribed")}'
                       f' &middot; {limit_label}</p>')
    elif status == "trial":
        te_fmt = (time.strftime("%d %b %Y", time.localtime(trial_end))
                  if trial_end else "soon")
        status_html = (f'<p style="margin:0"><span style="color:#2563eb;font-weight:700">'
                       f'Free Trial</span> &middot; {FREE_DEVICES} devices &middot; '
                       f'expires {te_fmt}</p>')
    elif status in ("grace",):
        ge_fmt = (time.strftime("%d %b %Y", time.localtime(grace_end))
                  if grace_end else "soon")
        status_html = (f'<p style="margin:0"><span style="color:#d97706;font-weight:700">'
                       f'Grace Period</span> &middot; subscribe before {ge_fmt} to '
                       f'avoid lockout</p>')
    elif status in ("canceled", "locked", "inactive"):
        status_html = (f'<p style="margin:0"><span style="color:#dc2626;font-weight:700">'
                       f'Suspended</span> &middot; choose a plan below to reactivate</p>')
    else:
        status_html = (f'<p style="margin:0"><span style="color:#64748b;font-weight:700">'
                       f'Free plan</span> &middot; {FREE_DEVICES} devices &middot; '
                       f'subscribe to add more</p>')

    note = (f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else "") + \
           (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")

    # Cancel button shown only when there's an active PayFast subscription token
    cancel_btn = ""
    if pf_token and status in ("active", "trialing"):
        cancel_btn = (f'<form method="POST" action="/billing/cancel-sub" '
                      f'style="display:inline" '
                      f'onsubmit="return confirm(\'Cancel your subscription? You will keep access until the end of the grace period.\');">'
                      f'<input type="hidden" name="csrf" value="{csrf}">'
                      f'<button class="btn ghost" type="submit" '
                      f'style="color:#dc2626;border-color:#dc2626">Cancel subscription</button>'
                      f'</form>')

    status_box = (f'<div class="box">'
                  f'<div style="display:flex;align-items:center;'
                  f'justify-content:space-between;flex-wrap:wrap;gap:10px">'
                  f'{status_html}{cancel_btn}</div>'
                  f'</div>')

    # --- plan table ---
    if pf_enabled:
        plan_rows = ""
        for p in PLANS:
            is_current = (status in ("active", "trialing") and plan_name == p["name"])
            per_dev = p["price_zar"] / p["devices"]
            if is_current:
                btn = '<span class="badge ok">Current plan</span>'
            else:
                btn = (f'<form method="POST" action="/billing/subscribe">'
                       f'<input type="hidden" name="csrf" value="{csrf}">'
                       f'<input type="hidden" name="plan" value="{esc(p["name"])}">'
                       f'<button class="btn" type="submit" style="padding:6px 14px">'
                       f'Subscribe</button></form>')
            plan_rows += (f'<tr>'
                          f'<td><b>{esc(p["label"])}</b></td>'
                          f'<td>{p["devices"]}</td>'
                          f'<td><b>R{p["price_zar"]:,.2f}</b>/mo</td>'
                          f'<td>R{per_dev:,.2f}/device</td>'
                          f'<td>{btn}</td>'
                          f'</tr>')
        plans_html = (f'<div class="box"><h2>Choose a plan</h2>'
                      f'<p class="muted" style="margin-top:0">All prices in ZAR, '
                      f'billed monthly via PayFast. Cancel anytime.</p>'
                      f'<table><thead><tr>'
                      f'<th>Plan</th><th>Devices</th><th>Monthly</th>'
                      f'<th>Per device</th><th></th>'
                      f'</tr></thead><tbody>{plan_rows}</tbody></table></div>')
    else:
        plans_html = (f'<div class="box"><p class="muted">PayFast billing is not '
                      f'yet configured on this server. Add a <code>billing:</code> '
                      f'section to config.yaml to enable subscriptions.</p></div>')

    inner = (f'<div class="wrap"><h1>Billing</h1>{note}'
             f'{status_box}{plans_html}</div>')
    return _page("Billing", _header(user, "/billing") + inner)


def _render_locked(user) -> str:
    """Full-page lockout shown when an org's grace period has expired."""
    inner = (f'<div class="wrap" style="max-width:560px;margin-top:10vh;text-align:center">'
             f'<div class="box">'
             f'<h1 style="color:#dc2626;margin-bottom:8px">Account Suspended</h1>'
             f'<p>Your subscription has lapsed and the {GRACE_DAYS}-day grace period '
             f'has expired. All access has been suspended.</p>'
             f'<p><a class="btn" href="/billing">Reactivate your account</a></p>'
             f'<p class="muted" style="margin-top:18px">'
             f'<a href="/logout">Log out</a></p>'
             f'</div></div>')
    return _page("Account Suspended", _header(user, "") + inner)


_TRIAL_DEVICES = FREE_DEVICES

_STATUS_COLOR = {
    "active":   ("#16a34a", "Active"),
    "trialing": ("#16a34a", "Active"),
    "trial":    ("#2563eb", "Trial"),
    "grace":    ("#d97706", "Grace"),
    "canceled": ("#dc2626", "Lapsed"),
    "locked":   ("#dc2626", "Locked"),
    "inactive": ("#64748b", "Free"),
    "none":     ("#64748b", "Free"),
}


def _render_superadmin(user, rows: list, msg: str = "", error: str = "") -> str:
    """Platform superadmin panel — shows all orgs, billing status, and device counts."""
    note = (f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else "") + \
           (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")

    _status_counts: dict[str, int] = {}
    tbody = ""
    for r in rows:
        bill = r.get("bill") or {}
        status = bill.get("status") or "none"
        color, label = _STATUS_COLOR.get(status, ("#64748b", status.title()))
        _status_counts[label] = _status_counts.get(label, 0) + 1

        plan = bill.get("plan") or ""
        device_limit = bill.get("device_limit") or FREE_DEVICES
        device_count = r.get("device_count", 0)
        trial_end = bill.get("trial_end")
        grace_end = bill.get("grace_period_end")

        trial_str = (time.strftime("%d %b %Y", time.localtime(trial_end))
                     if trial_end and status == "trial" else "")
        grace_str = (time.strftime("%d %b %Y", time.localtime(grace_end))
                     if grace_end and status == "grace" else "")
        created_str = (time.strftime("%d %b %Y", time.localtime(r["created"]))
                       if r.get("created") else "")

        tbody += (
            f'<tr>'
            f'<td><b>{esc(r["name"])}</b>'
            f'<br><span class="muted" style="font-size:11px">'
            f'{esc(r.get("owner_email",""))} &middot; '
            f'{r.get("user_count",0)} user(s)</span></td>'
            f'<td><span style="color:{color};font-weight:700">{label}</span>'
            f'{f"<br><span class=\'muted\' style=\'font-size:11px\'>trial ends {trial_str}</span>" if trial_str else ""}'
            f'{f"<br><span class=\'muted\' style=\'font-size:11px;color:#d97706\'>grace ends {grace_str}</span>" if grace_str else ""}'
            f'</td>'
            f'<td>{esc(plan) if plan else "<span class=\'muted\'>—</span>"}</td>'
            f'<td>{device_count} / {device_limit if device_limit else "∞"}</td>'
            f'<td>{created_str}</td>'
            f'</tr>'
        )

    # Summary tiles
    total = len(rows)
    active_n = _status_counts.get("Active", 0)
    trial_n = _status_counts.get("Trial", 0)
    grace_n = _status_counts.get("Grace", 0)
    locked_n = _status_counts.get("Locked", 0)
    free_n = _status_counts.get("Free", 0)

    tiles = (
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));'
        f'gap:12px;margin-bottom:20px">'
        f'{_sa_tile(total, "Total orgs", "#2563eb")}'
        f'{_sa_tile(active_n, "Active", "#16a34a")}'
        f'{_sa_tile(trial_n, "On trial", "#2563eb")}'
        f'{_sa_tile(free_n, "Free plan", "#64748b")}'
        f'{_sa_tile(grace_n, "Grace period", "#d97706")}'
        f'{_sa_tile(locked_n, "Locked", "#dc2626")}'
        f'</div>'
    )

    table = (
        f'<div class="box" style="overflow-x:auto">'
        f'<table style="min-width:700px"><thead><tr>'
        f'<th>Company</th><th>Status</th><th>Plan</th>'
        f'<th>Devices</th><th>Joined</th>'
        f'</tr></thead><tbody>{tbody or "<tr><td colspan=5 class=muted>No organisations yet.</td></tr>"}'
        f'</tbody></table></div>'
    )

    inner = (f'<div class="wrap"><h1>Platform admin</h1>{note}{tiles}{table}</div>')
    return _page("Platform Admin", _header(user, "/superadmin") + inner)


def _sa_tile(value, label: str, color: str) -> str:
    return (f'<div style="background:#fff;border-radius:10px;padding:12px 16px;'
            f'box-shadow:0 1px 3px rgba(0,0,0,.1);border-top:3px solid {color}">'
            f'<div style="font-size:26px;font-weight:700;color:{color}">{value}</div>'
            f'<div style="font-size:11px;color:#64748b;text-transform:uppercase;'
            f'letter-spacing:.04em;margin-top:4px">{label}</div>'
            f'</div>')
