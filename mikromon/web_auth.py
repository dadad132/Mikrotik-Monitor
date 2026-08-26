"""Auth, account, team-admin, and billing page renders for the web dashboard.

Extracted from web.py to keep that file manageable. Imports shared constants
and helpers from web_shared; web.py imports the render functions from here.
"""
from __future__ import annotations

import time

from .auth import AuthStore
from .billing import (payment_reference, PLANS, GRACE_DAYS, FREE_DEVICES,
                      TRIAL_DEVICES, _TRIAL_DAYS, TIER_STEP,
                      MAX_TIER_DEVICES, QUOTE_ABOVE_DEVICES, needs_quote,
                      plan_by_name)
from .util import human_bytes
from .web_shared import (
    _BRAND, _PAGE_CSS, esc, _header, _page, _who,
    _THEME_VARS, _THEME_INIT_JS, _THEME_TOGGLE_JS, _theme_toggle_btn,
)


_AUTH_BRAND = ('<div class="brand" style="justify-content:center;color:var(--text);'
               'font-size:22px;margin-bottom:6px">'
               '<span class="logo" style="color:var(--accent)">&#9670;</span>'
               + _BRAND + '</div>')


def _auth_page(title, body) -> str:
    # This page has no logged-in user (no sidebar to carry _THEME_VARS along
    # with it via _header/_page) — _PAGE_CSS now leans on those custom
    # properties for nearly every color, so without defining them here too,
    # var(--border)/var(--surface)/etc resolve to nothing: borders vanish
    # (reset to the "none" initial value) and backgrounds go transparent.
    # Confirmed live: exactly this — invisible input boxes, invisible button.
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'{_THEME_INIT_JS}<title>{esc(title)}</title>'
            f'<style>{_THEME_VARS}{_PAGE_CSS}</style></head><body>'
            f'<div class="wrap" style="max-width:400px;margin-top:9vh">'
            f'<div style="display:flex;justify-content:center;margin-bottom:6px">'
            f'{_theme_toggle_btn()}</div>'
            f'{_AUTH_BRAND}<div class="box">{body}</div></div>'
            f'{_THEME_TOGGLE_JS}</body></html>')


def _region_banner(has_regions: bool, go: str) -> str:
    return (f'<p class="muted" style="margin:0 0 14px;text-align:center;'
            f'font-size:12px">Not in the right place? '
            f'<a href="/regions?go={go}">Choose your region</a></p>'
            if has_regions else "")


def _render_login(error: str = "", has_regions: bool = False) -> str:
    msg = (f'<p style="color:#dc2626;margin-top:0">{esc(error)}</p>'
           if error else "")
    return _auth_page("Sign in",
            f'{_region_banner(has_regions, "login")}'
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


def _render_signup(error: str = "", values=None, has_regions: bool = False) -> str:
    v = values or {}
    msg = (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    return _auth_page("Create account",
            f'{_region_banner(has_regions, "signup")}'
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
            f'<div style="margin-top:12px;display:flex;align-items:center;gap:10px">'
            f'<button class="btn" data-csrf="{esc(csrf)}" '
            f'style="background:#0f766e;border-color:#0f766e" '
            f'onclick="mmSendTestEmail(this)">'
            f'&#9993; Send test email</button>'
            f'<span style="color:#64748b;font-size:12px">'
            f'Sends a test notification to the alert recipients above</span>'
            f'</div></div>'
            + _EMAIL_POPUP_HTML)
    inner = (
        f'<div class="wrap"><h1>My account</h1>'
        f'<p class="muted" style="margin-top:-8px">'
        f'Company: <b>{esc(org_name)}</b> &middot; Role: <b>{esc(user["role"])}</b></p>'
        f'{note}'
        f'{personal_box}'
        f'{company_box}'
        f'</div>')
    return _page("My account", _header(user, "/account") + inner)


_EMAIL_POPUP_HTML = """
<div id="mm-email-popup" style="display:none;position:fixed;inset:0;
  background:rgba(0,0,0,.5);z-index:9999;align-items:center;justify-content:center">
 <div style="background:#fff;border-radius:10px;max-width:440px;width:90%;
   padding:28px 28px 20px;box-shadow:0 8px 32px rgba(0,0,0,.25)">
  <div id="mm-ep-icon" style="font-size:36px;margin-bottom:10px"></div>
  <div id="mm-ep-title" style="font-weight:700;font-size:17px;margin-bottom:8px"></div>
  <div id="mm-ep-msg" style="font-size:14px;line-height:1.6;color:#374151;
    word-break:break-word"></div>
  <button class="btn" style="margin-top:20px"
    onclick="document.getElementById('mm-email-popup').style.display='none'">
   Close</button>
 </div>
</div>
<script>
function mmSendTestEmail(btn) {
  btn.textContent = '⏳ Sending…';
  btn.disabled = true;
  fetch('/account/send-test-email', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'csrf=' + encodeURIComponent(btn.getAttribute('data-csrf'))
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    btn.textContent = '✉ Send test email';
    btn.disabled = false;
    var ok = d.ok;
    document.getElementById('mm-ep-icon').textContent  = ok ? '✅' : '❌';
    document.getElementById('mm-ep-title').style.color = ok ? '#16a34a' : '#dc2626';
    document.getElementById('mm-ep-title').textContent = ok ? 'Email sent!' : 'Failed to send';
    document.getElementById('mm-ep-msg').textContent   = ok ? d.msg : d.error;
    document.getElementById('mm-email-popup').style.display = 'flex';
  })
  .catch(function(e) {
    btn.textContent = '✉ Send test email';
    btn.disabled = false;
    document.getElementById('mm-ep-icon').textContent  = '❌';
    document.getElementById('mm-ep-title').style.color = '#dc2626';
    document.getElementById('mm-ep-title').textContent = 'Failed to send';
    document.getElementById('mm-ep-msg').textContent   = 'Network error: ' + e.message;
    document.getElementById('mm-email-popup').style.display = 'flex';
  });
}
</script>"""


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
                  msg: str = "", error: str = "", roadwarrior_box: str = "") -> str:
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
        f'{roadwarrior_box}'
        f'</div>')
    return _page("Team", _header(user, "/admin") + inner + _ADMIN_JS)


def _contact_line(contact: dict | None) -> str:
    """'Email Jane at jane@x.com' — or '' if the superadmin never set one."""
    if not contact or not contact.get("email"):
        return ""
    email = contact["email"]
    name = (contact.get("name") or "").strip()
    who = f"{esc(name)} at " if name else ""
    return (f'Email {who}<a href="mailto:{esc(email)}">{esc(email)}</a> to '
            f'arrange payment and reactivation.')


def _grace_banner_html(days_left: float, contact: dict | None = None) -> str:
    days = max(1, int(days_left) + 1)
    plural = "day" if days == 1 else "days"
    line = _contact_line(contact)
    return (f'<div style="background:#fef3c7;border-bottom:2px solid #d97706;'
            f'padding:10px 20px;text-align:center;font-size:13px;color:#92400e">'
            f'<b>Subscription lapsed.</b> You have {days} {plural} before your '
            f'account is locked. '
            + (f'{line} ' if line else "")
            + f'<a href="/billing" style="color:#92400e;font-weight:700">Upgrade now</a>'
            f'</div>')


def _eft_reference_box(org_id, contact: dict | None = None,
                       org_name: str = "") -> str:
    """The company's own EFT reference, plus where to actually send the money.

    A bank statement line only says who a payment is from and what they typed
    in the reference field. If the customer was never given a reference, there
    is nothing on the deposit tying it to an account, and reconciling it means
    guessing from the name. So the reference has to be handed out up front --
    it cannot be worked out afterwards from the money arriving.

    Deliberately plain and copyable rather than decorative: it gets retyped
    into a banking app by hand, and every character is a chance to get it
    wrong.

    The bank details matter as much as the reference. A reference with no
    account to send it to is half an instruction, and a customer who cannot
    work out where to pay is a customer who does not pay. When no details have
    been configured this says so and points at whatever contact HAS been set,
    rather than showing a bare code and leaving them to guess."""
    from .billing import payment_reference

    ref = payment_reference(org_id, org_name)
    contact = contact or {}
    bank = ""
    if contact:
        fields = [("Bank", contact.get("bank_name")),
                  ("Account name", contact.get("bank_holder")),
                  ("Account number", contact.get("bank_account")),
                  ("Branch code", contact.get("bank_branch"))]
        filled = [(lbl, val) for lbl, val in fields if str(val or "").strip()]
        if filled:
            bank = ('<div style="margin-top:12px;font-size:13px">'
                    + "".join(
                        f'<div><span class="muted" '
                        f'style="display:inline-block;min-width:120px">'
                        f'{esc(lbl)}</span><b>{esc(str(val))}</b></div>'
                        for lbl, val in filled)
                    + "</div>")
    if not bank:
        who = " or ".join(x for x in (esc(str(contact.get("name") or "")),
                                      esc(str(contact.get("email") or "")))
                          if x)
        bank = ('<div style="margin-top:12px;font-size:13px;padding:10px 12px;'
                'border-radius:8px;background:var(--surface-2);'
                'border:1px solid var(--border)">'
                'Bank details are not published here yet &mdash; '
                + (f'contact <b>{who}</b> for them, quoting the reference '
                   f'above.' if who else
                   'contact your provider for them, quoting the reference '
                   'above.')
                + '</div>')
    return (
        f'<div class="box"><h2>Paying by EFT</h2>'
        f'<p class="muted" style="margin-top:0">Use this reference on the '
        f'payment so it can be matched to your account. Without it a deposit '
        f'arrives with nothing to identify it by.</p>'
        f'<div style="display:flex;align-items:center;gap:12px;margin:10px 0">'
        f'<code style="font-size:22px;font-weight:700;letter-spacing:1px;'
        f'padding:8px 14px;border-radius:8px;background:var(--surface-2);'
        f'border:1px solid var(--border)" id="eftRef">{esc(ref)}</code>'
        f'<button class="btn ghost" type="button" onclick="'
        f'navigator.clipboard&amp;&amp;navigator.clipboard.writeText('
        f"'{ref}'" f');this.textContent=&quot;Copied&quot;">Copy</button>'
        f'</div>{bank}'
        f'<p class="muted" style="font-size:12px;margin-bottom:0">This '
        f'reference belongs to your account and never changes.</p></div>')


def _fitting_tier(device_count: int):
    """The smallest packet that holds this many devices, or None if the
    company is past the last tier (and so needs a quote) or has none yet.

    Smallest-that-fits rather than nearest: a packet the company has already
    outgrown is not a recommendation, it is a cap they hit on the first day.
    """
    if not device_count or device_count <= 0:
        return None
    for p in PLANS:
        if p["devices"] >= device_count:
            return p
    return None


def _quote_request_box(csrf: str, device_count: int = 0) -> str:
    """The path out of the ladder for a company bigger than the last packet.

    Above 100 devices the shape of the deal stops being something a price
    table can answer -- support terms, onboarding, billing cycle -- so this
    asks for a conversation instead of quoting a number nobody can honour.
    Shown to everyone, not only to companies already over the line: a customer
    planning a 300-site rollout needs to know the door exists BEFORE they
    conclude the product stops at 100 and go elsewhere.
    """
    over = needs_quote(device_count)
    prompt = (f'You are monitoring {device_count} devices, which is past the '
              f'largest packet. Tell us what you need and the team will come '
              f'back to you with a quote.'
              if over else
              f'Packets go up to {MAX_TIER_DEVICES} devices. If you need more '
              f'than that, ask for a quote and the team will put together '
              f'pricing that fits.')
    return (
        f'<div class="box"'
        + (' style="border-color:#2563eb"' if over else '')
        + f'><h2>More than {QUOTE_ABOVE_DEVICES} devices?</h2>'
        f'<p class="muted" style="margin-top:0">{esc(prompt)}</p>'
        f'<form method="POST" action="/billing/quote">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<div style="display:grid;grid-template-columns:'
        f'repeat(auto-fit,minmax(200px,1fr));gap:10px">'
        f'<label>Devices you need<br><input name="devices" type="number" '
        f'min="{QUOTE_ABOVE_DEVICES + 1}" max="100000" '
        f'value="{max(int(device_count or 0), QUOTE_ABOVE_DEVICES + 1)}" '
        f'required style="width:100%"></label>'
        f'<label>Best contact<br><input name="contact" '
        f'placeholder="name@company.com or a phone number" '
        f'style="width:100%"></label>'
        f'</div>'
        f'<label style="display:block;margin-top:10px">Anything we should '
        f'know<br><textarea name="note" rows="3" style="width:100%" '
        f'placeholder="Timelines, sites, support needs — whatever helps us '
        f'quote accurately."></textarea></label>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Request a quote</button></div>'
        f'</form></div>')


def _render_billing(user, bill: dict | None, pf_enabled: bool, csrf: str,
                    msg: str = "", error: str = "", contact: dict | None = None,
                    device_count: int = 0) -> str:
    """Billing page: current subscription status + PayFast plan subscribe
    buttons, and the company's own EFT reference for paying by bank
    transfer."""
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
        limit_label = (f"{device_limit} device{'s' if device_limit != 1 else ''}"
                       if device_limit else "unlimited devices")
        status_html = (f'<p style="margin:0"><span style="color:#2563eb;font-weight:700">'
                       f'Free Trial</span> &middot; {limit_label} &middot; '
                       f'expires {te_fmt}</p>')
    elif status in ("grace",):
        ge_fmt = (time.strftime("%d %b %Y", time.localtime(grace_end))
                  if grace_end else "soon")
        contact_p = (f'<p class="muted" style="margin:4px 0 0">{_contact_line(contact)}</p>'
                    if _contact_line(contact) else "")
        status_html = (f'<p style="margin:0"><span style="color:#d97706;font-weight:700">'
                       f'Grace Period</span> &middot; subscribe before {ge_fmt} to '
                       f'avoid lockout</p>{contact_p}')
    elif status in ("canceled", "locked", "inactive"):
        contact_p = (f'<p class="muted" style="margin:4px 0 0">{_contact_line(contact)}</p>'
                    if _contact_line(contact) else "")
        status_html = ('<p style="margin:0"><span style="color:#dc2626;font-weight:700">'
                       'Suspended</span> &middot; choose a plan below to reactivate</p>'
                       + contact_p)
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
                  f'</div>'
                  # Shown whether or not card payment is switched on: a
                  # customer paying by EFT needs the reference regardless,
                  # and needs it BEFORE they pay rather than after.
                  + _eft_reference_box(user.get("org_id"), contact,
                                      user.get("org_name", "")))

    # --- packet ladder --------------------------------------------------
    # Twenty tiers is a lot to read, so the row that actually fits this
    # company is marked. Without it the customer has to do the arithmetic
    # themselves, and the usual outcome of that is picking the cheapest row
    # and hitting the device cap a week later.
    fits = _fitting_tier(device_count)
    if pf_enabled:
        plan_rows = ""
        for p in PLANS:
            is_current = (status in ("active", "trialing")
                          and plan_name == p["name"])
            per_dev = p["price_usd"] / p["devices"]
            if is_current:
                btn = '<span class="badge ok">Current plan</span>'
            else:
                btn = (f'<form method="POST" action="/billing/subscribe">'
                       f'<input type="hidden" name="csrf" value="{csrf}">'
                       f'<input type="hidden" name="plan" value="{esc(p["name"])}">'
                       f'<button class="btn" type="submit" style="padding:6px 14px">'
                       f'Subscribe</button></form>')
            hint = ""
            row_style = ""
            if fits and p["name"] == fits["name"] and not is_current:
                hint = ('<br><span style="font-size:11px;color:#2563eb;'
                        'font-weight:600">Fits your '
                        f'{device_count} device{"" if device_count == 1 else "s"}'
                        '</span>')
                row_style = ' style="background:rgba(37,99,235,.06)"'
            plan_rows += (f'<tr{row_style}>'
                          f'<td><b>{esc(p["label"])}</b>{hint}</td>'
                          f'<td>{p["devices"]}</td>'
                          f'<td><b>${p["price_usd"]:,.2f}</b>/mo</td>'
                          f'<td>${per_dev:,.2f}/device</td>'
                          f'<td>{btn}</td>'
                          f'</tr>')
        plans_html = (f'<div class="box"><h2>Choose a packet</h2>'
                      f'<p class="muted" style="margin-top:0">Packets step in '
                      f'{TIER_STEP}s up to {MAX_TIER_DEVICES} devices, and the '
                      f'price per device drops as the packet grows. All prices '
                      f'in USD, billed monthly via PayFast. Cancel anytime.</p>'
                      f'<table><thead><tr>'
                      f'<th>Packet</th><th>Devices</th><th>Monthly</th>'
                      f'<th>Per device</th><th></th>'
                      f'</tr></thead><tbody>{plan_rows}</tbody></table></div>')
    else:
        plans_html = ('<div class="box"><p class="muted">PayFast billing is not '
                      'yet configured on this server. Add a <code>billing:</code> '
                      'section to config.yaml to enable subscriptions.</p></div>')

    plans_html += _quote_request_box(csrf, device_count)

    inner = (f'<div class="wrap"><h1>Billing</h1>{note}'
             f'{status_box}{plans_html}</div>')
    return _page("Billing", _header(user, "/billing") + inner)


def _render_locked(user, contact: dict | None = None) -> str:
    """Full-page lockout shown when an org's grace period has expired."""
    line = _contact_line(contact)
    contact_p = f'<p style="margin-top:14px">{line}</p>' if line else ""
    inner = (f'<div class="wrap" style="max-width:560px;margin-top:10vh;text-align:center">'
             f'<div class="box">'
             f'<h1 style="color:#dc2626;margin-bottom:8px">Account Suspended</h1>'
             f'<p>Your subscription has lapsed and the {GRACE_DAYS}-day grace period '
             f'has expired. All access has been suspended.</p>'
             f'{contact_p}'
             f'<p><a class="btn" href="/billing">Reactivate your account</a></p>'
             f'<p class="muted" style="margin-top:18px">'
             f'<a href="/logout">Log out</a></p>'
             f'</div></div>')
    return _page("Account Suspended", _header(user, "") + inner)


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


def _plan_select(org_id, current_plan, csrf) -> str:
    """A per-company plan-assign control for the superadmin (manual billing)."""
    opts = ['<option value="">— assign —</option>']
    known = {p["name"] for p in PLANS}
    # A company still on a retired plan name would otherwise show "— assign —",
    # which reads as "no plan" and invites an admin to overwrite a cap the
    # customer is paying for. Surface it instead, clearly marked.
    if current_plan and current_plan not in known and current_plan != "unlimited":
        legacy = plan_by_name(current_plan)
        opts.append(f'<option value="{esc(current_plan)}" selected>'
                    f'{esc(current_plan)} (retired · '
                    f'{legacy["devices"] if legacy else "?"} dev)</option>')
    for p in PLANS:
        sel = " selected" if current_plan == p["name"] else ""
        opts.append(f'<option value="{esc(p["name"])}"{sel}>'
                    f'{p["devices"]} dev · ${p["price_usd"]:.0f}/mo</option>')
    opts.append('<option value="unlimited"'
                + (" selected" if current_plan == "unlimited" else "")
                + '>Unlimited</option>')
    opts.append('<option value="free">Free (5)</option>')
    return (f'<form method="POST" action="/superadmin/billing" '
            f'style="display:flex;gap:4px">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="org_id" value="{esc(str(org_id))}">'
            f'<select name="plan" style="font-size:12px">{"".join(opts)}</select>'
            f'<button class="btn ghost" type="submit" '
            f'style="font-size:12px;padding:2px 8px">Set</button></form>')


def _smtp_settings_box(smtp, csrf) -> str:
    """Superadmin email-relay settings form (stored in the DB, not config.yaml)."""
    s = smtp or {}
    def v(k, d=""):
        return esc(str(s.get(k, d)))
    chk = lambda k, on: " checked" if s.get(k, on) else ""
    has_pw = "•••••• (saved)" if s.get("password") else ""
    return (
        f'<div class="box"><h2>Email (SMTP) settings</h2>'
        f'<p class="muted">The relay used to send WAN-alert emails to every '
        f'company. Set it here once — no need to edit config.yaml. Companies pick '
        f'their own recipient addresses on their Company details page.</p>'
        f'<form method="POST" action="/superadmin/smtp">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">'
        f'<label>SMTP host<br><input name="host" value="{v("host")}" '
        f'placeholder="mail-eu.smtp2go.com" style="width:100%"></label>'
        f'<label>Port<br><input name="port" value="{v("port","587")}" '
        f'placeholder="2525" style="width:100%"></label>'
        f'<label>Username<br><input name="username" value="{v("username")}" '
        f'style="width:100%"></label>'
        f'<label>Password<br><input name="password" type="password" '
        f'placeholder="{has_pw or "SMTP password"}" style="width:100%"></label>'
        f'<label>From address<br><input name="from_addr" value="{v("from_addr")}" '
        f'placeholder="alerts@yourdomain.com" style="width:100%"></label>'
        f'<label>Subject prefix<br><input name="subject_prefix" '
        f'value="{v("subject_prefix","[EasyMikrotik]")}" style="width:100%"></label>'
        f'</div>'
        f'<div style="margin:10px 0"><label class="chk"><input type="checkbox" '
        f'name="use_tls" value="1"{chk("use_tls", True)}> STARTTLS (ports 587 / '
        f'2525)</label> &nbsp; <label class="chk"><input type="checkbox" '
        f'name="use_ssl" value="1"{chk("use_ssl", False)}> SSL (port 465)</label>'
        f'</div>'
        f'<button class="btn" type="submit">Save email settings</button>'
        f'</form></div>')


def _billing_contact_box(contact, csrf) -> str:
    """Superadmin setting: who a trial-expired/locked company should email to
    arrange payment — shown to them on the grace banner and lockout page."""
    c = contact or {}
    def v(k, d=""):
        return esc(str(c.get(k, d)))
    return (
        f'<div class="box"><h2>Billing contact</h2>'
        f'<p class="muted">Shown to a company once their free trial or '
        f'subscription lapses, so they know who to email to arrange payment '
        f'and get reactivated. Leave blank to hide this message.</p>'
        f'<form method="POST" action="/superadmin/billing-contact">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">'
        f'<label>Name<br><input name="name" value="{v("name")}" '
        f'placeholder="Jane Smith" style="width:100%"></label>'
        f'<label>Email<br><input name="email" type="email" value="{v("email")}" '
        f'placeholder="billing@yourdomain.com" style="width:100%"></label>'
        f'</div>'
        # The account customers paying by EFT actually pay INTO. Shown on
        # every company's billing page beside the reference they must quote --
        # a reference with nowhere to send the money is only half the
        # instruction.
        # Loud while empty: until these are filled in, every company's billing
        # page shows a reference with no account behind it, and the first time
        # anyone notices is when an invoice goes unpaid.
        + ('<p style="margin:14px 0 6px;font-size:12px;padding:8px 10px;'
           'border-radius:6px;background:rgba(217,119,6,0.12);'
           'color:#b45309">&#9888; <b>No bank details set.</b> Every '
           'company&rsquo;s billing page is currently showing a payment '
           'reference with nowhere to send the money. Fill these in and they '
           'can pay by EFT.</p>'
           if not any(str(c.get(k) or "").strip()
                      for k in ("bank_name", "bank_account",
                                "bank_holder", "bank_branch"))
           else '<p class="muted" style="margin:14px 0 6px;font-size:12px">'
                'Bank details for customers paying by EFT. Shown on their '
                'billing page next to the reference they quote.</p>')
        + f'<div style="display:grid;grid-template-columns:'
        f'repeat(auto-fit,minmax(220px,1fr));gap:10px">'
        f'<label>Bank<br><input name="bank_name" value="{v("bank_name")}" '
        f'placeholder="Capitec" style="width:100%"></label>'
        f'<label>Account number<br><input name="bank_account" '
        f'value="{v("bank_account")}" placeholder="1234567890" '
        f'style="width:100%"></label>'
        f'<label>Account name<br><input name="bank_holder" '
        f'value="{v("bank_holder")}" placeholder="Your company (Pty) Ltd" '
        f'style="width:100%"></label>'
        f'<label>Branch code<br><input name="bank_branch" '
        f'value="{v("bank_branch")}" placeholder="470010" '
        f'style="width:100%"></label>'
        f'</div>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Save billing contact</button></div>'
        f'</form></div>')


def _parse_regions_text(text: str) -> list:
    """One region per line, "Name|https://url" — the textarea format
    _regions_box's form submits and _post_superadmin_regions parses.
    Blank lines are ignored; a line missing "|" or a http(s) URL is
    dropped rather than saved half-broken (see the caller for surfacing
    that as an error instead of silently losing it)."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        name, sep, url = line.partition("|")
        name, url = name.strip(), url.strip().rstrip("/")
        if sep and name and (url.startswith("http://") or url.startswith("https://")):
            out.append({"name": name, "url": url})
    return out


def _regions_box(regions, csrf) -> str:
    """Superadmin setting: other independent mikromon deployments (each a
    separate, self-contained install) a visitor can choose between on
    signup/login — e.g. one per geographic region, for latency. Each
    regional server is set up exactly like this one (deploy/install.sh);
    this list is ONLY what powers the "choose your region" picker, it
    doesn't connect the servers to each other in any other way — every
    region keeps its own companies/billing/users entirely independently."""
    text = "\n".join(f'{r.get("name", "")}|{r.get("url", "")}' for r in regions)
    return (
        f'<div class="box"><h2>Regions</h2>'
        f'<p class="muted">Other independent mikromon servers a visitor can '
        f'choose between on the sign-up/sign-in pages — e.g. one server per '
        f'geographic region, for latency. Each is a fully separate install '
        f'(own companies, billing, users) set up the normal way '
        f'(<code>deploy/install.sh</code>) — this list only powers the '
        f'picker, it doesn\'t link the servers together otherwise. Leave '
        f'empty for a single-region install (no picker shown). One per '
        f'line: <code>Name|https://url</code></p>'
        f'<form method="POST" action="/superadmin/regions">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<textarea name="regions" rows="4" style="width:100%;'
        f'font-family:ui-monospace,monospace" '
        f'placeholder="South Africa|https://sa.easymikrotik.com&#10;'
        f'USA|https://us.easymikrotik.com">{esc(text)}</textarea>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Save regions</button></div>'
        f'</form></div>')


def _nextdns_settings_box(nextdns, csrf) -> str:
    """Superadmin setting: the platform's NextDNS.io API key, used to
    auto-create a separate NextDNS profile per router (each company's
    routers get their own blocklists/allowlists/query-logs, not one shared
    globally) — see mikromon/nextdns.py. The optional template profile id
    is an existing NextDNS profile whose settings new profiles are cloned
    from, so routers don't start from a blank NextDNS config."""
    n = nextdns or {}
    has_key = "•••••• (saved)" if n.get("api_key") else ""
    return (
        f'<div class="box"><h2>NextDNS</h2>'
        f'<p class="muted">Lets any router\'s "NextDNS" tab give itself its '
        f'own NextDNS.io profile with one click. Get an API key from '
        f'<a href="https://my.nextdns.io/account" target="_blank" '
        f'rel="noopener">your NextDNS account settings</a>. Leave empty to '
        f'keep the NextDNS tab hidden/unavailable for everyone.</p>'
        f'<form method="POST" action="/superadmin/nextdns">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,'
        f'minmax(220px,1fr));gap:10px">'
        f'<label>API key<br><input name="api_key" type="password" '
        f'placeholder="{has_key or "NextDNS API key"}" style="width:100%">'
        f'</label>'
        f'<label>Template profile id (optional)<br>'
        f'<input name="template_profile" '
        f'value="{esc(n.get("template_profile", ""))}" '
        f'placeholder="e.g. abc123" style="width:100%"></label>'
        f'</div>'
        f'<p class="muted" style="font-size:12px;margin:6px 0 0">Template: '
        f'an existing profile\'s blocklists/security/privacy settings to '
        f'clone into every new router\'s profile, instead of starting '
        f'blank. Find its id in the profile\'s NextDNS dashboard URL.</p>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Save NextDNS settings</button></div>'
        f'</form></div>')


def _render_region_picker(regions, go: str, this_url: str = "",
                          this_name: str = "This server") -> str:
    """Public "choose your region" page — linked from the signup/login
    pages (and the marketing landing page) whenever 2+ regions are
    configured. `go` is "signup" or "login": which page each region link
    ultimately lands on. Includes THIS server itself as one of the
    options (so clicking it just proceeds locally, no redirect loop to
    reason about) alongside every other configured region."""
    go = go if go in ("signup", "login") else "signup"
    rows = ""
    if this_url:
        rows += (f'<a class="btn" style="display:block;margin-bottom:8px" '
                 f'href="/{go}">{esc(this_name)} (this server)</a>')
    for r in regions:
        url = str(r.get("url", "")).rstrip("/")
        name = r.get("name") or url
        if not url:
            continue
        rows += (f'<a class="btn ghost" style="display:block;margin-bottom:8px" '
                 f'href="{esc(url)}/{go}">{esc(name)}</a>')
    if not rows:
        rows = f'<a class="btn" href="/{go}">Continue</a>'
    return _auth_page("Choose your region",
            f'<h2 style="margin-top:0">Choose your region</h2>'
            f'<p class="muted" style="margin-top:0">Pick whichever server is '
            f'closest to your routers for the best performance.</p>'
            f'{rows}')


def _hub_endpoint_box(hub_ip, hub_port, router_count, csrf,
                      hub_pubkey_current="") -> str:
    """Superadmin setting: the address every router dials home to. Lets you
    migrate the hub to a new server (or switch to a DDNS hostname) without
    re-provisioning every router by hand — saves the new default for
    future provisions, and can optionally push it out to every already-
    registered router right now. The optional "new public key" field is
    for a full identity migration (the new server generated its own fresh
    keypair rather than the old server's private key ever being copied
    between hosts by hand) — leave it blank for an address-only change on
    the SAME hub identity, e.g. adopting a DDNS hostname. Also displays
    THIS server's own public key read-only, so migrating TO this server
    is a copy-paste from here into the OLD server's "New hub public key"
    field — no SSH needed for that step either."""
    this_key = (
        f'<p class="muted" style="margin-top:10px">This server\'s own hub '
        f'public key (copy this into the OLD server\'s "New hub public '
        f'key" field when migrating TO this server):<br>'
        f'<code style="word-break:break-all">{esc(hub_pubkey_current)}</code></p>'
        if hub_pubkey_current else "")
    return (
        f'<div class="box"><h2>Hub endpoint</h2>'
        f'<p class="muted">The address every router dials home to (its '
        f'own WireGuard peer entry for this server). Changing this alone '
        f'only affects NEW provisions — tick "push to every router now" '
        f'to also update the {router_count} already-registered router(s), '
        f'so a server move or a switch to a DDNS hostname doesn\'t need '
        f're-provisioning anything.</p>'
        f'{this_key}'
        f'<form method="POST" action="/superadmin/hub-endpoint">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">'
        f'<label>Hostname or IP<br><input name="hub_ip" value="{esc(hub_ip)}" '
        f'placeholder="hub.yourdomain.com" style="width:100%"></label>'
        f'<label>Port<br><input name="hub_port" value="{esc(hub_port)}" '
        f'placeholder="51820" style="width:100%"></label>'
        f'</div>'
        f'<label style="display:block;margin-top:10px">New hub public key '
        f'<span class="muted">(only for a full server migration to a hub '
        f'with a DIFFERENT identity — leave blank otherwise)</span><br>'
        f'<input name="hub_pubkey" '
        f'placeholder="paste the new server\'s WireGuard public key here — only if it changed" '
        f'style="width:100%;font-family:ui-monospace,monospace"></label>'
        f'<label class="chk" style="display:block;margin-top:8px">'
        f'<input type="checkbox" name="push_now" value="1"> Push to every '
        f'already-registered router now (best-effort — an unreachable '
        f'router is skipped, not blocking; save again later to retry it)'
        f'</label>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Save</button></div>'
        f'</form></div>')


def _quote_inbox(quotes, org_names: dict | None = None, csrf: str = "") -> str:
    """Open quote requests from companies past the last packet.

    These are people who have said they want to pay more, so a request going
    unnoticed is the most expensive kind of silence on the platform. It sits
    at the top of the panel while open, and disappears once marked handled
    rather than piling up as permanent noise.
    """
    if not quotes:
        return ""
    org_names = org_names or {}
    rows = ""
    for q in quotes:
        when = time.strftime("%d %b %Y %H:%M", time.localtime(q.get("created") or 0))
        who = org_names.get(q.get("org_id")) or f'org {q.get("org_id")}'
        note = str(q.get("note") or "").strip()
        rows += (
            f'<tr><td><b>{esc(str(who))}</b><br>'
            f'<span class="muted" style="font-size:11px">{esc(when)}</span></td>'
            f'<td><b>{int(q.get("devices") or 0)}</b> devices</td>'
            f'<td>{esc(str(q.get("contact") or "")) or "<span class='muted'>—</span>"}</td>'
            f'<td style="max-width:340px">{esc(note) if note else "<span class='muted'>—</span>"}</td>'
            f'<td><form method="POST" action="/superadmin/quote-handled">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="id" value="{int(q.get("id") or 0)}">'
            f'<button class="btn ghost" type="submit" '
            f'style="padding:5px 12px">Mark handled</button></form></td></tr>')
    n = len(quotes)
    return (f'<div class="box" style="border-color:#2563eb">'
            f'<h2>Quote requests '
            f'<span class="badge" style="background:#2563eb;color:#fff">{n}</span>'
            f'</h2>'
            f'<p class="muted" style="margin-top:0">Companies that need more '
            f'than {QUOTE_ABOVE_DEVICES} devices and asked to be contacted. '
            f'Reach out, agree a price, then assign a cap with '
            f'<b>Unlimited</b> or a custom limit below.</p>'
            f'<table><thead><tr><th>Company</th><th>Needs</th>'
            f'<th>Contact</th><th>Notes</th><th></th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')


def _render_superadmin(user, rows: list, backups: list, csrf: str = "",
                       msg: str = "", error: str = "", smtp=None,
                       billing_on: bool = False, billing_contact=None,
                       hub_ip: str = "", hub_port: str = "",
                       router_count: int = 0, hub_pubkey: str = "",
                       regions=None, nextdns=None, quotes=None) -> str:
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
        active_count = r.get("active_count", device_count)
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
            f'{r.get("user_count",0)} user(s)</span>'
            # The reference this company was told to quote on an EFT. Shown
            # here so a bank statement line can be traced back to an account
            # by eye, which is the whole point of issuing one.
            f'<br><code style="font-size:11px">'
            f'{esc(payment_reference(r["id"], r.get("name", "")))}</code></td>'
            f'<td><span style="color:{color};font-weight:700">{label}</span>'
            f'{f"<br><span class=\'muted\' style=\'font-size:11px\'>trial ends {trial_str}</span>" if trial_str else ""}'
            f'{f"<br><span class=\'muted\' style=\'font-size:11px;color:#d97706\'>grace ends {grace_str}</span>" if grace_str else ""}'
            f'</td>'
            f'<td>{esc(plan) if plan else "<span class=\'muted\'>—</span>"}</td>'
            f'<td>{active_count}'
            f'{"" if active_count == device_count else f" <span class=\"muted\" style=\"font-size:11px\">({device_count} total)</span>"}'
            f' / {device_limit if device_limit else "∞"}</td>'
            f'<td>{created_str}</td>'
            + (f'<td>{_plan_select(r.get("id"), plan, csrf)}</td>'
               if billing_on else "")
            + '</tr>'
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
        '<div class="box" style="overflow-x:auto">'
        '<table style="min-width:700px"><thead><tr>'
        '<th>Company<br><span class="muted" style="font-weight:400;'
        'font-size:10px">with its EFT reference</span></th>'
        '<th>Status</th><th>Plan</th>'
        '<th>Devices</th><th>Joined</th>'
        + ("<th>Assign plan</th>" if billing_on else "")
        + f'</tr></thead><tbody>{tbody or "<tr><td colspan=6 class=muted>No organisations yet.</td></tr>"}'
        f'</tbody></table></div>'
    )

    def _post(action, label, cls="btn ghost", extra="", confirm=""):
        oc = f' onclick="return confirm(\'{confirm}\')"' if confirm else ""
        return (f'<form method="POST" action="{action}" style="display:inline">'
                f'<input type="hidden" name="csrf" value="{esc(csrf)}">{extra}'
                f'<button class="{cls}" type="submit"{oc}>{label}</button></form>')

    backup_rows = ""
    for b in backups:
        when = time.strftime("%d %b %Y %H:%M", time.localtime(b["mtime"]))
        name_q = esc(b["name"])
        backup_rows += (
            f'<tr><td><code>{name_q}</code></td>'
            f'<td>{esc(human_bytes(b["size"]))}</td>'
            f'<td class="muted">{when}</td>'
            f'<td style="white-space:nowrap">'
            f'<a class="btn ghost" href="/superadmin/backup/download?name={name_q}">'
            f'Download</a> '
            + _post("/superadmin/backup/restore", "Restore",
                    extra=f'<input type="hidden" name="name" value="{name_q}">',
                    confirm=f"Restore {b['name']}? This OVERWRITES every "
                            f"company's current data on this server with what "
                            f"was in this backup. You must restart the service "
                            f"afterward for it to take effect. Continue?")
            + " "
            + _post("/superadmin/backup/delete", "Delete",
                    extra=f'<input type="hidden" name="name" value="{name_q}">',
                    confirm=f"Delete backup {b['name']}? This cannot be undone.")
            + '</td></tr>')

    _no_backups = '<tr><td colspan=4 class="muted">No backups yet — create one below.</td></tr>'
    backup_table = (
        f'<table style="min-width:600px"><thead><tr>'
        f'<th>Backup</th><th>Size</th><th>Created</th><th></th>'
        f'</tr></thead><tbody>{backup_rows or _no_backups}</tbody></table>'
    )

    backup_box = (
        f'<div class="box"><h2>Server backup</h2>'
        f'<p class="muted">Bundles config, every company\'s accounts/devices/'
        f'billing/metrics, and the tunnel-IP registry into one archive — for '
        f'moving this install to a new server.</p>'
        f'<p class="muted" style="border-left:3px solid #d97706;padding-left:8px">'
        f'⚠ This does <b>not</b> include the hub\'s WireGuard identity '
        f'(<code>/etc/wireguard/</code> on this server) — copy that '
        f'separately (as root) so already-provisioned routers keep dialing '
        f'home without changes. Full restore steps: '
        f'<code>deploy/SERVER-MIGRATION.md</code>.</p>'
        f'<div style="overflow-x:auto">{backup_table}</div>'
        f'<div style="margin-top:12px">'
        + _post("/superadmin/backup/create", "Create new backup", cls="btn")
        + '</div>'
        f'<h3 style="margin:20px 0 8px">Restore from a file</h3>'
        f'<p class="muted" style="margin-top:0">Upload a backup archive '
        f'downloaded from this or another mikromon server.</p>'
        f'<form method="POST" action="/superadmin/backup/restore-upload" '
        f'enctype="multipart/form-data" '
        f'onsubmit="return confirm(\'Restore from this file? This OVERWRITES '
        f'every company\\\'s current data on this server. You must restart '
        f'the service afterward for it to take effect. Continue?\')">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="file" name="archive" accept=".gz,.tar.gz" required> '
        f'<button class="btn ghost" type="submit">Restore uploaded file</button>'
        f'</form>'
        f'</div>'
    )

    diagnostics_box = (
        '<div class="box"><h2>Diagnostics report</h2>'
        '<p class="muted">A plain-text dump of every device\'s live '
        'monitoring state across every company — enabled checks, cached '
        'facts, the latest reachability sample, and the full conditions '
        'list. Download this and share it when troubleshooting an alert '
        'that isn\'t showing up, without needing to SSH into the server.</p>'
        '<a class="btn" href="/superadmin/diagnostics/download">'
        'Download diagnostics report</a>'
        '</div>'
    )

    # Above the org table: a company asking to spend more is the one thing on
    # this page that goes stale if it is not seen today.
    quote_html = _quote_inbox(
        quotes or [], {r["id"]: r.get("name", "") for r in rows}, csrf)

    inner = (f'<div class="wrap"><h1>Platform admin</h1>{note}{tiles}'
             f'{quote_html}{table}'
             f'{_smtp_settings_box(smtp, csrf)}'
             f'{_billing_contact_box(billing_contact, csrf)}'
             f'{_hub_endpoint_box(hub_ip, hub_port, router_count, csrf, hub_pubkey)}'
             f'{_regions_box(regions or [], csrf)}'
             f'{_nextdns_settings_box(nextdns or {}, csrf)}'
             f'{diagnostics_box}{backup_box}</div>')
    return _page("Platform Admin", _header(user, "/superadmin") + inner)


def _guide_section(anchor: str, title: str, body: str) -> str:
    return (f'<div class="box" id="{anchor}"><h2 style="margin-top:0">{title}</h2>'
            f'{body}</div>')


def _render_guide(user, tab_intro: dict) -> str:
    """A plain-language walkthrough of every tab and a glossary of the
    networking terms used throughout the dashboard — for someone who isn't
    sure what a setting does or what a term means, without having to ask
    or guess. Static content; doesn't touch the database. `tab_intro` is
    web.py's _TAB_INTRO (passed in rather than imported, to avoid a
    circular import — web.py imports render functions from this module)."""
    toc_items = [
        ("overview", "What this dashboard does"),
        ("dashboard", "The Dashboard"),
        ("devices", "Devices, ownership &amp; team access"),
        ("provision", "Adding a new router (Provision)"),
        ("tabs", "What each device tab does"),
        ("vpn", "VPN — connecting sites together"),
        ("safety", "Backups, Preview/Apply &amp; Safe mode"),
        ("devicemode", "“Device Mode” errors"),
        ("billing", "Trials, plans &amp; billing"),
        ("activity", "Activity log"),
        ("glossary", "Glossary — what do these words mean?"),
    ]
    toc = ("<div class=\"box\"><h2 style=\"margin-top:0\">Contents</h2>"
           "<ul style=\"columns:2;column-gap:24px;margin:0;padding-left:20px\">"
           + "".join(f'<li style="margin-bottom:6px"><a href="#{a}">{t}</a></li>'
                     for a, t in toc_items)
           + "</ul></div>")

    overview = _guide_section("overview", "What this dashboard does", (
        '<p>This dashboard monitors and configures MikroTik routers — yours '
        'or your clients\' — from one place, without needing Winbox open on '
        'every site. It polls each router to show whether it\'s online and '
        'what its internet lines are doing, and it can push configuration '
        'changes (firewall, WAN failover, VPN, port forwarding, and more) '
        'to a router the same way you would by hand, just from a web page '
        'instead of the router\'s own tools.</p>'
        '<p>Every change is <b>previewed before it\'s applied</b> — you see '
        'exactly what would change on the router before anything actually '
        'happens, and a backup is taken automatically first. See '
        '<a href="#safety">Backups, Preview/Apply &amp; Safe mode</a>.</p>'))

    dashboard = _guide_section("dashboard", "The Dashboard", (
        '<p>The Dashboard lists every router you manage with its current '
        'status: <b>online/offline</b>, and any active <b>problems</b> '
        '(a WAN line down, high latency, a device that stopped checking in, '
        'etc). Click a router to open its own page, where every '
        'configuration tab for that specific router lives.</p>'
        '<p>A "problem" clears itself automatically once the underlying '
        'condition is fixed — there\'s nothing to manually dismiss.</p>'))

    devices = _guide_section("devices", "Devices, ownership &amp; team access", (
        '<p>The <b>Devices</b> tab (company owners only) is where routers '
        'are added, renamed or removed, and where you see every router '
        'that belongs to your company.</p>'
        '<p>Two account roles:</p>'
        '<ul>'
        '<li><b>Owner</b> — full control of every router in the company, '
        'plus Team, Billing and the Devices inventory.</li>'
        '<li><b>Member</b> — can only see and manage the specific routers '
        'an owner has allocated to them (Team page), and never sees the '
        'Devices inventory or Billing.</li>'
        '</ul>'
        '<p>Every router belongs to exactly one company. Nobody outside '
        'that company — not even another paying customer — can see it, '
        'connect to it, or add it to a VPN group with theirs.</p>'))

    provision = _guide_section("provision", "Adding a new router (Provision)", (
        '<p>The <b>Provision</b> tab generates a small script you paste '
        'into the router\'s own terminal (via Winbox/SSH) once, by hand. '
        'It creates a dedicated API user this dashboard uses from then on — '
        'your normal admin login is never stored here. It also sets up the '
        'router as a WireGuard peer of this dashboard\'s server (the '
        '<b>hub</b> — see the <a href="#vpn">VPN section</a>) so it can be '
        'reached even behind CGNAT/a home internet connection with no '
        'public IP, and enables Safe mode\'s self-check path.</p>'
        '<p>You only ever do this once per router. After that, every tab '
        'works purely from the dashboard.</p>'))

    tab_rows = [
        ("Routes — Gateway Failover", tab_intro.get("routes", "")),
        ("WAN — policy routing", tab_intro.get("wan", "")),
        ("Security", tab_intro.get("security", "")),
        ("Restrict management access", tab_intro.get("harden", "")),
        ("DNS", tab_intro.get("nextdns", "")),
        ("Queues (QoS)", tab_intro.get("qos", "")),
        ("Port forwarding", tab_intro.get("portfwd", "")),
        ("Interfaces", tab_intro.get("interfaces", "")),
        ("Remote access", tab_intro.get("remote", "")),
        ("Custom scripts", tab_intro.get("scripts", "")),
        ("Update RouterOS", tab_intro.get("update", "")),
    ]
    tabs_table = "".join(
        f'<tr><td style="white-space:nowrap;vertical-align:top"><b>{esc(name)}</b></td>'
        f'<td>{esc(desc)}</td></tr>'
        for name, desc in tab_rows if desc)
    tabs = _guide_section("tabs", "What each device tab does", (
        '<p>Open a router from the Dashboard to see its tabs. Every tab '
        'follows the same pattern: change something, click <b>Preview</b> '
        'to see exactly what would be sent to the router, then '
        '<b>Apply</b> to actually push it.</p>'
        f'<table><tr><th>Tab</th><th>What it\'s for</th></tr>{tabs_table}</table>'
        '<p class="muted" style="margin-top:10px">The VPN tab and the '
        'Backups tab work a little differently — see the sections below.</p>'))

    vpn = _guide_section("vpn", "VPN — connecting sites together", (
        '<p>This dashboard\'s server runs its own always-on WireGuard '
        'VPN — the <b>hub</b>. Every provisioned router dials home to it, '
        'which is also how the dashboard reaches routers with no public IP '
        '(CGNAT, mobile data, etc). This tunnel is what Remote access, '
        'the self-repair check, and the VPN tab all run over — there is '
        'no separate VPN product involved, it\'s all the same tunnel.</p>'
        '<h3>Personal VPN access — using Remote access from your own computer</h3>'
        '<p>Remote access shows a "Connect to" address that\'s the '
        'router\'s address <i>on this tunnel</i> — it only works if the '
        'computer running Winbox/SSH is itself connected to the same '
        'tunnel. If it isn\'t, Winbox won\'t show an error, it\'ll just '
        'hang on "Connecting…" forever (there\'s no route to that address '
        'from an ordinary computer, so nothing ever answers). The Team '
        'page\'s <b>Personal VPN access</b> box fixes this: it issues you '
        '(or a teammate) a WireGuard config — import it into the '
        'WireGuard app and your computer becomes a peer of the same '
        'tunnel every router uses, so those addresses become reachable. '
        'It only ever reaches your own company\'s routers and their '
        'linked VPN-group networks, never another company\'s.</p>'
        '<h3>Site-to-site: Main host &amp; sub-units</h3>'
        '<p>To let two (or more) of your sites reach each other\'s local '
        'network — e.g. so a computer at Site A can reach a printer or '
        'server at Site B — open the VPN tab on one router and click '
        '<b>"Make this the main VPN host."</b> Then, still on that same '
        'router\'s VPN tab, pick another one of your routers from the '
        'dropdown and click <b>"Add sub-unit."</b> The dashboard connects '
        'to that router live, detects its own local network automatically '
        '(no typing in IP ranges), and links the two. Routes are pushed to '
        'every affected router automatically the moment you add or remove '
        'a sub-unit — there\'s nothing further to apply by hand.</p>'
        '<p>A router that\'s already the main host of a group, or already '
        'a sub-unit of one, can\'t be reconfigured until it\'s removed from '
        'that group first (from the main host\'s VPN tab).</p>'
        '<p><b>What this does and doesn\'t do:</b> it links whole local '
        'networks together — devices on both sides can reach each other, '
        'and the routes plus the firewall rule that lets that traffic '
        'through the tunnel are both pushed automatically, no manual '
        'firewall work needed. It does not share internet access between '
        'sites, and it routes through this '
        'dashboard\'s hub rather than a direct tunnel between the two '
        'routers, so if the hub is down, cross-site traffic pauses (each '
        'site\'s own local network and internet keep working normally).</p>'))

    safety = _guide_section("safety", "Backups, Preview/Apply &amp; Safe mode", (
        '<p><b>Preview, then Apply.</b> Every change you make on a tab is a '
        'two-step process: Preview shows exactly what would be added, '
        'changed or removed on the router — nothing happens to the router '
        'yet. Apply actually sends it.</p>'
        '<p><b>Automatic backup.</b> Right before Apply commits anything, '
        'the dashboard takes a full snapshot of the router\'s configuration '
        'and stores it on the Backups tab, so you can restore to exactly '
        'how it was before if something goes wrong.</p>'
        '<p><b>Safe mode.</b> For changes that could cut off access to the '
        'router itself (e.g. firewall or WAN changes), you can tick '
        '"Safe mode" before applying. The router checks, a few minutes '
        'later, that it can still reach the dashboard\'s hub — if it can\'t '
        '(because the change locked everyone out), it automatically '
        'reverts itself back to the backup taken just before. You don\'t '
        'have to guess whether a change is risky.</p>'))

    devicemode = _guide_section("devicemode", "“Device Mode” errors", (
        '<p>Some newer MikroTik routers ship with a security feature '
        'called <b>Device Mode</b>, which blocks anything — including this '
        'dashboard — from remotely adding scheduled tasks or scripts '
        'unless someone has physically confirmed it at the router (a '
        'button press or a power-cycle, depending on the model). MikroTik '
        'added this after real-world attacks used remotely-added scheduler '
        'entries as a backdoor.</p>'
        '<p>If a tab reports this error, it means that specific change '
        'needs a one-time physical confirmation at the router before it '
        'can go through — the error message on the page spells out the '
        'exact steps for your router\'s hardware. There\'s no remote way '
        'around this by design, and there shouldn\'t be — an attacker who '
        'ever obtained your login should not also be able to bypass it.</p>'))

    billing = _guide_section("billing", "Trials, plans &amp; billing", (
        f'<p>A brand-new company gets a <b>{TRIAL_DEVICES}-device free '
        f'trial for {_TRIAL_DAYS} days</b>, no card required, to try things '
        f'out. After the trial (or a subscription) lapses, there\'s a '
        f'{GRACE_DAYS}-day grace period — you\'ll see a banner and can '
        f'still use everything — before the account is suspended.</p>'
        '<p>If a "who to contact" address has been set up for this server, '
        'it\'s shown on that banner and on the suspended page once it '
        'gets there, so you know exactly who to email to arrange payment '
        'and get switched back on.</p>'
        f'<p>Without an active plan, a company is capped at '
        f'{FREE_DEVICES} devices. Paid plans raise that cap — see the '
        f'Billing page (company owners) for current plan sizes and '
        f'pricing.</p>'))

    activity = _guide_section("activity", "Activity log", (
        '<p>The <b>Activity</b> tab (owners) is a timeline of every '
        'preview, apply, and result for every router in your company — '
        'who did what, when, and whether it succeeded. Use it to check '
        'what changed recently, or to see exactly why an applied change '
        'failed.</p>'))

    glossary_terms = [
        ("WAN", "The internet-facing side of a router — the line(s) that "
                "go out to your ISP. A router can have more than one "
                "(e.g. a fibre line and a backup LTE/PPPoE line)."),
        ("LAN", "The local network side — the devices, computers and "
                "Wi-Fi clients behind the router, on its own private "
                "network."),
        ("Gateway", "The next device a packet is sent to on its way "
                "somewhere else — usually your ISP's equipment for WAN "
                "traffic. \"Setting a gateway\" means telling the router "
                "who to hand off traffic to."),
        ("Subnet / CIDR", "A block of IP addresses written like "
                "192.168.1.0/24 — the network a device lives on. Two "
                "sites being linked over VPN must use different, "
                "non-overlapping subnets, or devices on each side "
                "would have clashing addresses."),
        ("DHCP", "The way most internet lines (and most home/office "
                "networks) hand out an IP address and gateway "
                "automatically, with nothing to type in by hand."),
        ("PPPoE / “dial-up”", "A connection type common on "
                "fibre and DSL lines, where the router \"dials\" the "
                "ISP with a username/password to get online (similar in "
                "spirit to old dial-up internet, hence the nickname) "
                "instead of just receiving an address over DHCP."),
        ("NAT", "Network Address Translation — lets many devices on a "
                "LAN share one public WAN IP address to reach the "
                "internet."),
        ("CGNAT", "Carrier-Grade NAT — your ISP sharing one public IP "
                "across many customers. If your WAN address looks like "
                "100.64.x.x–100.127.x.x, that's CGNAT, not a real public "
                "IP — it's why routers behind it can't normally be "
                "reached directly from the internet, and why this "
                "dashboard's WireGuard hub (see the VPN section) is used "
                "to reach them instead."),
        ("VPN", "Virtual Private Network — an encrypted tunnel that "
                "makes two networks (or a device and a network) behave "
                "as if they were directly connected, wherever they "
                "actually are."),
        ("WireGuard", "The specific, modern VPN technology this "
                "dashboard uses for its hub-and-spoke tunnel to every "
                "router."),
        ("Firewall", "Rules on the router that decide what traffic is "
                "allowed in, out, or through it."),
        ("QoS", "Quality of Service — capping or prioritizing how much "
                "bandwidth a device or network is allowed to use, so one "
                "user or app can't saturate the whole line."),
        ("Failover", "Automatically switching to a backup internet line "
                "if the primary one goes down, then switching back once "
                "it recovers."),
        ("Device Mode", "A MikroTik security feature — see the "
                "dedicated section above."),
        ("Safe mode", "This dashboard's own auto-revert safety net for "
                "risky changes — see the section above."),
        ("Hub", "This dashboard's own WireGuard server that every "
                "router dials home to."),
    ]
    if user.get("is_superadmin"):
        # Platform-internal concept — only relevant (and only ever visible)
        # to whoever manages the server itself, not every company's users.
        glossary_terms.append(
            ("Superadmin", "The platform-level account (not tied to any "
                    "one company) that manages billing, backups and "
                    "server-wide settings for every company on this "
                    "install."))
    glossary_rows = "".join(
        f'<tr><td style="white-space:nowrap;vertical-align:top"><b>{esc(term)}</b></td>'
        f'<td>{esc(defn)}</td></tr>'
        for term, defn in glossary_terms)
    glossary = _guide_section("glossary", "Glossary — what do these words mean?", (
        '<p class="muted" style="margin-top:0">Not sure what a term on one '
        'of the tabs means? Look it up here, or search for it online — '
        'these are all standard networking terms, not anything specific '
        'to this dashboard, so there\'s plenty written about each one.</p>'
        f'<table><tr><th>Term</th><th>Meaning</th></tr>{glossary_rows}</table>'))

    inner = (f'<div class="wrap"><h1>Guide</h1>'
             f'<p class="muted" style="margin-top:-8px">A plain-language '
             f'walkthrough of what everything on this dashboard does, and a '
             f'glossary of the networking terms it uses.</p>'
             f'{toc}{overview}{dashboard}{devices}{provision}{tabs}{vpn}'
             f'{safety}{devicemode}{billing}{activity}{glossary}</div>')
    return _page("Guide", _header(user, "/guide") + inner)


def _sa_tile(value, label: str, color: str) -> str:
    return (f'<div style="background:#fff;border-radius:10px;padding:12px 16px;'
            f'box-shadow:0 1px 3px rgba(0,0,0,.1);border-top:3px solid {color}">'
            f'<div style="font-size:26px;font-weight:700;color:{color}">{value}</div>'
            f'<div style="font-size:11px;color:#64748b;text-transform:uppercase;'
            f'letter-spacing:.04em;margin-top:4px">{label}</div>'
            f'</div>')
