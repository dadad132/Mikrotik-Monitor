"""Auth, account, and team-admin page renders for the web dashboard.

Extracted from web.py to keep that file manageable. Imports shared constants
and helpers from web_shared; web.py imports the render functions from here.
"""
from __future__ import annotations

from .auth import AuthStore
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
            f'<p><input name="password" type="password" '
            f'placeholder="Password (min 6 characters)" style="width:100%"></p>'
            f'<button class="btn" type="submit" style="width:100%">'
            f'Create account</button></form>'
            f'<p class="muted" style="margin:14px 0 0;text-align:center">'
            f'Already have an account? <a href="/login">Sign in</a></p>')


def _render_account(user, csrf: str, msg: str = "", error: str = "") -> str:
    note = (f'<p style="color:#16a34a">{esc(msg)}</p>' if msg else "") + \
           (f'<p style="color:#dc2626">{esc(error)}</p>' if error else "")
    org = user.get("org_name", "")
    uname_row = (f'<p>Username <span class="muted">(your existing login — you can '
                 f'keep using it)</span><br><input value="{esc(user["username"])}" '
                 f'disabled style="width:100%;max-width:360px;background:#f1f5f9">'
                 f'</p>') if user.get("username") else ""
    email_hint = ("Add an email to sign in with it too"
                  if user.get("username") and not user.get("email")
                  else "Used to sign in")
    inner = (
        f'<div class="wrap"><h1>My account</h1>{note}'
        f'<div class="box"><p class="muted" style="margin-top:0">'
        f'Company: <b>{esc(org)}</b> &middot; Role: <b>{esc(user["role"])}</b></p>'
        f'<form method="POST" action="/account">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'{uname_row}'
        f'<p>Email <span class="muted">({email_hint})</span><br>'
        f'<input name="email" type="email" value="{esc(user.get("email") or "")}" '
        f'style="width:100%;max-width:360px"></p>'
        f'<p>New password <span class="muted">(leave blank to keep current)</span>'
        f'<br><input name="password" type="password" placeholder="min 6 characters" '
        f'style="width:100%;max-width:360px"></p>'
        f'<button class="btn" type="submit">Save changes</button>'
        f'</form></div></div>')
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


def _render_admin(auth: AuthStore, known_devices, csrf: str, user) -> str:
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
    inner = (
        f'<div class="wrap"><h1>Team &mdash; {esc(user.get("org_name", ""))}</h1>'
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
        f'</form></div></div>')
    return _page("Team", _header(user, "/admin") + inner + _ADMIN_JS)
