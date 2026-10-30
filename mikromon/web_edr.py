"""The Antivirus page: what the agents on customers' PCs reported, who is
emailed about it, and each company's agent key.

Rendering only. The events, PCs and keys come from edr.py; this module never
decides anything.
"""
from __future__ import annotations

import time
from urllib.parse import quote

from .edr import (EMAIL_FAILED, EMAIL_GAP, EMAIL_HELD, EMAIL_SENT,
                  EMAILS_PER_HOUR, SOURCES, label)
from .util import human_duration
from .web_shared import _flash, _header, _page, confirm_attr, esc

# The agent says it is alive every 15 minutes. Two missed is a PC that is
# off, or an agent that is not running -- worth showing, not worth an email:
# office PCs go off every evening.
_QUIET_AFTER = 40 * 60

_SEV_STYLE = {
    "HIGH": "background:var(--danger-bg);color:var(--danger-text)",
    "MEDIUM": "background:var(--warning-bg);color:var(--warning-text)",
    "LOW": "background:var(--surface-2);color:var(--text-faint)",
}
_EMAILED = {
    EMAIL_SENT: "Emailed",
    EMAIL_HELD: "Held (same PC within "
                f"{EMAIL_GAP // 60} min, or hourly cap)",
    EMAIL_FAILED: "Email failed",
}


def _sev(severity: str) -> str:
    return (f'<span class="pill" style="{_SEV_STYLE.get(severity, "")}">'
            f'{esc(severity)}</span>')


def _when(ts) -> str:
    return time.strftime("%d %b %H:%M", time.localtime(ts or 0))


def _post_button(action_value: str, org_id, csrf: str, text: str,
                 cls: str = "btn ghost", confirm: str = "") -> str:
    onclick = f' onclick="{confirm_attr(confirm)}"' if confirm else ""
    return (f'<form method="POST" action="/superadmin/antivirus/key" '
            f'style="display:inline">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="org_id" value="{int(org_id)}">'
            f'<input type="hidden" name="action" value="{action_value}">'
            f'<button class="{cls}" type="submit"{onclick}>{text}</button>'
            f'</form>')


def _recipients_box(saved: list, fallback: list, csrf: str) -> str:
    if saved:
        who = "Alerts are emailed to these addresses."
    elif fallback:
        who = ("None set, so alerts go to the platform admins: "
               + esc(", ".join(fallback)) + ".")
    else:
        who = ("None set, and no platform admin has an email address, so "
               "alerts are only listed below.")
    return (
        f'<div class="box"><h2>Who is told</h2>'
        f'<p class="muted" style="margin:0 0 10px">{who}</p>'
        f'<form method="POST" action="/superadmin/antivirus/recipients">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<label>Support team email addresses<br>'
        f'<input name="recipients" value="{esc(", ".join(saved))}" '
        f'placeholder="support@yourdomain.com, oncall@yourdomain.com" '
        f'style="width:100%"></label>'
        f'<div style="margin-top:10px"><button class="btn" type="submit">'
        f'Save</button></div></form>'
        f'<p class="muted" style="margin:12px 0 0">The first alert from a PC '
        f'is emailed straight away. More from the same PC within '
        f'{EMAIL_GAP // 60} minutes are listed below and counted into its '
        f'next email, unless they are more serious. At most '
        f'{EMAILS_PER_HOUR} emails per company per hour. Agents starting and '
        f'stopping, and packed programs (low), are listed but not '
        f'emailed.</p></div>')


def _keys_box(orgs: list, keys: dict, pcs_by_org: dict, csrf: str) -> str:
    rows = ""
    for o in orgs:
        oid = o["id"]
        k = keys.get(oid)
        pcs = pcs_by_org.get(oid, 0)
        if k:
            key_cell = (f'<code>{esc(k["hint"])}&hellip;</code><br>'
                        f'<span class="muted">made {_when(k["created"])}</span>')
            buttons = (
                _post_button("new", oid, csrf, "Make a new key",
                             confirm=f"Replace {o['name']}'s key? Its PCs stop "
                                     f"reporting until they are given the "
                                     f"new one.")
                + " "
                + _post_button("revoke", oid, csrf, "Remove key", "btn red",
                               confirm=f"Remove {o['name']}'s key? Its PCs "
                                       f"stop reporting."))
        else:
            key_cell = '<span class="muted">No key yet</span>'
            buttons = _post_button("new", oid, csrf, "Make a key", "btn")
        rows += (f'<tr><td><b>{esc(o["name"])}</b><br><span class="muted">'
                 f'{esc(o.get("owner_email", ""))}</span></td>'
                 f'<td>{key_cell}</td><td>{pcs}</td>'
                 f'<td style="white-space:nowrap">{buttons}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="4" class="muted">No companies yet.</td></tr>'
    return (
        f'<div class="box"><h2>Company keys</h2>'
        f'<p class="muted" style="margin:0 0 10px">A company&rsquo;s PCs '
        f'report with that company&rsquo;s key, so a key that leaks can only '
        f'ever speak for that company. The key is shown once, when it is '
        f'made, with the steps to install the agent.</p>'
        f'<div style="overflow-x:auto"><table style="min-width:560px">'
        f'<thead><tr><th>Company</th><th>Key</th><th>PCs</th><th><span class="sr-only">Actions</span></th></tr>'
        f'</thead><tbody>{rows}</tbody></table></div></div>')


def _threat_form(sha256: str, action: str, text: str, csrf: str,
                 cls: str = "btn ghost", confirm: str = "",
                 name: str = "") -> str:
    onclick = f' onclick="{confirm_attr(confirm)}"' if confirm else ""
    named = (f'<input type="hidden" name="name" value="{esc(name)}">'
             if name else "")
    return (f'<form method="POST" action="/superadmin/antivirus/threat" '
            f'style="display:inline">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="sha256" value="{esc(sha256)}">'
            f'<input type="hidden" name="action" value="{action}">{named}'
            f'<button class="{cls}" type="submit" style="padding:3px 9px;'
            f'font-size:12px"{onclick}>{text}</button></form>')


def _verdict_cell(sha256: str, entry: dict | None, csrf: str,
                  names: dict) -> str:
    """Where this file stands on the shared list, and the support team's
    buttons for it."""
    if entry is None or entry["verdict"] == "removed":
        state = '<span class="muted">Not on the list</span>'
    elif entry["verdict"] == "safe":
        state = ('<span class="pill" style="background:var(--surface-2)">'
                 'Marked safe</span>')
    elif entry["org_id"] is None:
        state = (f'<span class="pill" style="{_SEV_STYLE["HIGH"]}">Blocked '
                 f'on every PC</span>')
    else:
        state = (f'<span class="pill" style="{_SEV_STYLE["MEDIUM"]}">Blocked '
                 f'at {esc(names.get(entry["org_id"], "one company"))}'
                 f'</span>')
    buttons = []
    if entry is None or entry["verdict"] != "malicious" \
            or entry["org_id"] is not None:
        buttons.append(_threat_form(sha256, "block", "Block everywhere", csrf))
    if entry is None or entry["verdict"] != "safe":
        buttons.append(_threat_form(
            sha256, "safe", "Safe", csrf,
            confirm="Mark this file safe? Every PC stops flagging it, and "
                    "PCs that quarantined it put it back."))
    return state + "<br>" + " ".join(buttons)


def _events_box(events: list, names: dict, *, show_company: bool = True,
                show_email: bool = True, verdicts: dict | None = None,
                csrf: str = "") -> str:
    """`verdicts` (sha256 -> list entry) adds each file's place on the
    shared list and the Block / Safe buttons: the support team's page."""
    rows = ""
    for e in events:
        what = esc(label(e["event_type"]))
        if e.get("reason"):
            what += f'<br><span class="muted">{esc(e["reason"])}</span>'
        where = esc(e.get("target") or "")
        if e.get("action"):
            where += (f'<br><span class="muted">{esc(e["action"])}</span>')
        if verdicts is not None and e.get("sha256"):
            where += (f'<br><code class="muted" style="font-size:11px">'
                      f'{esc(e["sha256"][:16])}&hellip;</code><br>'
                      + _verdict_cell(e["sha256"], verdicts.get(e["sha256"]),
                                      csrf, names))
        emailed = _EMAILED.get(e.get("emailed"), "")
        if e.get("emailed") == EMAIL_FAILED:
            emailed = f'<span style="color:var(--danger-text)">{emailed}</span>'
        rows += (f'<tr><td style="white-space:nowrap">{_when(e["ts"])}</td>'
                 + (f'<td>{esc(names.get(e["org_id"], "?"))}</td>'
                    if show_company else "")
                 + f'<td>{esc(e.get("hostname") or e["agent_id"])}</td>'
                 f'<td>{what}</td>'
                 f'<td style="overflow-wrap:anywhere">{where}</td>'
                 f'<td>{_sev(e["severity"])}</td>'
                 + (f'<td class="muted">{emailed}</td>' if show_email else "")
                 + '</tr>')
    if not rows:
        rows = (f'<tr><td colspan="{5 + show_company + show_email}" '
                f'class="muted">Nothing reported yet.</td></tr>')
    return (
        f'<div class="box"><h2>Recent alerts</h2>'
        f'<div style="overflow-x:auto"><table style="min-width:820px">'
        f'<thead><tr><th>When</th>'
        + ('<th>Company</th>' if show_company else '')
        + '<th>PC</th><th>What</th><th>File or process</th><th>Severity</th>'
        + ('<th>Email</th>' if show_email else '')
        + f'</tr></thead><tbody>{rows}</tbody></table></div></div>')


def _isolation_cell(a: dict, iso: dict | None, csrf: str,
                    manage: bool) -> str:
    """Whether the PC is cut off at its router -- and, for the support team,
    the button that does it or undoes it."""
    pc = a.get("hostname") or a["agent_id"]
    if iso:
        cell = (f'<span class="pill" style="{_SEV_STYLE["HIGH"]}">Isolated'
                f'</span><br><span class="muted">on {esc(iso["device"])} '
                f'since {_when(iso["since"])}</span>')
        if manage:
            cell += (
                f'<form method="POST" action="/superadmin/antivirus/release" '
                f'style="margin-top:4px">'
                f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                f'<input type="hidden" name="org" value="{int(a["org_id"])}">'
                f'<input type="hidden" name="agent" value="{esc(a["agent_id"])}">'
                f'<button class="btn ghost" type="submit" style="padding:4px '
                f'10px;font-size:12px" onclick="'
                f'{confirm_attr(f"Let {pc} back on the network?")}">Release'
                f'</button></form>')
        return cell
    if manage:
        return (f'<a class="btn ghost" style="padding:4px 10px;font-size:12px" '
                f'href="/superadmin/antivirus/isolate?org={int(a["org_id"])}'
                f'&amp;agent={quote(str(a["agent_id"]), safe="")}">'
                f'Isolate&hellip;</a>')
    return '<span class="muted">&mdash;</span>'


def _agents_box(agents: list, names: dict, now: float, *,
                show_company: bool = True, isolations: dict | None = None,
                csrf: str = "", manage: bool = False) -> str:
    isolations = isolations or {}
    rows = ""
    for a in agents:
        age = max(0, now - (a.get("last_seen") or 0))
        if age > _QUIET_AFTER:
            seen = (f'<span style="color:var(--warning-text)">'
                    f'{human_duration(age)} ago</span>')
        else:
            seen = f'{human_duration(age)} ago'
        iso = isolations.get((a["org_id"], a["agent_id"]))
        rows += (f'<tr><td><b>{esc(a.get("hostname") or a["agent_id"])}</b>'
                 f'<br><span class="muted">{esc(a.get("os_user") or "")}'
                 f'</span></td>'
                 + (f'<td>{esc(names.get(a["org_id"], "?"))}</td>'
                    if show_company else "")
                 + f'<td>{esc(a.get("os") or "")}<br><span class="muted">'
                 f'{"agent " + esc(a["version"]) if a.get("version") else ""}'
                 f'</span></td>'
                 f'<td>{esc(a.get("local_ip") or "")}<br><span class="muted">'
                 f'{esc(a.get("mac") or "")}</span></td>'
                 f'<td>{esc(a.get("public_ip") or "")}</td>'
                 f'<td style="white-space:nowrap">{seen}</td>'
                 f'<td style="white-space:nowrap">'
                 f'{_isolation_cell(a, iso, csrf, manage)}</td></tr>')
    if not rows:
        rows = (f'<tr><td colspan="{6 + show_company}" class="muted">No PC '
                f'has reported yet.</td></tr>')
    return (
        f'<div class="box"><h2>PCs with the agent</h2>'
        f'<p class="muted" style="margin:0 0 10px">Each agent checks in every '
        f'15 minutes. One not heard from for over '
        f'{_QUIET_AFTER // 60} minutes is shown in amber: the PC is off, or '
        f'the agent is not running.</p>'
        f'<div style="overflow-x:auto"><table style="min-width:760px">'
        f'<thead><tr><th>PC</th>'
        + ('<th>Company</th>' if show_company else '')
        + '<th>System</th><th>Network</th><th>Internet</th>'
          '<th>Last heard from</th><th>Isolation</th></tr>'
        f'</thead><tbody>{rows}</tbody></table></div></div>')


def _threats_box(t: dict, names: dict, csrf: str) -> str:
    """The shared threat list: how much every PC knows, and the finds
    waiting for the support team to put them on every PC."""
    c = t.get("counts") or {}
    src = c.get("by_source") or {}
    parts = [f'{src.get(k, 0):,} {what}' for k, what in (
        ("agent", "found on PCs"), ("defender", "from Windows Defender"),
        ("feed", "from MalwareBazaar"), ("support", "added by the support "
                                                     "team"))]
    rows = ""
    for p in t.get("pending") or []:
        more = int(p.get("orgs") or 1) - 1
        others = (f' and {more} other compan{"y" if more == 1 else "ies"}'
                  if more > 0 else "")
        rows += (
            f'<tr><td><code style="font-size:12px">{esc(p["sha256"][:16])}'
            f'&hellip;</code><br><span class="muted">{esc(p["name"])}'
            f'</span></td><td>{esc(names.get(p["org_id"], "?"))}{others}<br>'
            f'<span class="muted">{esc(SOURCES.get(p["source"], ""))}, '
            f'{_when(p["first_seen"])}</span></td>'
            f'<td style="white-space:nowrap">'
            f'{_threat_form(p["sha256"], "block", "Block everywhere", csrf, "btn")} '
            f'{_threat_form(p["sha256"], "safe", "Safe", csrf, confirm="Mark this file safe? Every PC stops flagging it, and PCs that quarantined it put it back.")}'
            f'</td></tr>')
    pending = (
        f'<h3 style="margin:16px 0 6px">Waiting for a decision</h3>'
        f'<p class="muted" style="margin:0 0 8px;font-size:13px">Found by '
        f'companies&rsquo; own PCs, so blocked only on the PCs of the '
        f'companies that found them. Only <b>Block everywhere</b> puts one '
        f'on every PC: however many companies report a file, that is no '
        f'proof when anyone can sign up twice.</p>'
        f'<div style="overflow-x:auto"><table style="min-width:620px"><thead>'
        f'<tr><th>File</th><th>Found at</th><th><span class="sr-only">Actions</span></th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>') if rows else ""
    recent = ""
    for r in t.get("recent") or []:
        verdict = {"malicious": "blocked", "safe": "marked safe",
                   "removed": "taken off"}.get(r["verdict"], r["verdict"])
        scope = ("" if r["org_id"] is None or r["verdict"] != "malicious"
                 else f' at {esc(names.get(r["org_id"], "one company"))}')
        recent += (f'<li><code style="font-size:12px">{esc(r["sha256"][:16])}'
                   f'&hellip;</code> {esc(r["name"])} &mdash; {verdict}'
                   f'{scope}, {_when(r["updated"])}'
                   + (f' by {esc(r["by_user"])}' if r["by_user"] else "")
                   + '</li>')
    recent = (f'<h3 style="margin:16px 0 6px">Latest changes</h3>'
              f'<ul style="margin:0;padding-left:18px;font-size:13px;'
              f'line-height:1.7">{recent}</ul>') if recent else ""
    add = (
        f'<h3 style="margin:16px 0 6px">Block a file by its fingerprint</h3>'
        f'<form method="POST" action="/superadmin/antivirus/threat" '
        f'style="display:flex;gap:8px;flex-wrap:wrap">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="hidden" name="action" value="add">'
        f'<input name="sha256" aria-label="SHA-256 fingerprint" placeholder="SHA-256 (64 characters)" '
        f'style="flex:2;min-width:260px" required>'
        f'<input name="name" aria-label="What it is (optional)" placeholder="What it is (optional)" '
        f'style="flex:1;min-width:160px">'
        f'<button class="btn" type="submit">Block everywhere</button></form>')
    return (
        f'<div class="box"><h2>Threat list</h2>'
        f'<p style="margin:0 0 4px"><b>{c.get("blocked", 0):,}</b> files '
        f'blocked on every PC: {", ".join(parts)}.'
        + (f' {c["safe"]:,} marked safe.' if c.get("safe") else "")
        + '</p>'
        f'<p class="muted" style="margin:0;font-size:13px">Every agent '
        f'downloads the list when it starts and every 15 minutes after, and '
        f'quarantines what is on it. What one PC finds is added by itself; '
        f'<b>Safe</b> takes a false alarm off every PC and puts the file '
        f'back where it was quarantined.</p>'
        f'{pending}{recent}{add}</div>')


def _feed_box(t: dict, csrf: str) -> str:
    """MalwareBazaar: fingerprints of malware found around the world, free
    with an abuse.ch key."""
    f = t.get("feed") or {}
    on = bool(t.get("feed_key"))

    def stamp(v):
        try:
            return _when(float(v)) if v and float(v) else ""
        except ValueError:
            return ""
    if not on:
        status = ('<p class="muted" style="margin:0 0 10px">Off. With a free '
                  'key the list gains the malware MalwareBazaar collects '
                  'from researchers worldwide &mdash; a few thousand new '
                  'files a day &mdash; each kept for 30 days.</p>')
    elif f.get("feed_error"):
        status = (f'<p style="margin:0 0 10px;color:var(--danger-text)">Last try '
                  f'{stamp(f.get("feed_tried"))}: {esc(f["feed_error"])}'
                  f'</p>')
    elif f.get("feed_ok"):
        status = (f'<p style="margin:0 0 10px">On. Last import '
                  f'{stamp(f["feed_ok"])}: {esc(f.get("feed_added") or "0")} '
                  f'new of {esc(f.get("feed_seen") or "0")} in its last 48 '
                  f'hours. Imports again every 6 hours.</p>')
    else:
        status = '<p style="margin:0 0 10px">On; not imported yet.</p>'
    hidden = f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
    return (
        f'<div class="box"><h2>MalwareBazaar feed</h2>{status}'
        f'<form method="POST" action="/superadmin/antivirus/feed" '
        f'style="display:flex;gap:8px;flex-wrap:wrap">{hidden}'
        f'<input type="hidden" name="action" value="save">'
        f'<input type="password" name="key" aria-label="abuse.ch Auth-Key" autocomplete="off" '
        f'placeholder="{"Key saved" if on else "abuse.ch Auth-Key"}" '
        f'style="flex:1;min-width:220px">'
        f'<button class="btn" type="submit">Save and import</button></form>'
        + (f'<div style="margin-top:8px">'
           f'<form method="POST" action="/superadmin/antivirus/feed" '
           f'style="display:inline">{hidden}'
           f'<input type="hidden" name="action" value="import">'
           f'<button class="btn ghost" type="submit">Import now</button>'
           f'</form> <form method="POST" action="/superadmin/antivirus/feed" '
           f'style="display:inline">{hidden}'
           f'<input type="hidden" name="action" value="clear">'
           f'<button class="btn ghost" type="submit">Switch the feed off'
           f'</button></form></div>' if on else "")
        + '<p class="muted" style="margin:10px 0 0;font-size:13px">Get a '
          'key free: sign in at <a href="https://auth.abuse.ch/" '
          'target="_blank" rel="noopener">auth.abuse.ch</a> and copy the '
          'Auth-Key it shows.</p></div>')


_SETUP_HREF = "/superadmin/antivirus/setup.exe"


def _windows_steps(base: str, key_html: str, setup_ready: bool) -> str:
    """Putting the agent on a Windows PC with the setup. `base` and
    `key_html` are already escaped."""
    if not setup_ready:
        return ('<p class="muted">The Windows setup is not on this server '
                'yet: build it with <code>agent/build_windows.py</code> and '
                'deploy. Until then, use the steps for Python below.</p>')
    return (
        f'<p><a class="btn" href="{_SETUP_HREF}" download>Download the '
        f'Windows setup</a></p>'
        f'<ol style="line-height:1.7;font-size:14px">'
        f'<li>Run it on the PC, signed in as the person who uses it. No '
        f'administrator is needed, and nor is Python.</li>'
        f'<li>Windows may say it protected the PC: the setup is not signed '
        f'yet. Choose <b>More info</b> &rarr; <b>Run anyway</b>.</li>'
        f'<li>Leave the address as <code>{base}</code>, paste the key '
        f'{key_html}, and choose <b>Install</b>. It checks the key, starts '
        f'now and at every sign-in, and offers to send a test alert.</li>'
        f'<li>The PC shows under <b>PCs with the agent</b> straight away. '
        f'It is removed under Settings &rarr; Apps.</li></ol>'
        f'<p class="muted" style="font-size:13px">For many PCs: '
        f'<code>EasyMikroTik-Antivirus-Setup.exe --url {base} --key '
        f'&lt;key&gt; --quiet</code> installs without the window.</p>')


def _install_box(base: str, setup_ready: bool) -> str:
    return (f'<div class="box"><h2>Install on a PC</h2>'
            f'{_windows_steps(esc(base), "(made under Company keys)", setup_ready)}'
            f'<p class="muted" style="font-size:13px;margin:8px 0 0">Linux '
            f'and macOS: the steps are shown with each new key.</p></div>')


def render_antivirus(user, csrf: str, *, orgs: list, keys: dict, agents: list,
                     events: list, saved: list, fallback: list,
                     isolations: dict | None = None, msg: str = "",
                     error: str = "", now: float | None = None,
                     base_url: str = "", setup_ready: bool = False,
                     threats: dict | None = None) -> str:
    now = time.time() if now is None else now
    names = {o["id"]: o["name"] for o in orgs}
    pcs_by_org: dict = {}
    for a in agents:
        pcs_by_org[a["org_id"]] = pcs_by_org.get(a["org_id"], 0) + 1
    inner = (
        f'<div class="wrap"><h1>Antivirus</h1>'
        f'<p class="muted" style="font-size:13px;margin:-6px 0 0">The '
        f'antivirus agent runs on customers&rsquo; PCs and reports here with '
        f'its company&rsquo;s key. What it quarantines or stops, and any '
        f'problem of its own, is emailed to the support team.</p>'
        f'{_flash(msg, error)}'
        f'{_events_box(events, names, verdicts=(threats or {}).get("verdicts") or {}, csrf=csrf)}'
        f'{_agents_box(agents, names, now, isolations=isolations, csrf=csrf, manage=True)}'
        f'{_threats_box(threats or {}, names, csrf)}'
        f'{_feed_box(threats or {}, csrf)}'
        f'{_recipients_box(saved, fallback, csrf)}'
        f'{_keys_box(orgs, keys, pcs_by_org, csrf)}'
        f'{_install_box(base_url or "https://your-easymikrotik-address", setup_ready)}'
        f'</div>')
    return _page("Antivirus", _header(user, "/superadmin/antivirus") + inner)


def render_company_antivirus(user, *, org_name: str, agents: list,
                             events: list, isolations: dict | None = None,
                             now: float | None = None) -> str:
    """A company's own page: its PCs and what their agents reported.
    Read-only; the support team holds the keys and acts on the alerts."""
    now = time.time() if now is None else now
    inner = (
        f'<div class="wrap"><h1>Antivirus</h1>'
        f'<p class="muted" style="font-size:13px;margin:-6px 0 0">The '
        f'antivirus agent on {esc(org_name or "your company")}&rsquo;s PCs '
        f'reports here, and your support team is emailed about every threat '
        f'it finds. A PC marked <b>Isolated</b> has been cut off the network '
        f'at its router by your support team until it is cleaned up.</p>'
        f'{_events_box(events, {}, show_company=False, show_email=False)}'
        f'{_agents_box(agents, {}, now, show_company=False, isolations=isolations)}'
        f'</div>')
    return _page("Antivirus", _header(user, "/antivirus") + inner)


def render_new_key(user, org_name: str, key: str, base_url: str,
                   replaced: bool = False, setup_ready: bool = False) -> str:
    """The new key, shown this once, with how to put it on a PC."""
    base = esc(base_url or "https://your-easymikrotik-address")
    k = esc(key)
    old = (f" {esc(org_name)}&rsquo;s old key has stopped working."
           if replaced else "")
    inner = (
        f'<div class="wrap"><div class="card" style="max-width:760px;'
        f'margin:30px auto">'
        f'<h2 style="margin-top:0">Agent key for {esc(org_name)}</h2>'
        f'<p>Copy it now. It is shown once and is <b>not</b> kept on this '
        f'server.{old}</p>'
        f'<pre style="font-size:15px;padding:14px;border:1px solid '
        f'var(--border);border-radius:8px;white-space:pre-wrap;'
        f'word-break:break-all">{k}</pre>'
        f'<h3>Windows PCs</h3>'
        f'{_windows_steps(base, "above", setup_ready)}'
        f'<h3>Linux and macOS, or Windows with Python</h3>'
        f'<ol style="line-height:1.7;font-size:14px">'
        f'<li>Copy <code>agent/antivirus.py</code> and '
        f'<code>agent/requirements.txt</code> from the EasyMikroTik code onto '
        f'the PC. It needs Python 3.8 or newer.</li>'
        f'<li>Install what it needs: <code>pip install -r requirements.txt'
        f'</code></li>'
        f'<li>Install the agent, signed in as the person who uses the PC. '
        f'This checks the key, saves it, and starts the agent now and at '
        f'every sign-in:'
        f'<pre style="font-size:13px;padding:10px;border:1px solid '
        f'var(--border);border-radius:8px;white-space:pre-wrap;'
        f'word-break:break-all">python antivirus.py --install --url {base} '
        f'--key {k}</pre>'
        f'(<code>python3</code> on Linux and macOS.) To check that alerts '
        f'reach the support team, run it once with <code>--test</code>: '
        f'that emails a test alert.</li>'
        f'<li>The PC shows under <b>PCs with the agent</b> straight away. '
        f'<code>--uninstall</code> takes it off again.</li></ol>'
        f'<p class="muted" style="font-size:13px">It runs as the signed-in '
        f'user, watching that user&rsquo;s Downloads, temp and start-up '
        f'folders. Without <code>yara-python</code> installed it still checks '
        f'known-bad files and packed programs; with it, it also catches '
        f'reverse shells and hidden PowerShell.</p>'
        f'<p><a class="btn ghost" href="/superadmin/antivirus">I have copied '
        f'it &mdash; back to Antivirus</a></p></div></div>')
    return _page("Agent key", _header(user, "/superadmin/antivirus") + inner)


# What isolating does and does not do, said before anyone relies on it.
_ISOLATE_DOES = (
    '<p>The router will drop everything this PC sends through it &mdash; to '
    'the internet and to the site&rsquo;s other networks &mdash; except its '
    'reports to EasyMikroTik, and the connections it already has open are '
    'cleared. It stays like that until you release it here.</p>')
_ISOLATE_CANNOT = (
    '<p class="muted" style="font-size:13px">It cannot stop the PC reaching '
    'other PCs on its own switch or Wi-Fi: that traffic never passes through '
    'the router&rsquo;s firewall. If that matters, have someone unplug it or '
    'take it off the Wi-Fi as well.</p>')


def _isolate_fields(csrf: str, org_id: int, agent_id: str) -> str:
    return (f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="org" value="{int(org_id)}">'
            f'<input type="hidden" name="agent" value="{esc(agent_id)}">')


def render_isolate_form(user, csrf: str, *, org_id: int, org_name: str,
                        agent: dict, routers: list, ip: str = "",
                        device: str = "", error: str = "") -> str:
    """Step one: which address, on which of the company's routers."""
    pc = agent.get("hostname") or agent["agent_id"]
    if not routers:
        body = (f'<p>{esc(org_name)} has no routers in EasyMikroTik, so there '
                f'is nothing to isolate {esc(pc)} on.</p>'
                f'<p><a class="btn ghost" href="/superadmin/antivirus">Back to '
                f'Antivirus</a></p>')
    else:
        pick = device or (routers[0] if len(routers) == 1 else "")
        options = ('' if pick else
                   '<option value="" selected disabled>Choose the router this '
                   'PC is behind</option>') + "".join(
            f'<option value="{esc(r)}"{" selected" if r == pick else ""}>'
            f'{esc(r)}</option>' for r in routers)
        seen = esc(agent.get("local_ip") or "")
        mac = esc(agent.get("mac") or "")
        body = (
            f'{_ISOLATE_DOES}{_ISOLATE_CANNOT}'
            f'<form method="POST" action="/superadmin/antivirus/isolate">'
            f'{_isolate_fields(csrf, org_id, agent["agent_id"])}'
            f'<input type="hidden" name="step" value="preview">'
            f'<div class="fields">'
            f'<label>The PC&rsquo;s address<br><input name="ip" required '
            f'value="{esc(ip or agent.get("local_ip") or "")}" '
            f'style="width:100%"></label>'
            f'<label>The router it is behind<br><select name="device" required '
            f'style="width:100%">{options}</select></label></div>'
            f'<p class="muted" style="font-size:12.5px">The agent last '
            f'reported {seen or "no address"}'
            f'{f", network card {mac}" if mac else ""}. If the PC has moved, '
            f'its network card is how to find it in the router&rsquo;s DHCP '
            f'leases.</p>'
            f'<div class="actions"><button class="btn" type="submit">Preview'
            f'</button><a class="btn ghost" href="/superadmin/antivirus">'
            f'Cancel</a></div></form>')
    inner = (f'<div class="wrap"><h1>Isolate {esc(pc)}</h1>'
             f'<p class="muted" style="margin:-6px 0 0">A PC at '
             f'{esc(org_name)}</p>{_flash("", error)}'
             f'<div class="box">{body}</div></div>')
    return _page("Isolate a PC", _header(user, "/superadmin/antivirus") + inner)


def render_isolate_preview(user, csrf: str, *, org_id: int, org_name: str,
                           agent: dict, device: str, ip: str, diff: str,
                           on_network, connections: int,
                           hub_host: str) -> str:
    """Step two: exactly what will be sent, then the button that sends it."""
    pc = agent.get("hostname") or agent["agent_id"]
    warn = []
    if on_network is False:
        warn.append(f"{ip} is not on any of {device}'s networks, so isolating "
                    f"it there would change nothing. Check that this is the "
                    f"router the PC is behind, and its address.")
    elif on_network is None:
        warn.append(f"{device}'s own addresses could not be read, so it is "
                    f"not checked that {ip} is behind it.")
    if not hub_host:
        warn.append("This server's public address is not known yet (it is "
                    "learned when Platform admin is opened on the public "
                    "domain), so while isolated the PC's agent cannot report.")
    warnings = "".join(
        f'<p style="margin:0 0 10px;padding:8px 10px;border-radius:6px;'
        f'background:var(--warning-bg);color:var(--warning-text);font-size:13px">'
        f'&#9888; {esc(w)}</p>' for w in warn)
    conns = (f"Then the {connections} connection"
             f"{'' if connections == 1 else 's'} it has open now "
             f"{'is' if connections == 1 else 'are'} cleared."
             if connections else "It has no connections open right now.")
    ask = f"Cut {pc} off the network at {device}?"
    inner = (
        f'<div class="wrap"><h1>Isolate {esc(pc)} on {esc(device)}?</h1>'
        f'<p class="muted" style="margin:-6px 0 0">A PC at {esc(org_name)}, '
        f'at {esc(ip)}. Nothing has been sent to the router yet.</p>'
        f'<div class="box">{warnings}'
        f'<pre style="background:var(--surface-2);border:1px solid '
        f'var(--border);padding:12px;border-radius:8px;white-space:pre-wrap">'
        f'{esc(diff)}</pre><p>{esc(conns)} It stays cut off until you '
        f'release it on the Antivirus page.</p>{_ISOLATE_CANNOT}'
        f'<form method="POST" action="/superadmin/antivirus/isolate" '
        f'class="actions">'
        f'{_isolate_fields(csrf, org_id, agent["agent_id"])}'
        f'<input type="hidden" name="step" value="apply">'
        f'<input type="hidden" name="ip" value="{esc(ip)}">'
        f'<input type="hidden" name="device" value="{esc(device)}">'
        f'<button class="btn red" type="submit" onclick="{confirm_attr(ask)}">'
        f'Isolate now</button>'
        f'<a class="btn ghost" href="/superadmin/antivirus">Cancel</a>'
        f'</form></div></div>')
    return _page("Isolate a PC", _header(user, "/superadmin/antivirus") + inner)
