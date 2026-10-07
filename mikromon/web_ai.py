"""The AI monitor on the page: the dashboard's "on the backup line now"
banner, the box on a router's own page, and the Platform admin settings.

Rendering only. The incidents themselves come from incidents.py, written by
the monitoring engine (aimonitor.py); this module never decides anything.
"""
from __future__ import annotations

import time
from urllib.parse import quote

from .aimonitor import (MAX_RUNS, VERDICTS, backup_bytes_used, evidence_lines,
                        for_how_long, human_bytes)
from .web_shared import esc


_PENDING = ("pending", "running")


def _src_links(sources, limit=3) -> str:
    return "".join(
        f'<a class="bk-src" href="{esc(s.get("url", ""))}" target="_blank" '
        f'rel="noopener noreferrer">{esc(s.get("title") or s.get("url", ""))}'
        f'</a>' for s in (sources or [])[:limit])


def _ai_status(inc: dict, ai_on: bool, now: float) -> str:
    st = inc.get("ai_state") or ""
    if st in _PENDING:
        return "Looking online for outages in the area…"
    if st == "done":
        ago = for_how_long(now - (inc.get("ai_checked") or now))
        n = int(inc.get("ai_searches") or 0)
        return (f"Checked online {ago} ago"
                + (f" ({n} search{'' if n == 1 else 'es'} so far)" if n else "")
                + ("; looks again every two hours while it lasts."
                   if not inc.get("ended") and int(inc.get("ai_runs") or 0)
                   < MAX_RUNS else "."))
    if st == "failed":
        return f"The online check failed: {inc.get('ai_error') or 'unknown error'}"
    if st == "skipped":
        return inc.get("ai_error") or "The online check was skipped."
    if not ai_on:
        return ("From what the router showed. The online check for outages "
                "in the area is switched off on this server.")
    return "From what the router showed."


def backup_banner(incidents: list, visible: set, state, now=None) -> str:
    """The dashboard's standing "these sites are on their backup line"
    card. Stays until every main line is back, which is the point: an
    alert email is read once, a dashboard is looked at all day."""
    now = now if now is not None else time.time()
    rows = []
    for inc in incidents or []:
        if inc.get("kind") != "wan_failover" or inc["device"] not in visible:
            continue
        used = backup_bytes_used(inc, state)
        since = time.strftime("%H:%M", time.localtime(inc["started"]))
        meta = (f'{esc(inc.get("primary_link") or "Main line")} down since '
                f'{since} ({esc(for_how_long(now - inc["started"]))}) · on '
                f'{esc(inc.get("backup_link") or "backup")}'
                + (f' · {esc(human_bytes(used))} used' if used else ""))
        verdict = VERDICTS.get(inc.get("verdict") or "", "")
        cause = ""
        if inc.get("summary"):
            cause = (f'<div class="bk-cause"><b>{esc(verdict)}.</b> '
                     f'{esc(inc["summary"])} {_src_links(inc.get("sources"), 2)}'
                     f'</div>')
        if inc.get("ai_state") in _PENDING:
            cause += ('<div class="bk-cause">Looking online for outages in '
                      'the area…</div>')
        rows.append(
            f'<div class="bk-row"><a class="bk-dev" '
            f'href="/device?name={quote(inc["device"])}">'
            f'{esc(inc["device"])}</a> <span class="bk-meta">{meta}</span>'
            f'{cause}</div>')
    if not rows:
        return ""
    n = len(rows)
    return (f'<div class="bk-card" role="status">'
            f'<div class="bk-head"><span class="bk-pill">On backup</span>'
            f'<h2>{n} site{"" if n == 1 else "s"} running on the backup '
            f'line</h2></div>{"".join(rows)}</div>')


def _history_line(history: list, now: float) -> str:
    """"Dropped 4 times in the last 30 days, mostly 18:00-20:00" -- the
    pattern that turns a string of single outages into a fault worth
    logging with the ISP."""
    drops = [h for h in history if h.get("kind") == "wan_failover"]
    if not drops:
        return ("The main line has not dropped in the last 30 days."
                if history is not None else "")
    total = sum(((h.get("ended") or now) - h["started"]) for h in drops)
    hours = [time.localtime(h["started"]).tm_hour for h in drops]
    line = (f"The main line dropped {len(drops)} time"
            f"{'' if len(drops) == 1 else 's'} in the last 30 days, "
            f"{for_how_long(total)} on the backup in all.")
    if len(drops) >= 3:
        best = max(range(24), key=lambda h: sum(
            1 for x in hours if x in (h, (h + 1) % 24)))
        n = sum(1 for x in hours if x in (best, (best + 1) % 24))
        if n >= max(3, len(drops) * 0.6):
            line += (f" Most of them started between {best:02d}:00 and "
                     f"{(best + 2) % 24:02d}:00: a pattern like that is worth "
                     f"giving the ISP when you log a fault.")
        week = [h for h in drops if now - h["started"] < 7 * 86400]
        if len(week) >= 3:
            line += (f" It has dropped {len(week)} times this week: log a "
                     f"fault with the ISP and quote the times.")
    return line


def ai_box(inc: dict | None, history: list | None, state, *, csrf: str = "",
           can_manage: bool = False, ai_on: bool = False, name: str = "",
           now=None) -> str:
    """The AI monitor's box on a router's page: the outage now, if there is
    one, with its likely cause and sources; otherwise the recent pattern."""
    now = now if now is not None else time.time()
    hist = _history_line(history or [], now) if history is not None else ""
    if not inc:
        if not hist:
            return ""
        return (f'<div class="box ai-box"><h2><span class="ai-tag">AI</span> '
                f'Line monitor</h2><p class="muted" style="margin:0">'
                f'{esc(hist)}</p></div>')
    kind = inc.get("kind")
    since = time.strftime("%d %b %H:%M", time.localtime(inc["started"]))
    dur = for_how_long(now - inc["started"])
    if kind == "wan_failover":
        head = (f'{inc.get("primary_link") or "The main line"} down since '
                f'{since} ({dur}) — running on '
                f'{inc.get("backup_link") or "the backup"}')
    elif kind == "internet_down":
        head = f"Every internet line down since {since} ({dur})"
    else:
        head = f"Not answering since {since} ({dur})"
    used = backup_bytes_used(inc, state)
    verdict = VERDICTS.get(inc.get("verdict") or "", "Not clear yet")
    sources = inc.get("sources") or []
    ev = evidence_lines(inc.get("evidence") or {})
    q = quote(name or inc["device"])
    look_again = ""
    if (can_manage and ai_on and inc.get("ai_state") not in _PENDING
            and not inc.get("ended")):
        look_again = (
            f'<form method="POST" action="/device/ai-recheck" '
            f'style="display:inline;margin-left:8px">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="device" value="{esc(inc["device"])}">'
            f'<button class="btn ghost" type="submit" '
            f'style="padding:4px 10px;font-size:12px">Look again now</button>'
            f'</form>')
    return (
        f'<div class="box ai-box" style="border-left:4px solid var(--warning)">'
        f'<h2><span class="ai-tag">AI</span> What happened</h2>'
        f'<p style="margin:0;font-weight:600">{esc(head)}</p>'
        + (f'<p class="muted" style="margin:2px 0 0">{esc(human_bytes(used))} '
           f'used on the backup line so far.</p>' if used else "")
        + f'<div class="ai-verdict"><b>Possible cause: {esc(verdict)}</b> '
          f'<span class="muted">({esc(inc.get("confidence") or "low")} '
          f'confidence)</span><br>{esc(inc.get("summary") or "")}'
        + (f'<br><b>What to do:</b> {esc(inc["action"])}'
           if inc.get("action") else "")
        + '</div>'
        + (f'<div style="font-size:12.5px">Sources: {_src_links(sources, 5)}'
           f'</div>' if sources else "")
        + (f'<details style="margin-top:6px"><summary class="muted" '
           f'style="cursor:pointer;font-size:12.5px">What the router showed'
           f'</summary><ul class="ai-ev">'
           + "".join(f"<li>{esc(x)}</li>" for x in ev) + '</ul></details>'
           if ev else "")
        + f'<div class="ai-status">{esc(_ai_status(inc, ai_on, now))}'
          f'{look_again}</div>'
        + (f'<p class="muted" style="margin:8px 0 0;font-size:12px">'
           f'{esc(hist)}</p>' if hist else "")
        + f'<p style="margin:8px 0 0;font-size:12px"><a href="/device?name={q}'
          f'&tab=wan">WAN settings</a></p>'
        '</div>')


def ai_settings_box(settings: dict, usage: dict, csrf: str,
                    sdk_ok: bool = True, msg: str = "") -> str:
    """Platform admin -> AI monitor. The key is never shown back: a blank
    field keeps the one already saved."""
    key = (settings.get("api_key") or "").strip()
    key_hint = (f"saved …{esc(key[-4:])} (blank keeps it)" if key
                else "not set yet")
    on = bool(settings.get("enabled"))
    last_err = ""
    if usage.get("last_error"):
        when = time.strftime("%d %b %H:%M",
                             time.localtime(usage.get("last_error_ts") or 0))
        last_err = (f'<p style="color:var(--danger);font-size:12.5px;'
                    f'margin:6px 0 0">Last failure ({when}): '
                    f'{esc(usage["last_error"])}</p>')
    sdk_note = ("" if sdk_ok else
                '<p style="color:var(--danger);font-size:12.5px">The '
                '<code>anthropic</code> package is not installed on this '
                'server yet: run <code>sudo bash deploy/install.sh</code>.</p>')
    return (
        f'<div class="box" id="ai"><h2>AI monitor</h2>'
        f'<p class="muted" style="margin:0 0 10px">When a site loses its '
        f'main line, the monitor works out the likely cause from what the '
        f'router shows and from the rest of the fleet straight away. With '
        f'this switched on it also asks Claude to search online for '
        f'outages, maintenance and load-shedding reported for that ISP in '
        f'the site\'s area, and emails what it found with its sources. Only '
        f'the ISP\'s name, the site\'s area, the time and what the router '
        f'showed are sent, never a company\'s or a router\'s name. Each '
        f'check is one request to Claude Opus 5.5 with up to the number of '
        f'searches below (web search costs $10 per 1,000 searches, plus '
        f'the tokens). Sites that drop together share one check.</p>'
        f'{msg}{sdk_note}'
        f'<form method="POST" action="/superadmin/ai">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<label class="chk" style="display:flex;margin:0 0 10px">'
        f'<input type="checkbox" name="enabled" value="1"'
        f'{" checked" if on else ""}> <b>Look online when a line drops</b>'
        f'</label>'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,'
        f'minmax(200px,1fr));gap:10px">'
        f'<label>Anthropic API key<br><input name="api_key" type="password" '
        f'autocomplete="off" placeholder="{key_hint}" style="width:100%">'
        f'</label>'
        f'<label>Searches per check<br><input name="max_searches" '
        f'type="number" min="1" max="8" value="{int(settings.get("max_searches") or 3)}" '
        f'style="width:100%"></label>'
        f'<label>Checks per day (all companies)<br><input name="daily_limit" '
        f'type="number" min="0" max="1000" '
        f'value="{int(settings.get("daily_limit") or 0)}" style="width:100%">'
        f'</label>'
        f'<label>Country (2 letters)<br><input name="country" maxlength="2" '
        f'value="{esc(settings.get("country") or "")}" style="width:100%">'
        f'</label>'
        f'<label>Time zone<br><input name="timezone" '
        f'value="{esc(settings.get("timezone") or "")}" style="width:100%">'
        f'</label></div>'
        f'<label class="chk" style="display:flex;margin:10px 0 0">'
        f'<input type="checkbox" name="web_search" value="1"'
        f'{" checked" if settings.get("web_search", True) else ""}> '
        f'Search the web (untick to have Claude reason from the router\'s '
        f'evidence only)</label>'
        f'<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">'
        f'<button class="btn" type="submit">Save AI settings</button>'
        f'<button class="btn ghost" type="submit" name="test" value="1">'
        f'Save and test the key</button></div></form>'
        f'<p class="muted" style="margin:12px 0 0;font-size:12.5px">Last 24 '
        f'hours: {usage.get("calls", 0)} check'
        f'{"" if usage.get("calls", 0) == 1 else "s"}, '
        f'{usage.get("searches", 0)} search'
        f'{"" if usage.get("searches", 0) == 1 else "es"}, '
        f'{usage.get("failed", 0)} failed.</p>{last_err}</div>')
