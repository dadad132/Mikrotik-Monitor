"""The AI monitor: when a site loses its main line, work out why, and keep
saying so until it is back.

Three layers, cheapest first, so it is useful even with no AI key at all:

  1. The router's own evidence, read at the moment of failover (checks/wan.py
     _link_evidence): is the port the line plugs into still up? A dead port
     is the cable, the ISP's box or its power; a live port carrying nothing
     is the ISP's network. Its PPPoE/DHCP state and its own log say more.
  2. The rest of the fleet: other sites on the same ISP, or in the same area,
     dropping within twenty minutes is an outage, not a fault on site. And a
     configuration change sent minutes before is the first suspect.
  3. A search online. Claude (with Anthropic's server-side web search) looks
     for outages and maintenance reported by that ISP or fibre network in the
     site's area, and for load-shedding or power cuts there, and answers in
     a fixed format with its sources. Only runs when the superadmin has
     switched it on with a key (Platform admin -> AI monitor), within a daily
     limit, and one search is shared by every site that dropped together.

Layers 1-2 go straight into the alert email ("Likely cause: ..."). Layer 3
arrives a minute later as a follow-up email, and from then on in the
"still on the backup line" reminders, which repeat (every two hours unless a
company picks otherwise) until the main line is back -- the reminder is the
point: a site quietly running on LTE for a week is the failure mode of an
alert that fires once.

Runs inside the monitoring engine: observe() on the poll thread, between
polling and dispatch, so the alert going out already carries the likely
cause; the AI work on a background thread, so a slow search never delays a
poll.
"""
from __future__ import annotations

import logging
import re
import threading
import time

from .incidents import IncidentStore, incidents_path, norm_key  # noqa: F401

log = logging.getLogger(__name__)

# ---- the AI call -------------------------------------------------------------
MODEL = "claude-opus-5-5"
WEB_SEARCH_TOOL = "web_search_20260318"
# Server-side fallback: if the model's safeguards decline a request, the API
# re-runs it on the model Anthropic recommends for that case, inside the same
# call. An outage search should never trip one; the parameter costs nothing
# when it does not.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORT = "medium"
MAX_CONTINUATIONS = 3

# ---- timing ------------------------------------------------------------------
FLEET_WINDOW = 20 * 60          # "dropped together" means within this
SHARE_RESULT_FOR = 30 * 60      # reuse a search for the same ISP+area
RECHECK_EVERY = 2 * 3600        # look again while the outage lasts...
MAX_RUNS = 6                    # ...but not forever
RETRY_FAILED = 30 * 60          # a check that failed is tried again
CHANGE_BLAME_MINUTES = 10

# alert key -> incident kind, and back again
KIND_OF = {"wan_failover": "wan_failover", "internet_down": "internet_down",
           "reachability": "offline"}
COND_OF = {v: k for k, v in KIND_OF.items()}

VERDICTS = {
    "isp_outage": "Outage at the ISP",
    "area_power": "Power cut or load-shedding in the area",
    "local_power": "Power or cabling at the ISP's box on site",
    "local_fault": "A fault on site",
    "isp_side": "A problem on the ISP's side",
    "change": "A configuration change",
    "unknown": "Not clear yet",
}

# Link names that say what KIND of line it is, not who provides it. Searching
# "fibre outage Durban" finds nothing useful; the provider's name is the key.
_GENERIC = {"", "wan", "wan1", "wan2", "wan3", "fibre", "fiber", "lte", "5g",
            "4g", "primary", "backup", "main", "internet", "dsl", "adsl",
            "vdsl", "pppoe", "dhcp", "line", "uplink", "isp", "microwave",
            "wireless", "satellite", "starlink line"}
_IFACE_RE = re.compile(r"^(ether|sfp|sfp-sfpplus|lte|pppoe-out|wlan|combo|"
                       r"qsfp|bridge|vlan)\d*", re.I)


def isp_of(link_name: str) -> str:
    """The provider named by a WAN link, or "" when the name is generic."""
    name = (link_name or "").strip()
    if _IFACE_RE.match(name) or norm_key(name) in _GENERIC:
        return ""
    return name


def city_of(area: str) -> str:
    """The last part of "Umhlanga, Durban" -- what localises a search."""
    parts = [p.strip() for p in (area or "").split(",") if p.strip()]
    return parts[-1] if parts else ""


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1000.0
    return ""


def for_how_long(seconds) -> str:
    if seconds is None or seconds < 0:
        return "an unknown time"
    mins = int(seconds // 60)
    if mins < 60:
        return f"{mins} minute" + ("" if mins == 1 else "s")
    hours, mins = divmod(mins, 60)
    if hours < 24:
        tail = f" {mins} min" if mins else ""
        return f"{hours} hour" + ("" if hours == 1 else "s") + tail
    days, hours = divmod(hours, 24)
    return f"{days} day" + ("" if days == 1 else "s") + (
        f" {hours} hour" + ("" if hours == 1 else "s") if hours else "")


# ---- layer 1+2: what the router and the fleet say ----------------------------
def rule_diagnosis(kind: str, ev: dict, fleet: dict, change_min,
                   link: str = "", isp: str = "", area: str = "") -> dict:
    """{"verdict", "confidence", "summary", "action"} from evidence alone.

    Ordered by how decisive each signal is: a change sent minutes before is
    checked first because it is the one thing on this list somebody here can
    undo, then the fleet (an outage everyone shares cannot be a fault on one
    site), then what the router itself saw.
    """
    ev = ev or {}
    fleet = fleet or {}
    link = link or "main"
    who = isp or "the ISP"
    if change_min is not None and change_min <= CHANGE_BLAME_MINUTES:
        return {"verdict": "change", "confidence": "medium",
                "summary": (f"A configuration change was sent to this router "
                            f"{change_min} min before this happened, so it is "
                            f"the first suspect."),
                "action": ("Check that change first: the Activity log shows "
                           "exactly what was sent, and Safe mode undoes a "
                           "change that cut the router off.")}
    same_isp, same_area = fleet.get("same_isp", 0), fleet.get("same_area", 0)
    if same_isp >= 2:
        return {"verdict": "isp_outage", "confidence": "high",
                "summary": (f"{same_isp} other sites on {who} lost their line "
                            f"within 20 minutes of this one, so this is an "
                            f"outage at {who}, not a fault on site."),
                "action": (f"Log a fault with {who} if they have not "
                           f"announced one; there is nothing to fix on site.")}
    if same_area >= 2:
        return {"verdict": "area_power", "confidence": "medium",
                "summary": (f"{same_area} other sites in {area or 'the area'} "
                            f"went down within 20 minutes of this one: a power "
                            f"cut or a wider network outage in the area is the "
                            f"likely cause."),
                "action": "Check for power cuts or load-shedding in the area."}
    if kind == "offline":
        return {"verdict": "unknown", "confidence": "low",
                "summary": ("The router itself stopped answering: power at the "
                            "site, every internet line at once, or the router."),
                "action": ("Check the site has power, then the router; the "
                           "dashboard shows when it is back.")}
    if kind == "internet_down":
        return {"verdict": "unknown", "confidence": "low",
                "summary": ("The router is on, but every internet line is down "
                            "at once: power at the ISPs' boxes, or a wider "
                            "outage."),
                "action": "Check the ISP boxes have power and their lights."}
    iface = ev.get("primary_iface") or link
    if ev.get("primary_running") is False and not ev.get("primary_disabled"):
        return {"verdict": "local_power", "confidence": "medium",
                "summary": (f"The port the {link} line plugs into ({iface}) "
                            f"lost its link. That is the cable, the ISP's box "
                            f"(ONT or modem) or its power: a power cut or "
                            f"load-shedding at the box, or a fibre break, "
                            f"looks exactly like this."),
                "action": ("Check the ISP's box has power and look at its "
                           f"lights. If it is on and its line light is red, "
                           f"log a fault with {who}.")}
    if ev.get("pppoe") == "down":
        return {"verdict": "isp_side", "confidence": "medium",
                "summary": (f"The cable to the ISP's box is fine, but the "
                            f"internet session with {who} (PPPoE) dropped. "
                            f"That is usually on the ISP's side, or the "
                            f"account."),
                "action": (f"If it is not back within a few minutes, log a "
                           f"fault with {who}.")}
    dhcp = (ev.get("dhcp_status") or "").lower()
    if dhcp and dhcp != "bound":
        return {"verdict": "isp_side", "confidence": "low",
                "summary": (f"The line is plugged in, but the ISP's box stopped "
                            f"handing this router an address (DHCP: {dhcp})."),
                "action": ("Restart the ISP's box; if that does not help, log "
                           f"a fault with {who}.")}
    status = ev.get("primary_status") or "not carrying traffic"
    return {"verdict": "isp_side", "confidence": "low",
            "summary": (f"The {link} line is plugged in and up, but traffic "
                        f"stopped flowing through it ({status}). That is "
                        f"usually the ISP's network."),
            "action": (f"Wait a few minutes; if it does not come back, log a "
                       f"fault with {who}.")}


def evidence_lines(ev: dict, link: str = "") -> list:
    """The router's evidence as short sentences, for emails and the page."""
    ev = ev or {}
    out = []
    iface = ev.get("primary_iface")
    if ev.get("primary_running") is False:
        out.append(f"Port {iface}: no link")
    elif ev.get("primary_running") is True:
        out.append(f"Port {iface}: link up")
    if ev.get("pppoe"):
        out.append(f"PPPoE session: {ev['pppoe']}")
    if ev.get("dhcp_status"):
        out.append(f"DHCP from the ISP's box: {ev['dhcp_status']}")
    if ev.get("primary_status"):
        out.append(f"Gateway: {ev['primary_status']}")
    for line in (ev.get("log") or [])[-3:]:
        out.append(f"Router log: {line}")
    return out


# ---- layer 3: the search online ---------------------------------------------
_SYSTEM = (
    "You are the outage analyst for a service that monitors business "
    "internet routers. A site's main internet line has just dropped and you "
    "are asked why. Search the web for outages, maintenance or faults "
    "reported by the named ISP or the fibre network it runs on, in the "
    "site's area, at that time; and for power cuts or load-shedding there. "
    "Prefer the providers' own status pages and announcements, then news, "
    "then outage-report sites. Never claim an outage you did not find a "
    "source for: if the searches turn up nothing relevant, say so plainly "
    "and fall back on what the router itself showed. Be brief and concrete; "
    "the reader is an IT administrator who has to decide whether to log a "
    "fault, send someone to site, or wait."
)

_FORMAT = (
    "Answer in exactly this format, four lines, nothing before or after:\n"
    "VERDICT: <one of: isp_outage, area_power, local_power, local_fault, "
    "isp_side, change, unknown>\n"
    "CONFIDENCE: <low, medium or high>\n"
    "SUMMARY: <at most three sentences: what you found online, or that you "
    "found nothing, and what that means for this site>\n"
    "ACTION: <one sentence: what the administrator should do next>"
)


def build_prompt(inc: dict, now: float | None = None) -> str:
    """What Claude is told. Deliberately leaves out the company's name and
    the router's name: the question needs a place, a provider and a time,
    and nothing that identifies a customer."""
    now = now if now is not None else time.time()
    ev = inc.get("evidence") or {}
    started = time.strftime("%Y-%m-%d %H:%M", time.localtime(inc["started"]))
    tz = time.strftime("%z")
    lines = []
    if inc["kind"] == "wan_failover":
        lines.append(f"The site's main internet line went down at about "
                     f"{started} (UTC{tz}) and the router moved to its backup "
                     f"line.")
    elif inc["kind"] == "internet_down":
        lines.append(f"Every internet line at the site went down at about "
                     f"{started} (UTC{tz}).")
    else:
        lines.append(f"The router at the site stopped answering at about "
                     f"{started} (UTC{tz}).")
    if inc.get("isp"):
        lines.append(f"Main line provider (as named by the customer): "
                     f"{inc['isp']}.")
    else:
        lines.append(f"The provider of the main line is not known (the line "
                     f"is labelled '{inc.get('primary_link') or 'main'}').")
    if inc.get("area"):
        lines.append(f"Site area: {inc['area']}.")
    if ev.get("primary_type"):
        lines.append(f"Line type on the router: {ev['primary_type']}.")
    ev_lines = evidence_lines(ev)
    if ev_lines:
        lines.append("What the router showed: " + "; ".join(ev_lines) + ".")
    fleet = ev.get("fleet") or {}
    if fleet.get("same_isp") or fleet.get("same_area"):
        lines.append(f"Other monitored sites that dropped within 20 minutes: "
                     f"{fleet.get('same_isp', 0)} on the same provider, "
                     f"{fleet.get('same_area', 0)} in the same area.")
    else:
        lines.append("No other monitored site dropped at the same time.")
    if inc.get("ended") is None:
        lines.append(f"It has been down for "
                     f"{for_how_long(now - inc['started'])} and is still "
                     f"down.")
    return "\n".join(lines) + "\n\n" + _FORMAT


_LINE = re.compile(r"^\s*(VERDICT|CONFIDENCE|SUMMARY|ACTION)\s*:\s*(.+?)\s*$",
                   re.I | re.M)


def parse_answer(text: str) -> dict:
    """The four fields out of Claude's answer, forgiving about layout."""
    got = {m.group(1).upper(): m.group(2).strip() for m in _LINE.finditer(text or "")}
    verdict = (got.get("VERDICT") or "unknown").strip().lower().strip(".")
    verdict = verdict if verdict in VERDICTS else "unknown"
    conf = (got.get("CONFIDENCE") or "low").strip().lower().strip(".")
    conf = conf if conf in ("low", "medium", "high") else "low"
    summary = got.get("SUMMARY") or ""
    if not summary:
        # Not in the format asked for. Keep what was said rather than lose it.
        summary = re.sub(r"\s+", " ", text or "").strip()[:600]
    return {"verdict": verdict, "confidence": conf, "summary": summary,
            "action": got.get("ACTION") or ""}


def _attr(obj, name, default=None):
    return (obj.get(name, default) if isinstance(obj, dict)
            else getattr(obj, name, default))


def collect_sources(content, limit: int = 5) -> list:
    """The pages Claude actually cited, in order, without repeats. Cited
    sources only: a page that was searched but not relied on is not a
    source for the answer."""
    out, seen = [], set()
    for block in content or []:
        if _attr(block, "type") != "text":
            continue
        for c in _attr(block, "citations") or []:
            if _attr(c, "type") != "web_search_result_location":
                continue
            url = _attr(c, "url") or ""
            if url and url not in seen:
                seen.add(url)
                out.append({"url": url, "title": _attr(c, "title") or url})
    return out[:limit]


NOTHING_FOUND = "Nothing about it was found reported online."


class AIError(Exception):
    """The online check could not be done. The message is shown to the
    superadmin as-is, so it says what to do."""


def claude_analyze(inc: dict, settings: dict, now: float | None = None,
                   client=None) -> dict:
    """Ask Claude, with web search, why this line dropped.

    Returns parse_answer()'s fields plus "sources" and "searches". Raises
    AIError for anything that should be shown rather than retried blindly.
    `client` is injectable for tests; normally the official SDK's.
    """
    try:
        import anthropic
    except ImportError as exc:
        raise AIError("The anthropic package is not installed on this "
                      "server; run: sudo bash deploy/install.sh") from exc
    if client is None:
        key = (settings.get("api_key") or "").strip()
        # No key in the settings: the SDK's own resolution (an
        # ANTHROPIC_API_KEY in the service environment) still applies.
        client = anthropic.Anthropic(api_key=key or None, timeout=180.0,
                                     max_retries=2)
    tools = []
    if settings.get("web_search", True):
        loc = {"type": "approximate"}
        if settings.get("country"):
            loc["country"] = str(settings["country"]).upper()[:2]
        if settings.get("timezone"):
            loc["timezone"] = settings["timezone"]
        city = city_of(inc.get("area", ""))
        if city:
            loc["city"] = city
        tools.append({"type": WEB_SEARCH_TOOL, "name": "web_search",
                      "max_uses": max(1, int(settings.get("max_searches") or 3)),
                      "user_location": loc})
    prompt = build_prompt(inc, now)
    messages = [{"role": "user", "content": prompt}]
    searches = 0
    try:
        for _ in range(MAX_CONTINUATIONS + 1):
            resp = client.beta.messages.create(
                model=MODEL, max_tokens=16000, system=_SYSTEM,
                messages=messages, tools=tools,
                output_config={"effort": EFFORT},
                betas=[FALLBACK_BETA], fallbacks="default")
            usage = getattr(resp, "usage", None)
            stu = getattr(usage, "server_tool_use", None) if usage else None
            searches += int(getattr(stu, "web_search_requests", 0) or 0)
            if resp.stop_reason != "pause_turn":
                break
            # A long search turn paused server-side: send it back unchanged
            # and the server carries on where it stopped.
            messages = [{"role": "user", "content": prompt},
                        {"role": "assistant", "content": resp.content}]
    except anthropic.AuthenticationError as exc:
        raise AIError("The AI key was rejected. Check it under Platform "
                      "admin -> AI monitor.") from exc
    except anthropic.PermissionDeniedError as exc:
        raise AIError("The AI key is not allowed to do this (web search may "
                      "be switched off for the organisation in the Claude "
                      "Console).") from exc
    except anthropic.RateLimitError as exc:
        raise AIError("Rate limited by the AI service; it will try again "
                      "on the next outage.") from exc
    except anthropic.BadRequestError as exc:
        raise AIError(f"The AI service refused the request: "
                      f"{getattr(exc, 'message', exc)}") from exc
    except anthropic.APIStatusError as exc:
        raise AIError(f"The AI service returned an error "
                      f"({exc.status_code}).") from exc
    except anthropic.APIConnectionError as exc:
        raise AIError("Could not reach the AI service from this server.") from exc
    if resp.stop_reason == "refusal":
        raise AIError("The AI declined to answer this one.")
    text = "".join(_attr(b, "text") or "" for b in resp.content
                   if _attr(b, "type") == "text")
    out = parse_answer(text)
    out["sources"] = collect_sources(resp.content)
    out["searches"] = searches
    return out


def test_key(settings: dict, client=None) -> str:
    """"" if the AI key works, else what is wrong -- for the Platform
    panel's "Save and test" button. One tiny request, no web search."""
    try:
        import anthropic
    except ImportError:
        return ("The anthropic package is not installed on this server; run: "
                "sudo bash deploy/install.sh")
    if client is None:
        key = (settings.get("api_key") or "").strip()
        client = anthropic.Anthropic(api_key=key or None, timeout=60.0,
                                     max_retries=1)
    try:
        resp = client.messages.create(
            model=MODEL, max_tokens=1024,
            messages=[{"role": "user",
                       "content": "Reply with the single word OK."}],
            output_config={"effort": "low"})
    except anthropic.AuthenticationError:
        return "The key was rejected: check it was copied in full."
    except anthropic.PermissionDeniedError:
        return "The key works but is not allowed to use this model."
    except anthropic.RateLimitError:
        return "The key works, but the account is rate limited right now."
    except anthropic.APIStatusError as exc:
        return f"The AI service returned an error ({exc.status_code})."
    except anthropic.APIConnectionError:
        return "Could not reach the AI service from this server."
    if getattr(resp, "stop_reason", "") == "refusal":
        return "The AI declined the test request."
    return ""


# ---- emails ------------------------------------------------------------------
def _when(ts) -> str:
    return time.strftime("%d %b %H:%M", time.localtime(ts)) if ts else "?"


def cause_email(inc: dict, prefix: str, every_hours: int) -> tuple:
    """(subject, text, html) for "here is what we found about why it went"."""
    from .notify import render
    dev = inc["device"]
    link = inc.get("primary_link") or "main"
    backup = inc.get("backup_link") or "its backup"
    what = (f"{dev} lost its {link} line at about {_when(inc['started'])} "
            f"and is running on {backup}."
            if inc["kind"] == "wan_failover" else
            f"{dev} went offline at about {_when(inc['started'])}.")
    verdict = VERDICTS.get(inc.get("verdict") or "unknown", "Not clear yet")
    sources = inc.get("sources") or []
    ev = evidence_lines(inc.get("evidence") or {})
    subject = f"{prefix} {dev}: possible cause — {verdict}"
    remind = (f"You will be reminded every {every_hours} hour"
              f"{'' if every_hours == 1 else 's'} while it stays on the "
              f"backup line, and told when the {link} line is back."
              if every_hours and inc["kind"] == "wan_failover" else "")
    text = (
        f"{what}\n\n"
        f"Possible cause ({inc.get('confidence') or 'low'} confidence): "
        f"{inc.get('summary') or ''}\n\n"
        + (f"What to do: {inc['action']}\n\n" if inc.get("action") else "")
        + ("Sources:\n" + "".join(f"  - {s['title']} — {s['url']}\n"
                                  for s in sources) + "\n" if sources else "")
        + ("What the router showed:\n" + "".join(f"  - {line}\n" for line in ev)
           + "\n" if ev else "")
        + (f"{remind}\n" if remind else "")
        + "\n-- easymikrotik AI monitor\n")
    src_html = "".join(
        f'<li><a href="{render.esc(s["url"])}">{render.esc(s["title"])}</a></li>'
        for s in sources)
    ev_html = "".join(f"<li>{render.esc(line)}</li>" for line in ev)
    html = (
        f'<div style="font:14px/1.55 system-ui,sans-serif;color:#0f172a">'
        f'<p style="margin:0 0 12px">{render.esc(what)}</p>'
        f'<div style="border-left:4px solid #2563eb;background:#eff6ff;'
        f'padding:10px 14px;margin:0 0 12px">'
        f'<b>Possible cause: {render.esc(verdict)}</b> '
        f'<span style="color:#64748b">({render.esc(inc.get("confidence") or "low")}'
        f' confidence)</span><br>{render.esc(inc.get("summary") or "")}</div>'
        + (f'<p><b>What to do:</b> {render.esc(inc["action"])}</p>'
           if inc.get("action") else "")
        + (f'<p style="margin:0">Sources:</p><ul style="margin:4px 0 12px">'
           f'{src_html}</ul>' if sources else "")
        + (f'<p style="margin:0">What the router showed:</p>'
           f'<ul style="margin:4px 0 12px;color:#475569">{ev_html}</ul>'
           if ev else "")
        + (f'<p style="color:#64748b;font-size:12.5px">{render.esc(remind)}</p>'
           if remind else "")
        + '</div>')
    return subject, text, html


def reminder_email(org_name: str, items: list, prefix: str,
                   every_hours: int) -> tuple:
    """(subject, text, html) for "these sites are STILL on their backup
    line". items: [{"device", "primary_link", "backup_link", "started",
    "seconds", "used", "verdict", "summary", "sources"}]."""
    from .notify import render
    n = len(items)
    if n == 1:
        it = items[0]
        subject = (f"{prefix} {it['device']} is still on its backup line "
                   f"({for_how_long(it['seconds'])})")
    else:
        subject = f"{prefix} {n} sites still on their backup line — {org_name}"
    lines, rows = [], []
    for it in items:
        used = f", {it['used']} used on it" if it.get("used") else ""
        head = (f"{it['device']}: {it.get('primary_link') or 'main'} line down "
                f"since {_when(it['started'])} ({for_how_long(it['seconds'])}), "
                f"running on {it.get('backup_link') or 'the backup'}{used}.")
        cause = ""
        if it.get("summary"):
            cause = (f"Possible cause: {VERDICTS.get(it.get('verdict'), '')}"
                     f" — {it['summary']}")
        srcs = it.get("sources") or []
        lines.append(f"  * {head}\n" + (f"    {cause}\n" if cause else "")
                     + "".join(f"    Source: {s['title']} — {s['url']}\n"
                               for s in srcs[:2]))
        rows.append(
            f'<li style="margin:0 0 10px"><b>{render.esc(it["device"])}</b>: '
            f'{render.esc(head[len(it["device"]) + 2:])}'
            + (f'<br><span style="color:#475569">{render.esc(cause)}</span>'
               if cause else "")
            + "".join(f'<br><a href="{render.esc(s["url"])}" '
                      f'style="font-size:12.5px">{render.esc(s["title"])}</a>'
                      for s in srcs[:2])
            + '</li>')
    every = (f"every {every_hours} hour{'' if every_hours == 1 else 's'}"
             if every_hours else "")
    foot = (f"This is a reminder, not a new fault. It repeats {every} for as "
            f"long as a site stays on its backup line, because a backup line "
            f"is slower, often metered, and has nothing behind it if it fails "
            f"too. It stops by itself when the main line is back. Change how "
            f"often under Account -> Alert notifications.")
    text = (f"{n} site{'' if n == 1 else 's'} at {org_name} "
            f"{'is' if n == 1 else 'are'} still running on the backup line:\n\n"
            + "\n".join(lines) + f"\n{foot}\n\n-- easymikrotik AI monitor\n")
    html = (f'<div style="font:14px/1.55 system-ui,sans-serif;color:#0f172a">'
            f'<p style="margin:0 0 12px;font-size:16px"><b>{n} '
            f'site{"" if n == 1 else "s"}</b> at {render.esc(org_name)} '
            f'{"is" if n == 1 else "are"} still running on the backup '
            f'line.</p><ul style="padding-left:18px">{"".join(rows)}</ul>'
            f'<p style="color:#64748b;font-size:12.5px">{render.esc(foot)}</p>'
            f'</div>')
    return subject, text, html


# ---- the monitor -------------------------------------------------------------
class AIMonitor:
    """Incidents, their causes, and the reminders.

    Every collaborator is optional so the pieces can be tested alone:
    without an auth DB there is no AI (no settings) and nobody to email;
    without a devices DB every device counts as one company's.
    """

    def __init__(self, store: IncidentStore, *, auth_db=None, devices_db=None,
                 smtp_cfg=None, billing_db=None, push_log_db=None,
                 poll_interval: int = 60, confirmations: int = 2,
                 clock=time.time, analyzer=None, quiet=None, sender=None):
        self.store = store
        self.auth_db = auth_db
        self.devices_db = devices_db
        self.smtp_cfg = smtp_cfg
        self.billing_db = billing_db
        self.push_log_db = push_log_db
        self.poll_interval = int(poll_interval or 60)
        self.confirmations = max(1, int(confirmations or 1))
        self.clock = clock
        self.analyzer = analyzer or claude_analyze
        # True while the engine is in its startup grace: nothing is mailed
        # then, the same as the alerts themselves.
        self.quiet = quiet or (lambda: False)
        # sender(to, subject, text, html): injectable for tests.
        self.sender = sender
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()   # one worker pass at a time

    # ----- helpers ---------------------------------------------------------
    def _auth(self):
        if not self.auth_db:
            return None
        from .auth import AuthStore
        return AuthStore(self.auth_db)

    def _org_of(self, device: str):
        if not self.devices_db:
            return None
        from .devices_store import DevicesStore
        ds = DevicesStore(self.devices_db)
        try:
            return ds.org_of(device)
        finally:
            ds.close()

    def settings(self) -> dict:
        from .auth import AI_DEFAULTS
        auth = self._auth()
        if auth is None:
            return dict(AI_DEFAULTS)
        try:
            return auth.get_ai()
        finally:
            auth.close()

    def _area_for(self, cfg, org_id) -> str:
        area = (getattr(cfg, "location", "") or "").strip()
        if area or org_id is None:
            return area
        auth = self._auth()
        if auth is None:
            return ""
        try:
            return ((auth.org(org_id) or {}).get("address") or "").strip()
        finally:
            auth.close()

    def _change_minutes(self, device: str, at: float):
        if not self.push_log_db:
            return None
        try:
            from .push.audit import AuditLog
            ts, _f = AuditLog(self.push_log_db).last_change(device)
        except Exception:  # noqa: BLE001
            return None
        if not ts or ts > at:
            return None
        return max(0, int((at - ts) / 60))

    def _fleet(self, device: str, started: float, isp: str, area: str) -> dict:
        ik, ak = norm_key(isp), norm_key(area)
        same_isp = same_area = 0
        for o in self.store.around(started, FLEET_WINDOW, exclude_device=device):
            if ik and norm_key(o.get("isp", "")) == ik:
                same_isp += 1
            elif ak and norm_key(o.get("area", "")) == ak:
                same_area += 1
        return {"same_isp": same_isp, "same_area": same_area}

    # ----- poll-thread side: open and close --------------------------------
    def observe(self, alerts, state=None, devices=None) -> None:
        """Open/close incidents for this cycle's alerts, and add the likely
        cause to each outgoing alert's "Why" while there is still time."""
        cfgs = {}
        for d in devices or []:
            c = getattr(d, "cfg", d)
            cfgs[getattr(c, "name", "")] = c
        for a in alerts or []:
            kind = KIND_OF.get(a.key)
            if not kind:
                continue
            try:
                if a.recovery:
                    self._close(a.device, kind, a.ts, state, a)
                else:
                    inc = self._open(a, kind, cfgs.get(a.device))
                    if inc and inc.get("summary"):
                        a.cause = ((a.cause + " ") if a.cause else "") + (
                            "Likely cause: " + inc["summary"])
            except Exception:  # noqa: BLE001 -- an alert must still go out
                log.exception("AI monitor: could not record %s for %s",
                              a.key, a.device)
        if state is not None:
            try:
                self._reconcile(state)
            except Exception:  # noqa: BLE001
                log.exception("AI monitor: reconcile failed")
        self._wake.set()

    def _open(self, alert, kind: str, cfg) -> dict | None:
        facts = alert.facts or {}
        ev = dict(facts.get("evidence") or {})
        links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])
        link = (facts.get("primary_link")
                or (links[0].label(0) if links else "")) or ""
        backup = facts.get("current_link") or ""
        isp = isp_of(links[0].name if links else link)
        org_id = self._org_of(alert.device)
        area = self._area_for(cfg, org_id)
        started = alert.ts - (self.confirmations - 1) * self.poll_interval
        fleet = self._fleet(alert.device, started, isp, area)
        ev["fleet"] = fleet
        change_min = self._change_minutes(alert.device, started)
        if change_min is not None:
            ev["change_min"] = change_min
        rules = rule_diagnosis(kind, ev, fleet, change_min, link=link,
                               isp=isp, area=area)
        settings = self.settings()
        ai_state = ("pending" if settings.get("enabled") else "off")
        return self.store.open_incident(
            alert.device, kind, started=started, detected=alert.ts,
            primary_link=link, backup_link=backup, isp=isp, area=area,
            evidence=ev, verdict=rules["verdict"],
            confidence=rules["confidence"], summary=rules["summary"],
            action=rules["action"], ai_state=ai_state)

    def _close(self, device: str, kind: str, at: float, state, alert=None):
        inc = self.store.open_for(device, kind)
        if inc is None:
            return None
        used = backup_bytes_used(inc, state) if state is not None else None
        return self.store.close_incident(device, kind, at, used)

    def _reconcile(self, state) -> None:
        """Close incidents whose condition is no longer a problem -- a
        recovery missed across a restart, or a device deleted mid-outage,
        must not leave a site "on backup" forever."""
        devices = (getattr(state, "data", state) or {}).get("devices", {})
        now = self.clock()
        for inc in self.store.open_all():
            dev = devices.get(inc["device"])
            cond = ((dev or {}).get("conditions") or {}).get(
                COND_OF.get(inc["kind"], ""), {})
            if dev is None or cond.get("status") != "problem":
                used = backup_bytes_used(inc, state)
                self.store.close_incident(inc["device"], inc["kind"],
                                          cond.get("since") or now, used)

    # ----- worker side: the AI and the cause email ---------------------------
    def work_once(self) -> None:
        with self._lock:
            settings = self.settings()
            now = self.clock()
            self._schedule_rechecks(settings, now)
            for inc in self.store.pending_ai():
                self._analyze(inc, settings, now)

    def _schedule_rechecks(self, settings, now) -> None:
        """Look again while an outage lasts (the ISP may have announced an
        estimate since), retry a check that failed, and pick up an outage
        that started before the AI was switched on."""
        if not settings.get("enabled"):
            return
        for inc in self.store.open_all():
            st, last = inc.get("ai_state"), inc.get("ai_checked")
            if int(inc.get("ai_runs") or 0) >= MAX_RUNS:
                continue
            due = ((st == "done" and now - (last or now) >= RECHECK_EVERY)
                   or (st == "off" and last is None)
                   or (st in ("failed", "skipped")
                       and now - (last or 0) >= RETRY_FAILED))
            if due:
                self.store.update(inc["id"], ai_state="pending")

    def recheck(self, incident_id: int) -> None:
        """Somebody pressed "Look again" on the dashboard."""
        self.store.update(incident_id, ai_state="pending")
        self._wake.set()

    def _analyze(self, inc: dict, settings: dict, now: float) -> None:
        if not settings.get("enabled"):
            self.store.update(inc["id"], ai_state="off")
            return
        usage = self.store.ai_usage(now - 86400)
        if usage["calls"] >= int(settings.get("daily_limit") or 0):
            self.store.update(inc["id"], ai_state="skipped",
                              ai_error="Today's limit of online checks was "
                                       "reached (Platform admin -> AI monitor).")
            return
        shared = self.store.recent_ai_result(
            norm_key(inc.get("isp", "")), norm_key(inc.get("area", "")),
            now - SHARE_RESULT_FOR)
        if shared and shared["id"] != inc["id"]:
            self.store.update(
                inc["id"], verdict=shared["verdict"],
                confidence=shared["confidence"], summary=shared["summary"],
                action=shared["action"], sources=shared["sources"],
                ai_state="done", ai_checked=now, ai_error="",
                ai_runs=int(inc.get("ai_runs") or 0) + 1)
            self._mail_cause(self.store.get(inc["id"]))
            return
        self.store.update(inc["id"], ai_state="running")
        try:
            res = self.analyzer(inc, settings, now)
        except AIError as exc:
            self.store.log_ai_call(inc["device"], 0, False, str(exc), ts=now)
            self.store.update(inc["id"], ai_state="failed", ai_checked=now,
                              ai_error=str(exc),
                              ai_runs=int(inc.get("ai_runs") or 0) + 1)
            log.warning("AI monitor: online check for %s failed: %s",
                        inc["device"], exc)
            return
        except Exception as exc:  # noqa: BLE001 -- never kill the worker
            log.exception("AI monitor: online check for %s crashed",
                          inc["device"])
            self.store.log_ai_call(inc["device"], 0, False, str(exc), ts=now)
            self.store.update(inc["id"], ai_state="failed", ai_checked=now,
                              ai_error=f"Unexpected error: {exc}",
                              ai_runs=int(inc.get("ai_runs") or 0) + 1)
            return
        self.store.log_ai_call(inc["device"], res.get("searches", 0), True,
                               ts=now)
        fields = {"ai_state": "done", "ai_checked": now, "ai_error": "",
                  "ai_runs": int(inc.get("ai_runs") or 0) + 1,
                  "ai_searches": int(inc.get("ai_searches") or 0)
                  + int(res.get("searches") or 0)}
        # An answer that found nothing and says "unknown" adds nothing to
        # what the router already showed: keep the router's reading, and
        # say the search came up empty.
        if res.get("verdict") == "unknown" and not res.get("sources"):
            summary = inc.get("summary") or ""
            if NOTHING_FOUND not in summary:
                summary = (summary + " " + NOTHING_FOUND).strip()
            fields["summary"] = summary
        else:
            fields.update(verdict=res["verdict"],
                          confidence=res["confidence"],
                          summary=res["summary"],
                          action=res.get("action") or inc.get("action") or "",
                          sources=res.get("sources") or [])
        self.store.update(inc["id"], **fields)
        self._mail_cause(self.store.get(inc["id"]))

    # ----- email -------------------------------------------------------------
    def _send(self, to: list, subject: str, text: str, html: str) -> None:
        if self.sender is not None:
            self.sender(to, subject, text, html)
            return
        from email.message import EmailMessage

        from .notify.org_email import _smtp_send, effective_smtp
        auth = self._auth()
        try:
            smtp = effective_smtp(auth, self.smtp_cfg)
        finally:
            if auth is not None:
                auth.close()
        if not (smtp and getattr(smtp, "host", "")):
            log.warning("AI monitor: nothing sent (%s) -- no mail server is "
                        "configured", subject)
            return
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp.from_addr
        msg["To"] = ", ".join(to)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
        _smtp_send(smtp, msg)

    def _prefix(self) -> str:
        from .notify.org_email import effective_smtp
        auth = self._auth()
        try:
            smtp = effective_smtp(auth, self.smtp_cfg)
        finally:
            if auth is not None:
                auth.close()
        return getattr(smtp, "subject_prefix", "") or "[EasyMikrotik]"

    def _suspended(self) -> set:
        if not self.billing_db:
            return set()
        try:
            from .billing import BillingStore
            b = BillingStore(self.billing_db)
            try:
                return b.suspended_orgs()
            finally:
                b.db.close()
        except Exception:  # noqa: BLE001 -- an alert beats this filter
            return set()

    def _mail_cause(self, inc: dict | None) -> None:
        """The follow-up email with what was found online. Once per outage,
        only for a fresh one (not one already old when the server started),
        and only to a company that has not switched these off."""
        if not inc or inc.get("cause_mailed") or inc.get("ended"):
            return
        if self.quiet() or self.clock() - inc["detected"] > 3600:
            self.store.update(inc["id"], cause_mailed=self.clock())
            return
        org_id = self._org_of(inc["device"])
        auth = self._auth()
        if auth is None or org_id is None:
            return
        try:
            if org_id in self._suspended() or not auth.get_cause_emails(org_id):
                self.store.update(inc["id"], cause_mailed=self.clock())
                return
            to = list(auth.recipients_for_device(org_id, inc["device"]))
            hours = auth.get_backup_reminder_hours(org_id)
        finally:
            auth.close()
        self.store.update(inc["id"], cause_mailed=self.clock())
        if not to:
            return
        subject, text, html = cause_email(inc, self._prefix(), hours)
        try:
            self._send(to, subject, text, html)
            log.info("AI monitor: told %d recipient(s) the possible cause for "
                     "%s", len(to), inc["device"])
        except Exception:  # noqa: BLE001
            log.exception("AI monitor: could not send the cause email for %s",
                          inc["device"])

    def check_reminders(self, state) -> None:
        """Tell each company which sites are STILL on their backup line.

        Called by the engine after each poll. One email per set of people,
        listing every site of theirs that is due, rather than one per site.
        """
        if self.quiet():
            return
        now = self.clock()
        auth = self._auth()
        if auth is None:
            return
        try:
            suspended = self._suspended()
            by_audience: dict = {}
            names: dict = {}
            hours_of: dict = {}
            for inc in self.store.open_all():
                if inc["kind"] != "wan_failover":
                    continue
                org_id = self._org_of(inc["device"])
                if org_id is None or org_id in suspended:
                    continue
                if org_id not in hours_of:
                    hours_of[org_id] = auth.get_backup_reminder_hours(org_id)
                hours = hours_of[org_id]
                if not hours:
                    continue
                last = inc.get("last_reminder") or inc["detected"]
                if now - last < hours * 3600:
                    continue
                to = tuple(auth.recipients_for_device(org_id, inc["device"]))
                if not to:
                    continue
                by_audience.setdefault((org_id, to), []).append(inc)
                names[org_id] = (auth.org(org_id) or {}).get("name", "")
        finally:
            auth.close()
        prefix = self._prefix() if by_audience else ""
        for (org_id, to), incs in by_audience.items():
            items = [{"device": i["device"],
                      "primary_link": i.get("primary_link"),
                      "backup_link": i.get("backup_link"),
                      "started": i["started"],
                      "seconds": now - i["started"],
                      "used": human_bytes(backup_bytes_used(i, state))
                      if backup_bytes_used(i, state) else "",
                      "verdict": i.get("verdict"),
                      "summary": i.get("summary"),
                      "sources": i.get("sources") or []} for i in incs]
            subject, text, html = reminder_email(names.get(org_id, ""), items,
                                                 prefix, hours_of[org_id])
            try:
                self._send(list(to), subject, text, html)
            except Exception:  # noqa: BLE001 -- not marked: try again
                log.exception("AI monitor: backup reminder failed for org %s",
                              org_id)
                continue
            for i in incs:
                self.store.update(i["id"], last_reminder=now,
                                  reminders=int(i.get("reminders") or 0) + 1)
            log.info("AI monitor: reminded %d recipient(s) that %d site(s) "
                     "are still on backup", len(to), len(incs))

    # ----- thread ------------------------------------------------------------
    def start(self, every: float = 15.0) -> threading.Event:
        def loop():
            while not self._stop.is_set():
                self._wake.wait(every)
                self._wake.clear()
                if self._stop.is_set():
                    break
                try:
                    self.work_once()
                except Exception:  # noqa: BLE001 -- the worker must not die
                    log.exception("AI monitor worker failed")

        threading.Thread(target=loop, name="mikromon-aimonitor",
                         daemon=True).start()
        return self._stop

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


def backup_bytes_used(inc: dict, state) -> int | None:
    """Data through the backup line since the failover: its byte counters
    now, minus what they were when the main line went. None when unknown,
    or when the counters went backwards (the router restarted)."""
    ev = inc.get("evidence") or {}
    bif = (ev.get("backup_iface") or "").strip().lower()
    if not bif or ev.get("backup_rx") is None or state is None:
        return None
    data = getattr(state, "data", state) or {}
    mem = (((data.get("devices") or {}).get(inc["device"]) or {})
           .get("memory") or {}).get("wan_traffic") or {}
    last = {str(k).strip().lower(): v for k, v in (mem.get("last") or {}).items()}
    cur = last.get(bif)
    if not cur:
        return None
    try:
        used = (int(cur["rx"]) - int(ev["backup_rx"])) + (
            int(cur["tx"]) - int(ev.get("backup_tx") or 0))
    except (KeyError, TypeError, ValueError):
        return None
    return used if used >= 0 else None
