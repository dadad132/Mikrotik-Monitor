"""Shared rendering for alert digests (used by the email and outbox notifiers)."""
from __future__ import annotations

from datetime import datetime

from ..alert import Severity

_COLORS = {Severity.INFO: "#2563eb", Severity.WARNING: "#d97706",
           Severity.CRITICAL: "#dc2626"}


def esc(text) -> str:
    # Also escape quotes: esc() is used inside HTML attribute values
    # (value="...") throughout the dashboard, so a bare " would break out
    # of the attribute.
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def ts(alert) -> str:
    return datetime.fromtimestamp(alert.ts).strftime("%Y-%m-%d %H:%M:%S")


def subject(prefix: str, alerts) -> str:
    worst = max(a.severity for a in alerts)
    devices = sorted({a.device for a in alerts})
    scope = devices[0] if len(devices) == 1 else f"{len(devices)} devices"
    tag = "RESOLVED" if all(a.recovery for a in alerts) else worst.label
    n = len(alerts)
    return f"{prefix} {tag}: {scope} ({n} event{'s' if n != 1 else ''})"


def render_text(alerts) -> str:
    lines = []
    for device in sorted({a.device for a in alerts}):
        lines.append(f"=== {device} ===")
        for a in [x for x in alerts if x.device == device]:
            tag = "RESOLVED" if a.recovery else a.severity.label
            lines.append(f"[{tag}] {a.title}  ({ts(a)})")
            if a.detail:
                lines.append(f"    What : {a.detail}")
            if a.cause:
                lines.append(f"    Why  : {a.cause}")
            lines.append("")
    lines.append("-- mikromon (MikroTik Monitor)")
    return "\n".join(lines)


def render_html(alerts) -> str:
    parts = ['<div style="font-family:Segoe UI,Arial,sans-serif;'
             'font-size:14px;color:#111">']
    for device in sorted({a.device for a in alerts}):
        parts.append(f'<h2 style="margin:18px 0 6px">{esc(device)}</h2>')
        for a in [x for x in alerts if x.device == device]:
            color = "#16a34a" if a.recovery else _COLORS.get(a.severity, "#111")
            tag = "RESOLVED" if a.recovery else a.severity.label
            parts.append(
                '<div style="border-left:4px solid {c};padding:6px 12px;'
                'margin:8px 0;background:#fafafa">'
                '<div style="font-weight:600;color:{c}">[{tag}] {title}</div>'
                '<div style="color:#666;font-size:12px">{ts}</div>'
                .format(c=color, tag=tag, title=esc(a.title), ts=ts(a)))
            if a.detail:
                parts.append(f'<div><b>What:</b> {esc(a.detail)}</div>')
            if a.cause:
                parts.append(f'<div><b>Why:</b> {esc(a.cause)}</div>')
            parts.append("</div>")
    parts.append('<p style="color:#999;font-size:12px">'
                 '— mikromon (MikroTik Monitor)</p></div>')
    return "".join(parts)
