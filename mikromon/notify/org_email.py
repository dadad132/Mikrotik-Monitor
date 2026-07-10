"""Per-org WAN failover email notifier (multi-tenant mode).

When the engine runs with both auth_db and devices_db configured, this notifier
routes WAN failover / internet-down alerts to each company's configured
recipients instead of the static smtp.to_addrs list in the YAML.

The SMTP relay (host, port, credentials, from_addr / no-reply address) still
comes from the smtp: section in config.yaml — only the destination list changes
per organisation.
"""
from __future__ import annotations

import logging
import smtplib
import socket
import ssl
import time
from datetime import datetime
from email.message import EmailMessage

from ..util import human_duration
from . import render
from .base import Notifier

log = logging.getLogger(__name__)

_NOTIFY_KEYS = {"wan_failover", "internet_down", "reachability"}


def _should_notify(alert) -> bool:
    return alert.key in _NOTIFY_KEYS or alert.key.startswith("wan_link:")


def effective_smtp(auth, fallback):
    """Prefer the SMTP relay the superadmin configured in the dashboard (stored
    in auth.db) over the smtp: block in config.yaml. `auth` is an open AuthStore
    (or None). Returns a SmtpConfig; falls back unchanged when nothing is set."""
    try:
        d = auth.get_smtp() if auth is not None else None
    except Exception:  # noqa: BLE001 — never let settings lookup break alerts
        d = None
    if not d:
        return fallback
    from ..config import SmtpConfig
    prefix = (d.get("subject_prefix")
              or (fallback.subject_prefix if fallback else "[EasyMikrotik]"))
    return SmtpConfig(
        host=d.get("host", ""), port=int(d.get("port") or 587),
        username=d.get("username", ""), password=d.get("password", ""),
        use_tls=bool(d.get("use_tls", True)), use_ssl=bool(d.get("use_ssl", False)),
        from_addr=d.get("from_addr", ""), subject_prefix=prefix)


def _smtp_send(smtp_cfg, msg: EmailMessage) -> None:
    """Send a pre-built EmailMessage via the configured SMTP relay."""
    ctx = ssl.create_default_context()
    if smtp_cfg.use_ssl:
        with smtplib.SMTP_SSL(smtp_cfg.host, smtp_cfg.port,
                              timeout=45, context=ctx) as srv:
            _login_and_send(srv, smtp_cfg, msg)
    else:
        with smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=45) as srv:
            if smtp_cfg.use_tls:
                srv.starttls(context=ctx)
            _login_and_send(srv, smtp_cfg, msg)


def _login_and_send(srv, smtp_cfg, msg: EmailMessage) -> None:
    if smtp_cfg.username:
        srv.login(smtp_cfg.username, smtp_cfg.password)
    srv.send_message(msg)


def send_test_email(smtp_cfg, recipients: list[str], org_name: str,
                    subject_prefix: str = "[EasyMikrotik]") -> None:
    """Send a one-off test notification to `recipients`."""
    if not recipients:
        raise ValueError("No recipient email addresses configured.")
    subject = f"{subject_prefix} Test notification — {org_name}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    text = (f"This is a test notification from EasyMikrotik.\n\n"
            f"If you received this email, WAN alert notifications are correctly "
            f"configured for {org_name}.\n\nSent: {now_str}")
    html = (f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">'
            f'<h2 style="color:#2563eb">EasyMikrotik — Test Notification</h2>'
            f'<p>If you received this email, WAN alert notifications are correctly '
            f'configured for <b>{render.esc(org_name)}</b>.</p>'
            f'<p style="color:#64748b;font-size:12px">Sent: {now_str}</p></div>')
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    _smtp_send(smtp_cfg, msg)
    log.info("Test email sent to %s for org '%s'", recipients, org_name)


def _pair_events(rows: list) -> list:
    """Turn a device's ordered alert_log rows (oldest first) into events:
    {title, start, end} — end is None if still unresolved at the end of the
    window. A recovery row with no matching open problem in this window means
    the problem actually started before it (start is left None so the caller
    can label it "already in progress")."""
    open_by_key: dict = {}
    events = []
    for r in rows:
        if not r["recovery"]:
            open_by_key[r["key"]] = r
        else:
            start_row = open_by_key.pop(r["key"], None)
            events.append({
                "title": (start_row or r)["title"],
                "start": start_row["ts"] if start_row else None,
                "end": r["ts"],
            })
    for r in open_by_key.values():
        events.append({"title": r["title"], "start": r["ts"], "end": None})
    events.sort(key=lambda e: e["start"] if e["start"] is not None else 0)
    return events


def _event_line(e: dict, until: float) -> str:
    start_str = (datetime.fromtimestamp(e["start"]).strftime("%d %b %H:%M")
                 if e["start"] is not None else "before this period")
    if e["end"] is not None:
        dur = human_duration(e["end"] - (e["start"] or e["end"]))
        end_str = datetime.fromtimestamp(e["end"]).strftime("%d %b %H:%M")
        return f"{e['title']} — {start_str} to {end_str} ({dur})"
    dur = human_duration(until - (e["start"] or until))
    return f"{e['title']} — since {start_str}, still ongoing ({dur} so far)"


def _build_report(org_name: str, device_names: list[str], state_data: dict,
                  schedule: str, subject_prefix: str, since: float,
                  until: float, events_by_device: dict | None = None
                  ) -> tuple[str, str, str]:
    """Return (subject, text_body, html_body) summarizing what happened for
    each device between `since` and `until` — not just a live snapshot.
    `events_by_device` (device name -> list of alert_log rows in the window)
    comes from AlertLog.between(); pass None when alert_log_db isn't
    configured on this server, in which case the report falls back to
    listing only currently-active conditions with a note that history isn't
    available yet."""
    schedule_label = {"weekly": "Weekly", "biweekly": "Bi-weekly",
                      "monthly": "Monthly"}.get(schedule, "Scheduled")
    period_str = (f"{datetime.fromtimestamp(since).strftime('%d %b')} – "
                  f"{datetime.fromtimestamp(until).strftime('%d %b %Y')}")
    subject = (f"{subject_prefix} {schedule_label} Status Report "
               f"— {org_name}")
    devices_state = state_data.get("devices", {})
    history_available = events_by_device is not None

    healthy, problems = [], []
    rows_text, rows_html = [], []

    for name in sorted(device_names):
        dev_state = devices_state.get(name, {})
        conditions = dev_state.get("conditions", {})
        facts = dev_state.get("facts", {})
        model = facts.get("model") or ""
        version = facts.get("version") or ""
        identity = facts.get("identity") or name
        reachable = conditions.get("reachability", {}).get("status") != "problem"
        status = "UP" if reachable else "DOWN"

        dev_rows = (events_by_device or {}).get(name, [])
        events = _pair_events(dev_rows)
        # A condition that's live-unhealthy right now but has no "still open"
        # event from the log (e.g. alert_log was only just enabled, or it
        # started right before `since`) — surface it anyway using the live
        # condition's own since-timestamp, so nothing currently broken goes
        # unmentioned just because history is incomplete.
        logged_keys = {r["key"] for r in dev_rows}
        for key, cond in conditions.items():
            if (not history_available or key not in logged_keys) \
                    and cond.get("status") == "problem":
                events.append({"title": cond.get("title", key),
                              "start": cond.get("since"), "end": None})

        if events:
            problems.append(name)
        else:
            healthy.append(name)

        alert_lines_text = "".join(f"    ⚠ {_event_line(e, until)}\n" for e in events)
        alert_lines_html = "".join(
            f'<div style="color:{"#dc2626" if e["end"] is None else "#d97706"};'
            f'margin-left:16px">&#9888; {render.esc(_event_line(e, until))}</div>'
            for e in events)

        info = f" — {model}" if model else ""
        ver_str = f" RouterOS {version}" if version else ""
        no_events_text = ("    ✓ No WAN issues this period\n" if history_available
                          else "    ✓ All checks currently healthy\n")
        no_events_html = ('<span style="color:#16a34a">&#10003; No WAN issues '
                         'this period</span>' if history_available
                         else '<span style="color:#16a34a">&#10003; Currently '
                              'healthy</span>')
        rows_text.append(
            f"[{status}] {identity}{info}{ver_str}\n"
            + (alert_lines_text if alert_lines_text else no_events_text))
        status_color = "#16a34a" if not events and reachable else "#dc2626"
        rows_html.append(
            f'<tr><td style="padding:6px 12px;font-weight:600">'
            f'<span style="color:{status_color}">{render.esc(status)}</span></td>'
            f'<td style="padding:6px 12px">{render.esc(identity)}'
            f'<span style="color:#64748b;font-size:12px"> {render.esc(info + ver_str)}</span></td>'
            f'<td style="padding:6px 12px">'
            + (alert_lines_html if alert_lines_html else no_events_html)
            + '</td></tr>')

    total = len(device_names)
    summary = (f"{total} device(s): {len(healthy)} with no WAN issues"
               + (f", {len(problems)} had at least one" if problems else "")
               + f" — {period_str}")
    history_note = ("" if history_available else
                    "\n(Event history logging isn't enabled on this server yet "
                    "— showing current status only, not the full period.)\n")

    text_body = (
        f"EasyMikrotik {schedule_label} Status Report\n"
        f"{org_name}  |  {period_str}\n"
        f"{'=' * 50}\n"
        f"{summary}\n{history_note}\n"
        + "\n".join(rows_text)
        + "\n-- EasyMikrotik\n"
    )
    history_note_html = ("" if history_available else
                         '<p style="color:#d97706;font-size:12px">Event history '
                         "logging isn't enabled on this server yet — showing "
                         "current status only, not the full period.</p>")
    html_body = (
        f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111">'
        f'<h2 style="color:#2563eb;margin-bottom:4px">EasyMikrotik {schedule_label} Report</h2>'
        f'<p style="color:#64748b;margin-top:0">{render.esc(org_name)} &mdash; {render.esc(period_str)}</p>'
        f'<p style="background:#f1f5f9;padding:8px 12px;border-radius:4px">{render.esc(summary)}</p>'
        f'{history_note_html}'
        f'<table style="border-collapse:collapse;width:100%">'
        f'<tr style="background:#f8fafc"><th style="padding:6px 12px;text-align:left">Status</th>'
        f'<th style="padding:6px 12px;text-align:left">Device</th>'
        f'<th style="padding:6px 12px;text-align:left">This period</th></tr>'
        + "".join(rows_html)
        + '</table>'
        '<p style="color:#999;font-size:12px;margin-top:16px">— EasyMikrotik</p></div>'
    )
    return subject, text_body, html_body


class OrgEmailNotifier(Notifier):
    """Delivers WAN alerts and scheduled reports to each org's recipient list."""
    name = "org_email"

    def __init__(self, smtp_cfg, auth_db_path: str, devices_db_path: str,
                alert_log_db: str | None = None):
        self._smtp = smtp_cfg
        self._auth_db = auth_db_path
        self._devices_db = devices_db_path
        self._alert_log_db = alert_log_db

    def send(self, alerts) -> None:
        targets = [a for a in alerts if _should_notify(a)]
        if not targets:
            return

        if self._alert_log_db:
            from ..alert_log import AlertLog
            try:
                alog = AlertLog(self._alert_log_db)
                for a in targets:
                    alog.append(a.device, a.key, a.title, int(a.severity),
                               a.recovery, ts=a.ts)
            except Exception:  # noqa: BLE001 — history must never break alerting
                log.exception("OrgEmailNotifier: could not log alert history")

        from ..auth import AuthStore
        from ..devices_store import DevicesStore

        try:
            ds = DevicesStore(self._devices_db)
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier: cannot open stores: %s", exc)
            return

        try:
            smtp = effective_smtp(auth, self._smtp)
            by_org: dict[int, list] = {}
            for a in targets:
                org_id = ds.org_of(a.device)
                if org_id is not None:
                    by_org.setdefault(org_id, []).append(a)

            for org_id, org_alerts in by_org.items():
                recipients = auth.get_alert_emails(org_id)
                if not recipients:
                    continue
                try:
                    self._deliver(recipients, org_alerts, smtp)
                except Exception:  # noqa: BLE001
                    log.exception("OrgEmailNotifier: delivery failed for org %s",
                                  org_id)
        finally:
            ds.close()
            auth.close()

    def send_test(self) -> None:
        pass  # org-scoped test uses send_test_email() directly from web handler

    def check_scheduled(self, state, devices_store) -> None:
        """Called by the engine after each poll to send any overdue reports."""
        from ..auth import REPORT_INTERVALS, AuthStore, _next_report_due
        now = time.time()
        try:
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier.check_scheduled: cannot open auth DB: %s", exc)
            return
        alog = None
        if self._alert_log_db:
            from ..alert_log import AlertLog
            try:
                alog = AlertLog(self._alert_log_db)
            except Exception:  # noqa: BLE001
                log.exception("OrgEmailNotifier.check_scheduled: could not open "
                              "alert_log_db")
        try:
            due = auth.orgs_with_report_due(now)
            if not due:
                return
            smtp = effective_smtp(auth, self._smtp)
            state_data = state.data if state is not None else {}
            prefix = smtp.subject_prefix
            for org in due:
                recipients = org["alert_emails"]
                if not recipients:
                    auth.set_report_next_due(
                        org["org_id"],
                        _next_report_due(org["schedule"], now))
                    continue
                dev_names = (devices_store.names_for_org(org["org_id"])
                             if devices_store else [])
                period_secs = REPORT_INTERVALS.get(org["schedule"], 7 * 86400)
                since = (org["due"] - period_secs) if org.get("due") else now - period_secs
                events_by_device = None
                if alog is not None:
                    events_by_device = {}
                    for name in dev_names:
                        events_by_device[name] = alog.between(
                            [name], since, now)
                try:
                    subj, txt, htm = _build_report(
                        org["name"], dev_names, state_data,
                        org["schedule"], prefix, since, now,
                        events_by_device=events_by_device)
                    msg = EmailMessage()
                    msg["Subject"] = subj
                    msg["From"] = smtp.from_addr
                    msg["To"] = ", ".join(recipients)
                    msg.set_content(txt)
                    msg.add_alternative(htm, subtype="html")
                    _smtp_send(smtp, msg)
                    log.info("Scheduled %s report sent for org '%s' to %d recipient(s)",
                             org["schedule"], org["name"], len(recipients))
                except Exception:  # noqa: BLE001
                    log.exception("Scheduled report delivery failed for org %s",
                                  org["org_id"])
                finally:
                    auth.set_report_next_due(
                        org["org_id"],
                        _next_report_due(org["schedule"], now))
        finally:
            auth.close()

    def _deliver(self, to_addrs: list[str], alerts, smtp=None) -> None:
        smtp = smtp or self._smtp
        subject = render.subject(smtp.subject_prefix, alerts)
        text = render.render_text(alerts)
        html = render.render_html(alerts)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp.from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        try:
            _smtp_send(smtp, msg)
            log.info("Org WAN alert sent to %d recipient(s): %s",
                     len(to_addrs), subject)
        except (smtplib.SMTPException, OSError, socket.error) as exc:
            log.error("Org WAN alert delivery failed: %s", exc)
