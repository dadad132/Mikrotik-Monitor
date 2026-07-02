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

from . import render
from .base import Notifier

log = logging.getLogger(__name__)

_NOTIFY_KEYS = {"wan_failover", "internet_down", "reachability"}


def _should_notify(alert) -> bool:
    return alert.key in _NOTIFY_KEYS or alert.key.startswith("wan_link:")


def _smtp_send(smtp_cfg, msg: EmailMessage) -> None:
    """Send a pre-built EmailMessage via the configured SMTP relay.

    Tries the configured port/mode first, then falls back to port 465 (SSL)
    if that fails, so a single transient error or wrong-port config doesn't
    silently drop the message.
    """
    ctx = ssl.create_default_context()

    def _try_ssl(port):
        with smtplib.SMTP_SSL(smtp_cfg.host, port, timeout=45, context=ctx) as srv:
            _login_and_send(srv, smtp_cfg, msg)

    def _try_starttls(port):
        with smtplib.SMTP(smtp_cfg.host, port, timeout=45) as srv:
            if smtp_cfg.use_tls:
                srv.starttls(context=ctx)
            _login_and_send(srv, smtp_cfg, msg)

    if smtp_cfg.use_ssl:
        # Configured for SSL — try configured port, then 587 STARTTLS fallback.
        try:
            _try_ssl(smtp_cfg.port)
            return
        except (OSError, smtplib.SMTPException, socket.error) as primary_exc:
            log.warning("SMTP SSL on port %s failed (%s: %s), trying 587 STARTTLS",
                        smtp_cfg.port, type(primary_exc).__name__, primary_exc)
        _try_starttls(587)
    else:
        # Configured for STARTTLS — try configured port, then 465 SSL fallback.
        try:
            _try_starttls(smtp_cfg.port)
            return
        except (OSError, smtplib.SMTPException, socket.error) as primary_exc:
            log.warning("SMTP STARTTLS on port %s failed (%s: %s), trying 465 SSL",
                        smtp_cfg.port, type(primary_exc).__name__, primary_exc)
        _try_ssl(465)


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


def _build_report(org_name: str, device_names: list[str], state_data: dict,
                  schedule: str, subject_prefix: str) -> tuple[str, str, str]:
    """Return (subject, text_body, html_body) for a scheduled status report."""
    schedule_label = {"weekly": "Weekly", "biweekly": "Bi-weekly",
                      "monthly": "Monthly"}.get(schedule, "Scheduled")
    subject = (f"{subject_prefix} {schedule_label} Status Report "
               f"— {org_name}")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    devices_state = state_data.get("devices", {})

    healthy, problems = [], []
    rows_text, rows_html = [], []

    for name in sorted(device_names):
        dev_state = devices_state.get(name, {})
        conditions = dev_state.get("conditions", {})
        facts = dev_state.get("facts", {})
        model = facts.get("model") or ""
        version = facts.get("version") or ""
        identity = facts.get("identity") or name

        reachable = conditions.get("reachability", {}).get("healthy", True)
        active_alerts = [
            c for c, v in conditions.items()
            if not v.get("healthy", True)
        ]
        status = "UP" if reachable else "DOWN"
        if active_alerts:
            problems.append(name)
        else:
            healthy.append(name)

        alert_lines_text = ""
        alert_lines_html = ""
        for key in active_alerts:
            title = conditions[key].get("title", key)
            since_ts = conditions[key].get("since")
            since_str = (f" (since {datetime.fromtimestamp(since_ts).strftime('%Y-%m-%d %H:%M')})"
                         if since_ts else "")
            sev = conditions[key].get("severity", 20)
            color = "#dc2626" if sev >= 30 else "#d97706"
            alert_lines_text += f"    ⚠ {title}{since_str}\n"
            alert_lines_html += (
                f'<div style="color:{color};margin-left:16px">'
                f'&#9888; {render.esc(title)}'
                f'<span style="color:#999;font-size:11px">{render.esc(since_str)}</span>'
                f'</div>')

        info = f" — {model}" if model else ""
        ver_str = f" RouterOS {version}" if version else ""
        rows_text.append(
            f"[{status}] {identity}{info}{ver_str}\n"
            + (alert_lines_text if alert_lines_text else "    ✓ All checks healthy\n"))
        status_color = "#16a34a" if not active_alerts and reachable else "#dc2626"
        rows_html.append(
            f'<tr><td style="padding:6px 12px;font-weight:600">'
            f'<span style="color:{status_color}">{render.esc(status)}</span></td>'
            f'<td style="padding:6px 12px">{render.esc(identity)}'
            f'<span style="color:#64748b;font-size:12px"> {render.esc(info + ver_str)}</span></td>'
            f'<td style="padding:6px 12px">'
            + (alert_lines_html if alert_lines_html
               else '<span style="color:#16a34a">&#10003; Healthy</span>')
            + '</td></tr>')

    total = len(device_names)
    summary = (f"{total} device(s): {len(healthy)} healthy"
               + (f", {len(problems)} with alerts" if problems else ""))

    text_body = (
        f"EasyMikrotik {schedule_label} Status Report\n"
        f"{org_name}  |  {now_str}\n"
        f"{'=' * 50}\n"
        f"{summary}\n\n"
        + "\n".join(rows_text)
        + "\n-- EasyMikrotik\n"
    )
    html_body = (
        f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111">'
        f'<h2 style="color:#2563eb;margin-bottom:4px">EasyMikrotik {schedule_label} Report</h2>'
        f'<p style="color:#64748b;margin-top:0">{render.esc(org_name)} &mdash; {now_str}</p>'
        f'<p style="background:#f1f5f9;padding:8px 12px;border-radius:4px">{render.esc(summary)}</p>'
        f'<table style="border-collapse:collapse;width:100%">'
        f'<tr style="background:#f8fafc"><th style="padding:6px 12px;text-align:left">Status</th>'
        f'<th style="padding:6px 12px;text-align:left">Device</th>'
        f'<th style="padding:6px 12px;text-align:left">Alerts</th></tr>'
        + "".join(rows_html)
        + f'</table>'
        f'<p style="color:#999;font-size:12px;margin-top:16px">— EasyMikrotik</p></div>'
    )
    return subject, text_body, html_body


class OrgEmailNotifier(Notifier):
    """Delivers WAN alerts and scheduled reports to each org's recipient list."""
    name = "org_email"

    def __init__(self, smtp_cfg, auth_db_path: str, devices_db_path: str):
        self._smtp = smtp_cfg
        self._auth_db = auth_db_path
        self._devices_db = devices_db_path

    def send(self, alerts) -> None:
        targets = [a for a in alerts if _should_notify(a)]
        if not targets:
            return

        from ..auth import AuthStore
        from ..devices_store import DevicesStore

        try:
            ds = DevicesStore(self._devices_db)
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier: cannot open stores: %s", exc)
            return

        try:
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
                    self._deliver(recipients, org_alerts)
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
        from ..auth import AuthStore, _next_report_due
        now = time.time()
        try:
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier.check_scheduled: cannot open auth DB: %s", exc)
            return
        try:
            due = auth.orgs_with_report_due(now)
            if not due:
                return
            state_data = state.data if state is not None else {}
            prefix = self._smtp.subject_prefix
            for org in due:
                recipients = org["alert_emails"]
                if not recipients:
                    auth.set_report_next_due(
                        org["org_id"],
                        _next_report_due(org["schedule"], now))
                    continue
                dev_names = (devices_store.names_for_org(org["org_id"])
                             if devices_store else [])
                try:
                    subj, txt, htm = _build_report(
                        org["name"], dev_names, state_data,
                        org["schedule"], prefix)
                    msg = EmailMessage()
                    msg["Subject"] = subj
                    msg["From"] = self._smtp.from_addr
                    msg["To"] = ", ".join(recipients)
                    msg.set_content(txt)
                    msg.add_alternative(htm, subtype="html")
                    _smtp_send(self._smtp, msg)
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

    def _deliver(self, to_addrs: list[str], alerts) -> None:
        subject = render.subject(self._smtp.subject_prefix, alerts)
        text = render.render_text(alerts)
        html = render.render_html(alerts)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._smtp.from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        try:
            _smtp_send(self._smtp, msg)
            log.info("Org WAN alert sent to %d recipient(s): %s",
                     len(to_addrs), subject)
        except (smtplib.SMTPException, OSError, socket.error) as exc:
            log.error("Org WAN alert delivery failed: %s", exc)
