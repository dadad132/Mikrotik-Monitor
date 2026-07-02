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
from email.message import EmailMessage

from . import render
from .base import Notifier

log = logging.getLogger(__name__)

_NOTIFY_KEYS = {"wan_failover", "internet_down", "reachability"}


def _should_notify(alert) -> bool:
    return alert.key in _NOTIFY_KEYS or alert.key.startswith("wan_link:")


class OrgEmailNotifier(Notifier):
    """Delivers WAN alerts to each org's alert recipients list."""
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
        pass  # test-email uses the standard EmailNotifier

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
            if self._smtp.use_ssl:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(self._smtp.host, self._smtp.port,
                                      timeout=20, context=ctx) as srv:
                    self._login_send(srv, msg)
            else:
                with smtplib.SMTP(self._smtp.host, self._smtp.port, timeout=20) as srv:
                    if self._smtp.use_tls:
                        srv.starttls(context=ssl.create_default_context())
                    self._login_send(srv, msg)
            log.info("Org WAN alert sent to %d recipient(s): %s",
                     len(to_addrs), subject)
        except (smtplib.SMTPException, OSError, socket.error) as exc:
            log.error("Org WAN alert delivery failed: %s", exc)

    def _login_send(self, srv, msg) -> None:
        if self._smtp.username:
            srv.login(self._smtp.username, self._smtp.password)
        srv.send_message(msg)
