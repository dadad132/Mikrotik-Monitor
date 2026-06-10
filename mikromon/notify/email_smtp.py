"""Email/SMTP notifier.

All alerts produced in a single poll are delivered as ONE digest email (grouped
by device, worst severity in the subject) so a multi-device incident doesn't
flood the admin's inbox with dozens of separate messages.
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


class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, cfg):
        self.cfg = cfg
        self.min_severity = cfg.min_severity

    def send(self, alerts) -> None:
        alerts = self.applicable(alerts)
        if not alerts:
            return
        self._deliver(render.subject(self.cfg.subject_prefix, alerts),
                      render.render_text(alerts), render.render_html(alerts))

    def send_test(self) -> None:
        subject = f"{self.cfg.subject_prefix} Test — monitoring is configured"
        body = ("This is a test message from MikroTik Monitor (mikromon).\n"
                "If you received it, email alerting is working.\n")
        self._deliver(subject, body, f"<p>{body.replace(chr(10), '<br>')}</p>")

    # ----- back-compat helpers (also used by tests) -------------------------
    def _plain(self, alerts):
        return render.render_text(alerts)

    def _html(self, alerts):
        return render.render_html(alerts)

    # ----- transport --------------------------------------------------------
    def _deliver(self, subject: str, text: str, html: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.from_addr
        msg["To"] = ", ".join(self.cfg.to_addrs)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        try:
            if self.cfg.use_ssl:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.cfg.host, self.cfg.port,
                                      timeout=20, context=ctx) as srv:
                    self._login_send(srv, msg)
            else:
                with smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=20) as srv:
                    if self.cfg.use_tls:
                        srv.starttls(context=ssl.create_default_context())
                    self._login_send(srv, msg)
            log.info("Email sent: %s", subject)
        except (smtplib.SMTPException, OSError, socket.error) as exc:
            log.error("Failed to send email '%s': %s", subject, exc)

    def _login_send(self, srv, msg):
        if self.cfg.username:
            srv.login(self.cfg.username, self.cfg.password)
        srv.send_message(msg)
