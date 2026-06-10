"""File-outbox notifier.

Writes each alert digest to a local folder as a `.eml` (openable in any mail
client) and a `.html` (openable in a browser). Lets you see exactly what the IT
admin would receive — no SMTP server required. Ideal for local testing/demos.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from email.message import EmailMessage

from . import render
from .base import Notifier

log = logging.getLogger(__name__)


class OutboxNotifier(Notifier):
    name = "outbox"

    def __init__(self, directory: str = "outbox", min_severity=None,
                 subject_prefix: str = "[MikroMon]"):
        from ..alert import Severity

        self.directory = directory
        self.min_severity = min_severity or Severity.INFO
        self.subject_prefix = subject_prefix
        self._seq = 0

    def send(self, alerts) -> None:
        alerts = self.applicable(alerts)
        if not alerts:
            return
        subject = render.subject(self.subject_prefix, alerts)
        self._write(subject, render.render_text(alerts), render.render_html(alerts))

    def send_test(self) -> None:
        self._write(f"{self.subject_prefix} Test", "Outbox test message.",
                    "<p>Outbox test message.</p>")

    def _write(self, subject: str, text: str, html: str) -> None:
        os.makedirs(self.directory, exist_ok=True)
        # Microseconds + a per-instance counter guarantee unique filenames even
        # when many digests are written within the same second (e.g. the demo).
        self._seq += 1
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        base = os.path.join(self.directory, f"{stamp}-{self._seq:03d}")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = "mikromon@localhost"
        msg["To"] = "itadmin@localhost"
        msg["Date"] = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
        with open(base + ".eml", "wb") as fh:
            fh.write(bytes(msg))
        with open(base + ".html", "w", encoding="utf-8") as fh:
            fh.write(html)
        log.info("Wrote alert digest to %s.eml / .html (%s)", base, subject)
