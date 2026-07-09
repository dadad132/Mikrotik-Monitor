"""Notification layer.

`build_notifiers(config)` returns the configured channels. The layer is
deliberately pluggable: add a TelegramNotifier / WebhookNotifier with the same
`send(alerts)` interface and wire it in here — the engine stays unchanged.
"""
from __future__ import annotations

from .base import Notifier  # noqa: F401  (re-export)
from .email_smtp import EmailNotifier
from .file_outbox import OutboxNotifier
from .org_email import OrgEmailNotifier  # noqa: F401  (re-export)


def build_notifiers(config):
    notifiers = []
    if config.smtp:
        notifiers.append(EmailNotifier(config.smtp))
    if getattr(config, "outbox_dir", None):
        prefix = config.smtp.subject_prefix if config.smtp else "[MikroMon]"
        notifiers.append(OutboxNotifier(config.outbox_dir, subject_prefix=prefix))
    # Multi-tenant mode: route WAN alerts to per-org recipients.
    if (config.smtp
            and getattr(config, "auth_db", None)
            and getattr(config, "devices_db", None)):
        notifiers.append(OrgEmailNotifier(
            config.smtp, config.auth_db, config.devices_db,
            alert_log_db=getattr(config, "alert_log_db", None)))
    return notifiers
