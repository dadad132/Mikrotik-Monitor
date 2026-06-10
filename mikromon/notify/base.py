"""Notifier interface."""
from __future__ import annotations

from ..alert import Alert, Severity


class Notifier:
    name = "notifier"
    min_severity: Severity = Severity.INFO

    def applicable(self, alerts):
        """Filter a batch down to alerts this channel should deliver."""
        return [a for a in alerts if a.severity >= self.min_severity]

    def send(self, alerts: "list[Alert]") -> None:
        raise NotImplementedError

    def send_test(self) -> None:
        """Send a 'monitoring is working' test message."""
        raise NotImplementedError
