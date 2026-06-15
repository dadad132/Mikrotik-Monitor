"""Thin read-write wrapper over librouteros that executes plan Operations.

Kept deliberately small and side-effect-only so the risky decision-making lives
in the (pure, unit-tested) reconcile/runner layers. Any object with the same
fetch()/execute() shape can stand in for this — the tests inject a fake.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class PushError(Exception):
    """Raised when a read-write operation cannot be carried out."""


class PushApi:
    def __init__(self, device):
        self.device = device  # a mikromon.device.Device opened with RW creds

    def connect(self):
        self.device.connect()
        return self

    def close(self):
        self.device.close()

    def fetch(self, path) -> list:
        """Read all rows from a menu path (e.g. ("ip","firewall","filter"))."""
        return list(self.device.api.path(*path))

    def execute(self, op):
        """Carry out one Operation. Returns the new id for an 'add'."""
        api = self.device.api
        if api is None:
            raise PushError("not connected")
        path = api.path(*op.path)
        try:
            if op.action == "add":
                return path.add(**op.params)
            if op.action == "set":
                path.update(**op.params)
                return None
            if op.action == "remove":
                path.remove(op.params[".id"])
                return None
            if op.action == "run":
                params = dict(op.params)
                cmd = params.pop("_cmd", "")
                return list(api.path(*op.path)(cmd, **params))
        except Exception as exc:  # noqa: BLE001 — normalize to PushError
            raise PushError(f"{op.action} {op.menu()} failed: {exc}") from exc
        raise PushError(f"unknown action {op.action!r}")
