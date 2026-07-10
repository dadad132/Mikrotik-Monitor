"""Persistent state store.

Everything that must survive between polls (and restarts) lives here:
  * the current status of each monitored condition (so we only alert on change),
  * per-check memory (known DHCP MACs, already-seen log lines, last uptime, ...).

Stored as a single JSON file, written atomically so a crash mid-write cannot
corrupt it.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile

log = logging.getLogger(__name__)


class StateStore:
    def __init__(self, path: str):
        self.path = path
        self.data: dict = {"version": 1, "devices": {}}

    # ----- persistence ------------------------------------------------------
    def load(self) -> "StateStore":
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh)
                self.data.setdefault("devices", {})
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not read state file %s (%s); starting fresh",
                            self.path, exc)
                self.data = {"version": 1, "devices": {}}
        return self

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)  # atomic on POSIX and Windows
        except OSError as exc:
            log.error("Failed to persist state to %s: %s", self.path, exc)
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ----- accessors --------------------------------------------------------
    def _device(self, name: str) -> dict:
        return self.data["devices"].setdefault(
            name, {"conditions": {}, "memory": {}}
        )

    def condition(self, device: str, key: str) -> dict:
        """Return the (live, mutable) condition record for a device+key.

        Mutating the returned dict is persisted on the next save().
        """
        return self._device(device)["conditions"].setdefault(key, {})

    def memory(self, device: str, namespace: str) -> dict:
        """Return a (live, mutable) per-check scratch dict."""
        return self._device(device)["memory"].setdefault(namespace, {})

    def facts(self, device: str) -> dict:
        """Return a (live, mutable) dict of device inventory facts
        (model, RouterOS version, serial, identity, host, uptime)."""
        return self._device(device).setdefault("facts", {})

    def forget_device(self, name: str) -> None:
        self.data["devices"].pop(name, None)

    def prune_unknown_devices(self, known_names) -> None:
        """Drop state for devices no longer in the config."""
        for name in list(self.data["devices"]):
            if name not in known_names:
                log.info("Pruning state for removed device %s", name)
                self.data["devices"].pop(name, None)
