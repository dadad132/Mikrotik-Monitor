"""The Alert model and severity levels.

An Alert always answers two questions for the IT admin:
  * WHAT happened  -> `title` (+ optional `detail`)
  * WHY it happened -> `cause` (best-effort, derived from router data)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 10
    WARNING = 20
    CRITICAL = 30

    @property
    def label(self) -> str:
        return self.name

    @property
    def emoji(self) -> str:
        return {self.INFO: "ℹ️", self.WARNING: "⚠️", self.CRITICAL: "🔴"}[self]

    @classmethod
    def parse(cls, value, default: "Severity | None" = None) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                pass
        if default is not None:
            return default
        raise ValueError(f"Unknown severity: {value!r}")


@dataclass
class Alert:
    device: str               # device name the alert is about
    key: str                  # stable condition key, e.g. "wan_failover"
    severity: Severity
    title: str                # WHAT happened (one line)
    detail: str = ""          # extra human-readable context
    cause: str = ""           # WHY it happened (best-effort)
    recovery: bool = False    # True => this is a "cleared / back to normal" notice
    ts: float = field(default_factory=time.time)
    facts: dict = field(default_factory=dict)  # structured extras for the record

    def one_line(self) -> str:
        sev = "RESOLVED" if self.recovery else self.severity.label
        return f"[{sev}] {self.device}: {self.title}"
