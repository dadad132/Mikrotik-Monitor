"""CheckContext — the bridge between a check and the alerting/state machinery.

Checks never build Alerts directly. Instead they describe observations and the
context decides whether an alert is warranted:

  * ctx.transition(...)  — a two-state condition (healthy <-> problem). Fires a
    problem alert when it flips bad and a recovery alert when it flips good.
    Supports `confirm` (N consecutive bad polls required) for flap dampening.

  * ctx.threshold(...)   — a numeric value graded ok / warn / crit. Fires when
    the grade changes, picking WARNING or CRITICAL automatically.

  * ctx.event(...)       — a point-in-time event (reboot, new login, config
    change). The check is responsible for de-duplicating via ctx.memory().
"""
from __future__ import annotations

import time

from .alert import Alert, Severity
from .util import human_duration


class CheckContext:
    def __init__(self, device: str, store, now: float | None = None,
                 default_confirm: int = 1):
        self.device = device
        self.store = store
        self.now = now if now is not None else time.time()
        self.default_confirm = max(1, int(default_confirm))
        self.alerts: list[Alert] = []
        self.samples: list[tuple] = []  # (metric, value, label) for the metrics store

    # ----- metrics ----------------------------------------------------------
    def sample(self, metric: str, value, label: str = "") -> None:
        """Record a numeric time-series sample for the dashboard/Prometheus."""
        try:
            self.samples.append((metric, float(value), label))
        except (TypeError, ValueError):
            pass

    # ----- helpers ----------------------------------------------------------
    def memory(self, namespace: str) -> dict:
        return self.store.memory(self.device, namespace)

    def _emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    # ----- two-state conditions --------------------------------------------
    def transition(self, key: str, healthy: bool, *, severity: Severity,
                   title: str, detail: str = "", cause: str = "",
                   facts: dict | None = None, recovery_title: str | None = None,
                   recovery_detail: str = "", confirm: int | None = None) -> None:
        """Track a healthy/problem condition and alert only on confirmed flips."""
        confirm = self.default_confirm if confirm is None else max(1, int(confirm))
        cond = self.store.condition(self.device, key)
        status = cond.get("status", "ok")  # assume healthy until proven otherwise
        desired = "ok" if healthy else "problem"

        if desired == status:
            cond["pending"] = None
            cond["pending_n"] = 0
            return

        # Debounce: require `confirm` consecutive observations of the new state.
        if cond.get("pending") == desired:
            cond["pending_n"] = cond.get("pending_n", 0) + 1
        else:
            cond["pending"] = desired
            cond["pending_n"] = 1
        if cond["pending_n"] < confirm:
            return

        prev_since = cond.get("since", self.now)
        cond["status"] = desired
        cond["since"] = self.now
        cond["pending"] = None
        cond["pending_n"] = 0

        if desired == "problem":
            self._emit(Alert(self.device, key, severity, title, detail, cause,
                             recovery=False, ts=self.now, facts=facts or {}))
        else:
            dur = human_duration(self.now - prev_since)
            self._emit(Alert(
                self.device, key, Severity.INFO,
                recovery_title or f"Resolved: {title}",
                recovery_detail or f"Condition cleared after {dur}.",
                cause="", recovery=True, ts=self.now,
                facts={**(facts or {}), "down_for": dur},
            ))

    # ----- graded numeric thresholds ---------------------------------------
    def threshold(self, key: str, value: float, *, warn: float, crit: float,
                  what: str, unit: str = "", higher_is_bad: bool = True,
                  cause: str = "", fmt=None) -> None:
        """Grade a numeric value ok/warn/crit and alert when the grade changes."""
        def grade(v):
            if higher_is_bad:
                if v >= crit:
                    return "crit"
                return "warn" if v >= warn else "ok"
            else:
                if v <= crit:
                    return "crit"
                return "warn" if v <= warn else "ok"

        shown = fmt(value) if fmt else f"{value:g}{unit}"
        cond = self.store.condition(self.device, key)
        old = cond.get("level", "ok")
        new = grade(value)
        if new == old:
            return
        cond["level"] = new
        cond["since"] = self.now

        if new == "ok":
            self._emit(Alert(self.device, key, Severity.INFO,
                             f"{what} back to normal ({shown})",
                             recovery=True, ts=self.now))
        else:
            sev = Severity.CRITICAL if new == "crit" else Severity.WARNING
            self._emit(Alert(self.device, key, sev,
                             f"{what} {new.upper()}: {shown}",
                             cause=cause, ts=self.now,
                             facts={"value": value, "level": new}))

    # ----- point-in-time events --------------------------------------------
    def event(self, key: str, severity: Severity, title: str, *, detail: str = "",
              cause: str = "", facts: dict | None = None) -> None:
        self._emit(Alert(self.device, key, severity, title, detail, cause,
                         recovery=False, ts=self.now, facts=facts or {}))
