"""Pusher: turn intent into a Plan, preview it, and apply it with rollback.

This is the engine the future GUI tabs (SD-WAN, Security, NextDNS, QoS,
Port-forwarding, Backups) call into. It is transport-agnostic: it talks to any
object exposing fetch()/execute() (the real PushApi, or a fake in tests).
"""
from __future__ import annotations

import copy
import datetime
import logging

from .api import PushError
from .plan import Operation, Plan
from .reconcile import _norm, reconcile_list

log = logging.getLogger(__name__)


def rw_device(cfg):
    """Build a Device that authenticates with the read-write push credentials
    (falling back to the monitor credentials when none are set)."""
    from ..device import Device

    c = copy.copy(cfg)
    if cfg.push_username:
        c.username = cfg.push_username
        c.password = cfg.push_password
    return Device(c)


class Pusher:
    def __init__(self, cfg, api, dry_run: bool = True, audit=None, user=""):
        self.cfg = cfg
        self.api = api          # PushApi-like (fetch/execute)
        self.dry_run = dry_run
        self.audit = audit      # optional AuditLog
        self.user = user        # who is driving this push (for the log)

    # ----- backups (the safest write: a single, reversible-by-nature save) --
    def list_backups(self) -> list:
        rows = self.api.fetch(("file",))
        out = []
        for r in rows:
            name = str(r.get("name", ""))
            if name.endswith(".backup") or name.endswith(".rsc"):
                out.append({"name": name, "size": r.get("size", ""),
                            "time": r.get("creation-time", "")})
        out.sort(key=lambda x: x.get("time", ""), reverse=True)
        return out

    def plan_backup(self, name: str | None = None) -> Plan:
        name = name or ("mikromon-" +
                        datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        op = Operation("run", ("system", "backup"),
                       {"_cmd": "save", "name": name},
                       desc=f"create backup '{name}.backup' on the router")
        return Plan(self.cfg.name, [op], summary="backup")

    # ----- generic managed-list reconcile (firewall, NAT, queues, …) --------
    def plan_managed_list(self, path, key, desired, *, manage_tag=None,
                          owns=None, label="rule") -> Plan:
        current = self.api.fetch(tuple(path))
        ops = reconcile_list(tuple(path), key, desired, current,
                             manage_tag=manage_tag, owns=owns, label=label)
        return Plan(self.cfg.name, ops, summary=label + "s")

    # ----- a singleton settings menu (e.g. /ip/dns) -------------------------
    def plan_settings(self, path, desired, *, label="settings") -> Plan:
        current = self.api.fetch(tuple(path))
        row = current[0] if current else {}
        changed = {f: v for f, v in desired.items()
                   if _norm(row.get(f, "")) != _norm(v)}
        ops = []
        if changed:
            params = dict(changed)
            old = {f: row.get(f, "") for f in changed}
            if ".id" in row:
                params[".id"] = old[".id"] = row[".id"]
            menu = "/" + "/".join(path)
            ops.append(Operation(
                "set", tuple(path), params,
                desc=f"update {menu}: " +
                     ", ".join(f"{f}={v}" for f, v in changed.items()),
                inverse=Operation("set", tuple(path), old,
                                  desc=f"revert {menu}")))
        return Plan(self.cfg.name, ops, summary=label)

    # ----- preview / apply --------------------------------------------------
    def apply(self, plan: Plan, rollback_on_error: bool = True,
              feature: str = "") -> dict:
        """Dry-run by default. When committed, execute every op; if one fails,
        undo the ones already done (in reverse) using their inverses. Every
        outcome (preview / ok / error) is written to the audit log."""
        if self.dry_run:
            self._log(feature, "dry-run", "preview", plan.summary or "preview",
                      plan.diff_text())
            return {"dry_run": True, "changes": len(plan.ops),
                    "diff": plan.diff_text()}
        done: list[Operation] = []
        try:
            for op in plan.ops:
                result = self.api.execute(op)
                # An add's inverse needs the id the router just assigned.
                if op.action == "add" and op.inverse is not None and result:
                    op.inverse.params[".id"] = result
                done.append(op)
        except PushError as exc:
            rolled = self._rollback(done) if rollback_on_error else 0
            detail = (plan.diff_text() + f"\n\nFAILED after {len(done)} op(s): "
                      f"{exc}\nRolled back {rolled} op(s).")
            self._log(feature, "apply", "error",
                      f"failed: {exc}", detail)
            raise PushError(
                f"apply failed after {len(done)} op(s); "
                f"rolled back {rolled}. {exc}") from None
        self._log(feature, "apply", "ok",
                  f"{len(done)} change(s) applied", plan.diff_text())
        return {"dry_run": False, "applied": len(done)}

    def _log(self, feature, mode, status, summary, detail) -> None:
        if self.audit is not None:
            self.audit.append(self.cfg.name, self.user, feature, mode, status,
                              summary, detail)

    def _rollback(self, done) -> int:
        undone = 0
        for op in reversed(done):
            if op.inverse is None:
                continue
            try:
                self.api.execute(op.inverse)
                undone += 1
            except PushError:
                log.exception("rollback step failed: %s", op.inverse.line())
        return undone
