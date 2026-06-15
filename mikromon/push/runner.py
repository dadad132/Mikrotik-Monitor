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
from .reconcile import reconcile_list

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
    def __init__(self, cfg, api, dry_run: bool = True):
        self.cfg = cfg
        self.api = api          # PushApi-like (fetch/execute)
        self.dry_run = dry_run

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
    def plan_managed_list(self, path, key, desired, *, manage_tag,
                          label="rule") -> Plan:
        current = self.api.fetch(tuple(path))
        ops = reconcile_list(tuple(path), key, desired, current,
                             manage_tag=manage_tag, label=label)
        return Plan(self.cfg.name, ops, summary=label + "s")

    # ----- preview / apply --------------------------------------------------
    def apply(self, plan: Plan, rollback_on_error: bool = True) -> dict:
        """Dry-run by default. When committed, execute every op; if one fails,
        undo the ones already done (in reverse) using their inverses."""
        if self.dry_run:
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
        except PushError:
            rolled = self._rollback(done) if rollback_on_error else 0
            raise PushError(
                f"apply failed after {len(done)} op(s); "
                f"rolled back {rolled}.") from None
        return {"dry_run": False, "applied": len(done)}

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
