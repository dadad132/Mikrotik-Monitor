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

# Name of the on-router scheduler that performs the commit-confirm auto-revert.
_REVERT_SCHED = "mikromon-autorevert"


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
                out.append({"id": r.get(".id"), "name": name,
                            "size": r.get("size", ""),
                            "time": r.get("creation-time", "")})
        out.sort(key=lambda x: x.get("time", ""), reverse=True)
        return out

    def plan_backup(self, name: str | None = None, keep: int = 10) -> Plan:
        name = name or ("mikromon-" +
                        datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        # dont-encrypt=yes so the restore (load) works without a password prompt
        # — the file lives on the router's own flash, which already requires
        # router access to read.
        op = Operation("run", ("system", "backup"),
                       {"_cmd": "save", "name": name, "dont-encrypt": "yes"},
                       desc=f"create backup '{name}.backup' on the router")
        # Prune old server-created backups in the same plan so the router never
        # accumulates more than `keep` mikromon backups.  We delete `keep-1`
        # from the current list because one new backup is about to be added.
        return Plan(self.cfg.name, [op] + self._prune_backup_ops(keep - 1),
                    summary="backup")

    def _prune_backup_ops(self, keep: int) -> list:
        """Return remove ops for mikromon-created backups beyond the newest `keep`."""
        try:
            all_files = self.api.fetch(("file",))
        except Exception:
            return []
        managed = sorted(
            [r for r in all_files
             if str(r.get("name", "")).startswith("mikromon-")
             and str(r.get("name", "")).endswith(".backup")],
            key=lambda r: r.get("creation-time", ""),
            reverse=True,  # newest first
        )
        return [
            Operation("remove", ("file",), {".id": r[".id"]},
                      desc=f"prune old backup '{r['name']}'")
            for r in managed[keep:] if r.get(".id")
        ]

    def plan_restore(self, name: str) -> Plan:
        """Restore a .backup file. RouterOS REBOOTS to apply, so this is a
        detached run (the API session drops — treated as submitted)."""
        if not name.endswith(".backup"):
            name += ".backup"
        op = Operation("run", ("system", "backup"),
                       {"_cmd": "load", "name": name},
                       desc=f"restore backup '{name}' (REBOOTS the router)",
                       detach=True)
        return Plan(self.cfg.name, [op], summary=f"restore {name}")

    def plan_delete_backup(self, name: str) -> Plan:
        """Delete a backup file from the router by its name."""
        fid = next((r.get(".id") for r in self.api.fetch(("file",))
                    if str(r.get("name", "")) == name), None)
        if fid is None:
            return Plan(self.cfg.name, [], summary="delete backup (not found)")
        op = Operation("remove", ("file",), {".id": fid},
                       desc=f"delete backup file '{name}'")
        return Plan(self.cfg.name, [op], summary=f"delete {name}")

    # ----- commit-confirm auto-revert (safe mode) ---------------------------
    def plan_arm_revert(self, backup_name: str, minutes: int = 2,
                        hub_ip: str = "10.10.0.1") -> Plan:
        """Arm a local scheduler that, `minutes` after a change, VERIFIES the
        router can still reach the management hub and reverts to `backup_name`
        if it can't.

        Why connectivity-checked rather than "revert unless a human cancels":
        a bad change often only bites a minute or two later, so a human clicking
        'approve' early would cancel the net before the failure shows. Here the
        router itself decides — at the mark it pings the hub; if it gets NO
        replies the change cut us off, so it restores the backup (reboot into the
        pre-change config); if it can still reach the hub the change is safe and
        the scheduler just removes itself. Runs on the router, so it works even
        when the box is otherwise unreachable from outside."""
        if not backup_name.endswith(".backup"):
            backup_name += ".backup"
        event = (f':if ([/ping {hub_ip} count=4] = 0) do={{'
                 f'/system backup load name="{backup_name}"'
                 f'}} else={{'
                 f'/system scheduler remove [find name="{_REVERT_SCHED}"]'
                 f'}}')
        op = Operation(
            "add", ("system", "scheduler"),
            {"name": _REVERT_SCHED, "interval": f"{int(minutes)}m",
             "on-event": event, "comment": "mikromon:autorevert",
             "policy": "ftp,reboot,read,write,policy,test,password,"
                       "sensitive,romon"},
            desc=f"arm auto-revert to {backup_name} in {minutes} min unless the "
                 f"router can still reach the hub ({hub_ip})")
        return Plan(self.cfg.name, [op], summary="arm auto-revert")

    def plan_disarm_revert(self) -> Plan:
        """Cancel the pending auto-revert (the user approved the change)."""
        sid = next((s.get(".id") for s in self.api.fetch(("system", "scheduler"))
                    if s.get("name") == _REVERT_SCHED), None)
        if sid is None:
            return Plan(self.cfg.name, [], summary="auto-revert already cleared")
        op = Operation("remove", ("system", "scheduler"), {".id": sid},
                       desc="confirm change — cancel the pending auto-revert")
        return Plan(self.cfg.name, [op], summary="confirm (cancel auto-revert)")

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
