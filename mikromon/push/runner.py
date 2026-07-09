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

_ROS_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun",
               "jul", "aug", "sep", "oct", "nov", "dec"]


def _router_datetime(api) -> datetime.datetime | None:
    """Fetch the router's current date+time via the API clock resource."""
    try:
        rows = api.fetch(("system", "clock"))
        if not rows:
            return None
        c = rows[0]
        ds = str(c.get("date", ""))  # e.g. "jul/02/2026"
        ts = str(c.get("time", ""))  # e.g. "14:35:22"
        dp = ds.split("/")
        tp = ts.split(":")
        if len(dp) != 3 or len(tp) != 3:
            return None
        mon = _ROS_MONTHS.index(dp[0].lower()) + 1
        return datetime.datetime(int(dp[2]), mon, int(dp[1]),
                                 int(tp[0]), int(tp[1]), int(tp[2]))
    except Exception:
        return None


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

    # Prefixes for backups THIS app creates: on-demand ones from the Backups
    # tab ("mikromon-YYYYMMDD-HHMMSS") and the automatic pre-change safety net
    # ("before-<feature>-YYYYMMDD-HHMMSS", written by _device_push_post before
    # every committed config change). Both are pruned from the SAME pool of
    # `keep` so the router never accumulates more than that many regardless of
    # which one made them.
    _MANAGED_PREFIXES = ("mikromon-", "before-")

    @staticmethod
    def _backup_ts_key(fname: str) -> str:
        """The trailing YYYYMMDD-HHMMSS both naming schemes share, so sorting
        by it (rather than the whole name) interleaves the two prefixes in
        true chronological order instead of grouping alphabetically by
        prefix ("before-..." < "mikromon-..." for every timestamp)."""
        stem = fname[:-len(".backup")] if fname.endswith(".backup") else fname
        parts = stem.split("-")
        return "-".join(parts[-2:]) if len(parts) >= 2 else stem

    def _prune_backup_ops(self, keep: int) -> list:
        """Return remove ops for mikromon-created backups beyond the newest
        `keep`, across every prefix this app creates (see _MANAGED_PREFIXES).
        Backups the user created manually under any other name are never
        touched."""
        try:
            all_files = self.api.fetch(("file",))
        except Exception:
            return []
        managed = sorted(
            [r for r in all_files
             if str(r.get("name", "")).startswith(self._MANAGED_PREFIXES)
             and str(r.get("name", "")).endswith(".backup")],
            key=lambda r: self._backup_ts_key(str(r.get("name", ""))),
            reverse=True,  # newest first
        )
        return [
            Operation("remove", ("file",), {".id": r[".id"]},
                      desc=f"prune old backup '{r['name']}'")
            for r in managed[keep:] if r.get(".id")
        ]

    def plan_tempuser(self, *, username: str, password: str,
                      group: str = "read", allowed_ip: str = "",
                      duration_mins: int = 30) -> Plan:
        """Create a temporary local router user that auto-deletes after duration_mins.

        A RouterOS scheduler entry is created alongside the user; when it fires
        it removes the user and then removes itself. The user's source-IP can be
        restricted to `allowed_ip` (CIDR or bare IP); leave empty for no restriction.
        """
        sched_name = f"mm-tmpd-{username}"
        now = _router_datetime(self.api) or datetime.datetime.now()
        expiry = now + datetime.timedelta(minutes=duration_mins)
        exp_date = f"{_ROS_MONTHS[expiry.month - 1]}/{expiry.day:02d}/{expiry.year}"
        exp_time = expiry.strftime("%H:%M:%S")
        on_event = (f'/user remove [find name="{username}"]\r\n'
                    f'/system scheduler remove [find name="{sched_name}"]')
        user_params: dict = {"name": username, "password": password,
                             "group": group, "comment": "mikromon:tempuser"}
        if allowed_ip:
            user_params["address"] = (allowed_ip if "/" in allowed_ip
                                      else f"{allowed_ip}/32")
        add_user = Operation(
            "add", ("user",), user_params,
            desc=f"create temp user '{username}' (expires in {duration_mins} min)",
            inverse=Operation("remove", ("user",), {},
                              desc=f"remove temp user '{username}'"))
        add_sched = Operation(
            "add", ("system", "scheduler"), {
                "name": sched_name,
                "start-date": exp_date, "start-time": exp_time,
                "interval": "00:00:00",
                "on-event": on_event,
                "policy": "read,write,policy",
                "comment": "mikromon:tempuser",
            },
            desc=f"auto-delete temp user at {exp_date} {exp_time}",
            inverse=Operation("remove", ("system", "scheduler"), {},
                              desc=f"cancel auto-delete for '{username}'"))
        return Plan(self.cfg.name, [add_user, add_sched], summary="temp user")

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
