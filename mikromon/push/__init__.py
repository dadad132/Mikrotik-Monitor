"""Config-push (read-write) engine.

The *read* side of mikromon (monitoring, dashboard) never changes a router.
This package is the deliberately separate, opt-in *write* side: it renders a
desired configuration, diffs it against what is on the router, shows that diff
(dry-run), and only applies it when asked — capturing an inverse for every
operation so a half-applied change can be rolled back automatically.

Safety model:
  * Pushes authenticate with SEPARATE read-write credentials
    (`push_username`/`push_password`); the monitor user stays read-only.
  * Everything is **dry-run by default** — you see the plan before anything
    is written.
  * Managed resources are scoped by a comment tag, so rules a human created by
    hand are never touched or deleted.
  * apply() rolls back completed operations if a later one fails.
"""
from .audit import AuditLog
from .features import (FEATURES, TAB_SLUGS, adopt_plan, provision_apply,
                       wireguard_repair)
from .plan import Operation, Plan
from .reconcile import reconcile_list
from .runner import Pusher, PushError, rw_device

__all__ = ["Operation", "Plan", "reconcile_list", "Pusher", "PushError",
           "rw_device", "AuditLog", "FEATURES", "TAB_SLUGS", "adopt_plan",
           "provision_apply", "wireguard_repair"]
