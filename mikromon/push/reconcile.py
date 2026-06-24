"""Idempotent reconciliation of a RouterOS "list" resource.

Given the rows we *want* and the rows currently on the router, produce the
minimal set of add / set / remove Operations to converge them — each with an
inverse for rollback. This is the heart of config-push: firewall rules,
address-lists, NAT/port-forwards, simple queues (QoS), NextDNS bypass lists,
etc. are all "managed lists".

Safety: when `manage_tag` is given, only rows whose `comment` equals that tag
are considered ours. Rules a human created by hand have a different (or no)
comment, so they are never modified or deleted — we only own what we created.
"""
from __future__ import annotations

from .plan import Operation


def _norm(v) -> str:
    """RouterOS returns everything as strings; compare booleans/ints loosely."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def reconcile_list(path, key, desired, current, *, manage_tag=None,
                   owns=None, label="rule"):
    """Return a list of Operations to make `current` match `desired`.

    path        RouterOS menu path tuple, e.g. ("ip","firewall","address-list")
    key         field used to match a desired row to an existing one (e.g. "address")
    desired     list of dicts: the params each managed row should have
    current     list of dicts as read from the router (each incl. ".id", "comment")
    manage_tag  if set, the default `comment` stamped on rows we create
    owns        optional predicate(row)->bool deciding which existing rows are
                ours (defaults to comment == manage_tag). Use this for features
                that own several rules sharing a comment *prefix*.
    """
    ops: list[Operation] = []

    if owns is None:
        def owns(row):
            return manage_tag is None or str(row.get("comment", "")) == manage_tag

    def owned(row) -> bool:
        return owns(row)

    cur_owned = [r for r in current if owned(r)]
    # De-duplicate rows we own that share a key. Older, non-idempotent builds
    # could stack several identical managed rows (same comment / public-key /
    # address); keep the FIRST ("the open one") and remove the rest so every
    # apply converges on a single rule instead of letting duplicates pile up.
    cur_by_key = {}
    for r in cur_owned:
        k = r.get(key)
        if k in cur_by_key:
            ops.append(Operation(
                "remove", path, {".id": r[".id"]},
                desc=f"remove duplicate {label} {key}={k}",
                inverse=Operation(
                    "add", path, {f: v for f, v in r.items() if f != ".id"},
                    desc=f"restore duplicate {label} {key}={k}")))
        else:
            cur_by_key[k] = r
    desired_keys = set()

    for raw in desired:
        d = dict(raw)
        if manage_tag is not None:
            d.setdefault("comment", manage_tag)
        k = d.get(key)
        desired_keys.add(k)
        cur = cur_by_key.get(k)
        if cur is None:
            # create — inverse is "remove the row we add" (id filled in at apply)
            ops.append(Operation(
                "add", path, d,
                desc=f"add {label} {key}={k}",
                inverse=Operation("remove", path, {},
                                  desc=f"remove added {label} {key}={k}")))
        else:
            changed = {f: v for f, v in d.items()
                       if f != ".id" and _norm(cur.get(f, "")) != _norm(v)}
            if changed:
                params = {".id": cur[".id"], **changed}
                old = {".id": cur[".id"],
                       **{f: cur.get(f, "") for f in changed}}
                ops.append(Operation(
                    "set", path, params,
                    desc=f"update {label} {key}={k}: " +
                         ", ".join(f"{f}={v}" for f, v in changed.items()),
                    inverse=Operation("set", path, old,
                                      desc=f"revert {label} {key}={k}")))

    # removals: rows we own that are no longer desired
    for k, r in cur_by_key.items():
        if k not in desired_keys:
            restore = {f: v for f, v in r.items() if f != ".id"}
            ops.append(Operation(
                "remove", path, {".id": r[".id"]},
                desc=f"remove {label} {key}={k}",
                inverse=Operation("add", path, restore,
                                  desc=f"restore {label} {key}={k}")))
    return ops
