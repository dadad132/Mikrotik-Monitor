"""Security / 'strange activity' monitoring.

Sources, all read-only:
  * /log           — failed logins, successful logins, user add/remove.
  * /user/active   — currently logged-in sessions (detect NEW admin sessions).
  * /system/history— configuration changes (the RouterOS undo buffer).

De-duplication: every interesting item gets a stable signature stored in state,
so the same log line is never alerted twice — even across restarts. On the very
first poll of a device we *seed* the signatures silently, so you are not flooded
with the entire pre-existing log buffer when the monitor starts.
"""
from __future__ import annotations

from ..alert import Severity
from ..util import ip_in_subnets, short_hash
from .base import Check

_SEEN_CAP = 800  # max remembered signatures per stream


def _remember(mem: dict, stream: str, sig: str) -> bool:
    """Return True if `sig` is new for `stream`, recording it. Bounded."""
    seen = mem.setdefault(stream, [])
    if sig in seen:
        return False
    seen.append(sig)
    if len(seen) > _SEEN_CAP:
        del seen[: len(seen) - _SEEN_CAP]
    return True


def _source_ip(message: str) -> str:
    import re

    m = re.search(r"from\s+([0-9a-fA-F:.]+)", message)
    return m.group(1) if m else ""


class SecurityCheck(Check):
    flags = ("security",)
    requires = ("log", "history", "active", "users")
    name = "security"

    def run(self, snap, dev, ctx) -> None:
        mem = ctx.memory("security")
        seeding = not mem.get("initialized")

        self._scan_log(snap, dev, ctx, mem, seeding)
        self._scan_users(snap, dev, ctx, mem, seeding)
        self._scan_sessions(snap, dev, ctx, mem, seeding)
        self._scan_history(snap, ctx, mem, seeding)

        mem["initialized"] = True

    # ----- /log -------------------------------------------------------------
    def _scan_log(self, snap, dev, ctx, mem, seeding):
        for row in snap.rows("log")[-300:]:
            topics = str(row.get("topics", "")).lower()
            message = str(row.get("message", ""))
            low = message.lower()
            sig = short_hash(row.get("time"), topics, message)

            sev = None
            title = None
            cause = ""
            if "login failure" in low or ("login" in low and "failure" in low):
                sev = Severity.WARNING
                src = _source_ip(message)
                title = "Failed login attempt" + (f" from {src}" if src else "")
                cause = ("Someone tried to authenticate and failed. Repeated "
                         "failures may indicate a brute-force attempt.")
            elif "account" in topics and "logged in" in low:
                src = _source_ip(message)
                external = src and not ip_in_subnets(src, dev.lan_subnets)
                sev = Severity.WARNING if external else Severity.INFO
                title = "Admin login" + (f" from {src}" if src else "")
                cause = ("Login originated from outside the configured LAN "
                         "subnets." if external else "Administrative login.")
            elif ("user" in low and ("added" in low or "removed" in low)
                  and "account" in topics):
                sev = Severity.WARNING
                title = "User account changed"
                cause = "A RouterOS user account was added or removed."

            if sev is None:
                continue
            if not _remember(mem, "log", sig):
                continue
            if seeding:
                continue  # silently baseline pre-existing entries
            ctx.event(sig_key(sig), sev, title, detail=message, cause=cause,
                      facts={"topics": topics})

    # ----- /user (the account list, not sessions) ---------------------------
    def _scan_users(self, snap, dev, ctx, mem, seeding):
        """A login appearing on the router that was not there last poll.

        Read from /user directly rather than inferred from log lines. The log
        was the only source before, which meant the detection depended on the
        router still holding the relevant entry -- /log is a small ring buffer
        that a busy router overwrites in minutes, and the wording varies
        between RouterOS versions. The account list is the fact itself.

        Removal of somebody else's account is deliberately not alerted:
        that is usually us or the operator tidying up, and pairing every add
        with a remove alert is how people learn to filter the whole lot.

        OUR OWN account is the exception, and it is not a small one. Losing
        it ends the monitoring and the ability to put it back, and it is the
        first thing an intruder with full access removes.
        """
        if "users" in snap.errors:
            return                      # could not read it; say nothing
        current = {}
        for row in snap.rows("users"):
            nm = str(row.get("name", "")).strip()
            if nm:
                current[nm] = str(row.get("group", "") or "")

        known = set(mem.get("router_users", []))
        if not seeding:
            # Removals are otherwise ignored on purpose (see the docstring),
            # but OUR OWN account going is the single most consequential
            # change anyone can make to a router we manage: it ends both the
            # monitoring and the ability to put it back. Seen live, where it
            # was silent -- the router just began failing to authenticate,
            # which reads exactly like a password drifting out of step.
            ours = {str(getattr(dev.cfg, "username", "") or "").strip(),
                    str(getattr(dev.cfg, "push_username", "") or "").strip()}
            ours.discard("")
            for nm in sorted(ours & (known - set(current))):
                ctx.event(
                    f"router_user_gone:{nm}", Severity.CRITICAL,
                    f"The monitoring login '{nm}' was DELETED from this router",
                    cause=(f"'{nm}' is the account this dashboard uses to "
                           f"read and configure the router. It existed at "
                           f"the last check and is gone now, so monitoring "
                           f"and remote changes have both stopped. If nobody "
                           f"removed it deliberately, treat it as a "
                           f"compromise: whoever did it has full access and "
                           f"has just removed the thing that would notice. "
                           f"Re-run Provision from this device's page to "
                           f"recreate the login on the router and store the "
                           f"new password here in one step."),
                    facts={"user": nm},
                )
            for nm, group in sorted(current.items()):
                if nm in known:
                    continue
                grp = f" in group '{group}'" if group else ""
                ctx.event(
                    f"router_user:{nm}", Severity.WARNING,
                    f"New login '{nm}' created on the router",
                    cause=(f"A RouterOS account{grp} appeared that was not "
                           f"there at the last check. If you did not create "
                           f"it, treat this as a compromise: someone with "
                           f"access has given themselves a way back in that "
                           f"survives a password change."),
                    facts={"user": nm, "group": group},
                )
        mem["router_users"] = sorted(current)

    # ----- /user/active -----------------------------------------------------
    def _scan_sessions(self, snap, dev, ctx, mem, seeding):
        current = {}
        for row in snap.rows("active"):
            name = str(row.get("name", ""))
            address = str(row.get("address", ""))
            via = str(row.get("via", ""))
            sig = short_hash(name, address, via)
            current[sig] = (name, address, via)

        previous = set(mem.get("sessions", []))
        for sig, (name, address, via) in current.items():
            if sig in previous:
                continue
            if not seeding:
                external = address and not ip_in_subnets(address, dev.lan_subnets)
                sev = Severity.WARNING if external else Severity.INFO
                where = f" from {address}" if address else ""
                how = f" via {via}" if via else ""
                ctx.event(
                    sig_key("sess", sig), sev,
                    f"New session: user '{name}'{where}{how}",
                    cause=("Session opened from outside the LAN." if external
                           else "A new management session was opened."),
                    facts={"user": name, "address": address, "via": via},
                )
        mem["sessions"] = list(current.keys())

    # ----- /system/history --------------------------------------------------
    def _scan_history(self, snap, ctx, mem, seeding):
        for row in snap.rows("history"):
            action = str(row.get("action", "")).strip()
            by = str(row.get("by", "")).strip()
            if not action:
                continue
            sig = short_hash(row.get(".id"), action, by, row.get("message"))
            if not _remember(mem, "history", sig):
                continue
            if seeding:
                continue
            desc = action + (f" by {by}" if by else "")
            ctx.event(
                sig_key("hist", sig), Severity.INFO,
                f"Configuration changed: {desc}",
                detail=str(row.get("message", "")),
                cause="A configuration change was recorded in the RouterOS "
                      "history (undo) buffer.",
            )


def sig_key(*parts) -> str:
    """A condition key that is unique per event (keeps alerts independent)."""
    return "security:" + ":".join(str(p) for p in parts)
