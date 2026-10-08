"""Pusher: turn intent into a Plan, preview it, and apply it with rollback.

This is the engine the future GUI tabs (SD-WAN, Security, NextDNS, QoS,
Port-forwarding, Backups) call into. It is transport-agnostic: it talks to any
object exposing fetch()/execute() (the real PushApi, or a fake in tests).
"""
from __future__ import annotations

import copy
import datetime
import logging
import re

from .api import PushError
from .plan import Operation, Plan
from .reconcile import _norm, reconcile_list

log = logging.getLogger(__name__)

# Name of the on-router scheduler that performs the commit-confirm auto-revert.
_REVERT_SCHED = "mikromon-autorevert"
# Its comment: this tag, then ":<token>" naming the change that armed it, then
# ":grace" once the router has passed its own check and is waiting for the
# server. See Pusher.plan_arm_revert.
_REVERT_TAG = "mikromon:autorevert"


def revert_token(row: dict) -> str:
    """The token in an auto-revert scheduler's comment, or "" for none."""
    comment = str(row.get("comment", "") or "")
    if not comment.startswith(_REVERT_TAG + ":"):
        return ""
    rest = comment[len(_REVERT_TAG) + 1:]
    return rest.split(":", 1)[0] if rest != "grace" else ""

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


# ---- the router's flash ----------------------------------------------------
# The 16 MB models (hAP lite, hAP ac lite, hEX lite, mAP lite, the older
# RB750/RB951) often have only 1-3 MB free on RouterOS 7, and ten backups can
# fill that. On those the app keeps just two of its own.
SMALL_FLASH_BYTES = 64 * 1024 * 1024
KEEP_BACKUPS = 10
KEEP_BACKUPS_SMALL_FLASH = 2
# Free flash that must be left after a backup is saved. A router with none
# accepts configuration changes and silently fails to save them, so they are
# gone at its next reboot -- much worse than one backup fewer.
FLASH_RESERVE_BYTES = 256 * 1024
# The size assumed for a backup when the router has none to go by.
_GUESS_BACKUP_BYTES = 128 * 1024

_UNITS = {"": 1, "b": 1, "kib": 1024, "kb": 1000, "mib": 1024 ** 2,
          "mb": 1000 ** 2, "gib": 1024 ** 3, "gb": 1000 ** 3}


def keep_for(total_flash: int) -> int:
    """How many of the app's own backups a router with this much flash
    keeps."""
    return (KEEP_BACKUPS_SMALL_FLASH if 0 < total_flash <= SMALL_FLASH_BYTES
            else KEEP_BACKUPS)


def _bytes(v) -> int:
    """A RouterOS size -- "123456" over the API, "120.5KiB" as printed --
    in bytes; -1 when it cannot be read."""
    if isinstance(v, (int, float)):
        return int(v)
    m = re.match(r"^\s*([0-9.]+)\s*([A-Za-z]*)\s*$", str(v or ""))
    if not m:
        return -1
    unit = _UNITS.get(m.group(2).lower())
    try:
        return int(float(m.group(1)) * unit) if unit else -1
    except ValueError:
        return -1


def _human(n: int) -> str:
    for unit, size in (("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{max(n, 0)} bytes"


def _flash_full_message(files, free: int, need: int) -> str:
    """Why the backup was refused, and what is taking the space."""
    others = sorted(
        [f for f in files
         if not made_by_dashboard(f.get("name"))
         and _bytes(f.get("size")) > 0
         and str(f.get("type", "")) != "directory"],
        key=lambda f: _bytes(f.get("size")), reverse=True)[:3]
    big = ", ".join(f"{f['name']} ({_human(_bytes(f.get('size')))})"
                    for f in others)
    return (f"Not enough free flash on the router for a safety backup: "
            f"{_human(max(free, 0))} free, and it needs about {_human(need)} "
            f"(the backup plus room for RouterOS to save its own settings). "
            f"The dashboard's own older backups are already cleared. "
            + (f"Largest other files: {big}. " if big else "")
            + "Remove what is not needed in Winbox → Files (old backups, "
              ".npk packages, downloads), or set /system logging to memory "
              "if log files are filling it, then try again. Check for space "
              "to free on the Backups tab lists them all.")


# ---- which files the dashboard made ----------------------------------------
# The dashboard deletes only files it made itself, and knows them by the names
# it gives them: an automatic backup is before-<feature>-<date>-<time> or
# mikromon-<date>-<time>; one labelled on the Backups tab is
# mikromon-<label>-<date>-<time>. Anything else on a router was put there
# some other way -- by hand in Winbox, by a script, by RouterOS itself -- and
# is never deleted, automatically or from the page, however alike it looks.
_AUTO_BACKUP_RE = re.compile(
    r"^(?:before-[A-Za-z0-9_.-]+?|mikromon)-\d{8}-\d{6}\.backup$")
_LABELLED_BACKUP_RE = re.compile(
    r"^mikromon-[A-Za-z0-9_.-]+-\d{8}-\d{6}\.backup$")


def _top_name(name) -> str:
    """The file's name without RouterOS's "flash/" folder, where small
    routers keep the files that must survive a reboot; "" for a file deeper
    in any folder (hotspot pages, user-manager data and the like)."""
    name = str(name or "")
    if name.startswith("flash/"):
        name = name[len("flash/"):]
    return "" if "/" in name else name


def made_by_dashboard(name) -> bool:
    """Is this one of the dashboard's own files -- the only kind it will
    ever delete?"""
    base = _top_name(name)
    return bool(base and (_AUTO_BACKUP_RE.match(base)
                          or _LABELLED_BACKUP_RE.match(base)))


def auto_backup(name) -> bool:
    """One of the dashboard's automatic backups: the pool it prunes on its
    own. A labelled one stays until somebody deletes it."""
    base = _top_name(name)
    return bool(base and _AUTO_BACKUP_RE.match(base))


def labelled_backup_name(label: str, now=None) -> str:
    """mikromon-<label>-<date>-<time>: a backup labelled on the Backups tab,
    named so the dashboard can tell later that it is its own."""
    clean = re.sub(r"[^A-Za-z0-9_-]+", "-", str(label or "")).strip("-_")[:40]
    stamp = (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"mikromon-{clean}-{stamp}" if clean else f"mikromon-{stamp}"


def _what_is(name: str) -> str:
    """A plain description of a file the dashboard did not make."""
    base = str(name).rsplit("/", 1)[-1].lower()
    if base.endswith(".npk"):
        return ("RouterOS package. Left in storage, a package is installed at "
                "the next reboot.")
    if base.endswith(".rif"):
        return ("Support file (supout). Only needed for a MikroTik support "
                "case.")
    if re.match(r"^[\w.-]*log[\w-]*\.\d+\.txt$", base):
        return "Log file: /system logging is writing to disk."
    if base.endswith(".backup"):
        return "Backup made outside the dashboard."
    if base.endswith(".rsc"):
        return "Export or script file."
    return ""


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

    def plan_backup(self, name: str | None = None,
                    keep: int | None = None) -> Plan:
        """Save a .backup on the router's flash, making room for it first.

        Backups live on flash, not in RAM, because they have to outlive a
        reboot: Safe mode's timer is stored in the router's config and loads
        this file after a change has cut the router off -- and if a power cut
        comes first, a copy in RAM would be gone and the revert with it.

        Flash is small on some routers, though, so the app's own old backups
        are deleted BEFORE the new one is written (written first, a full
        router could never save it, and so never clear its own space), only
        a couple are kept on small-flash models, and the save is refused if
        it would leave RouterOS too little room to save its own settings.
        `keep` overrides how many of the app's backups to keep in all.
        """
        name = name or ("mikromon-" +
                        datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        # dont-encrypt=yes so the restore (load) works without a password prompt
        # — the file lives on the router's own flash, which already requires
        # router access to read.
        op = Operation("run", ("system", "backup"),
                       {"_cmd": "save", "name": name, "dont-encrypt": "yes"},
                       desc=f"create backup '{name}.backup' on the router")
        # keep-1 of the existing ones survive: the new one makes it `keep`.
        return Plan(self.cfg.name, self._prune_backup_ops(keep) + [op],
                    summary="backup")

    # Backups THIS app creates automatically -- on-demand ones from the
    # Backups tab ("mikromon-YYYYMMDD-HHMMSS") and the pre-change safety net
    # ("before-<feature>-YYYYMMDD-HHMMSS", written before every committed
    # config change) -- are pruned from the SAME pool of `keep`, so the router
    # never accumulates more than that many whichever made them. They are
    # recognised by their whole name (auto_backup), not a prefix: a file
    # somebody called "before-upgrade.backup" by hand is not ours to delete.

    @staticmethod
    def _backup_ts_key(fname: str) -> str:
        """The trailing YYYYMMDD-HHMMSS both naming schemes share, so sorting
        by it (rather than the whole name) interleaves the two prefixes in
        true chronological order instead of grouping alphabetically by
        prefix ("before-..." < "mikromon-..." for every timestamp)."""
        fname = _top_name(fname) or fname
        stem = fname[:-len(".backup")] if fname.endswith(".backup") else fname
        parts = stem.split("-")
        return "-".join(parts[-2:]) if len(parts) >= 2 else stem

    def _prune_backup_ops(self, keep: int | None = None) -> list:
        """Remove ops for the app's own backups (see _MANAGED_PREFIXES) so
        that, with the one about to be saved, `keep` remain -- fewer if the
        flash needs the room. Backups somebody named themselves are never
        touched, nor the one a pending Safe mode timer would restore.

        Raises PushError when even with all of the app's old backups gone
        the new one would leave less than FLASH_RESERVE_BYTES free."""
        try:
            all_files = self.api.fetch(("file",))
        except Exception:
            return []      # a preview with no router: nothing to measure
        try:
            res = (self.api.fetch(("system", "resource")) or [{}])[0]
        except Exception:
            res = {}
        total = _bytes(res.get("total-hdd-space"))
        free = _bytes(res.get("free-hdd-space"))
        if keep is None:
            keep = keep_for(total)
        managed = sorted(
            [r for r in all_files if auto_backup(r.get("name"))],
            key=lambda r: self._backup_ts_key(str(r.get("name", ""))),
            reverse=True,  # newest first
        )
        protected = self._pending_revert_backups()
        survivors = managed[:max(0, keep - 1)]
        doomed = [r for r in managed[max(0, keep - 1):]
                  if _top_name(r.get("name")) not in protected]
        if res and free >= 0:
            # The new backup will be about as big as the last one was.
            sizes = [_bytes(r.get("size")) for r in managed or all_files
                     if str(r.get("name", "")).endswith(".backup")]
            need = max([s for s in sizes if s > 0][:1] or
                       [_GUESS_BACKUP_BYTES]) + FLASH_RESERVE_BYTES
            room = free + sum(max(0, _bytes(r.get("size"))) for r in doomed)
            # Short of room: give up the oldest survivors too, one at a time.
            for r in reversed(survivors):
                if room >= need:
                    break
                if _top_name(r.get("name")) in protected:
                    continue
                doomed.append(r)
                room += max(0, _bytes(r.get("size")))
            if room < need:
                raise PushError(_flash_full_message(all_files, free, need))
        return [
            Operation("remove", ("file",), {".id": r[".id"]},
                      desc=f"prune old backup '{r['name']}'")
            for r in doomed if r.get(".id")
        ]

    def flash_info(self) -> dict:
        """{"free", "total", "keep"} for the Backups tab; {} if unknown."""
        try:
            res = (self.api.fetch(("system", "resource")) or [{}])[0]
        except Exception:
            return {}
        total = _bytes(res.get("total-hdd-space"))
        if total <= 0:
            return {}
        return {"total": total, "free": _bytes(res.get("free-hdd-space")),
                "keep": keep_for(total)}

    def _pending_revert_backups(self) -> set:
        """Backup files a waiting Safe mode timer would restore, by name
        without the flash/ folder (a timer may name either form)."""
        try:
            scheds = self.api.fetch(("system", "scheduler"))
        except Exception:
            return set()
        out = set()
        for s in scheds:
            if s.get("name") == _REVERT_SCHED:
                out.update(_top_name(n) or n for n in re.findall(
                    r'backup load name="([^"]+)"', str(s.get("on-event") or "")))
        return out

    def find_backup(self, stem: str) -> str:
        """The name RouterOS actually saved backup `stem` under -- a small
        router puts it in its flash/ folder -- or "" when it cannot be seen.
        Safe mode loads the file by this name: given the bare one on such a
        router, the load would find nothing and the revert would not happen."""
        want = stem if stem.endswith(".backup") else stem + ".backup"
        try:
            names = [str(f.get("name", "")) for f in self.api.fetch(("file",))]
        except Exception:
            return ""
        if want in names:
            return want
        return next((n for n in names if n == "flash/" + want), "")

    # ----- what is using the flash, and freeing it ---------------------------
    def space_report(self, others_shown: int = 15) -> dict:
        """What is using the router's storage, for the Backups tab.

        "ours": the dashboard's own files, each marked whether it is ticked
        for deletion by default (old automatic backups), locked (a pending
        Safe mode timer would restore it) or kept by default (the newest
        automatic backup, or one somebody labelled). "others": everything
        else, biggest first, with what it probably is -- shown so it can be
        removed in Winbox, never deleted from here.
        """
        files = self.api.fetch(("file",))
        protected = self._pending_revert_backups()
        ours = sorted([r for r in files if made_by_dashboard(r.get("name"))],
                      key=lambda r: self._backup_ts_key(str(r.get("name"))),
                      reverse=True)
        newest = next((r["name"] for r in ours if auto_backup(r["name"])), "")
        items = []
        for r in ours:
            name = str(r["name"])
            locked = _top_name(name) in protected
            labelled = not auto_backup(name)
            note = ("Safe mode may still need it to undo a change"
                    if locked else
                    "The newest automatic backup: the way back from the "
                    "last change" if name == newest else
                    "Labelled on the Backups tab" if labelled else "")
            items.append({"name": name, "size": _bytes(r.get("size")),
                          "time": str(r.get("creation-time")
                                      or r.get("last-modified") or ""),
                          "locked": locked,
                          "tick": not (locked or labelled or name == newest),
                          "note": note})
        others = []
        for r in files:
            name = str(r.get("name", ""))
            size = _bytes(r.get("size"))
            if (made_by_dashboard(name) or size <= 0
                    or str(r.get("type", "")) == "directory"):
                continue
            others.append({"name": name, "size": size, "what": _what_is(name)})
        others.sort(key=lambda o: o["size"], reverse=True)
        return {"ours": items, "others": others[:others_shown],
                "others_count": len(others),
                "others_total": sum(o["size"] for o in others),
                "flash": self.flash_info(),
                "disk_logging": self._disk_logging()}

    def _disk_logging(self) -> list:
        """Logging actions that write to disk and are in use: the usual way
        a router's flash fills up by itself."""
        try:
            actions = self.api.fetch(("system", "logging", "action"))
            rules = self.api.fetch(("system", "logging"))
        except Exception:
            return []
        disk = {a.get("name") for a in actions if a.get("target") == "disk"}
        return sorted({str(r.get("action")) for r in rules
                       if r.get("action") in disk
                       and str(r.get("disabled", "")).lower()
                       not in ("true", "yes")})

    def plan_free_space(self, names) -> Plan:
        """Delete the chosen files -- but only ever the dashboard's own, and
        never the backup a pending Safe mode timer would restore. A name
        that is neither is skipped, whatever the form sent."""
        want = {str(n) for n in names}
        protected = self._pending_revert_backups()
        ops = [Operation("remove", ("file",), {".id": r[".id"]},
                         desc=f"delete '{r['name']}' to free space")
               for r in self.api.fetch(("file",))
               if r.get("name") in want and r.get(".id")
               and made_by_dashboard(r.get("name"))
               and _top_name(r.get("name")) not in protected]
        return Plan(self.cfg.name, ops, summary="free space")

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
        # password="" is REQUIRED even though plan_backup writes these with
        # dont-encrypt=yes. RouterOS rejects the load without it -- "missing
        # =password=" -- and the restore fails having changed nothing.
        op = Operation("run", ("system", "backup"),
                       {"_cmd": "load", "name": name, "password": ""},
                       desc=f"restore backup '{name}' (REBOOTS the router)",
                       detach=True)
        return Plan(self.cfg.name, [op], summary=f"restore {name}")

    def plan_delete_backup(self, name: str) -> Plan:
        """Delete a backup file from the router by its name -- only ever one
        the dashboard made itself."""
        if not made_by_dashboard(name):
            raise PushError(
                f"'{name}' was not made by the dashboard, so it will not "
                f"delete it. If it is no longer needed, remove it in Winbox → "
                f"Files.")
        fid = next((r.get(".id") for r in self.api.fetch(("file",))
                    if str(r.get("name", "")) == name), None)
        if fid is None:
            return Plan(self.cfg.name, [], summary="delete backup (not found)")
        op = Operation("remove", ("file",), {".id": fid},
                       desc=f"delete backup file '{name}'")
        return Plan(self.cfg.name, [op], summary=f"delete {name}")

    # ----- commit-confirm auto-revert (safe mode) ---------------------------
    #
    # The order matters more than anything else here. The timer is armed
    # BEFORE the change goes out: a change that cuts the connection while it
    # is being sent leaves nothing behind to add a timer afterwards, and that
    # is exactly the change this exists for.
    #
    # Two things have to agree before a change is kept: the router can still
    # reach the hub (it pings it, from the router, about a minute after the
    # change), and the server can still manage the router (it logs in over
    # the API and takes the timer down). Ping alone passes a change that
    # blocks the API while leaving ICMP open -- the router answers pings and
    # nobody can configure it any more.
    def plan_arm_revert(self, backup_name: str, seconds: int = 60,
                        hub_ip: str = "10.10.0.1", token: str = "",
                        ping_check: bool = True) -> Plan:
        """Arm a scheduler on the router that puts `backup_name` back unless
        the change is confirmed.

        It fires every `seconds` until something removes it:

          * first firing -- pings the hub (three tries). No reply means the
            change cut the router off: it restores the backup and reboots
            into the pre-change config. A reply means the tunnel is fine, so
            it marks itself and waits one more round for the server.
          * second firing -- the server has had a full extra round to log in
            and take the timer down, and has not. The router can reach the
            hub but cannot be managed, so it restores the backup.

        The server removes the timer as soon as it has logged in over the API
        after the first round (see push/safemode.py), so a good change is
        normally confirmed a little over a minute after it was sent.

        `ping_check=False` skips the ping and goes straight to waiting for the
        server -- for a router that could not reach the hub even BEFORE the
        change (managed over a public address, say), where a failed ping
        would only revert every change it was ever given.

        `token` goes in the comment so the server only ever takes down the
        timer it armed: a second change made inside the window replaces the
        timer, and the first change's watcher must not confirm the second.
        """
        if not backup_name.endswith(".backup"):
            backup_name += ".backup"
        # password="" for the same reason as plan_restore. It matters more
        # here: this runs on the router AFTER a change has cut us off, so a
        # silent failure means no revert and no way in to do one by hand.
        load = f'/system backup load name="{backup_name}" password=""'
        mark = '/system scheduler set $s comment=($c . ":grace")'
        if ping_check:
            # Three tries a few seconds apart, so one lost burst on an LTE
            # backup does not reboot a site into yesterday's config.
            first = (':local ok 0; '
                     ':for i from=1 to=3 do={ :if ($ok = 0) do={ '
                     f':set ok [/ping {hub_ip} count=2]; '
                     ':if ($ok = 0) do={ :delay 3s } } }; '
                     f':if ($ok = 0) do={{ {load} }} else={{ {mark} }}')
        else:
            first = mark
        event = (f':local s [/system scheduler find name="{_REVERT_SCHED}"]; '
                 ':if ([:len $s] > 0) do={ '
                 ':local c [/system scheduler get $s comment]; '
                 f':if ($c ~ ":grace") do={{ {load} }} else={{ {first} }} }}')
        comment = _REVERT_TAG + (f":{token}" if token else "")
        how = (f"unless the router can still reach the hub ({hub_ip}) and "
               f"the server can still log in" if ping_check else
               "unless the server can still log in")
        op = Operation(
            "add", ("system", "scheduler"),
            {"name": _REVERT_SCHED, "interval": f"{int(seconds)}s",
             "on-event": event, "comment": comment,
             "policy": "ftp,reboot,read,write,policy,test,password,"
                       "sensitive,romon"},
            desc=f"arm safe mode: put {backup_name} back {how}")
        return Plan(self.cfg.name, [op], summary="arm auto-revert")

    def plan_disarm_revert(self, token: str | None = None) -> Plan:
        """Take the pending auto-revert down: the change is confirmed.

        With `token`, only the timer that carries it is removed. A timer with
        a different token belongs to a later change, which has its own
        watcher; removing it from here would confirm a change nobody checked.
        Without one (a person pressing Keep, or clearing the way for a new
        change) every pending timer goes.
        """
        ops = []
        for s in self.api.fetch(("system", "scheduler")):
            if s.get("name") != _REVERT_SCHED or not s.get(".id"):
                continue
            if token is not None and revert_token(s) != token:
                continue
            ops.append(Operation(
                "remove", ("system", "scheduler"), {".id": s[".id"]},
                desc="confirm change — cancel the pending auto-revert"))
        if not ops:
            return Plan(self.cfg.name, [], summary="auto-revert already cleared")
        return Plan(self.cfg.name, ops, summary="confirm (cancel auto-revert)")

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
