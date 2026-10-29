"""Antivirus agents on customers' PCs: their keys, their reports, and the
email that tells the support team.

The agent itself (agent/antivirus.py) runs on a PC, never on this server.
When it finds something -- a file it quarantined, a process it stopped, a
fault of its own -- it posts one event to /api/v1/edr/alerts with its
company's key. This is the server's half: whose key it is, whether the
event makes sense, whether it is worth an email, and the email itself.

A key per company, not one for everybody. The key sits on PCs nobody here
controls, so one day it will leak; a per-company key can then only ever
speak for that company's PCs, and replacing it moves one company's PCs over
rather than every customer's. Only a hash is kept: the key itself is shown
once, when it is made.

An infected PC is one incident, not forty emails. The first alert from a PC
is emailed at once; more from the same PC within EMAIL_GAP are held and
counted into its next email, unless one is more serious than the last thing
sent. A company gets at most EMAILS_PER_HOUR, so a leaked key cannot be used
to flood the support inbox. Everything is listed on the Antivirus page
either way.

SQLite in WAL mode beside devices.db, like the other stores the web process
shares.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import quote

log = logging.getLogger(__name__)

# On since the agent installs on Windows without Python (SETUP_FILE). While
# False nothing of this is reachable: the agents' endpoint, both Antivirus
# pages and the setup download answer 404, the sidebar links are hidden,
# and no edr.db is created.
ENABLED = True

# The Windows setup, built by agent/build_windows.py, which copies it here so
# a deploy ships it with the code.
SETUP_NAME = "EasyMikroTik-Antivirus-Setup.exe"
SETUP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "downloads", SETUP_NAME)

KEY_PREFIX = "emk_"
# How long after emailing about a PC its further alerts are only counted.
EMAIL_GAP = 15 * 60
EMAILS_PER_HOUR = 20
KEEP_DAYS = 90
# One event is a few hundred bytes; this is room for a long command line.
MAX_BODY = 64 * 1024
# Platform setting: who is emailed. Empty means the platform admins.
SETTING_RECIPIENTS = "edr_support_emails"

SEVERITIES = ("LOW", "MEDIUM", "HIGH")
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
# Other agents' words for the same three levels.
_SEVERITY_ALIASES = {"INFO": "LOW", "WARNING": "MEDIUM", "CRITICAL": "HIGH"}

# Recorded against the PC but never emailed: the agent saying it is alive,
# started or stopped. AGENT_ERROR is deliberately not here -- an agent that
# cannot watch a folder is a PC that is not protected.
QUIET_EVENTS = frozenset({"HEARTBEAT", "AGENT_STARTED", "AGENT_STOPPED"})
# Something found on the PC, as opposed to news about the agent: the alerts
# whose email offers to cut the PC off the network.
THREAT_EVENTS = frozenset({"FILE_QUARANTINED", "THREAT_DETECTED",
                           "SUSPICIOUS_PROCESS", "SUSPICIOUS_FILE"})

_LABELS = {
    "FILE_QUARANTINED": "Threat quarantined",
    "THREAT_DETECTED": "Threat found, NOT quarantined",
    "SUSPICIOUS_PROCESS": "Suspicious process",
    "SUSPICIOUS_FILE": "Packed program downloaded",
    "AGENT_ERROR": "Antivirus agent problem",
    # `antivirus.py --test`: checks a PC's key and the email path, no malware.
    "AGENT_TEST": "Test alert",
    "AGENT_STARTED": "Agent started",
    "AGENT_STOPPED": "Agent stopped",
    "HEARTBEAT": "Agent running",
}

_EVENT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS edr_keys (
    org_id   INTEGER PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    hint     TEXT NOT NULL,              -- the key's first characters
    created  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS edr_agents (
    org_id        INTEGER NOT NULL,
    agent_id      TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    os_user       TEXT,
    local_ip      TEXT,
    mac           TEXT,
    public_ip     TEXT,
    version       TEXT,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    last_emailed  REAL,
    last_severity TEXT,
    held          INTEGER NOT NULL DEFAULT 0,  -- alerts since the last email
    PRIMARY KEY (org_id, agent_id)
);
CREATE TABLE IF NOT EXISTS edr_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,                   -- when this server got it
    org_id     INTEGER NOT NULL,
    agent_id   TEXT NOT NULL,
    hostname   TEXT,
    event_type TEXT NOT NULL,
    severity   TEXT NOT NULL,
    target     TEXT,
    reason     TEXT,
    action     TEXT,
    sha256     TEXT,
    details    TEXT,                            -- JSON
    agent_ts   TEXT,                            -- the PC's own clock
    emailed    INTEGER NOT NULL DEFAULT 0       -- see EMAIL_* below
);
CREATE INDEX IF NOT EXISTS ix_edr_events_ts ON edr_events(ts);
CREATE INDEX IF NOT EXISTS ix_edr_events_org ON edr_events(org_id, ts);
-- PCs the support team has cut off the network at their router
-- (push/isolate.py), until released.
CREATE TABLE IF NOT EXISTS edr_isolations (
    org_id   INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    device   TEXT NOT NULL,              -- the router it is isolated on
    ip       TEXT NOT NULL,
    since    REAL NOT NULL,
    by_user  TEXT,
    PRIMARY KEY (org_id, agent_id)
);
"""

# edr_events.emailed
EMAIL_NONE = 0     # not worth an email (LOW, or the agent starting)
EMAIL_SENT = 1
EMAIL_HELD = 2     # same PC inside EMAIL_GAP, or the company's hourly cap
EMAIL_FAILED = 3   # no mail server, nobody to send to, or the send failed


class EventError(ValueError):
    """An event this server will not take, with the reason the agent logs."""


def edr_path(devices_db: str | None, explicit: str | None = None) -> str:
    """Where the antivirus store lives: beside devices.db, like incidents.db,
    so the web process and the backups find it without being told."""
    if explicit:
        return explicit
    base = os.path.dirname(os.path.abspath(devices_db)) if devices_db else "."
    return os.path.join(base, "edr.db")


def label(event_type: str) -> str:
    return _LABELS.get(event_type) or event_type.replace("_", " ").capitalize()


def _clean_details(details) -> dict:
    """What the agent sent besides the known fields, kept small: plain
    values and short lists only, so one report cannot grow the database by
    megabytes."""
    out = {}
    if not isinstance(details, dict):
        return out
    for k, v in list(details.items())[:20]:
        key = str(k)[:40]
        if isinstance(v, bool) or isinstance(v, (int, float)) or v is None:
            out[key] = v
        elif isinstance(v, str):
            out[key] = v[:1000]
        elif isinstance(v, (list, tuple)):
            out[key] = [str(x)[:300] for x in v[:20]]
    return out


def parse_event(payload) -> dict:
    """The agent's JSON, checked and trimmed to what is stored.

    Severity, reason and sha256 are read from the top level or from
    `details`, so the first version of the agent -- which nested them --
    is understood as well."""
    if not isinstance(payload, dict):
        raise EventError("expected a JSON object")
    details = payload.get("details")
    details = details if isinstance(details, dict) else {}

    def text(name, limit, *, nested=False):
        for src in ((payload, details) if nested else (payload,)):
            value = src.get(name)
            if value not in (None, ""):
                return str(value).strip()[:limit]
        return ""

    agent_id = text("agent_id", 128)
    if not agent_id:
        raise EventError("agent_id is missing")
    event_type = text("event_type", 40).upper()
    if not _EVENT_RE.match(event_type):
        raise EventError("event_type is missing or not LIKE_THIS")
    severity = text("severity", 10, nested=True).upper() or "MEDIUM"
    severity = _SEVERITY_ALIASES.get(severity, severity)
    if severity not in SEVERITIES:
        raise EventError(f"severity must be one of {', '.join(SEVERITIES)}")
    sha = text("sha256", 64, nested=True).lower()
    known = {"reason", "severity", "sha256", "action"}
    return {
        "agent_id": agent_id,
        # Blank when not sent: record() then keeps the name already known,
        # and falls back to the agent id only for a PC never named.
        "hostname": text("hostname", 255),
        "os": text("os", 80),
        "os_user": text("user", 120),
        "local_ip": text("local_ip", 64),
        "mac": text("mac", 32),
        "version": text("version", 20),
        "agent_ts": text("timestamp", 40),
        "event_type": event_type,
        "severity": severity,
        "target": text("target", 1024),
        "reason": text("reason", 500, nested=True),
        "action": text("action", 500, nested=True),
        "sha256": sha if _SHA256_RE.match(sha) else "",
        "details": _clean_details({k: v for k, v in details.items()
                                   if k not in known}),
    }


def parse_recipients(text: str) -> list:
    """Addresses from the page's box: commas, semicolons or spaces between
    them. Raises ValueError naming the ones that are not addresses."""
    parts = [p.strip() for p in re.split(r"[,;\s]+", text or "") if p.strip()]
    bad = [p for p in parts if not _EMAIL_RE.match(p)]
    if bad:
        raise ValueError("Not an email address: " + ", ".join(bad[:3]))
    seen, out = set(), []
    for p in parts:
        if p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    return out[:20]


def saved_recipients(auth) -> list:
    try:
        saved = auth.get_setting(SETTING_RECIPIENTS) or []
    except Exception:  # noqa: BLE001 -- a settings problem must not lose an alert
        saved = []
    return [a for a in saved if isinstance(a, str) and a.strip()]


def support_recipients(auth) -> list:
    """Who is told: the addresses on the Antivirus page, else the platform
    admins -- so the very first alert reaches somebody even before anyone
    has thought to set a list."""
    return saved_recipients(auth) or list(auth.superadmin_emails())


class EdrStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()
        self._pruned = 0.0

    def close(self) -> None:
        with self._lock:
            self.db.close()

    # ----- keys ---------------------------------------------------------------
    @staticmethod
    def _hash(key: str) -> str:
        # A plain hash is enough: the key is 32 random bytes, so there is
        # nothing to guess, and the lookup has to be fast for every report.
        return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()

    def new_key(self, org_id: int, now: float | None = None) -> str:
        """A fresh key for the company, replacing any it had. Returned once;
        only its hash is kept."""
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        with self._lock:
            self.db.execute(
                "INSERT INTO edr_keys (org_id, key_hash, hint, created) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(org_id) DO UPDATE SET "
                "key_hash = excluded.key_hash, hint = excluded.hint, "
                "created = excluded.created",
                (int(org_id), self._hash(key), key[:len(KEY_PREFIX) + 6],
                 time.time() if now is None else now))
            self.db.commit()
        return key

    def revoke_key(self, org_id: int) -> bool:
        with self._lock:
            cur = self.db.execute("DELETE FROM edr_keys WHERE org_id = ?",
                                  (int(org_id),))
            self.db.commit()
        return cur.rowcount > 0

    def keys(self) -> dict:
        """{org_id: {"hint", "created"}} for every company with a key."""
        return {r["org_id"]: {"hint": r["hint"], "created": r["created"]}
                for r in self.db.execute("SELECT * FROM edr_keys")}

    def in_use(self, org_id) -> bool:
        """Whether this company has a key or a PC that has reported."""
        if org_id is None:
            return False
        org_id = int(org_id)
        return bool(
            self.db.execute("SELECT 1 FROM edr_keys WHERE org_id = ?",
                            (org_id,)).fetchone()
            or self.db.execute("SELECT 1 FROM edr_agents WHERE org_id = ? "
                               "LIMIT 1", (org_id,)).fetchone())

    def org_for_key(self, key: str) -> int | None:
        key = (key or "").strip()
        if not key.startswith(KEY_PREFIX) or len(key) > 200:
            return None
        row = self.db.execute("SELECT org_id FROM edr_keys WHERE key_hash = ?",
                              (self._hash(key),)).fetchone()
        return int(row[0]) if row else None

    # ----- events -------------------------------------------------------------
    def record(self, org_id: int, ev: dict, public_ip: str = "",
               now: float | None = None) -> dict:
        """Store one parsed event and decide whether it is emailed.

        Returns {"id", "email", "held"}: the event's id (None for a
        heartbeat, which only updates the PC), whether to email it now, and
        how many alerts from this PC were held since its last email."""
        now = time.time() if now is None else now
        org_id = int(org_id)
        with self._lock:
            agent = self.db.execute(
                "SELECT * FROM edr_agents WHERE org_id = ? AND agent_id = ?",
                (org_id, ev["agent_id"])).fetchone()
            ident = (ev["hostname"], ev["os"], ev["os_user"], ev["local_ip"],
                     ev["mac"], public_ip, ev["version"])
            # The first version of the agent sent its PC name as its id.
            hostname = (ev["hostname"]
                        or (agent["hostname"] if agent is not None else "")
                        or ev["agent_id"])
            if agent is None:
                self.db.execute(
                    "INSERT INTO edr_agents (org_id, agent_id, hostname, os, "
                    "os_user, local_ip, mac, public_ip, version, first_seen, "
                    "last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (org_id, ev["agent_id"], hostname, *ident[1:], now, now))
            else:
                # A blank field keeps what was known: a heartbeat from a PC
                # that briefly lost its network still names the PC.
                self.db.execute(
                    "UPDATE edr_agents SET "
                    "hostname = COALESCE(NULLIF(?, ''), hostname), "
                    "os = COALESCE(NULLIF(?, ''), os), "
                    "os_user = COALESCE(NULLIF(?, ''), os_user), "
                    "local_ip = COALESCE(NULLIF(?, ''), local_ip), "
                    "mac = COALESCE(NULLIF(?, ''), mac), "
                    "public_ip = COALESCE(NULLIF(?, ''), public_ip), "
                    "version = COALESCE(NULLIF(?, ''), version), "
                    "last_seen = ? WHERE org_id = ? AND agent_id = ?",
                    (*ident, now, org_id, ev["agent_id"]))
            if ev["event_type"] == "HEARTBEAT":
                self.db.commit()
                return {"id": None, "email": False, "held": 0}

            email, held, status = False, 0, EMAIL_NONE
            if (ev["event_type"] not in QUIET_EVENTS
                    and _RANK[ev["severity"]] >= _RANK["MEDIUM"]):
                last = agent["last_emailed"] if agent is not None else None
                last_sev = agent["last_severity"] if agent is not None else None
                fresh = last is None or now - last >= EMAIL_GAP
                worse = (last_sev is not None
                         and _RANK[ev["severity"]] > _RANK.get(last_sev, 0))
                sent = self.db.execute(
                    "SELECT COUNT(*) FROM edr_events WHERE org_id = ? AND "
                    "emailed = ? AND ts > ?",
                    (org_id, EMAIL_SENT, now - 3600)).fetchone()[0]
                if (fresh or worse) and sent < EMAILS_PER_HOUR:
                    email, status = True, EMAIL_SENT
                    held = int(agent["held"]) if agent is not None else 0
                    self.db.execute(
                        "UPDATE edr_agents SET last_emailed = ?, "
                        "last_severity = ?, held = 0 "
                        "WHERE org_id = ? AND agent_id = ?",
                        (now, ev["severity"], org_id, ev["agent_id"]))
                else:
                    status = EMAIL_HELD
                    self.db.execute(
                        "UPDATE edr_agents SET held = held + 1 "
                        "WHERE org_id = ? AND agent_id = ?",
                        (org_id, ev["agent_id"]))
            cur = self.db.execute(
                "INSERT INTO edr_events (ts, org_id, agent_id, hostname, "
                "event_type, severity, target, reason, action, sha256, "
                "details, agent_ts, emailed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (now, org_id, ev["agent_id"], hostname, ev["event_type"],
                 ev["severity"], ev["target"], ev["reason"], ev["action"],
                 ev["sha256"], json.dumps(ev["details"]), ev["agent_ts"],
                 status))
            event_id = cur.lastrowid
            self._prune(now)
            self.db.commit()
        return {"id": event_id, "email": email, "held": held}

    def email_failed(self, event_id: int) -> None:
        """The email for this event did not go. Marked so the page says so,
        and the PC's next alert is emailed rather than held behind it."""
        with self._lock:
            row = self.db.execute(
                "SELECT org_id, agent_id FROM edr_events WHERE id = ?",
                (int(event_id),)).fetchone()
            self.db.execute("UPDATE edr_events SET emailed = ? WHERE id = ?",
                            (EMAIL_FAILED, int(event_id)))
            if row is not None:
                self.db.execute(
                    "UPDATE edr_agents SET last_emailed = NULL, "
                    "last_severity = NULL WHERE org_id = ? AND agent_id = ?",
                    (row["org_id"], row["agent_id"]))
            self.db.commit()

    def _prune(self, now: float) -> None:
        """At most hourly: events and silent PCs older than KEEP_DAYS go --
        but never a PC still isolated, which would leave nothing on the page
        to release it with."""
        if now - self._pruned < 3600:
            return
        self._pruned = now
        cutoff = now - KEEP_DAYS * 86400
        self.db.execute("DELETE FROM edr_events WHERE ts < ?", (cutoff,))
        self.db.execute(
            "DELETE FROM edr_agents WHERE last_seen < ? AND NOT EXISTS ("
            "SELECT 1 FROM edr_isolations i WHERE i.org_id = "
            "edr_agents.org_id AND i.agent_id = edr_agents.agent_id)",
            (cutoff,))

    # ----- isolation ----------------------------------------------------------
    def isolations(self, org_id: int | None = None) -> dict:
        """{(org_id, agent_id): row} for every PC cut off at its router."""
        sql, args = "SELECT * FROM edr_isolations", []
        if org_id is not None:
            sql += " WHERE org_id = ?"
            args.append(int(org_id))
        return {(r["org_id"], r["agent_id"]): dict(r)
                for r in self.db.execute(sql, args)}

    def set_isolated(self, org_id: int, agent_id: str, device: str, ip: str,
                     by_user: str = "", now: float | None = None) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO edr_isolations (org_id, agent_id, device, ip, "
                "since, by_user) VALUES (?,?,?,?,?,?) ON CONFLICT(org_id, "
                "agent_id) DO UPDATE SET device = excluded.device, "
                "ip = excluded.ip, since = excluded.since, "
                "by_user = excluded.by_user",
                (int(org_id), agent_id, device, ip,
                 time.time() if now is None else now, by_user))
            self.db.commit()

    def clear_isolated(self, org_id: int, agent_id: str) -> None:
        with self._lock:
            self.db.execute("DELETE FROM edr_isolations WHERE org_id = ? AND "
                            "agent_id = ?", (int(org_id), agent_id))
            self.db.commit()

    def event(self, event_id: int) -> dict | None:
        row = self.db.execute("SELECT * FROM edr_events WHERE id = ?",
                              (int(event_id),)).fetchone()
        return self._event_row(row) if row is not None else None

    @staticmethod
    def _event_row(row) -> dict:
        d = dict(row)
        try:
            d["details"] = json.loads(d.get("details") or "{}")
        except ValueError:
            d["details"] = {}
        return d

    def recent(self, limit: int = 100, org_id: int | None = None) -> list:
        """Newest first."""
        sql, args = "SELECT * FROM edr_events", []
        if org_id is not None:
            sql += " WHERE org_id = ?"
            args.append(int(org_id))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return [self._event_row(r) for r in self.db.execute(sql, args)]

    def agent(self, org_id: int, agent_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM edr_agents WHERE org_id = ? AND agent_id = ?",
            (int(org_id), agent_id)).fetchone()
        return dict(row) if row is not None else None

    def agents(self, org_id: int | None = None) -> list:
        """Most recently heard from first."""
        sql, args = "SELECT * FROM edr_agents", []
        if org_id is not None:
            sql += " WHERE org_id = ?"
            args.append(int(org_id))
        sql += " ORDER BY last_seen DESC"
        return [dict(r) for r in self.db.execute(sql, args)]

    def purge_org(self, org_id: int) -> None:
        """A deleted company: its key stops working and its PCs go."""
        with self._lock:
            for table in ("edr_keys", "edr_agents", "edr_events",
                          "edr_isolations"):
                self.db.execute(f"DELETE FROM {table} WHERE org_id = ?",
                                (int(org_id),))
            self.db.commit()


def build_email(ev: dict, agent: dict | None, org_name: str, held: int,
                page_url: str = "", prefix: str = "[EasyMikrotik]") -> tuple:
    """(subject, body) for one alert. Plain text: whoever reads it will be
    copying the hash, the path and the addresses out of it."""
    agent = agent or {}
    pc = agent.get("hostname") or ev.get("hostname") or ev["agent_id"]
    what = label(ev["event_type"])
    subject = f"{prefix} Antivirus: {what} on {pc} ({org_name})".strip()
    when = time.strftime("%d %b %Y %H:%M:%S", time.localtime(ev["ts"]))
    lines = [f"{what} on {pc}, a PC at {org_name}.", ""]
    if ev.get("reason"):
        lines.append(f"Found:     {ev['reason']}")
    if ev.get("target"):
        lines.append(f"Where:     {ev['target']}")
    if ev.get("action"):
        lines.append(f"Done:      {ev['action']}")
    lines += [f"Severity:  {ev['severity']}", f"When:      {when}", ""]
    who = f"PC:        {pc}"
    if agent.get("os_user"):
        who += f" (signed in: {agent['os_user']})"
    lines.append(who)
    if agent.get("os"):
        lines.append(f"System:    {agent['os']}")
    if agent.get("local_ip"):
        lan = f"Network:   {agent['local_ip']}"
        if agent.get("mac"):
            lan += f", network card {agent['mac']}"
        lines.append(lan)
    if agent.get("public_ip"):
        lines.append(f"Internet:  {agent['public_ip']}")
    lines.append(f"Agent:     {ev['agent_id']}"
                 + (f" (version {agent['version']})" if agent.get("version")
                    else ""))
    details = ev.get("details") or {}
    if details.get("cmdline"):
        lines.append(f"Command:   {details['cmdline']}")
    if ev.get("sha256"):
        lines += ["", f"SHA-256:   {ev['sha256']}",
                  f"Look it up: https://www.virustotal.com/gui/file/"
                  f"{ev['sha256']}"]
    lines.append("")
    if held:
        lines.append(f"{held} more alert{'' if held == 1 else 's'} from this "
                     f"PC came in since the last email; "
                     f"{'it is' if held == 1 else 'they are'} on the "
                     f"Antivirus page.")
    lines.append(f"More alerts from this PC in the next {EMAIL_GAP // 60} "
                 f"minutes go on the Antivirus page instead of email, unless "
                 f"they are more serious than this one.")
    if page_url:
        lines.append(f"Antivirus page: {page_url}")
        if ev["event_type"] in THREAT_EVENTS:
            lines.append(f"Cut this PC off the network: {page_url}/isolate?"
                         f"org={int(ev['org_id'])}&agent="
                         f"{quote(str(ev['agent_id']), safe='')}")
    return subject, "\n".join(lines) + "\n"


def send_alert_email(auth, smtp_cfg, store: EdrStore, event_id: int,
                     held: int, page_url: str = "") -> bool:
    """Email the support team about one stored event. Marks it failed (and
    says why in the log) when there is no mail server, nobody to send to,
    or the send itself fails. Returns whether it went."""
    from email.message import EmailMessage

    from .notify.org_email import _smtp_send, effective_smtp
    ev = store.event(event_id)
    if ev is None:
        return False
    smtp = effective_smtp(auth, smtp_cfg)
    to = support_recipients(auth) if auth is not None else []
    if not (smtp and getattr(smtp, "host", "") and to):
        log.warning("antivirus alert %s from %s not emailed: %s", event_id,
                    ev.get("hostname"), "no mail server is set up"
                    if not (smtp and getattr(smtp, "host", ""))
                    else "nobody to send it to")
        store.email_failed(event_id)
        return False
    org_name = (auth.org_name(ev["org_id"]) or f"company {ev['org_id']}")
    subject, body = build_email(
        ev, store.agent(ev["org_id"], ev["agent_id"]), org_name, held,
        page_url, getattr(smtp, "subject_prefix", "") or "[EasyMikrotik]")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp.from_addr
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    try:
        _smtp_send(smtp, msg)
    except Exception:  # noqa: BLE001
        log.exception("could not email antivirus alert %s", event_id)
        store.email_failed(event_id)
        return False
    return True
