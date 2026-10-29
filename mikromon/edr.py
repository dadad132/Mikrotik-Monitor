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

The shared threat list is how one PC's find protects the rest. Every agent
downloads it (GET /api/v1/edr/threats) and quarantines what is on it. It
grows from four places: what agents quarantine, what Windows Defender
catches on a PC, the MalwareBazaar feed (with a free abuse.ch key), and the
support team marking a file malicious -- or safe, which frees it from
quarantine on every PC. A find reported by a company's PCs blocks on that
company's PCs at once -- and on the PCs of any other company whose PCs
report it too -- but only the support team puts it on everyone's. However
many companies report it: anyone can sign up twice, and a leaked key or a
made-up company must not be able to get somebody's accounting software
quarantined across every customer.

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
                           "SUSPICIOUS_PROCESS", "SUSPICIOUS_FILE",
                           "DEFENDER_DETECTION"})
# Finds whose file goes on the shared threat list. Not SUSPICIOUS_FILE: a
# packed program is as often an ordinary installer.
LEARN_EVENTS = frozenset({"FILE_QUARANTINED", "THREAT_DETECTED",
                          "DEFENDER_DETECTION"})

_LABELS = {
    "FILE_QUARANTINED": "Threat quarantined",
    "THREAT_DETECTED": "Threat found, NOT quarantined",
    "SUSPICIOUS_PROCESS": "Suspicious process",
    "SUSPICIOUS_FILE": "Packed program downloaded",
    "DEFENDER_DETECTION": "Windows Defender found a threat",
    "DEFENDER_OFF": "Windows Defender is off or out of date",
    "DEFENDER_OK": "Windows Defender is back on",
    "FILE_RESTORED": "Released from quarantine",
    "AGENT_ERROR": "Antivirus agent problem",
    # `antivirus.py --test`: checks a PC's key and the email path, no malware.
    "AGENT_TEST": "Test alert",
    "AGENT_STARTED": "Agent started",
    "AGENT_STOPPED": "Agent stopped",
    "HEARTBEAT": "Agent running",
}

# The shared threat list. `verdict` is what agents do with a file:
# quarantine it, leave it alone, or forget it.
VERDICTS = ("malicious", "safe", "removed")
SOURCES = {"agent": "Found on a PC", "defender": "Windows Defender",
           "feed": "MalwareBazaar", "support": "Support team"}
# Agents download the list in pages this long.
SYNC_PAGE = 5000
# MalwareBazaar: "recent" holds the last 48 hours and is rebuilt every 5
# minutes; fetched every FEED_EVERY, each sample kept FEED_KEEP_DAYS. Most
# malware is rebuilt into new files within weeks, so an old fingerprint
# catches little and only makes every PC's list longer.
SETTING_FEED_KEY = "edr_feed_key"
FEED_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
FEED_EVERY = 6 * 3600
FEED_RETRY = 3600
FEED_KEEP_DAYS = 30
FEED_EXPIRED = "expired"         # by_user on a feed sample aged off the list

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
-- The shared threat list every agent downloads. `rev` numbers each change,
-- so an agent asks only for what changed since it last looked.
CREATE TABLE IF NOT EXISTS edr_threats (
    sha256     TEXT PRIMARY KEY,
    verdict    TEXT NOT NULL,              -- malicious | safe | removed
    name       TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'HIGH',
    source     TEXT NOT NULL,              -- agent | defender | feed | support
    org_id     INTEGER,                    -- only this company's PCs; NULL: all
    first_seen REAL NOT NULL,
    updated    REAL NOT NULL,
    by_user    TEXT NOT NULL DEFAULT '',   -- who decided, if a person did
    rev        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_edr_threats_rev ON edr_threats(rev);
-- Which companies' PCs reported a file: each of them blocks it. Only the
-- support team makes it fleet-wide.
CREATE TABLE IF NOT EXISTS edr_sightings (
    sha256     TEXT NOT NULL,
    org_id     INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (sha256, org_id)
);
CREATE INDEX IF NOT EXISTS ix_edr_sightings_org ON edr_sightings(org_id);
CREATE TABLE IF NOT EXISTS edr_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
            if ev["event_type"] in LEARN_EVENTS and ev["sha256"]:
                self._learn(org_id, ev, now)
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

    # ----- the shared threat list --------------------------------------------
    def _next_rev(self) -> int:
        """A change number never handed out before. Kept apart from the
        entries: counting from the highest entry would hand a number out
        again after that entry is deleted (a company leaving), and agents
        already past it would never see the change made under it."""
        row = self.db.execute("SELECT value FROM edr_meta WHERE key = 'rev'"
                              ).fetchone()
        top = self.db.execute("SELECT COALESCE(MAX(rev), 0) FROM edr_threats"
                              ).fetchone()[0]
        rev = max(int(row[0]) if row else 0, int(top)) + 1
        self.db.execute("INSERT INTO edr_meta (key, value) VALUES ('rev', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (str(rev),))
        return rev

    def _put_threat(self, sha256: str, verdict: str, *, name: str,
                    severity: str, source: str, org_id, by_user: str,
                    now: float, first_seen: float | None = None) -> None:
        """Write one entry under the next change number. The caller holds
        the lock and commits."""
        rev = self._next_rev()
        self.db.execute(
            "INSERT INTO edr_threats (sha256, verdict, name, severity, source, "
            "org_id, first_seen, updated, by_user, rev) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
            "verdict = excluded.verdict, name = excluded.name, "
            "severity = excluded.severity, source = excluded.source, "
            "org_id = excluded.org_id, updated = excluded.updated, "
            "by_user = excluded.by_user, rev = excluded.rev",
            (sha256, verdict, name[:200], severity, source, org_id,
             now if first_seen is None else first_seen, now, by_user, rev))

    def _learn(self, org_id: int, ev: dict, now: float) -> None:
        """A PC found this file: block it on the PCs of every company whose
        PCs found it -- never on everyone's. Two companies reporting a file
        is no proof when anyone can sign up twice and report any file they
        like; only the support team (Block everywhere) or the feed puts one
        on every PC. Never over the support team's word that it is safe.

        The entry's org_id is the first company to find it, and is only
        ever None once it is everyone's; which other companies block it is
        in edr_sightings (see threats_since)."""
        sha = ev["sha256"]
        new_here = self.db.execute(
            "INSERT OR IGNORE INTO edr_sightings (sha256, org_id, first_seen) "
            "VALUES (?,?,?)", (sha, org_id, now)).rowcount > 0
        row = self.db.execute("SELECT * FROM edr_threats WHERE sha256 = ?",
                              (sha,)).fetchone()
        if row is not None and row["verdict"] == "safe":
            return
        if row is not None and row["verdict"] == "removed" \
                and row["by_user"] not in ("", FEED_EXPIRED):
            return                      # a person took it off; stays off
        if row is not None and row["verdict"] == "malicious":
            if row["org_id"] is None or not new_here:
                return                  # everyone's already, or this one's
            # One more company: the same entry under a new change number,
            # or its PCs, already past the old one, would never fetch it.
            self._put_threat(sha, "malicious", name=row["name"],
                             severity=row["severity"], source=row["source"],
                             org_id=row["org_id"], by_user=row["by_user"],
                             now=now, first_seen=row["first_seen"])
            return
        details = ev.get("details") or {}
        name = str(details.get("threat") or ev.get("reason") or
                   label(ev["event_type"]))
        self._put_threat(
            sha, "malicious", name=name, severity=ev["severity"],
            source="defender" if ev["event_type"] == "DEFENDER_DETECTION"
            else "agent", org_id=org_id, by_user="", now=now)

    def set_verdict(self, sha256: str, verdict: str, by_user: str,
                    name: str = "", now: float | None = None) -> dict:
        """The support team's decision, for every company's PCs: block it,
        call it safe (agents free it from quarantine), or take it off the
        list. Returns the entry as it now is."""
        sha = (sha256 or "").strip().lower()
        if not _SHA256_RE.match(sha):
            raise ValueError("That is not a SHA-256 fingerprint (64 letters "
                             "and digits, 0-9 and a-f).")
        if verdict not in VERDICTS:
            raise ValueError(f"Unknown verdict {verdict!r}.")
        now = time.time() if now is None else now
        with self._lock:
            row = self.db.execute("SELECT * FROM edr_threats WHERE sha256 = ?",
                                  (sha,)).fetchone()
            self._put_threat(
                sha, verdict,
                name=(name or "").strip() or (row["name"] if row else "")
                or "Added by the support team",
                severity=row["severity"] if row else "HIGH",
                source=row["source"] if row else "support",
                org_id=None, by_user=by_user or "support", now=now,
                first_seen=row["first_seen"] if row else None)
            self.db.commit()
        return self.threat(sha)

    def threat(self, sha256: str) -> dict | None:
        row = self.db.execute("SELECT * FROM edr_threats WHERE sha256 = ?",
                              ((sha256 or "").lower(),)).fetchone()
        return dict(row) if row is not None else None

    def threats_for(self, shas) -> dict:
        """{sha256: entry} for these fingerprints, for the alerts list."""
        shas = sorted({s for s in shas if s})
        out = {}
        for i in range(0, len(shas), 500):
            part = shas[i:i + 500]
            for r in self.db.execute(
                    "SELECT * FROM edr_threats WHERE sha256 IN (%s)"
                    % ",".join("?" * len(part)), part):
                out[r["sha256"]] = dict(r)
        return out

    def threats_since(self, org_id: int, since: int,
                      limit: int = SYNC_PAGE) -> tuple:
        """(items, rev, more) for one company's agents: every change after
        `since` that applies to them, as [sha256, verdict, name, severity].
        `rev` is where to ask from next time."""
        try:
            since = max(0, int(since))
        except (TypeError, ValueError):
            since = 0
        # Under the lock: the connection is shared, so without it a writer
        # mid-way through could add a row between reading the changes and
        # reading the top rev, and the PC would be sent past a change it
        # never got.
        with self._lock:
            row = self.db.execute("SELECT value FROM edr_meta WHERE key = "
                                  "'rev'").fetchone()
            top = max(int(row[0]) if row else 0, self.db.execute(
                "SELECT COALESCE(MAX(rev), 0) FROM edr_threats").fetchone()[0])
            # A PC asking from past the top has a list from before this one
            # was restored or started over: send it everything again.
            if since > top:
                since = 0
            # Everyone's entries, and those this company's own PCs found.
            rows = self.db.execute(
                "SELECT sha256, verdict, name, severity, rev FROM edr_threats "
                "WHERE rev > ? AND (org_id IS NULL OR org_id = ? OR sha256 IN "
                "(SELECT sha256 FROM edr_sightings WHERE org_id = ?)) "
                "ORDER BY rev LIMIT ?",
                (since, int(org_id), int(org_id), int(limit) + 1)
            ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        items = [[r["sha256"], r["verdict"], r["name"], r["severity"]]
                 for r in rows]
        if more:
            rev = rows[-1]["rev"]
        else:
            # Past other companies' entries too, so they are not looked at
            # again on every visit.
            rev = max(since, top)
        return items, rev, more

    def threat_counts(self) -> dict:
        """For the page: what the list holds."""
        out = {"blocked": 0, "pending": 0, "safe": 0,
               "by_source": {s: 0 for s in SOURCES}}
        for r in self.db.execute(
                "SELECT verdict, source, org_id IS NULL AS everyone, "
                "COUNT(*) AS n FROM edr_threats GROUP BY 1, 2, 3"):
            if r["verdict"] == "safe":
                out["safe"] += r["n"]
            elif r["verdict"] == "malicious" and r["everyone"]:
                out["blocked"] += r["n"]
                out["by_source"][r["source"]] = (
                    out["by_source"].get(r["source"], 0) + r["n"])
            elif r["verdict"] == "malicious":
                out["pending"] += r["n"]
        return out

    def pending_threats(self, limit: int = 50) -> list:
        """Blocked only at the companies whose PCs found them: waiting for
        the support team before every PC blocks them. Newest first, each
        with `orgs`, how many companies found it."""
        return [dict(r) for r in self.db.execute(
            "SELECT t.*, (SELECT COUNT(*) FROM edr_sightings s "
            "WHERE s.sha256 = t.sha256) AS orgs FROM edr_threats t "
            "WHERE t.verdict = 'malicious' AND t.org_id IS NOT NULL "
            "ORDER BY t.updated DESC LIMIT ?", (int(limit),))]

    def recent_threats(self, limit: int = 20) -> list:
        """What people and PCs added or decided lately; not the feed, which
        would bury them."""
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM edr_threats WHERE source != 'feed' OR by_user "
            "NOT IN ('', ?) ORDER BY updated DESC LIMIT ?",
            (FEED_EXPIRED, int(limit)))]

    def add_feed(self, samples, now: float | None = None) -> int:
        """MalwareBazaar's samples, blocked on every PC. Never over a
        person's decision: one marked safe or taken off stays that way.
        Returns how many were new."""
        now = time.time() if now is None else now
        added = 0
        with self._lock:
            for sha, name in samples:
                row = self.db.execute(
                    "SELECT verdict, by_user FROM edr_threats WHERE sha256 = ?",
                    (sha,)).fetchone()
                if row is not None and not (
                        row["verdict"] == "removed"
                        and row["by_user"] == FEED_EXPIRED):
                    continue
                self._put_threat(sha, "malicious", name=name, severity="HIGH",
                                 source="feed", org_id=None, by_user="",
                                 now=now)
                # Aged off and back in the feed: seen afresh, so its 30 days
                # start again rather than ending at once.
                self.db.execute("UPDATE edr_threats SET first_seen = ? "
                                "WHERE sha256 = ?", (now, sha))
                added += 1
            self.db.commit()
        return added

    def expire_feed(self, now: float | None = None) -> int:
        """Feed samples older than FEED_KEEP_DAYS come off every PC's list,
        unless a person has decided about them."""
        now = time.time() if now is None else now
        with self._lock:
            old = [r[0] for r in self.db.execute(
                "SELECT sha256 FROM edr_threats WHERE source = 'feed' AND "
                "verdict = 'malicious' AND by_user = '' AND first_seen < ?",
                (now - FEED_KEEP_DAYS * 86400,))]
            for sha in old:
                row = self.db.execute("SELECT * FROM edr_threats WHERE "
                                      "sha256 = ?", (sha,)).fetchone()
                self._put_threat(sha, "removed", name=row["name"],
                                 severity=row["severity"], source="feed",
                                 org_id=None, by_user=FEED_EXPIRED, now=now,
                                 first_seen=row["first_seen"])
            self.db.commit()
        return len(old)

    def meta(self, key: str, default: str = "") -> str:
        row = self.db.execute("SELECT value FROM edr_meta WHERE key = ?",
                              (key,)).fetchone()
        return row[0] if row is not None else default

    def set_meta(self, **values) -> None:
        with self._lock:
            for k, v in values.items():
                self.db.execute("INSERT INTO edr_meta (key, value) VALUES "
                                "(?, ?) ON CONFLICT(key) DO UPDATE SET "
                                "value = excluded.value", (k, str(v)))
            self.db.commit()

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
                          "edr_isolations", "edr_sightings"):
                self.db.execute(f"DELETE FROM {table} WHERE org_id = ?",
                                (int(org_id),))
            # Its finds stay blocked at the other companies that found them
            # too, now under one of theirs; the rest go with it.
            self.db.execute(
                "UPDATE edr_threats SET org_id = (SELECT MIN(s.org_id) FROM "
                "edr_sightings s WHERE s.sha256 = edr_threats.sha256) "
                "WHERE org_id = ? AND EXISTS (SELECT 1 FROM edr_sightings s "
                "WHERE s.sha256 = edr_threats.sha256)", (int(org_id),))
            self.db.execute("DELETE FROM edr_threats WHERE org_id = ?",
                            (int(org_id),))
            self.db.commit()


# ----- the MalwareBazaar feed ---------------------------------------------------
class FeedError(Exception):
    """Why the feed could not be read, in words for the Antivirus page."""


def parse_feed_csv(text: str) -> list:
    """[(sha256, name)] from MalwareBazaar's CSV export.

    Its header is a comment line ("# "first_seen_utc","sha256_hash",...),
    so the columns are found by name there, and a file without it still
    gives up its fingerprints. The name is the malware family when
    MalwareBazaar knows it."""
    import csv
    import io
    header = []
    out, seen = [], set()
    for line in io.StringIO(text or ""):
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if "sha256" in line:
                header = next(csv.reader([line.lstrip("# ")],
                                         skipinitialspace=True), [])
            continue
        fields = next(csv.reader([line], skipinitialspace=True), [])
        col = dict(zip(header, fields)) if header else {}
        sha = (col.get("sha256_hash") or "").strip().lower()
        if not _SHA256_RE.match(sha):
            sha = next((f.strip().lower() for f in fields
                        if _SHA256_RE.match(f.strip().lower())), "")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        family = (col.get("signature") or "").strip()
        kind = (col.get("file_type_guess") or "").strip()
        if family and family.lower() != "n/a":
            name = f"MalwareBazaar: {family}"
        elif kind and kind.lower() != "n/a":
            name = f"MalwareBazaar: {kind} sample"
        else:
            name = "MalwareBazaar sample"
        out.append((sha, name))
    return out


def fetch_feed(key: str, fetch=None) -> str:
    """The recent-additions CSV. `fetch(url) -> (status, bytes)` stands in
    for the network in tests."""
    import urllib.error
    import urllib.request
    url = FEED_URL.format(key=quote((key or "").strip(), safe=""))
    if fetch is None:
        def fetch(u):
            req = urllib.request.Request(u, headers={
                "User-Agent": "EasyMikroTik antivirus feed"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, r.read(50 * 1024 * 1024)
            except urllib.error.HTTPError as e:
                return e.code, e.read(2000)
    try:
        status, body = fetch(url)
    except OSError as exc:
        raise FeedError(f"MalwareBazaar could not be reached: {exc}") from exc
    if status in (401, 403):
        raise FeedError("abuse.ch did not accept the key. Check it on "
                        "auth.abuse.ch and paste it again.")
    if status != 200:
        raise FeedError(f"MalwareBazaar answered {status}.")
    if body[:2] == b"PK":                       # served zipped
        import io
        import zipfile
        import zlib
        # Capped unpacked too: 50 MB zipped could otherwise unpack to far
        # more than the server has memory for.
        cap = 200 * 1024 * 1024
        try:
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                with z.open(z.namelist()[0]) as fh:
                    body = fh.read(cap + 1)
        except (zipfile.BadZipFile, IndexError, NotImplementedError,
                RuntimeError, zlib.error, OSError) as exc:
            raise FeedError(f"MalwareBazaar sent a broken zip: {exc}") from exc
        if len(body) > cap:
            raise FeedError("MalwareBazaar's list unpacked to more than "
                            "200 MB; not imported.")
    return body.decode("utf-8", "replace")


def run_feed(store: EdrStore, auth, now: float | None = None,
             fetch=None) -> tuple:
    """Fetch, add and age off, and record how it went for the page.
    Returns (ok, message)."""
    now = time.time() if now is None else now
    key = (auth.get_setting(SETTING_FEED_KEY) or "") if auth else ""
    if not key:
        return False, "No abuse.ch key is saved, so the feed is off."
    store.set_meta(feed_tried=now)
    try:
        samples = parse_feed_csv(fetch_feed(key, fetch))
        if not samples:
            raise FeedError("MalwareBazaar sent no fingerprints.")
    except FeedError as exc:
        store.set_meta(feed_error=str(exc))
        log.warning("antivirus feed: %s", exc)
        return False, str(exc)
    added = store.add_feed(samples, now)
    expired = store.expire_feed(now)
    store.set_meta(feed_ok=now, feed_error="", feed_added=added,
                   feed_seen=len(samples), feed_expired=expired)
    log.info("antivirus feed: %d new of %d, %d aged off", added,
             len(samples), expired)
    return True, (f"{added} new fingerprint{'' if added == 1 else 's'} from "
                  f"MalwareBazaar ({len(samples)} in its last 48 hours); "
                  f"{expired} older than {FEED_KEEP_DAYS} days taken off.")


def feed_due(store: EdrStore, now: float) -> bool:
    """Every FEED_EVERY after a good import; an hour after a failed one."""
    try:
        tried = float(store.meta("feed_tried", "0") or 0)
        ok = float(store.meta("feed_ok", "0") or 0)
    except ValueError:
        return True
    if ok and ok >= tried:
        return now - ok >= FEED_EVERY
    return now - tried >= FEED_RETRY


def start_feed_thread(store: EdrStore, auth, check_every: int = 1800):
    """Import the feed on a timer inside the dashboard process. Does
    nothing until a key is saved."""
    def loop():
        while True:
            time.sleep(check_every)
            try:
                if auth.get_setting(SETTING_FEED_KEY) and feed_due(
                        store, time.time()):
                    run_feed(store, auth)
            except Exception:  # noqa: BLE001 -- try again next time round
                log.exception("antivirus feed import failed")
    t = threading.Thread(target=loop, name="mikromon-edr-feed", daemon=True)
    t.start()
    return t


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
