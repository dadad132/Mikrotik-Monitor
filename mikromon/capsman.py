"""CAPsMAN: one controller set, many APs, three SSIDs, live clients.

A fleet of APs is only useful when the controller configuration is identical
on every site. This module keeps the *desired* state in SQLite (SSIDs, their
VLANs and isolation, controller status, blocked clients) and turns it into a
RouterOS Plan: no write happens when a page is merely opened, every row we own
carries our own comment tag, and every operation can be rolled back.

Two RouterOS generations speak different API menus. RouterOS 7 uses
``/interface/wifi/*``; older boxes use ``/caps-man/*``. The driver is detected
per router (or pinned by the controller row) and the same desired state is
translated into whichever dialect the router speaks.

Secrets follow the same rule as the rest of the app: Wi-Fi passphrases are
sealed in SQLite with ``vault``, unsealed only while a plan is built, and
redacted from Plan descriptions so they never reach the audit log.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import time

from . import vault
from .push.plan import Operation, Plan
from .push.reconcile import reconcile_list
from .push.runner import Pusher

log = logging.getLogger(__name__)

TAG = "mikromon:capsman:"

_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")
_IFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_MAC_FULL = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_MAC_SEP = re.compile(r"^([0-9A-F]{2})([-:.])(?:[0-9A-F]{2}\2){4}[0-9A-F]{2}$")
_MAC_PLAIN = re.compile(r"^[0-9A-F]{12}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_SIGNAL = re.compile(r"^\s*(-?\d+)")

_PURPOSES = ("guest", "staff", "iot")
_MODES = ("open", "wpa2-psk", "wpa3-psk", "wpa2-wpa3")
_BANDS = ("2ghz", "5ghz", "dual")
_DRIVERS = ("auto", "wifi", "legacy")
_STATUSES = ("", "ok", "unchanged", "error", "offline")
_AUTH = {"wpa2-psk": "wpa2-psk", "wpa3-psk": "wpa3-psk",
         "wpa2-wpa3": "wpa2-psk,wpa3-psk"}

# RouterOS menus, kept in one place so the reader, the adopter and the sync
# planner cannot drift into reading one menu and writing another.
W_MGR = ("interface", "wifi", "capsman")
W_RCAP = ("interface", "wifi", "capsman", "remote-cap")
W_RADIO = ("interface", "wifi", "radio")
W_IFACE = ("interface", "wifi")
W_REG = ("interface", "wifi", "registration-table")
W_DP = ("interface", "wifi", "datapath")
W_SEC = ("interface", "wifi", "security")
W_CFG = ("interface", "wifi", "configuration")
W_PROV = ("interface", "wifi", "provisioning")
W_ACL = ("interface", "wifi", "access-list")
L_MGR = ("caps-man", "manager")
L_RCAP = ("caps-man", "remote-cap")
L_RADIO = ("caps-man", "radio")
L_IFACE = ("caps-man", "interface")
L_REG = ("caps-man", "registration-table")
L_DP = ("caps-man", "datapath")
L_SEC = ("caps-man", "security")
L_CFG = ("caps-man", "configuration")
L_PROV = ("caps-man", "provisioning")
L_ACL = ("caps-man", "access-list")
_LEASES = ("ip", "dhcp-server", "lease")
_ARP = ("ip", "arp")
_SEC_PATHS = (W_SEC, L_SEC)

DEFAULTS = {
    "ssid": "",
    "purpose": "guest",
    "vlan_id": None,
    "security_mode": "wpa2-psk",
    "passphrase": "",
    "client_isolation": "auto",
    "band": "dual",
    "bridge": "bridge",
    "down_mbps": None,
    "up_mbps": None,
    "enabled": 1,
}

_SSID_FIELDS = ("org_id", "name", "ssid", "purpose", "vlan_id",
                "security_mode", "passphrase", "client_isolation", "band",
                "bridge", "down_mbps", "up_mbps", "enabled")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS capsman_ssids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    ssid TEXT NOT NULL,
    purpose TEXT NOT NULL,
    vlan_id INTEGER,
    security_mode TEXT NOT NULL DEFAULT 'wpa2-psk',
    passphrase TEXT NOT NULL DEFAULT '',
    client_isolation INTEGER NOT NULL DEFAULT 0,
    band TEXT NOT NULL DEFAULT 'dual',
    bridge TEXT NOT NULL DEFAULT 'bridge',
    down_mbps REAL,
    up_mbps REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at REAL NOT NULL,
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS ix_capsman_ssids_org ON capsman_ssids(org_id);
CREATE TABLE IF NOT EXISTS capsman_controllers (
    org_id INTEGER NOT NULL,
    device TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    driver TEXT NOT NULL DEFAULT 'auto',
    last_sync_at REAL,
    last_sync_status TEXT NOT NULL DEFAULT '',
    last_sync_summary TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (org_id, device)
);
CREATE TABLE IF NOT EXISTS capsman_blocked_macs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    mac TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    blocked_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    UNIQUE (org_id, mac)
);
CREATE INDEX IF NOT EXISTS ix_capsman_blocked_org
    ON capsman_blocked_macs(org_id);
"""


class CapsmanError(ValueError):
    """Bad SSID/controller/client data, or a request we refuse to send."""


# ---------------------------------------------------------------------------
# Small, shared normalisers
# ---------------------------------------------------------------------------

def _text(value, field, limit) -> str:
    out = str(value if value is not None else "").strip()
    if _CTRL.search(out):
        raise CapsmanError(f"{field} may not contain line breaks or control "
                           "characters.")
    if len(out) > limit:
        raise CapsmanError(f"{field} is too long (maximum {limit} characters).")
    return out


def _safe_summary(text) -> str:
    """Router errors are untrusted text; keep them storable and readable."""
    out = _CTRL.sub(" ", str(text if text is not None else "")).strip()
    return out[:1000] or "sync failed"


def _slug(value) -> str:
    out = _text(value, "name", 48).lower()
    if not _SLUG.match(out):
        raise CapsmanError(
            "A profile name must be URL-safe: lowercase letters, numbers "
            "and single dashes, like 'guest-net'.")
    return out


def _flag(value, field="enabled") -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None or value == "":
        return 0
    low = str(value).strip().lower()
    if low in ("1", "true", "yes", "on"):
        return 1
    if low in ("0", "false", "no", "off"):
        return 0
    raise CapsmanError(f"{field} must be yes or no.")


def _yn(value) -> str:
    """RouterOS reads a bool back as true/false, but we write yes/no."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    low = str(value if value is not None else "").strip().lower()
    if low in ("true", "yes", "1", "on"):
        return "yes"
    return "no"


def _number(value, field, low, high, *, integer=False):
    try:
        num = int(str(value).strip()) if integer else float(str(value).strip())
    except (TypeError, ValueError):
        raise CapsmanError(
            f"{field} must be a number between {low} and {high}.") from None
    if not low <= num <= high:
        raise CapsmanError(f"{field} must be between {low} and {high}.")
    return num


def _mac(value) -> str:
    """Accept the shapes people paste; return strict AA:BB:CC:DD:EE:FF."""
    raw = str(value if value is not None else "").strip().upper()
    if _MAC_FULL.match(raw):
        return raw
    if _MAC_PLAIN.match(raw):
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    separated = _MAC_SEP.match(raw)
    if separated:
        return raw.replace(separated.group(2), ":")
    raise CapsmanError("A MAC address must look like AA:BB:CC:DD:EE:FF.")


def _mac_or_raw(value) -> str:
    """Router data need not be well formed; never let it break a whole read."""
    try:
        return _mac(value)
    except CapsmanError:
        return str(value if value is not None else "").strip().upper()


def _signal_pct(dbm) -> int:
    match = _SIGNAL.match(str(dbm if dbm is not None else ""))
    if not match:
        return 0
    return max(0, min(100, round((int(match.group(1)) + 90) * 100 / 60)))


def _signal_dbm(value):
    match = _SIGNAL.match(str(value if value is not None else ""))
    return int(match.group(1)) if match else None


def _row_of(value) -> dict:
    return dict(value) if value is not None else {}


def _norm_rows(rows, yes_fields=()) -> list[dict]:
    """librouteros returns strings (or bools) where we wrote yes/no."""
    out = []
    for source in rows:
        row = {}
        for key, value in _row_of(source).items():
            if key == ".id":
                row[key] = value
                continue
            if value is None:
                row[key] = ""
            elif key in ("mac-address", "radio-mac", "active-mac-address"):
                # RouterOS may hand back lowercase or abbreviated MACs. The
                # planner compares keys as text, so normalise before that.
                row[key] = _mac_or_raw(value)
            elif key in yes_fields:
                row[key] = _yn(value)
            else:
                row[key] = str(value)
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def _validate_ssid(values: dict) -> dict:
    """Return a complete, normalised row (before the passphrase is sealed)."""
    out = dict(DEFAULTS)
    out.update({k: values[k] for k in _SSID_FIELDS if k in values})
    out["org_id"] = _number(out["org_id"], "org_id", 1, 2_000_000_000,
                             integer=True)
    out["name"] = _slug(out.get("name"))
    out["ssid"] = _text(out["ssid"], "ssid", 32)
    if not out["ssid"]:
        raise CapsmanError("An SSID needs a network name (1 to 32 characters).")
    if out["purpose"] not in _PURPOSES:
        raise CapsmanError("purpose must be guest, staff or iot.")
    vlan = out["vlan_id"]
    out["vlan_id"] = (None if vlan in (None, "") else
                      _number(vlan, "vlan_id", 2, 4094, integer=True))
    if out["security_mode"] not in _MODES:
        raise CapsmanError("security_mode must be open, wpa2-psk, wpa3-psk "
                           "or wpa2-wpa3.")
    phrase = _text(out["passphrase"], "passphrase", 63)
    if out["security_mode"] == "open":
        # An open network must not quietly keep a previous key.
        phrase = ""
    elif len(phrase) < 8:
        raise CapsmanError("A WPA passphrase must be 8 to 63 characters.")
    out["passphrase"] = phrase
    if out["client_isolation"] == "auto":
        out["client_isolation"] = 1 if out["purpose"] in ("guest", "iot") else 0
    else:
        out["client_isolation"] = _flag(out["client_isolation"],
                                        "client_isolation")
    if out["band"] not in _BANDS:
        raise CapsmanError("band must be 2ghz, 5ghz or dual.")
    out["bridge"] = _text(out["bridge"], "bridge", 64)
    if not _IFACE.match(out["bridge"]):
        raise CapsmanError("bridge must be a RouterOS interface name.")
    for field in ("down_mbps", "up_mbps"):
        raw = out[field]
        out[field] = (None if raw in (None, "") else
                      _number(raw, field, 0, 10000))
    out["enabled"] = _flag(out["enabled"])
    return out


class CapsmanStore:
    """SSIDs, controller status and blocked clients in SQLite WAL.

    The store is shared by web threads and the background sync runner, hence
    WAL, a 5s busy timeout and one lock around each transaction. Every query
    is parameterised and scoped to the org the caller was authenticated for.
    """

    def __init__(self, path: str):
        self.path = path
        self._dir = os.path.dirname(os.path.abspath(path))
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def _ssid_row(self, row) -> dict | None:
        if row is None:
            return None
        out = dict(row)
        out["passphrase"] = vault.unseal(out.get("passphrase", ""), self._dir)
        return out

    def upsert_ssid(self, org_id, data) -> dict:
        """Create or update an SSID. Bad data raises CapsmanError."""
        given = {k: v for k, v in dict(data or {}).items() if k != "org_id"}
        given["org_id"] = org_id
        with self._lock:
            ssid_id = given.get("id")
            existing = None
            if ssid_id not in (None, ""):
                existing = self.db.execute(
                    "SELECT * FROM capsman_ssids WHERE id=? AND org_id=?",
                    (ssid_id, org_id)).fetchone()
                if existing is None:
                    raise CapsmanError("That SSID does not belong to this "
                                       "organisation.")
            elif given.get("name"):
                try:
                    wanted = _slug(given["name"])
                except CapsmanError:
                    wanted = ""
                found = self.db.execute(
                    "SELECT * FROM capsman_ssids WHERE org_id=? AND name=?",
                    (org_id, wanted)).fetchone()
                existing = found
            if existing is not None:
                # RouterOS rows are keyed on this name. Renaming would strand
                # the tagged datapath/security/configuration rows on the box.
                wanted = _slug(given.get("name", existing["name"]))
                if wanted != existing["name"]:
                    raise CapsmanError(
                        "An SSID's profile name cannot be changed. Create a "
                        "new profile instead, then remove the old one.")
                given["name"] = existing["name"]
            merged = dict(DEFAULTS)
            if existing is not None:
                merged.update(self._ssid_row(existing))
            merged.update(given)
            values = _validate_ssid(merged)
            values["updated_at"] = time.time()
            sealed = dict(values)
            sealed["passphrase"] = vault.seal(values["passphrase"], self._dir)
            cols = list(_SSID_FIELDS) + ["updated_at"]
            try:
                if existing is not None:
                    self.db.execute(
                        "UPDATE capsman_ssids SET " +
                        ", ".join(f"{c}=?" for c in cols) + " WHERE id=?",
                        [sealed[c] for c in cols] + [existing["id"]])
                    new_id = existing["id"]
                else:
                    self.db.execute(
                        "INSERT INTO capsman_ssids (" + ", ".join(cols) +
                        ") VALUES (" + ", ".join("?" for _ in cols) + ")",
                        [sealed[c] for c in cols])
                    new_id = self.db.execute(
                        "SELECT last_insert_rowid()").fetchone()[0]
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                raise CapsmanError(
                    f"The profile name {values['name']!r} is already in use."
                ) from exc
            return self._ssid_row(self.db.execute(
                "SELECT * FROM capsman_ssids WHERE id=? AND org_id=?",
                (new_id, org_id)).fetchone())

    def list_ssids(self, org_id) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM capsman_ssids WHERE org_id=? "
                "ORDER BY CASE purpose WHEN 'staff' THEN 0 "
                "WHEN 'guest' THEN 1 ELSE 2 END, id",
                (org_id,)).fetchall()
            return [self._ssid_row(r) for r in rows]

    def delete_ssid(self, org_id, ssid_id) -> bool:
        with self._lock:
            cur = self.db.execute(
                "DELETE FROM capsman_ssids WHERE id=? AND org_id=?",
                (ssid_id, org_id))
            self.db.commit()
            return cur.rowcount > 0

    def set_controller(self, org_id, device, *, enabled=True,
                       driver="auto") -> dict:
        device = _text(device, "device", 64)
        if not _DEVICE.match(device):
            raise CapsmanError("device must be a router name like 'R1'.")
        if driver not in _DRIVERS:
            raise CapsmanError("driver must be auto, wifi or legacy.")
        flag = _flag(enabled)
        with self._lock:
            self.db.execute(
                "INSERT INTO capsman_controllers "
                "(org_id, device, enabled, driver) VALUES (?,?,?,?) "
                "ON CONFLICT(org_id, device) DO UPDATE SET "
                "enabled=excluded.enabled, driver=excluded.driver",
                (org_id, device, flag, driver))
            self.db.commit()
            return dict(self.db.execute(
                "SELECT * FROM capsman_controllers "
                "WHERE org_id=? AND device=?", (org_id, device)).fetchone())

    def list_controllers(self, org_id) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM capsman_controllers WHERE org_id=? "
                "ORDER BY device", (org_id,)).fetchall()]

    def record_sync(self, org_id, device, status, summary):
        if status not in _STATUSES:
            raise CapsmanError("Unknown controller sync status.")
        summary = _text(summary, "summary", 1000)
        with self._lock:
            cur = self.db.execute(
                "UPDATE capsman_controllers SET last_sync_at=?, "
                "last_sync_status=?, last_sync_summary=? "
                "WHERE org_id=? AND device=?",
                (time.time(), status, summary, org_id, device))
            self.db.commit()
            if not cur.rowcount:
                return None
            return dict(self.db.execute(
                "SELECT * FROM capsman_controllers "
                "WHERE org_id=? AND device=?", (org_id, device)).fetchone())

    def block_mac(self, org_id, mac, *, reason="", blocked_by="") -> dict:
        mac = _mac(mac)
        reason = _text(reason, "reason", 500)
        blocked_by = _text(blocked_by, "blocked_by", 120)
        with self._lock:
            existing = self.db.execute(
                "SELECT id, created_at FROM capsman_blocked_macs "
                "WHERE org_id=? AND mac=?", (org_id, mac)).fetchone()
            if existing is not None:
                self.db.execute(
                    "UPDATE capsman_blocked_macs SET reason=?, blocked_by=? "
                    "WHERE id=? AND org_id=?",
                    (reason, blocked_by, existing["id"], org_id))
                new_id = existing["id"]
            else:
                cur = self.db.execute(
                    "INSERT INTO capsman_blocked_macs "
                    "(org_id, mac, reason, blocked_by, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (org_id, mac, reason, blocked_by, time.time()))
                new_id = cur.lastrowid
            self.db.commit()
            return dict(self.db.execute(
                "SELECT * FROM capsman_blocked_macs "
                "WHERE id=? AND org_id=?", (new_id, org_id)).fetchone())

    def unblock_mac(self, org_id, mac) -> bool:
        mac = _mac(mac)
        with self._lock:
            cur = self.db.execute(
                "DELETE FROM capsman_blocked_macs WHERE org_id=? AND mac=?",
                (org_id, mac))
            self.db.commit()
            return cur.rowcount > 0

    def list_blocked_macs(self, org_id) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM capsman_blocked_macs WHERE org_id=? "
                "ORDER BY created_at DESC, id DESC", (org_id,)).fetchall()]


# ---------------------------------------------------------------------------
# Reading a controller
# ---------------------------------------------------------------------------

def detect_driver(api, preference="auto") -> str:
    """Which API dialect this router speaks: wifi (RouterOS 7) or legacy."""
    pref = str(preference or "auto").strip().lower()
    if pref not in _DRIVERS:
        raise CapsmanError("driver must be auto, wifi or legacy.")
    if pref != "auto":
        return pref
    try:
        api.fetch(W_MGR)
        return "wifi"
    except Exception:  # noqa: BLE001 - a missing menu is the probe itself
        pass
    try:
        api.fetch(L_MGR)
        return "legacy"
    except Exception:  # noqa: BLE001
        pass
    # A RouterOS 7 box whose CAPsMAN menu is temporarily unreadable is still
    # much more likely to be wifi than a v6 box. The caller records the read
    # error; a sensible default is better than refusing to look at the site.
    return "wifi"


def _safe_fetch(api, path, errors=None) -> list[dict]:
    """An optional menu (ARP, radios, leases) may not exist on every box.

    A failed read must not masquerade as an empty menu: when ``errors`` is
    supplied, the caller reports the partial view to the user.
    """
    try:
        return [dict(r) for r in api.fetch(path)]
    except Exception as exc:  # noqa: BLE001
        msg = f"/{'/'.join(path)}: {exc}"
        log.debug("capsman: optional read failed: %s", msg)
        if errors is not None:
            errors.append(msg)
        return []


def _ip_by_mac(api, errors=None) -> dict:
    """Join DHCP leases and ARP so a client has an IP even when RouterOS's
    registration table only reports the MAC and the radio interface."""
    out = {}
    for path in (_LEASES, _ARP):
        for row in _safe_fetch(api, path, errors):
            mac = _mac_or_raw(row.get("mac-address")
                              or row.get("active-mac-address") or "")
            ip = str(row.get("address") or row.get("ip-address") or "")
            if mac and ip and mac not in out:
                out[mac] = ip
    return out


def _read_aps(rcaps, radios, ifaces) -> list[dict]:
    aps = {}

    def ensure(mac) -> dict:
        if mac not in aps:
            aps[mac] = {"id": "", "name": "", "identity": "", "address": "",
                        "radio_mac": mac, "model": "", "version": "",
                        "state": "", "radios": 0, "clients_count": 0,
                        "pending": False}
        return aps[mac]

    for row in rcaps:
        mac = _mac_or_raw(row.get("radio-mac") or row.get("mac-address") or "")
        ap = ensure(mac)
        ap.update({
            "id": str(row.get(".id", "")),
            "name": str(row.get("name") or row.get("identity") or mac),
            "identity": str(row.get("identity", "")),
            "address": str(row.get("address", "")),
            "model": str(row.get("board-name") or row.get("model") or ""),
            "version": str(row.get("version", "")),
            "state": str(row.get("state", "")),
            "pending": str(row.get("state", "")).lower() in (
                "pending", "waiting", "unprovisioned", "unauthorized"),
        })
    for row in radios:
        mac = _mac_or_raw(row.get("radio-mac") or row.get("mac-address") or "")
        ap = ensure(mac)
        ap["radios"] += 1
        if not ap["id"]:
            ap["id"] = str(row.get(".id", ""))
        if not ap["name"]:
            ap["name"] = str(row.get("name") or mac)
        if row.get("state") and not ap["state"]:
            ap["state"] = str(row["state"])
    for row in ifaces:
        mac = _mac_or_raw(row.get("radio-mac") or row.get("mac-address") or "")
        if mac:
            ap = ensure(mac)
            if not ap["name"]:
                ap["name"] = str(row.get("name") or mac)
    return list(aps.values())


def _read_clients(api, path, configs, ifaces, device, blocked,
                  errors=None) -> list[dict]:
    ips = _ip_by_mac(api, errors)
    ssids = {str(r.get("name", "")): str(r.get("ssid", ""))
             for r in configs}
    iface_rows = {str(r.get("name", "")): r for r in ifaces}
    out = []
    for row in _safe_fetch(api, path, errors):
        mac = _mac_or_raw(row.get("mac-address")
                          or row.get("address") or "")
        iface = str(row.get("interface", ""))
        config = str(iface_rows.get(iface, {}).get("configuration", ""))
        ssid = (str(row.get("ssid", ""))
                or ssids.get(config, "")
                or str(iface_rows.get(iface, {}).get("ssid", "")))
        dbm = _signal_dbm(row.get("signal-strength")
                          or row.get("signal"))
        out.append({
            "id": str(row.get(".id", "")),
            "device": device,
            "mac": mac,
            "ip": str(row.get("ip-address") or row.get("address") or "")
                  or ips.get(mac, ""),
            "ssid": ssid,
            # The registration table names the WLAN interface the client is
            # on; that is the AP identity an operator can actually act on.
            "ap": iface,
            "interface": iface,
            "signal_dbm": dbm,
            "signal_pct": _signal_pct(dbm),
            "tx_rate": str(row.get("tx-rate", "")),
            "rx_rate": str(row.get("rx-rate", "")),
            "uptime": str(row.get("uptime", "")),
            "blocked": mac in blocked,
        })
    return out


def _read_blocked(api, path, errors=None) -> list[dict]:
    out = []
    for row in _safe_fetch(api, path, errors):
        if str(row.get("action", "")).lower() != "reject":
            continue
        out.append({"id": str(row.get(".id", "")),
                    "mac": _mac_or_raw(row.get("mac-address") or ""),
                    "comment": str(row.get("comment", ""))})
    return out


def read_controller(api, device_name: str, driver_pref="auto") -> dict:
    """Everything the CAPsMAN page needs about one router, in one read.

    Failure to read the controller is reported in ``error`` rather than
    raising: the fleet view has other sites to show, and an offline AP must
    not blank the whole page.
    """
    device = str(device_name or "")
    out = {"device": device, "driver": driver_pref, "capsman_enabled": False,
           "aps": [], "ssids": [], "clients": [], "blocked": [], "error": ""}
    try:
        driver = detect_driver(api, driver_pref)
        out["driver"] = driver
        if driver == "wifi":
            mgr, rcap, radio, iface, reg, cfg, acl = (
                W_MGR, W_RCAP, W_RADIO, W_IFACE, W_REG, W_CFG, W_ACL)
        else:
            mgr, rcap, radio, iface, reg, cfg, acl = (
                L_MGR, L_RCAP, L_RADIO, L_IFACE, L_REG, L_CFG, L_ACL)
        manager = api.fetch(mgr)
        out["capsman_enabled"] = bool(manager) and (
            _yn(manager[0].get("enabled")) == "yes")
        errors = []
        rcaps = _safe_fetch(api, rcap, errors)
        radios = _safe_fetch(api, radio, errors)
        ifaces = _safe_fetch(api, iface, errors)
        configs = _safe_fetch(api, cfg, errors)
        blocked_rows = _read_blocked(api, acl, errors)
        out["blocked"] = blocked_rows
        blocked = {r["mac"] for r in blocked_rows}
        clients = _read_clients(api, reg, configs, ifaces, device, blocked,
                                errors)
        aps = _read_aps(rcaps, radios, ifaces)
        iface_mac = {str(r.get("name", "")):
                     _mac_or_raw(r.get("radio-mac")
                                 or r.get("mac-address") or "")
                     for r in ifaces}
        for client in clients:
            mac = iface_mac.get(client["interface"], "")
            for ap in aps:
                if mac and ap["radio_mac"] == mac:
                    ap["clients_count"] += 1
                    break
        out["aps"] = aps
        out["clients"] = clients
        if errors:
            out["error"] = "; ".join(errors)
        out["ssids"] = [
            {"id": str(r.get(".id", "")), "name": str(r.get("name", "")),
             "ssid": str(r.get("ssid", "")),
             "datapath": str(r.get("datapath", "")),
             "security": str(r.get("security", "")),
             "comment": str(r.get("comment", ""))}
            for r in configs]
    except Exception as exc:  # noqa: BLE001 - a dead site is a normal result
        out["error"] = str(exc)
        log.info("capsman: could not read %s: %s", device, exc)
    return out


# ---------------------------------------------------------------------------
# Planning helpers
# ---------------------------------------------------------------------------

def _manager_ops(api, path, label) -> list[Operation]:
    rows = [dict(r) for r in api.fetch(path)]
    row = rows[0] if rows else {}
    got = _yn(row.get("enabled", "no"))
    if got == "yes":
        return []
    params, old = {"enabled": "yes"}, {"enabled": got}
    if ".id" in row:
        params[".id"] = row[".id"]
        old[".id"] = row[".id"]
    return [Operation(
        "set", path, params, desc=f"enable {label}",
        inverse=Operation("set", path, old, desc=f"restore {label}"))]


def _owns(kind: str):
    """All rows of one managed menu, regardless of which SSID they serve."""
    prefix = TAG + kind
    return lambda row: str(row.get("comment", "")).startswith(prefix)


def _reconcile(api, path, key, desired, comment, label, *, owns=None,
               clear=()) -> list[Operation]:
    """Reconcile one managed menu, leaving unowned rows strictly alone."""
    current = _norm_rows(api.fetch(path),
                         yes_fields=("enabled", "disabled",
                                     "client-isolation", "local-forwarding",
                                     "client-to-client-forwarding"))
    if owns is None:
        owns = lambda row: str(row.get("comment", "")) == comment  # noqa: E731
    ops = reconcile_list(path, key, desired, current,
                         owns=owns, label=label)
    if clear:
        # reconcile_list only compares fields present in the desired row, so
        # a VLAN removed in the UI would otherwise stay on the router forever.
        current_by_key = {}
        for row in current:
            if owns(row) and key in row:
                current_by_key.setdefault(str(row[key]), row)
        for row in desired:
            old = current_by_key.get(str(row.get(key, "")))
            if old is None:
                continue
            stale = {f: "" for f in clear
                     if f not in row and str(old.get(f, "")) not in ("", "None")}
            if not stale:
                continue
            ident = {key: old[key]} if key in old else {}
            params = {".id": old[".id"], **ident, **stale}
            inverse = {".id": old[".id"], **ident,
                       **{f: old.get(f, "") for f in stale}}
            ops.append(Operation(
                "set", path, params,
                desc=f"clear stale {label} fields: " + ", ".join(stale),
                inverse=Operation("set", path, inverse,
                                  desc=f"restore {label} fields")))
    return ops


def _ssid_plan_rows(ssids) -> list[dict]:
    """Validate stored SSIDs and give back concise rows for the planner."""
    out = []
    for source in ssids or []:
        row = _row_of(source)
        name = _slug(row.get("name"))
        ssid = _text(row.get("ssid", ""), "ssid", 32)
        if not ssid:
            raise CapsmanError(f"SSID {name!r} has no network name.")
        mode = str(row.get("security_mode", "wpa2-psk"))
        if mode not in _MODES:
            raise CapsmanError(f"SSID {name!r} has an unknown security mode.")
        vlan = row.get("vlan_id")
        if vlan in (None, ""):
            vlan = ""
        else:
            vlan = str(_number(vlan, "vlan_id", 2, 4094, integer=True))
        phrase = _text(row.get("passphrase", ""), "passphrase", 63)
        if mode != "open" and len(phrase) < 8:
            raise CapsmanError(f"SSID {name!r} needs an 8..63 character key.")
        out.append({
            "name": name, "ssid": ssid, "purpose": row.get("purpose", "guest"),
            "vlan_id": vlan, "mode": mode, "passphrase": phrase,
            "isolation": _flag(row.get("client_isolation", 0)),
            "band": row.get("band", "dual"),
            "bridge": _text(row.get("bridge", "bridge"), "bridge", 64),
        })
    return out


def _redact_secrets(ops) -> None:
    """A passphrase belongs in the API call, never in the audit log."""
    for op in ops:
        if tuple(op.path) not in _SEC_PATHS or "passphrase" not in op.params:
            continue
        visible = ", ".join(
            f"{key}=<redacted>" if key == "passphrase" else f"{key}={value}"
            for key, value in op.params.items() if key != ".id")
        op.desc = f"{op.action} WiFi security {visible}".rstrip()


def _provisioning_row(rows) -> dict | None:
    """Master + slave configurations make every SSID broadcast on each AP."""
    if not rows:
        return None
    master = next((r for r in rows if r["purpose"] == "staff"), rows[0])
    slaves = [r for r in rows if r["name"] != master["name"]]
    return {
        "action": "create-dynamic-enabled",
        "master-configuration": f"mm-cfg-{master['name']}",
        "slave-configurations": ",".join(f"mm-cfg-{r['name']}"
                                         for r in slaves),
        "comment": TAG + "prov:fleet",
    }


def build_adopt_ap_plan(api, cfg, *, ap_mac: str = "", ap_name: str = "",
                        driver_pref="auto") -> Plan:
    """Enable CAPsMAN and approve one pending CAP, with rollback inverses.

    The AP is identified either by its radio MAC or by its name/identity. If
    its WLAN interface already exists but is disabled, it is enabled too.
    Nothing is changed for a human's provisioning rule: only rows with our
    own tag are considered when deciding whether work is already done.
    """
    owner = cfg.name if cfg is not None else ""
    mac = _mac(ap_mac) if ap_mac else ""
    name = _text(ap_name, "ap_name", 64)
    if not mac and not name:
        raise CapsmanError("An AP needs a radio MAC or a name to adopt.")
    driver = detect_driver(api, driver_pref)
    if driver == "wifi":
        mgr, rcap, prov, iface = W_MGR, W_RCAP, W_PROV, W_IFACE
    else:
        mgr, rcap, prov, iface = L_MGR, L_RCAP, L_PROV, L_IFACE

    ops = _manager_ops(api, mgr, "CAPsMAN manager")
    remotes = _norm_rows(_safe_fetch(api, rcap))
    target = None
    for row in remotes:
        row_mac = _mac_or_raw(row.get("radio-mac")
                              or row.get("mac-address") or "")
        names = (str(row.get("name", "")), str(row.get("identity", "")))
        if (mac and row_mac == mac) or (name and name.lower() in
                                        [n.lower() for n in names if n]):
            target = row
            break
    if target is None:
        raise CapsmanError(
            f"No CAP named {name or mac!r} is known to this controller. "
            "Check that the AP is powered and can reach the router.")

    target_mac = _mac_or_raw(target.get("radio-mac")
                             or target.get("mac-address") or "")
    key = (target_mac or name or str(target.get("identity", ""))).lower()
    comment = TAG + "ap:" + key
    already = False
    for row in _norm_rows(_safe_fetch(api, prov)):
        got = str(row.get("comment", ""))
        if got != comment and not got.startswith(TAG + "ap:"):
            continue
        if got == comment or (target_mac and row.get("radio-mac")
                              == target_mac):
            already = True
            break
    if not already:
        params = {"action": "create-dynamic-enabled", "comment": comment}
        if target_mac:
            params["radio-mac"] = target_mac
        else:
            params["identity"] = str(target.get("identity") or name)
        ops.append(Operation(
            "add", prov, params,
            desc=f"approve CAP {name or target_mac}",
            inverse=Operation("remove", prov, {},
                              desc=f"undo approval of CAP {name or target_mac}")))

    for row in _safe_fetch(api, iface):
        row_mac = _mac_or_raw(row.get("radio-mac")
                              or row.get("mac-address") or "")
        names = (str(row.get("name", "")), str(row.get("identity", "")))
        matches = ((target_mac and row_mac == target_mac) or
                   (name and name.lower() in [n.lower() for n in names if n]))
        if matches and _yn(row.get("disabled")) == "yes":
            ident = str(row.get(".id", ""))
            ops.append(Operation(
                "set", iface, {".id": ident, "disabled": "no"},
                desc=f"enable CAP interface {row.get('name', ident)}",
                inverse=Operation(
                    "set", iface, {".id": ident, "disabled": "yes"},
                    desc=f"disable CAP interface {row.get('name', ident)}")))
    return Plan(owner, ops, summary=f"adopt CAP {name or target_mac}")


def build_sync_plan(pusher, cfg, ssids: list[dict],
                    blocked_macs: list[dict], *, driver_pref="auto") -> Plan:
    """Reconcile every published SSID and block onto one controller.

    Each datapath, security profile, configuration, provisioning rule and
    reject rule owns its own exact comment. A hand-made lookalike is neither
    rewritten nor deleted, and applying the same plan twice does nothing.
    """
    owner = cfg.name if cfg is not None else pusher.cfg.name
    driver = detect_driver(pusher.api, driver_pref)
    rows = _ssid_plan_rows([r for r in (ssids or [])
                            if _flag(_row_of(r).get("enabled", 1))])
    blocks = []
    for source in blocked_macs or []:
        mac = _mac(_row_of(source).get("mac"))
        if mac not in blocks:
            blocks.append(mac)

    if driver == "wifi":
        mgr, dp, sec, conf, prov, acl = (
            W_MGR, W_DP, W_SEC, W_CFG, W_PROV, W_ACL)
        dp_rows = []
        for s in rows:
            row = {"name": f"mm-dp-{s['name']}", "bridge": s["bridge"],
                   "client-isolation": "yes" if s["isolation"] else "no",
                   "comment": TAG + "dp:" + s["name"]}
            if s["vlan_id"]:
                row["vlan-id"] = s["vlan_id"]
            dp_rows.append(row)
        clear_dp = ("vlan-id",)
    else:
        mgr, dp, sec, conf, prov, acl = (
            L_MGR, L_DP, L_SEC, L_CFG, L_PROV, L_ACL)
        dp_rows = []
        for s in rows:
            row = {"name": f"mm-dp-{s['name']}", "bridge": s["bridge"],
                   "local-forwarding": "no",
                   "client-to-client-forwarding":
                       "no" if s["isolation"] else "yes",
                   "comment": TAG + "dp:" + s["name"]}
            if s["vlan_id"]:
                row.update({"vlan-mode": "use-tag", "vlan-id": s["vlan_id"]})
            else:
                row["vlan-mode"] = "no-tag"
            dp_rows.append(row)
        clear_dp = ("vlan-id",)

    sec_rows = []
    for s in rows:
        sec_row = {"name": f"mm-sec-{s['name']}",
                   "comment": TAG + "sec:" + s["name"]}
        if s["mode"] != "open":
            sec_row["auth-types"] = _AUTH[s["mode"]]
            sec_row["passphrase"] = s["passphrase"]
        sec_rows.append(sec_row)
    conf_rows = [{"name": f"mm-cfg-{s['name']}", "ssid": s["ssid"],
                  "datapath": f"mm-dp-{s['name']}",
                  "security": f"mm-sec-{s['name']}",
                  "comment": TAG + "cfg:" + s["name"]} for s in rows]

    # One reconciliation per menu: seeing all our rows at once is what lets
    # a disabled SSID's tagged rows be removed without touching a human's.
    ops = _manager_ops(pusher.api, mgr, "CAPsMAN manager")
    ops += _reconcile(pusher.api, dp, "name", dp_rows, "", "WiFi datapath",
                      owns=_owns("dp:"), clear=clear_dp)
    ops += _reconcile(pusher.api, sec, "name", sec_rows, "", "WiFi security",
                      owns=_owns("sec:"),
                      clear=("auth-types", "passphrase"))
    ops += _reconcile(pusher.api, conf, "name", conf_rows, "",
                      "WiFi configuration", owns=_owns("cfg:"))

    # Reconcile provisioning even with no SSIDs: otherwise the last tagged
    # rule would be left pointing at configuration rows we just removed.
    provisioning = _provisioning_row(rows)
    ops += _reconcile(pusher.api, prov, "comment",
                      [provisioning] if provisioning is not None else [],
                      TAG + "prov:fleet", "WiFi provisioning")

    acl_rows = [{"mac-address": mac, "action": "reject",
                 "comment": TAG + "blk:" + mac} for mac in blocks]
    ops += _reconcile(pusher.api, acl, "mac-address", acl_rows, "",
                      "blocked client",
                      owns=lambda row: str(row.get("comment", "")).startswith(
                          TAG + "blk:"))
    _redact_secrets(ops)
    return Plan(owner, ops,
                summary=f"CAPsMAN fleet: {len(rows)} SSID(s), "
                        f"{len(blocks)} blocked client(s)",
                note="down/up Mbps are stored as rate notes for reporting; "
                     "AP radios are not shaped by this plan.")


def disconnect_client(api, *, client_id: str = "", mac: str = "",
                      driver_pref="auto") -> bool:
    """Remove the live registration so a client must authenticate again."""
    ident = _text(client_id, "client_id", 64)
    wanted = _mac(mac) if mac else ""
    if not ident and not wanted:
        raise CapsmanError("A client needs a registration id or a MAC.")
    driver = detect_driver(api, driver_pref)
    path = W_REG if driver == "wifi" else L_REG
    for row in api.fetch(path):
        if ((ident and str(row.get(".id", "")) == ident) or
                (wanted and _mac_or_raw(row.get("mac-address") or
                                        row.get("address") or "") == wanted)):
            api.execute(Operation(
                "remove", path, {".id": row.get(".id", "")},
                desc=f"disconnect client {wanted or ident}"))
            return True
    return False


def block_client_plan(pusher, cfg, mac: str, *, reason: str = "",
                      driver_pref="auto") -> Plan:
    """Add our reject ACL and kick the client off the air right now."""
    owner = cfg.name if cfg is not None else pusher.cfg.name
    wanted = _mac(mac)
    reason = _text(reason, "reason", 500)
    driver = detect_driver(pusher.api, driver_pref)
    acl = W_ACL if driver == "wifi" else L_ACL
    reg = W_REG if driver == "wifi" else L_REG
    acl_rows = _norm_rows(pusher.api.fetch(acl))
    comment = TAG + "blk:" + wanted
    # A reject rule someone else made does not satisfy our desired state:
    # they may delete it at any moment, and it has no rollback inverse here.
    already_rejected = any(
        _mac_or_raw(r.get("mac-address") or "") == wanted
        and str(r.get("action", "")).lower() == "reject"
        and str(r.get("comment", "")) == comment
        for r in acl_rows)
    ops = []
    if not already_rejected:
        ops += _reconcile(
            pusher.api, acl, "mac-address",
            [{"mac-address": wanted, "action": "reject",
              "comment": comment}], "", "blocked client",
            owns=lambda row: str(row.get("comment", "")).startswith(
                TAG + "blk:"))
    for row in pusher.api.fetch(reg):
        if _mac_or_raw(row.get("mac-address")
                       or row.get("address") or "") == wanted:
            # A registration is live state, not configuration: there is no
            # meaningful inverse, and the client may simply reconnect later.
            ops.append(Operation(
                "remove", reg, {".id": row.get(".id", "")},
                desc=f"disconnect newly blocked client {wanted}"))
            break
    return Plan(owner, ops,
                summary=f"block client {wanted}" + (f": {reason}" if reason
                                                    else ""),
                note="A live registration cannot be inverted: the client "
                     "may reconnect if the block is lifted.")


def unblock_client_plan(pusher, cfg, mac: str, *, driver_pref="auto") -> Plan:
    """Remove only the reject rule this app tagged for that MAC."""
    owner = cfg.name if cfg is not None else pusher.cfg.name
    wanted = _mac(mac)
    driver = detect_driver(pusher.api, driver_pref)
    acl = W_ACL if driver == "wifi" else L_ACL
    comment = TAG + "blk:" + wanted
    ops = _reconcile(pusher.api, acl, "mac-address", [], comment,
                     "blocked client",
                     owns=lambda row: str(row.get("comment", "")) == comment)
    return Plan(owner, ops, summary=f"unblock client {wanted}")


def _looks_offline(exc) -> bool:
    text = str(exc).lower()
    return (isinstance(exc, (ConnectionError, OSError, TimeoutError)) or
            any(word in text for word in (
                "offline", "unreachable", "timed out", "timeout",
                "connection refused", "connection failed", "not connected")))


def sync_all_controllers(org_id, caps_store, device_configs: list, *,
                         connect_fn, user="", audit=None) -> list[dict]:
    """Publish one org's state to every enabled controller.

    ``connect_fn(cfg)`` opens a router and returns either a Pusher or a bare
    PushApi-like object (which is wrapped in a non-dry-run Pusher). One dead
    site is recorded and skipped; it never stops the others. The result list
    always has device, status, changes, summary and error, and every attempt
    is written back to the controller row.
    """
    ssids = caps_store.list_ssids(org_id)
    blocked = caps_store.list_blocked_macs(org_id)
    by_name = {}
    for source in device_configs or []:
        if isinstance(source, dict):
            name = str(source.get("name", ""))
        else:
            name = str(getattr(source, "name", ""))
        if name:
            by_name[name] = source

    results = []
    for controller in caps_store.list_controllers(org_id):
        if not _flag(controller.get("enabled", 1)):
            continue
        device = str(controller["device"])
        cfg = by_name.get(device)
        api = None
        changes = 0
        if cfg is None:
            status = "error"
            summary = f"no device config for {device}"
            error = summary
        else:
            status, summary, error = "error", "", ""
            try:
                resource = connect_fn(cfg)
                if hasattr(resource, "apply") and hasattr(resource, "api"):
                    api = resource.api
                    # A preview pusher from a caller still means "publish the
                    # fleet"; silently applying nothing would be a false OK.
                    pusher = (Pusher(cfg, api, dry_run=False,
                                     audit=audit, user=user)
                              if getattr(resource, "dry_run", True)
                              else resource)
                else:
                    api = resource
                    if hasattr(api, "connect"):
                        api.connect()
                    pusher = Pusher(cfg, api, dry_run=False,
                                    audit=audit, user=user)
                plan = build_sync_plan(pusher, cfg, ssids, blocked,
                                       driver_pref=controller.get("driver",
                                                                  "auto"))
                if plan.empty:
                    status = "unchanged"
                    summary = plan.summary or "no changes"
                else:
                    outcome = pusher.apply(plan, feature="capsman")
                    status = "ok"
                    changes = int(outcome.get(
                        "applied", outcome.get("changes", len(plan.ops))))
                    summary = plan.summary
            except Exception as exc:  # noqa: BLE001 - one site must not stop
                status = "offline" if _looks_offline(exc) else "error"
                error = str(exc)
                summary = _safe_summary(f"sync failed: {exc}")
                log.info("capsman: %s sync failed: %s", device, exc)
            finally:
                if api is not None and hasattr(api, "close"):
                    try:
                        api.close()
                    except Exception:  # noqa: BLE001 - teardown is best effort
                        pass
        summary = _safe_summary(summary)
        try:
            caps_store.record_sync(org_id, device, status, summary)
        except Exception:  # noqa: BLE001 - status must not stop the fleet
            log.exception("capsman: could not record sync status for %s",
                          device)
        results.append({"device": device, "status": status,
                        "changes": changes, "summary": summary,
                        "error": error})
    return results


__all__ = [
    "TAG", "CapsmanError", "CapsmanStore", "detect_driver",
    "read_controller", "build_adopt_ap_plan", "build_sync_plan",
    "disconnect_client", "block_client_plan", "unblock_client_plan",
    "sync_all_controllers",
]
