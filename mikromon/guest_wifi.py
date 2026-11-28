"""Branded guest Wi-Fi: a lead magnet that hands off to RouterOS.

A guest network has two front doors. The first is a splash page somebody
actually looks at, which is why it carries the company's brand and asks for a
name and email rather than a bare "accept and connect". The second is the
router, where five Hotspot menus have to agree before anybody gets online.

Three rules drive this module:

  * Nothing from a browser reaches HTML unescaped, or reaches SQLite outside
    a `?` placeholder. The splash page is public and hostile input is normal.
  * The guest credential is deliberately public -- guests must type it -- but
    it is still sealed at rest, so a copied database does not hand it over.
  * The router work is a Plan, not a side effect. Every operation carries an
    inverse, and reconciliation is keyed on our own comment tag so a human's
    Hotspot entry is never adopted, rewritten or removed.
"""
from __future__ import annotations

import csv
import html
import io
import ipaddress
import logging
import os
import re
import sqlite3
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from . import vault
from .push.plan import Operation, Plan
from .push.reconcile import reconcile_list

log = logging.getLogger(__name__)

TAG = "mikromon:guestwifi:"

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_DEVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")
_IFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}$")
_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_MAC_COLON = re.compile(r"^[0-9a-fA-F]{12}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

# Defaults live here as well as in the schema: a partial upsert must not turn
# an omitted field into an empty string or, worse, into a NULL.
DEFAULTS = {
    "device": "",
    "headline": "Welcome to Free Guest Wi-Fi",
    "subheadline": "Sign in below to get online.",
    "logo_url": "",
    "accent_color": "#2563eb",
    "bg_color": "#0f172a",
    "terms_text": "By connecting, you agree to acceptable use of our guest network.",
    "redirect_url": "",
    "hotspot_iface": "vlan-guest",
    "subnet": "10.99.0.0/24",
    "vlan_id": None,
    "down_mbps": 10.0,
    "up_mbps": 5.0,
    "session_minutes": 120,
    "guest_username": "guest",
    "guest_password": "",
    "shared_secret": "",
    "require_name": 1,
    "require_email": 1,
    "require_phone": 0,
    "require_company": 0,
    "show_marketing_optin": 1,
    "enabled": 1,
}

_PORTAL_FIELDS = ("org_id", "slug", "device", "brand_name", "headline",
                 "subheadline", "logo_url", "accent_color", "bg_color",
                 "terms_text", "redirect_url", "hotspot_iface", "subnet",
                 "vlan_id", "down_mbps", "up_mbps", "session_minutes",
                 "guest_username", "guest_password", "shared_secret",
                 "require_name", "require_email", "require_phone",
                 "require_company", "show_marketing_optin", "enabled")

_FLAGS = ("require_name", "require_email", "require_phone", "require_company",
          "show_marketing_optin", "enabled")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS guest_portals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    device TEXT NOT NULL DEFAULT '',
    brand_name TEXT NOT NULL,
    headline TEXT NOT NULL DEFAULT 'Welcome to Free Guest Wi-Fi',
    subheadline TEXT NOT NULL DEFAULT 'Sign in below to get online.',
    logo_url TEXT NOT NULL DEFAULT '',
    accent_color TEXT NOT NULL DEFAULT '#2563eb',
    bg_color TEXT NOT NULL DEFAULT '#0f172a',
    terms_text TEXT NOT NULL DEFAULT 'By connecting, you agree to acceptable use of our guest network.',
    redirect_url TEXT NOT NULL DEFAULT '',
    hotspot_iface TEXT NOT NULL DEFAULT 'vlan-guest',
    subnet TEXT NOT NULL DEFAULT '10.99.0.0/24',
    vlan_id INTEGER,
    down_mbps REAL NOT NULL DEFAULT 10.0,
    up_mbps REAL NOT NULL DEFAULT 5.0,
    session_minutes INTEGER NOT NULL DEFAULT 120,
    guest_username TEXT NOT NULL DEFAULT 'guest',
    guest_password TEXT NOT NULL DEFAULT '',
    shared_secret TEXT NOT NULL DEFAULT '',
    require_name INTEGER NOT NULL DEFAULT 1,
    require_email INTEGER NOT NULL DEFAULT 1,
    require_phone INTEGER NOT NULL DEFAULT 0,
    require_company INTEGER NOT NULL DEFAULT 0,
    show_marketing_optin INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_guest_portals_org ON guest_portals(org_id);
CREATE TABLE IF NOT EXISTS guest_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    portal_id INTEGER NOT NULL,
    device TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    company TEXT NOT NULL DEFAULT '',
    marketing_optin INTEGER NOT NULL DEFAULT 0,
    client_mac TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_guest_leads_org ON guest_leads(org_id);
CREATE INDEX IF NOT EXISTS ix_guest_leads_portal ON guest_leads(portal_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_guest_leads_email ON guest_leads(org_id, email);
"""


class GuestWifiError(ValueError):
    """Bad portal data, or a handoff URL that would be unsafe to render."""


# ---------------------------------------------------------------------------
# Validation. Every one of these is also what the HTML renderer relies on:
# a colour that passed here cannot break out of a style attribute.
# ---------------------------------------------------------------------------

def _text(value, field, limit) -> str:
    out = str(value if value is not None else "").strip()
    if _CTRL.search(out):
        raise GuestWifiError(f"{field} may not contain line breaks or control characters.")
    if len(out) > limit:
        raise GuestWifiError(f"{field} is too long (maximum {limit} characters).")
    return out


def _slug(value) -> str:
    out = _text(value, "slug", 48).lower()
    if not _SLUG.match(out):
        raise GuestWifiError(
            "A portal slug must be URL-safe: lowercase letters, numbers and "
            "single dashes, like 'acme-guest'.")
    return out


def _color(value, field) -> str:
    out = _text(value, field, 7).lower()
    if not _COLOR.match(out):
        raise GuestWifiError(f"{field} must be a hex colour like #2563eb.")
    return out


def _http_url(value, field, *, allow_path=False) -> str:
    raw = str(value if value is not None else "").strip()
    if not raw:
        return ""
    raw = _text(raw, field, 2048)
    if _CTRL.search(raw) or any(ch.isspace() for ch in raw) or "\\" in raw:
        raise GuestWifiError(f"{field} contains characters a URL may not have.")
    if allow_path and raw.startswith(("/static/", "/assets/")):
        if _CTRL.search(raw):
            raise GuestWifiError(f"{field} is not a valid local path.")
        return raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise GuestWifiError(f"{field} is not a valid URL.") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        allowed = ("https:// or http://" if not allow_path else
                   "https://, http://, or a /static/ or /assets/ path")
        raise GuestWifiError(f"{field} must be {allowed}.")
    try:
        parts.port  # a bad port raises ValueError
    except ValueError:
        raise GuestWifiError(f"{field} has an invalid port.") from None
    if parts.username is not None or parts.password is not None:
        raise GuestWifiError(f"{field} may not contain login credentials.")
    return raw


def _subnet(value) -> str:
    raw = _text(value, "subnet", 64)
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise GuestWifiError(
            f"{raw!r} is not an IP range. Use a private IPv4 range like "
            "10.99.0.0/24.") from None
    if net.version != 4 or not net.is_private or net.prefixlen > 30:
        raise GuestWifiError(
            "The guest subnet must be a private IPv4 range with room for "
            "clients, e.g. 10.99.0.0/24.")
    return str(net)


def _number(value, field, low, high, *, integer=False) -> int | float:
    try:
        num = int(str(value).strip()) if integer else float(str(value).strip())
    except (TypeError, ValueError):
        raise GuestWifiError(f"{field} must be a number between {low} and {high}.") from None
    if not low <= num <= high:
        raise GuestWifiError(f"{field} must be between {low} and {high}.")
    return num


def _flag(value, field) -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None or value == "":
        return 0
    if str(value).strip().lower() in ("1", "true", "yes", "on"):
        return 1
    if str(value).strip().lower() in ("0", "false", "no", "off"):
        return 0
    raise GuestWifiError(f"{field} must be yes or no.")


def _hostname(value, field) -> str:
    host = _text(value, field, 253).rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host             # a literal IP: caller decides if it is private
    except ValueError:
        pass
    if not _HOST.match(host):
        raise GuestWifiError(f"{field} is not a valid hostname or IP address.")
    return host


def _validate(values: dict) -> dict:
    """Return a complete, normalised portal row (before secrets are sealed)."""
    out = dict(DEFAULTS)
    out.update({k: values[k] for k in _PORTAL_FIELDS if k in values})
    out["org_id"] = _number(out["org_id"], "org_id", 1, 2_000_000_000,
                            integer=True)
    out["slug"] = _slug(out.get("slug"))
    out["device"] = _text(out["device"], "device", 64)
    if out["device"] and not _DEVICE.match(out["device"]):
        raise GuestWifiError("device must be a router name like 'R1'.")
    out["brand_name"] = _text(out.get("brand_name"), "brand_name", 120)
    if not out["brand_name"]:
        raise GuestWifiError("A portal needs a brand name.")
    for field, limit in (("headline", 300), ("subheadline", 500),
                         ("terms_text", 1000)):
        out[field] = _text(out[field], field, limit)
    out["logo_url"] = _http_url(out["logo_url"], "logo_url", allow_path=True)
    out["redirect_url"] = _http_url(out["redirect_url"], "redirect_url")
    out["accent_color"] = _color(out["accent_color"], "accent_color")
    out["bg_color"] = _color(out["bg_color"], "bg_color")
    out["hotspot_iface"] = _text(out["hotspot_iface"], "hotspot_iface", 32)
    if not _IFACE.match(out["hotspot_iface"]):
        raise GuestWifiError("hotspot_iface must be a RouterOS interface name "
                             "like 'vlan-guest'.")
    out["subnet"] = _subnet(out["subnet"])
    vlan = out["vlan_id"]
    if vlan is None or vlan == "":
        out["vlan_id"] = None
    else:
        out["vlan_id"] = _number(vlan, "vlan_id", 2, 4094, integer=True)
    out["down_mbps"] = _number(out["down_mbps"], "down_mbps", 0.5, 10000)
    out["up_mbps"] = _number(out["up_mbps"], "up_mbps", 0.5, 10000)
    out["session_minutes"] = _number(out["session_minutes"], "session_minutes",
                                     5, 10080, integer=True)
    out["guest_username"] = _text(out["guest_username"], "guest_username", 32)
    if not _IFACE.match(out["guest_username"]):
        raise GuestWifiError("guest_username must be a plain RouterOS user name.")
    for field, limit in (("guest_password", 128), ("shared_secret", 256)):
        out[field] = _text(out[field], field, limit)
    for field in _FLAGS:
        out[field] = _flag(out[field], field)
    return out


def _safe_color(value, default: str) -> str:
    """A colour from a hand-built portal dict, never from a form POST."""
    text = str(value or "").strip().lower()
    return html.escape(text if _COLOR.match(text) else default, quote=True)


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _enabled(portal) -> bool:
    """The kill switch, read the same way everywhere (including form strings)."""
    return _flag(portal.get("enabled", 1), "enabled") == 1


def _unavailable_html() -> str:
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, "
            "initial-scale=1\"><title>Guest Wi-Fi</title></head><body>"
            "<main><h1>This guest Wi-Fi portal is unavailable.</h1>"
            "<p>Please ask the venue for help.</p></main></body></html>")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class GuestWifiStore:
    """Portals and leads in SQLite WAL, safe to use from web and worker threads."""

    _SECRET_FIELDS = ("guest_password", "shared_secret")

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

    def _seal(self, values: dict) -> dict:
        out = dict(values)
        for field in self._SECRET_FIELDS:
            out[field] = vault.seal(out.get(field, ""), self._dir)
        return out

    def _row(self, row, *, public=False) -> dict:
        if row is None:
            return None
        out = dict(row)
        out["guest_password"] = vault.unseal(out.get("guest_password", ""),
                                             self._dir)
        if vault.is_sealed(out.get("shared_secret")):
            out["shared_secret"] = vault.unseal(out["shared_secret"], self._dir)
        if public:
            # The guest password is printed on the public page by design.
            # The RADIUS secret is an operator-only setting: never expose it
            # through a lookup keyed by a public slug.
            out.pop("shared_secret", None)
        return out

    def upsert_portal(self, org_id, data) -> dict:
        """Create or update a portal. Bad data raises GuestWifiError."""
        # The trusted org_id is the one the caller was authenticated for,
        # never one that arrived in the same form/JSON blob as the portal.
        given = {k: v for k, v in dict(data or {}).items() if k != "org_id"}
        given["org_id"] = org_id
        if "guest_password" not in given and "hotspot_password" in given:
            given["guest_password"] = given.pop("hotspot_password")
        with self._lock:
            portal_id = given.get("id")
            existing = None
            if portal_id not in (None, ""):
                existing = self.db.execute(
                    "SELECT * FROM guest_portals WHERE id=? AND org_id=?",
                    (portal_id, org_id)).fetchone()
                if existing is None:
                    raise GuestWifiError("That portal does not belong to this "
                                         "organisation.")
                given["org_id"] = org_id
            elif given.get("slug"):
                try:
                    wanted = _slug(given["slug"])
                except GuestWifiError:
                    wanted = ""
                found = self.db.execute(
                    "SELECT * FROM guest_portals WHERE slug=?",
                    (wanted,)).fetchone()
                if found is not None and found["org_id"] != org_id:
                    raise GuestWifiError(
                        f"The slug {wanted!r} is already in use by another "
                        "organisation. Pick another.")
                existing = found
            if existing is not None:
                # Router entries are owned by comments carrying this slug.
                # Letting it change would strand five managed entries on the
                # router that no future plan would ever clean up.
                wanted = _slug(given.get("slug", existing["slug"]))
                if wanted != existing["slug"]:
                    raise GuestWifiError(
                        "A portal's slug cannot be changed. Create a new "
                        "portal instead, then remove the old one.")
                given["slug"] = existing["slug"]
            merged = {k: DEFAULTS[k] for k in DEFAULTS}
            if existing is not None:
                merged.update({k: existing[k] for k in _PORTAL_FIELDS
                               if k in existing.keys()})
            merged.update(given)
            values = _validate(merged)
            if values["device"]:
                # A named router gets one active portal. RouterOS user names
                # are global on that box, so two portals for the same device
                # must not both provision the default 'guest' user: the second
                # apply would fail with a duplicate-name error.
                clash = self.db.execute(
                    "SELECT slug FROM guest_portals WHERE org_id=? "
                    "AND device=? AND enabled=1 AND id<>? "
                    "AND LOWER(guest_username)=LOWER(?) LIMIT 1",
                    (org_id, values["device"],
                     existing["id"] if existing is not None else -1,
                     values["guest_username"])).fetchone()
                if clash is not None:
                    raise GuestWifiError(
                        f"Portal {clash['slug']!r} already uses guest user "
                        f"{values['guest_username']!r} on router "
                        f"{values['device']!r}. Give this portal a different "
                        "guest_username.")
            values["updated_at"] = time.time()
            sealed = self._seal(values)
            cols = list(_PORTAL_FIELDS) + ["updated_at"]
            try:
                if existing is not None:
                    self.db.execute(
                        "UPDATE guest_portals SET " +
                        ", ".join(f"{c}=?" for c in cols) + " WHERE id=?",
                        [sealed[c] for c in cols] + [existing["id"]])
                    new_id = existing["id"]
                else:
                    self.db.execute(
                        "INSERT INTO guest_portals (" + ", ".join(cols) +
                        ") VALUES (" + ", ".join("?" for _ in cols) + ")",
                        [sealed[c] for c in cols])
                    new_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                raise GuestWifiError(
                    f"The slug {values['slug']!r} is already in use.") from exc
            return self._row(self.db.execute(
                "SELECT * FROM guest_portals WHERE id=?", (new_id,)).fetchone())

    def get_portal(self, org_id, portal_id=None, device=None) -> dict | None:
        """One portal for this org: an explicit id, a router's own, or default."""
        with self._lock:
            if portal_id not in (None, ""):
                row = self.db.execute(
                    "SELECT * FROM guest_portals WHERE id=? AND org_id=?",
                    (portal_id, org_id)).fetchone()
            elif device:
                row = self.db.execute(
                    "SELECT * FROM guest_portals WHERE org_id=? AND "
                    "(device=? OR device='') "
                    "ORDER BY (device<>'') DESC, id DESC LIMIT 1",
                    (org_id, device)).fetchone()
            else:
                row = self.db.execute(
                    "SELECT * FROM guest_portals WHERE org_id=? AND device='' "
                    "ORDER BY id DESC LIMIT 1", (org_id,)).fetchone()
            return self._row(row)

    def list_portals(self, org_id) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM guest_portals WHERE org_id=? ORDER BY id DESC",
                (org_id,)).fetchall()
            return [self._row(r) for r in rows]

    def get_portal_by_slug(self, slug) -> dict | None:
        """Public lookup for the splash route: no RADIUS secret in the result."""
        try:
            clean = _slug(slug)
        except GuestWifiError:
            return None
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM guest_portals WHERE slug=?", (clean,)).fetchone()
            return self._row(row, public=True)

    def delete_portal(self, org_id, portal_id) -> bool:
        with self._lock:
            cur = self.db.execute(
                "DELETE FROM guest_portals WHERE id=? AND org_id=?",
                (portal_id, org_id))
            self.db.commit()
            return cur.rowcount > 0

    @staticmethod
    def _mac(value) -> str:
        raw = _text(value, "client_mac", 64).strip()
        if not raw:
            return ""
        compact = re.sub(r"[-:.]", "", raw).lower()
        if len(compact) != 12 or not _MAC_COLON.match(compact):
            raise GuestWifiError("That MAC address is not in a recognised format.")
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))

    @staticmethod
    def _ip(value) -> str:
        raw = _text(value, "client_ip", 64).strip()
        if not raw:
            return ""
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            raise GuestWifiError("That client IP address is not valid.") from None

    def record_lead(self, portal, *, name, email, phone="", company="",
                    marketing_optin=False, client_mac="", client_ip="") -> dict:
        """Store a lead, enforcing exactly the fields this portal asks for."""
        if not _enabled(portal):
            raise GuestWifiError("This guest Wi-Fi portal is disabled.")
        org_id = portal["org_id"]
        portal_id = portal["id"]
        values = {"name": name, "email": email, "phone": phone,
                  "company": company}
        for field in ("name", "email", "phone", "company"):
            values[field] = _text(values[field], field, 200).strip()
            require = "require_" + field
            if portal.get(require, DEFAULTS.get(require, 0)) and not values[field]:
                label = field.capitalize()
                raise GuestWifiError(f"{label} is required on this network.")
        if values["email"]:
            if len(values["email"]) > 254 or not _EMAIL.match(values["email"]):
                raise GuestWifiError("Enter a valid email address.")
            values["email"] = values["email"].lower()
        mac = self._mac(client_mac)
        ip_addr = self._ip(client_ip)
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO guest_leads (org_id, portal_id, device, name, "
                "email, phone, company, marketing_optin, client_mac, client_ip, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (org_id, portal_id, portal.get("device", ""), values["name"],
                 values["email"], values["phone"], values["company"],
                 int(bool(marketing_optin)), mac, ip_addr, time.time()))
            self.db.commit()
            return dict(self.db.execute(
                "SELECT * FROM guest_leads WHERE id=?",
                (cur.lastrowid,)).fetchone())

    def _lead_query(self, org_id, portal_id, search):
        sql = "SELECT * FROM guest_leads WHERE org_id=?"
        args = [org_id]
        if portal_id not in (None, ""):
            sql += " AND portal_id=?"
            args.append(portal_id)
        if search:
            # Escape LIKE metacharacters: a search for '%' must mean a
            # percent sign, not "every lead in the organisation".
            like = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += (" AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' "
                    "OR phone LIKE ? ESCAPE '\\' OR company LIKE ? ESCAPE '\\' "
                    "OR client_mac LIKE ? ESCAPE '\\')")
            args.extend([f"%{like}%"] * 5)
        return sql, args

    def list_leads(self, org_id, *, portal_id=None, search="", limit=200,
                   offset=0) -> list[dict]:
        limit = _number(limit, "limit", 0, 1000, integer=True)
        offset = _number(offset, "offset", 0, 2_000_000_000, integer=True)
        sql, args = self._lead_query(org_id, portal_id, search)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def lead_stats(self, org_id) -> dict:
        now = time.time()
        with self._lock:
            row = self.db.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS d1, "
                "SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS d7, "
                "SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS d30, "
                "SUM(marketing_optin) AS optin "
                "FROM guest_leads WHERE org_id=?",
                (now - 86400, now - 7 * 86400, now - 30 * 86400,
                 org_id)).fetchone()
        total = int(row["total"] or 0)
        optin = int(row["optin"] or 0)
        return {"total": total, "last_24h": int(row["d1"] or 0),
                "last_7d": int(row["d7"] or 0), "last_30d": int(row["d30"] or 0),
                "optin_count": optin,
                "optin_pct": round(100 * optin / total, 1) if total else 0.0}

    @staticmethod
    def _csv_cell(value) -> str:
        """A cell starting with a formula character becomes inert text.

        Spreadsheet programs execute =, +, - and @ cells on open, and tabs /
        carriage returns can move the rest of the text into a new cell.
        """
        cell = "" if value is None else str(value)
        return "'" + cell if cell[:1] in ("=", "+", "-", "@", "\t", "\r") else cell

    def export_leads_csv(self, org_id, *, portal_id=None) -> str:
        sql, args = self._lead_query(org_id, portal_id, "")
        sql += " ORDER BY created_at DESC, id DESC"
        with self._lock:
            rows = self.db.execute(sql, args).fetchall()
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        writer.writerow(("id", "org_id", "portal_id", "device", "name",
                         "email", "phone", "company", "marketing_optin",
                         "client_mac", "client_ip", "created_at"))
        for row in rows:
            writer.writerow([self._csv_cell(row[k]) for k in
                             ("id", "org_id", "portal_id", "device", "name",
                              "email", "phone", "company", "marketing_optin",
                              "client_mac", "client_ip", "created_at")])
        return out.getvalue()


# ---------------------------------------------------------------------------
# The public pages
# ---------------------------------------------------------------------------

def _safe_destination(value, allowed_hosts=None) -> str:
    """An http(s) URL safe to put in an href or a hidden form value.

    `allowed_hosts`, when supplied, is the caller's server-side allowlist.
    Without one we keep the original RouterOS destination as given: guests
    are redirected back to whatever site they asked for before the hotspot
    intercepted them, which is often a public hostname.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        raw = _text(raw, "link-orig", 2048)
    except GuestWifiError:
        return ""
    if _CTRL.search(raw) or any(ch.isspace() for ch in raw):
        return ""
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return ""
        parts.port  # raises on a nonsense port
    except ValueError:
        return ""
    if parts.username is not None or parts.password is not None:
        return ""
    if allowed_hosts is not None:
        allowed = {str(h).lower().rstrip(".") for h in allowed_hosts}
        if parts.hostname.lower().rstrip(".") not in allowed:
            return ""
    return raw


def safe_hotspot_url(value, allowed_hosts=None) -> str:
    """Only a local gateway or a valid hostname may receive a hotspot login.

    A login form whose action came from a query string is an open redirect
    with free credentials attached. Private/link-local IPs and real hostnames
    cover the MikroTik gateways guests actually see; a public IP literal,
    javascript:, data: or a CRLF injection gets no form at all.

    A DNS hostname is accepted because RouterOS hotspot templates use one;
    a web route that knows its own gateways should pass `allowed_hosts` so a
    tampered hidden field cannot send the guest credential elsewhere.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        raw = _text(raw, "link-login-only", 2048)
    except GuestWifiError:
        return ""
    if _CTRL.search(raw) or any(ch.isspace() for ch in raw) or "\\" in raw:
        return ""
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return ""
        parts.port
    except ValueError:
        return ""
    if parts.username is not None or parts.password is not None:
        return ""
    host = parts.hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_unspecified):
            return ""
    except ValueError:
        if not _HOST.match(host) or len(host) > 253:
            return ""
    if allowed_hosts is not None:
        allowed = {str(h).lower().strip("[]").rstrip(".")
                   for h in allowed_hosts}
        if host.lower().strip("[]").rstrip(".") not in allowed:
            return ""
    return raw


def _hidden(name: str, value) -> str:
    return f'<input type="hidden" name="{_esc(name)}" value="{_esc(value)}">'


def render_splash_html(portal: dict, *, link_login_only: str = "",
                       link_orig: str = "", client_mac: str = "",
                       client_ip: str = "", error: str = "",
                       values: dict | None = None) -> str:
    """The branded page a guest sees before giving us their details.

    It posts to our own connect route rather than straight to the router: the
    lead has to be recorded first. The MikroTik variables travel as hidden
    values and come back in render_connected_html()'s auto-submit form.
    """
    values = values or {}
    if not _enabled(portal):
        return _unavailable_html()
    accent = _safe_color(portal.get("accent_color"), DEFAULTS["accent_color"])
    bg = _safe_color(portal.get("bg_color"), DEFAULTS["bg_color"])
    brand = _text(portal.get("brand_name", ""), "brand_name", 200)
    logo = portal.get("logo_url", "") or ""
    try:
        logo = _http_url(logo, "logo_url", allow_path=True)
    except GuestWifiError:
        logo = ""

    fields = []
    specs = (
        ("name", "Full name", "text", "require_name"),
        ("email", "Email address", "email", "require_email"),
        ("phone", "Phone number", "tel", "require_phone"),
        ("company", "Company", "text", "require_company"),
    )
    for name, label, kind, flag in specs:
        if not portal.get(flag, DEFAULTS.get(flag, 0)):
            continue
        required = " required" if portal.get(flag) else ""
        fields.append(
            f'<label>{_esc(label)}<input type="{kind}" name="{name}"'
            f' value="{_esc(values.get(name, ""))}"{required}></label>')
    if portal.get("show_marketing_optin", DEFAULTS["show_marketing_optin"]):
        checked = " checked" if values.get("marketing_optin") else ""
        fields.append(
            '<label class="check"><input type="checkbox" name="marketing_optin"'
            f' value="1"{checked}> Send me occasional updates</label>')
    fields.append(
        '<label class="check"><input type="checkbox" name="terms" value="1"'
        ' required> ' + _esc(portal.get("terms_text", DEFAULTS["terms_text"]))
        + '</label>')

    err = (f'<div class="error" role="alert">{_esc(error)}</div>'
           if error else "")
    logo_html = (f'<img src="{_esc(logo)}" alt="{_esc(brand)} logo">'
                 if logo else "")
    slug = _text(portal.get("slug", ""), "slug", 48)
    hidden = "".join((
        _hidden("link-login-only", safe_hotspot_url(link_login_only)),
        _hidden("link-orig", _safe_destination(link_orig)),
        _hidden("mac", GuestWifiStore._mac(client_mac)),
        _hidden("ip", GuestWifiStore._ip(client_ip)),
    ))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(brand)} — Guest Wi-Fi</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;background:{bg};color:#f8fafc;
 font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
 display:flex;align-items:center;justify-content:center;padding:20px}}
.card{{width:100%;max-width:440px;background:#fff;color:#0f172a;
 border-radius:16px;padding:28px;box-shadow:0 20px 50px #0004}}
.logo{{display:block;max-height:64px;max-width:100%;margin:0 auto 16px}}
h1{{margin:0 0 8px;font-size:1.5rem;text-align:center;color:{bg}}}
p.sub{{margin:0 0 20px;text-align:center;color:#475569}}
label{{display:block;margin:12px 0 0;font-weight:600;font-size:.9rem}}
input[type=text],input[type=email],input[type=tel]{{width:100%;
 padding:11px 12px;margin-top:5px;border:1px solid #cbd5e1;
 border-radius:8px;font:inherit}}
label.check{{display:flex;gap:8px;align-items:flex-start;font-weight:400;
 font-size:.85rem;color:#475569}}
button{{width:100%;margin-top:20px;padding:13px;border:0;border-radius:8px;
 background:{accent};color:#fff;font:inherit;font-weight:700;cursor:pointer}}
.error{{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;
 border-radius:8px;padding:10px;margin-bottom:14px}}
a{{color:{accent}}}
</style>
</head>
<body>
<main class="card">
{logo_html}
<h1>{_esc(portal.get('headline', DEFAULTS['headline']))}</h1>
<p class="sub">{_esc(portal.get('subheadline', DEFAULTS['subheadline']))}</p>
{err}
<form method="post" action="/guest/{_esc(slug)}/connect">
{hidden}
{''.join(fields)}
<button type="submit">Connect to Wi-Fi</button>
</form>
</main>
</body>
</html>
"""


def render_connected_html(portal: dict, *, link_login_only: str = "",
                          link_orig: str = "", allowed_hosts=None,
                          allowed_origins=None) -> str:
    """Hand the guest to the router's own login endpoint, or show a preview.

    The router login form carries the guest credential, so its action is
    validated rather than echoed: javascript:, data:, public IP literals and
    CR/LF are all refused. Opened outside a hotspot (a preview, a browser
    refresh) there is no gateway to post to, so a plain connected card with a
    redirect button is shown instead.

    `allowed_hosts` / `allowed_origins` let a web route that knows the router's
    own gateway and its trusted redirect targets constrain both hidden fields
    server-side. Left unset, the RouterOS conventions apply.
    """
    if not _enabled(portal):
        return _unavailable_html()
    action = safe_hotspot_url(link_login_only, allowed_hosts=allowed_hosts)
    dst = _safe_destination(link_orig, allowed_hosts=allowed_origins)
    brand = _text(portal.get("brand_name", ""), "brand_name", 200)
    accent = _safe_color(portal.get("accent_color"), DEFAULTS["accent_color"])
    bg = _safe_color(portal.get("bg_color"), DEFAULTS["bg_color"])
    head = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(brand)} — Connected</title>
<style>body{{margin:0;min-height:100vh;background:{bg};color:#0f172a;
 font:16px/1.5 system-ui,sans-serif;display:flex;align-items:center;
 justify-content:center;padding:20px}}
.card{{width:100%;max-width:420px;background:#fff;border-radius:16px;
 padding:32px;text-align:center;box-shadow:0 20px 50px #0004}}
h1{{margin:0 0 8px;color:{bg}}}p{{color:#475569}}
.btn{{display:inline-block;margin-top:12px;padding:12px 22px;
 border-radius:8px;background:{accent};color:#fff;text-decoration:none}}
</style></head><body><main class="card">"""
    tail = "</main></body></html>"
    if not action:
        return (head + "<h1>You're connected!</h1>"
                "<p>This page is being viewed outside the hotspot, so there is "
                "no gateway to sign in to.</p>"
                f'<a class="btn" href="{_esc(dst or "#")}">Continue</a>' + tail)
    form = "".join((
        '<form id="mm-hotspot-connect" method="post" action="',
        _esc(action), '">',
        _hidden("username", portal.get("guest_username", "guest")),
        _hidden("password", portal.get("guest_password", "")),
        _hidden("dst", dst),
        '<button type="submit" class="btn">Connect</button></form>',
    ))
    return (head + "<h1>Connecting you now…</h1>"
            "<p>Your details have been saved. One moment while the hotspot "
            "signs you in.</p>" + form +
            '<script>document.getElementById("mm-hotspot-connect").submit();'
            '</script>' + tail)


def hotspot_login_html_snippet(portal_url: str) -> str:
    """The small /hotspot/login.html override that sends guests to the portal.

    RouterOS expands $(...) template variables before serving the file, so the
    four tokens are left literal in the query string. RouterOS performs that
    expansion after HTML escaping, so a gateway that puts quotes into a URL
    variable can still disturb the attribute; this is a limitation of the
    hotspot template format, not of the portal URL we validate here.
    """
    target = _safe_destination(portal_url)
    if not target:
        raise GuestWifiError("The portal URL must be an http(s) URL with a host.")
    parts = urlsplit(target)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    sep = "&" if parts.query else "?"
    dest = (base + sep + "link-login-only=$(link-login-only)"
            "&link-orig=$(link-orig)&mac=$(mac)&ip=$(ip)")
    safe = _esc(dest)
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            f'<meta http-equiv="refresh" content="0; url={safe}">'
            f'<title>Guest Wi-Fi</title></head><body>'
            f'<p>Redirecting to the guest portal… '
            f'<a href="{safe}">Continue</a></p></body></html>\n')


# ---------------------------------------------------------------------------
# Router provisioning
# ---------------------------------------------------------------------------

def _hotspot_name(slug: str) -> str:
    return f"mm-guest-{_slug(slug)}"


def _managed_ops(pusher, path, key, row, label) -> list[Operation]:
    """Reconcile one managed row, tolerating RouterOS's yes/no read-back.

    RouterOS hands a boolean back as `false` (or a Python False), while its
    config is usually written `no`. Without normalising the read side, every
    apply would issue a pointless `set disabled=no` forever. The params sent
    to the router keep the familiar spelling.
    """
    current = [dict(r) for r in pusher.api.fetch(path)]
    for existing in current:
        for field, want in row.items():
            if want not in ("no", "yes"):
                continue
            got = existing.get(field)
            if isinstance(got, bool) or str(got).lower() in ("false", "true"):
                low = str(got).lower()
                existing[field] = ("no" if low in ("false", "no")
                                   else "yes")
    return reconcile_list(path, key, [row], current,
                          manage_tag=row["comment"], label=label)


def build_hotspot_plan(pusher, cfg, portal: dict, portal_host: str) -> Plan:
    """Reconcile the five Hotspot entries one portal needs, with rollback.

    Each list is owned by its own exact comment, not by the TAG prefix: two
    portals on one router must not delete each other's entries when either one
    is applied. A human's entry with a lookalike name is never touched.
    RouterOS requires distinct user names on one box: the store refuses to
    save two enabled portals for the same named router with the same
    `guest_username`, so the shared default 'guest' stays unambiguous.
    """
    slug = _slug(portal.get("slug", ""))
    owner = cfg.name if cfg is not None else pusher.cfg.name
    if not _enabled(portal):
        return Plan(owner, [], summary="guest Wi-Fi portal disabled",
                    note="The portal is disabled; no router changes were made.")
    name = _hotspot_name(slug)
    iface = _text(portal.get("hotspot_iface", DEFAULTS["hotspot_iface"]),
                  "hotspot_iface", 32)
    if not _IFACE.match(iface):
        raise GuestWifiError("hotspot_iface must be a RouterOS interface name.")
    username = _text(portal.get("guest_username", "guest"), "guest_username", 32)
    if not _IFACE.match(username):
        raise GuestWifiError("guest_username must be a plain RouterOS user name.")
    password = _text(portal.get("guest_password", ""), "guest_password", 128)
    down = _number(portal.get("down_mbps", DEFAULTS["down_mbps"]),
                   "down_mbps", 0.5, 10000)
    up = _number(portal.get("up_mbps", DEFAULTS["up_mbps"]),
                 "up_mbps", 0.5, 10000)
    minutes = _number(portal.get("session_minutes", DEFAULTS["session_minutes"]),
                      "session_minutes", 5, 10080, integer=True)
    host = _hostname(portal_host, "portal_host")
    if _CTRL.search(host):
        raise GuestWifiError("portal_host may not contain control characters.")

    desired = [
        (("ip", "hotspot", "user", "profile"), "name",
         {"name": name,
          "rate-limit": f"{up:g}M/{down:g}M",
          "session-timeout": f"{minutes}m",
          "shared-users": "unlimited",
          "comment": TAG + "uprof:" + slug}, "guest user profile"),
        (("ip", "hotspot", "profile"), "name",
         {"name": name, "login-by": "http-chap,http-pap",
          "comment": TAG + "hprof:" + slug}, "guest hotspot profile"),
        (("ip", "hotspot"), "name",
         {"name": name, "interface": iface, "profile": name,
          "disabled": "no", "comment": TAG + "hs:" + slug}, "guest hotspot"),
        (("ip", "hotspot", "user"), "name",
         {"name": username, "password": password, "profile": name,
          "comment": TAG + "user:" + slug}, "guest user"),
        (("ip", "hotspot", "walled-garden"), "dst-host",
         {"dst-host": host, "action": "allow",
          "comment": TAG + "wg:" + slug}, "walled garden"),
    ]
    ops: list[Operation] = []
    for path, key, row, label in desired:
        ops += _managed_ops(pusher, path, key, row, label)
    # reconcile_list puts changed values in the human-readable description,
    # which Pusher writes to the audit log on preview and apply. The guest
    # password is public by design, but it need not be copied into that log.
    for op in ops:
        if tuple(op.path) == ("ip", "hotspot", "user"):
            visible = ", ".join(
                f"{k}={v}" for k, v in op.params.items()
                if k not in (".id", "password"))
            op.desc = f"{op.action} guest user {visible}".rstrip()
    return Plan(owner, ops, summary=f"guest Wi-Fi hotspot ({slug})")


__all__ = [
    "TAG", "DEFAULTS", "GuestWifiError", "GuestWifiStore",
    "safe_hotspot_url", "render_splash_html", "render_connected_html",
    "hotspot_login_html_snippet", "build_hotspot_plan",
]
