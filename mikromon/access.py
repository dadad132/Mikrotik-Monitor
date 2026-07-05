"""On-demand remote access to managed routers, proxied through the hub.

A customer opens WebFig or Winbox for one device from the dashboard; the web app
records a time-limited **access grant** and the hub exposes a public port that
proxies to that router over the existing WireGuard tunnel:

  * **WebFig** -> HTTPS terminated at the hub (nginx `http`), proxied to the
    router's WebFig (port 80). The browser<->hub leg is encrypted by the hub's
    TLS certificate; the router itself never needs a public IP or a cert.
  * **Winbox** -> a raw TCP proxy (nginx `stream`) to the router's Winbox port
    (8291). The Winbox protocol encrypts itself, so no TLS termination is needed.

Grants AUTO-EXPIRE (default 15 min). The hub re-renders its proxy config from the
currently-active grants on every change and on a one-minute timer, so an expired
grant's port is torn down automatically — routers are never left permanently
exposed. This is the "on-demand" model.

The store is a small JSON file under the app dir (same place as hub.json), which
the hardened web service is already allowed to write; a privileged reload unit on
the hub turns it into nginx config (see deploy/install.sh).
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time

# Public port pools on the hub. WebFig (HTTPS) and Winbox (raw TCP) are kept in
# separate ranges so the renderer can tell them apart at a glance.
WEBFIG_PORTS = (20000, 24999)
WINBOX_PORTS = (25000, 29999)
DEFAULT_TTL = 15 * 60          # seconds an access grant stays open

KINDS = {
    "webfig": {"label": "WebFig", "router_port": 80, "ports": WEBFIG_PORTS,
               "scheme": "https", "tls": True},
    "winbox": {"label": "Winbox", "router_port": 8291, "ports": WINBOX_PORTS,
               "scheme": "winbox", "tls": False},
}


def _gid(device: str, kind: str) -> str:
    return f"{device}\x1f{kind}"


class AccessStore:
    """Time-limited access grants, persisted as JSON. Thread-safe."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    # ----- persistence ------------------------------------------------------
    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, ValueError):
            data = {}
        data.setdefault("grants", {})
        return data

    def _save(self, data: dict) -> None:
        tmp = f"{self.path}.tmp"
        # 0600 — the grants file maps devices to tunnel IPs and open ports.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)

    # ----- queries ----------------------------------------------------------
    def active(self, now: float | None = None) -> list:
        """Non-expired grants (does not modify the file)."""
        now = time.time() if now is None else now
        return [g for g in self._load()["grants"].values()
                if g.get("expires", 0) > now]

    def grant_for(self, device: str, kind: str,
                  now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        g = self._load()["grants"].get(_gid(device, kind))
        return g if g and g.get("expires", 0) > now else None

    # ----- mutations --------------------------------------------------------
    def open(self, device: str, kind: str, tunnel_ip: str,
             ttl: int = DEFAULT_TTL, now: float | None = None) -> dict:
        """Create (or extend) a grant and return it. Reuses the existing port
        for a device+kind so a refresh keeps the same URL."""
        if kind not in KINDS:
            raise ValueError(f"unknown access kind: {kind!r}")
        now = time.time() if now is None else now
        with self._lock:
            data = self._load()
            self._prune(data, now)
            gid = _gid(device, kind)
            existing = data["grants"].get(gid)
            port = existing["port"] if existing else self._alloc_port(data, kind)
            grant = {"device": device, "kind": kind, "port": port,
                     "tunnel_ip": tunnel_ip, "scheme": KINDS[kind]["scheme"],
                     "router_port": KINDS[kind]["router_port"],
                     "created": (existing or {}).get("created", now),
                     "expires": now + ttl}
            data["grants"][gid] = grant
            self._save(data)
            return grant

    def close(self, device: str, kind: str) -> None:
        with self._lock:
            data = self._load()
            data["grants"].pop(_gid(device, kind), None)
            self._save(data)

    def sweep(self, now: float | None = None) -> int:
        """Drop expired grants; return how many remain. Called by the hub timer
        path so ports close on their own."""
        now = time.time() if now is None else now
        with self._lock:
            data = self._load()
            self._prune(data, now)
            self._save(data)
            return len(data["grants"])

    # ----- helpers ----------------------------------------------------------
    @staticmethod
    def _prune(data: dict, now: float) -> None:
        for gid in [g for g, v in data["grants"].items()
                    if v.get("expires", 0) <= now]:
            del data["grants"][gid]

    @staticmethod
    def _alloc_port(data: dict, kind: str) -> int:
        lo, hi = KINDS[kind]["ports"]
        # Only this kind's grants occupy this range — counting all kinds
        # would declare exhaustion while half the range is still free.
        taken = {g["port"] for g in data["grants"].values()
                 if lo <= g.get("port", 0) <= hi}
        if len(taken) >= (hi - lo + 1):
            raise RuntimeError("no free access ports left")
        while True:
            port = secrets.randbelow(hi - lo + 1) + lo
            if port not in taken:
                return port


# ===== hub-side rendering (turn grants into nginx config) ===================
def render_nginx_http(grants, cert: str, key: str) -> str:
    """`http {}`-context server blocks for the WebFig (HTTPS) grants."""
    blocks = []
    for g in grants:
        if g.get("kind") != "webfig":
            continue
        blocks.append(
            f"# {g['device']} (WebFig) — expires {int(g['expires'])}\n"
            f"server {{\n"
            f"    listen {g['port']} ssl;\n"
            f"    ssl_certificate {cert};\n"
            f"    ssl_certificate_key {key};\n"
            f"    location / {{\n"
            f"        proxy_pass http://{g['tunnel_ip']}:{g['router_port']};\n"
            f"        proxy_set_header Host $host;\n"
            f"        proxy_http_version 1.1;\n"
            f"        proxy_set_header Upgrade $http_upgrade;\n"
            f'        proxy_set_header Connection "upgrade";\n'
            f"        proxy_read_timeout 3600s;\n"
            f"    }}\n"
            f"}}")
    return "\n".join(blocks) + ("\n" if blocks else "")


def render_nginx_stream(grants) -> str:
    """`stream {}`-context server blocks for the Winbox (raw TCP) grants."""
    blocks = []
    for g in grants:
        if g.get("kind") != "winbox":
            continue
        blocks.append(
            f"# {g['device']} (Winbox) — expires {int(g['expires'])}\n"
            f"server {{\n"
            f"    listen {g['port']};\n"
            f"    proxy_pass {g['tunnel_ip']}:{g['router_port']};\n"
            f"    proxy_timeout 1h;\n"
            f"}}")
    return "\n".join(blocks) + ("\n" if blocks else "")


def grant_ports(grants) -> list:
    """The public ports currently in use — for the firewall to open/close."""
    return sorted(g["port"] for g in grants)


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def apply_hub_config(grants_file: str, cert: str, key: str,
                     http_conf: str, stream_conf: str,
                     now: float | None = None) -> list:
    """Hub-side: prune expired grants, then render the active ones into the two
    nginx include files (WebFig http + Winbox stream). Returns the active ports.
    The caller reloads nginx afterwards. Run by the access-reload unit as root."""
    store = AccessStore(grants_file)
    store.sweep(now)                       # drop expired grants + persist
    grants = store.active(now)
    _write(http_conf, "# easymikrotik WebFig access — generated, do not edit\n"
           + render_nginx_http(grants, cert, key))
    _write(stream_conf, "# easymikrotik Winbox access — generated, do not edit\n"
           + render_nginx_stream(grants))
    return grant_ports(grants)
