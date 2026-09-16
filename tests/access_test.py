"""Offline tests for on-demand remote access (WebFig/Winbox through the hub):
grant lifecycle, expiry/auto-close, per-device+kind port reuse, and the nginx
http/stream config rendering. No network — the hub reload is not exercised here.

Run:  ./.venv/Scripts/python.exe tests/access_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import access

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()
store = access.AccessStore(os.path.join(tmp, "access.json"))
T0 = 1_000_000.0

print("Grant lifecycle:")
g = store.open("R1", "webfig", "10.10.0.2", ttl=900, now=T0)
check("opening a grant returns an HTTPS WebFig mapping",
      g["scheme"] == "https" and g["router_port"] == 80
      and access.WEBFIG_PORTS[0] <= g["port"] <= access.WEBFIG_PORTS[1])
check("grant is active before it expires",
      store.grant_for("R1", "webfig", now=T0 + 800) is not None)
check("grant is gone after it expires",
      store.grant_for("R1", "webfig", now=T0 + 901) is None)

print("Refresh reuses the same port; Winbox uses its own range:")
again = store.open("R1", "webfig", "10.10.0.2", ttl=900, now=T0 + 100)
check("re-opening keeps the same port (stable URL)", again["port"] == g["port"])
wb = store.open("R1", "winbox", "10.10.0.2", ttl=900, now=T0 + 100)
check("Winbox grant is raw TCP to 8291 in the Winbox range",
      wb["scheme"] == "winbox" and wb["router_port"] == 8291
      and access.WINBOX_PORTS[0] <= wb["port"] <= access.WINBOX_PORTS[1])
check("WebFig and Winbox ports differ", wb["port"] != again["port"])

print("Isolation + close + sweep:")
other = store.open("R2", "webfig", "10.10.0.3", ttl=900, now=T0 + 100)
check("a second device gets a different port", other["port"] != again["port"])
store.close("R1", "winbox")
check("close drops just that grant",
      store.grant_for("R1", "winbox", now=T0 + 100) is None
      and store.grant_for("R1", "webfig", now=T0 + 100) is not None)
# Two active (R1 webfig @T0+100 expires T0+1000, R2 webfig same); sweep past both.
remaining = store.sweep(now=T0 + 100)
check("sweep keeps still-valid grants", remaining == 2)
remaining = store.sweep(now=T0 + 5000)
check("sweep removes all expired grants (ports auto-close)", remaining == 0)
check("active() reflects the swept state", store.active(now=T0 + 5000) == [])

print("nginx rendering:")
store.open("R1", "webfig", "10.10.0.2", ttl=900, now=T0 + 6000)
store.open("R1", "winbox", "10.10.0.2", ttl=900, now=T0 + 6000)
grants = store.active(now=T0 + 6000)
http_cfg = access.render_nginx_http(grants, "/etc/ssl/hub.crt", "/etc/ssl/hub.key")
stream_cfg = access.render_nginx_stream(grants)
check("http render emits a TLS server -> router :80 for WebFig only",
      "listen" in http_cfg and "ssl_certificate /etc/ssl/hub.crt" in http_cfg
      and "proxy_pass http://10.10.0.2:80" in http_cfg
      and http_cfg.count("server {") == 1)
check("http render carries websocket upgrade headers (WebFig terminal)",
      "Upgrade $http_upgrade" in http_cfg)
check("stream render emits a raw TCP proxy -> router :8291 for Winbox only",
      "proxy_pass 10.10.0.2:8291" in stream_cfg
      and "ssl" not in stream_cfg and stream_cfg.count("server {") == 1)
check("grant_ports lists every open public port",
      access.grant_ports(grants) == sorted(g["port"] for g in grants))

print("Hub apply (renders both nginx include files, prunes expired):")
http_f = os.path.join(tmp, "http.conf")
stream_f = os.path.join(tmp, "stream.conf")
store.open("R9", "webfig", "10.10.0.9", ttl=10, now=T0 + 6000)  # will be expired
ports = access.apply_hub_config(store.path, "/c.crt", "/c.key", http_f, stream_f,
                                now=T0 + 6100)  # past R9's 10s ttl
http_txt = open(http_f, encoding="utf-8").read()
stream_txt = open(stream_f, encoding="utf-8").read()
check("apply writes a WebFig server block to the http include",
      "proxy_pass http://10.10.0.2:80" in http_txt)
check("apply writes a Winbox server block to the stream include",
      "proxy_pass 10.10.0.2:8291" in stream_txt)
check("apply pruned the expired grant (its port is not served)",
      "10.10.0.9" not in http_txt and "10.10.0.9" not in stream_txt
      and all("R9" not in g["device"] for g in store.active(now=T0 + 6100)))

print("An unreadable grants file is tolerated, not fatal:")
# The grants file's ownership legitimately flips between the web service and
# the root-run access-reload timer that prunes it every minute — a device
# page renders this on every view, so a permission mismatch here must never
# crash it (reported in production: it did, with no graceful fallback).
unreadable = os.path.join(tmp, "unreadable-access.json")
with open(unreadable, "w") as fh:
    fh.write('{"grants": {}}')
os.chmod(unreadable, 0o000)
try:
    ustore = access.AccessStore(unreadable)
    check("grant_for() on an unreadable file returns None, doesn't raise",
          ustore.grant_for("R1", "webfig") is None)
    check("active() on an unreadable file returns [], doesn't raise",
          ustore.active() == [])
finally:
    os.chmod(unreadable, 0o644)  # so cleanup can remove tmp/ afterward

print("")
print("WebFig proxying (the details that decide whether it actually works):")

_g = [{"kind": "webfig", "device": "B1", "port": 9443,
       "tunnel_ip": "10.10.1.1", "router_port": 80, "expires": 1.0}]
_http = access.render_nginx_http(_g, "/c.pem", "/k.pem")

# WebFig is NOT a WebSocket app -- it is plain HTTP POSTs to /jsproxy. Sending
# "Connection: upgrade" on every request announces an upgrade that is not
# happening, and invites RouterOS to close the connection.
check("Connection: upgrade is sent only when the CLIENT asked for one, via a "
      "map -- not hard-coded onto every request",
      "$mm_connection_upgrade" in _http
      and "map $http_upgrade $mm_connection_upgrade" in _http
      and 'Connection "upgrade"' not in _http)

# nginx caps a request body at 1 MB by default, so the page loads and the one
# thing it was opened to do -- upload a .npk, restore a backup -- fails 413.
check("uploads are allowed through: firmware, backups and certificates all "
      "go through this proxy and none of them fit in nginx's 1 MB default",
      "client_max_body_size" in _http)

# The documented symptom of WebFig behind nginx is being thrown back to the
# login page after about ninety seconds. That is the send and connect
# timeouts, not the read one, which was the only one set.
check("all three timeouts are set, not just the read one",
      "proxy_read_timeout" in _http and "proxy_send_timeout" in _http
      and "proxy_connect_timeout" in _http)

check("responses are not buffered -- WebFig polls for state, and buffering "
      "holds small replies back and makes the UI look stuck",
      "proxy_buffering off" in _http)

check("the router is told the original scheme and client, rather than seeing "
      "every request as coming from the hub over plain http",
      "X-Forwarded-Proto https" in _http and "X-Real-IP" in _http)

check("with no grants the file is empty -- a dangling map with no server "
      "behind it is just something else to go wrong",
      access.render_nginx_http([], "/c.pem", "/k.pem") == "")

check("a Winbox grant is never rendered into the http context by mistake",
      "9443" in _http and "winbox" not in _http.lower())

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ACCESS TESTS PASSED")
