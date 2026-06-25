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

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ACCESS TESTS PASSED")
