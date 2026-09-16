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

print("")
print("A grant is not a working link (ERR_CONNECTION_REFUSED, reported live):")

import socket as _sk
import mikromon.web as _w
import time as _tm

# A grant is a row in a JSON file. Between it and a link that works sit
# nginx, a systemd path unit, a rendered server block and a certificate --
# and when any of them is missing the browser only says "connection refused".
_g = {"webfig": {"port": 1, "expires": _tm.time() + 900}, "winbox": None}
_html = _w._access_box("B1", "TOK", "38.54.63.107", "10.10.1.1",
                       {"user": "u", "pwd": "p"}, _g)
check("a granted port with nothing listening is called out instead of being "
      "offered as a link that can only fail",
      "not listening on port 1" in _html
      and "https://38.54.63.107:1" not in _html)
check("...with the command that fixes it, since the failure is on the hub "
      "and not on the router",
      "easymikrotik-access-reload.service" in _html)
check("...and Close is still offered, so a broken grant can be cleared",
      'value="close"' in _html)

# A port that IS listening must still produce the ordinary link.
_srv = _sk.socket()
_srv.bind(("127.0.0.1", 0))
_srv.listen(1)
_port = _srv.getsockname()[1]
try:
    _g2 = {"webfig": {"port": _port, "expires": _tm.time() + 900}, "winbox": None}
    _html2 = _w._access_box("B1", "TOK", "38.54.63.107", "10.10.1.1",
                            {"user": "u", "pwd": "p"}, _g2)
    check("a port that IS listening gives the normal link and no warning",
          f"https://38.54.63.107:{_port}" in _html2
          and "not listening" not in _html2)
finally:
    _srv.close()

check("the probe says no for a port nothing holds",
      not _w._port_is_listening(1))

print("")
print("The grants file is written by two different users:")

# The web service writes it when somebody opens or closes access. The reload
# unit writes it as ROOT when it sweeps expired grants. A rename installs a
# brand-new inode, so without carrying the owner across, the first root write
# left it root:root 0600 and the web service could no longer record anything.
# Clicking Open then did nothing at all -- the grant went nowhere and the
# button came straight back.
_gd = tempfile.mkdtemp()
_gp = os.path.join(_gd, "grants.json")
_gs = access.AccessStore(_gp)
_grant = _gs.open("B1", "webfig", "10.10.1.1", ttl=900)

check("a grant is recorded and can be read back",
      _grant["port"] > 0 and _gs.grant_for("B1", "webfig") is not None)

_seen = {"chmod": 0, "chown": 0}
_rc, _ro = os.chmod, getattr(os, "chown", None)


def _spy_chmod(path, mode):
    _seen["chmod"] += 1
    return _rc(path, mode)


def _spy_chown(path, uid, gid):
    _seen["chown"] += 1
    if _ro:
        return _ro(path, uid, gid)


os.chmod = _spy_chmod
if _ro:
    os.chown = _spy_chown
try:
    _gs.open("B2", "webfig", "10.10.1.2", ttl=900)
finally:
    os.chmod = _rc
    if _ro:
        os.chown = _ro

check("rewriting it carries the existing owner and mode across, rather than "
      "installing a fresh root-owned file the web service cannot touch",
      _seen["chmod"] >= 1 and (_seen["chown"] >= 1 or _ro is None))

# The reload timer runs once a minute as root. Rewriting an unchanged file
# that often is pure risk for no gain -- and is how it came to be re-owned.
_mt = os.stat(_gp).st_mtime_ns
_tm.sleep(0.02)
_gs.sweep()
check("a sweep with nothing expired does not rewrite the file at all",
      os.stat(_gp).st_mtime_ns == _mt)
check("...and leaves the live grants alone",
      _gs.grant_for("B1", "webfig") is not None)

_gs.open("B3", "winbox", "10.10.1.3", ttl=1)
_tm.sleep(1.1)
_gs.sweep()
check("an expired grant IS swept, which is the job the timer exists for",
      _gs.grant_for("B3", "winbox") is None)
check("...without taking the live ones with it",
      _gs.grant_for("B1", "webfig") is not None)

print("")
print("Which address a remote-access link points at:")

# The whole feature can be working perfectly -- grant recorded, nginx
# listening, port open, firewall allowing it -- and still be useless, because
# the address in the link is one the reader's browser cannot route to. That is
# what a NATed server's auto-detected 172.16.x.x host does, and the only
# symptom is a browser timing out with nothing to point at.
from mikromon.web import _access_link_host, _host_is_unroutable, _strip_port

check("a private address is known to be unreachable from elsewhere",
      all(_host_is_unroutable(h) for h in
          ("172.16.1.246", "10.1.2.3", "192.168.0.1", "127.0.0.1",
           "localhost", "169.254.1.1", "")))
check("a public address and a hostname are not",
      not any(_host_is_unroutable(h) for h in
              ("38.54.63.107", "easymikrotik.co.za", "8.8.8.8")))

check("a port is stripped off the Host header",
      _strip_port("easymikrotik.co.za:8080") == "easymikrotik.co.za"
      and _strip_port("[::1]:80") == "::1"
      and _strip_port("example.com") == "example.com")

check("a configured PUBLIC host is used as-is, whatever the browser used -- "
      "an explicit setting is a decision, not a guess to second-guess",
      _access_link_host({"hub_host": "hub.example.com"},
                        "10.0.0.9:8080") == "hub.example.com")

check("a configured PRIVATE host is overridden by the address the browser "
      "actually reached us on, because that address demonstrably routes here",
      _access_link_host({"hub_host": "172.16.1.246"},
                        "easymikrotik.co.za") == "easymikrotik.co.za")

check("...including when the dashboard is on a non-default port",
      _access_link_host({"hub_host": "172.16.1.246"},
                        "38.54.63.107:8080") == "38.54.63.107")

check("a private host stays when the browser is ALSO on the LAN -- that "
      "reader can reach it, and swapping in their own address helps nobody",
      _access_link_host({"hub_host": "172.16.1.246"},
                        "192.168.8.2") == "172.16.1.246")

check("no Host header at all falls back to what is configured",
      _access_link_host({"hub_host": "172.16.1.246"}, "") == "172.16.1.246")

check("nothing configured and nothing to fall back on stays empty, which "
      "switches the feature off rather than inventing a link",
      _access_link_host({}, "") == "")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ACCESS TESTS PASSED")
