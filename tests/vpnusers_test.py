"""VPN remote users, end to end through the dashboard, against a fake router.

A laptop gets onto a site's network: the owner names it, pastes its public
key (or lets the dashboard make the keys), previews, applies -- and is handed
the settings once. Checked here:
  * what goes to the router, in what order (Safe mode's timer first)
  * that it never touches the management tunnel, or its port
  * the settings file: right key, address, endpoint and networks; a private
    key only when the dashboard made it, and never on the router
  * a router behind someone else's NAT is called out before anyone tests
  * removing one device, and switching the feature off

Run:  ./.venv/Scripts/python.exe tests/vpnusers_test.py
"""
from __future__ import annotations

import http.cookiejar
import itertools
import json
import os
import re
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.push as push_pkg  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import vpnusers as vu  # noqa: E402
from mikromon.push.api import PlanRefused  # noqa: E402
from mikromon.wgkeys import keypair, public_key  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


# ---- a router, as far as librouteros is concerned --------------------------
class FakePath:
    def __init__(self, router, segs):
        self.r, self.segs = router, segs

    def __iter__(self):
        return iter([dict(x) for x in self.r.tables.setdefault(self.segs, [])])

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        row = {".id": nid, **{k: str(v) for k, v in params.items()
                              if k != "place-before"}}
        if self.segs == ("interface", "wireguard"):
            row["public-key"] = self.r.iface_pub
        self.r.tables.setdefault(self.segs, []).append(row)
        self.r.log.append(("add", self.segs, dict(params)))
        return nid

    def update(self, **params):
        rows = self.r.tables.setdefault(self.segs, [])
        target = [x for x in rows if x.get(".id") == params.get(".id")] or rows[:1]
        for x in target:
            x.update({k: str(v) for k, v in params.items() if k != ".id"})
        self.r.log.append(("set", self.segs, dict(params)))

    def remove(self, rid):
        rows = self.r.tables.setdefault(self.segs, [])
        self.r.tables[self.segs] = [x for x in rows if x.get(".id") != rid]
        self.r.log.append(("remove", self.segs, rid))

    def __call__(self, cmd, **params):
        self.r.log.append(("run", self.segs, cmd))
        if self.segs == ("ping",):
            return iter([{"received": "2", "packet-loss": "0"}])
        return iter([{"ret": "ok"}])


class FakeRouter:
    def __init__(self, wan_ip="41.1.2.3/29"):
        self.ids = itertools.count(100)
        self.log = []
        self.iface_pub = keypair()[1]
        self.tables = {
            ("system", "resource"): [{"version": "7.15.3", "uptime": "3d"}],
            ("interface", "wireguard"): [
                {".id": "*1", "name": "mikromon", "listen-port": "13231",
                 "comment": "mikromon:tunnel:if", "public-key": keypair()[1]}],
            ("interface", "wireguard", "peers"): [
                {".id": "*2", "interface": "mikromon",
                 "comment": "mikromon:tunnel:hub", "allowed-address": "10.10.0.0/16"}],
            ("ip", "address"): [
                {".id": "*3", "address": wan_ip, "interface": "ether1",
                 "network": wan_ip.split("/")[0]},
                {".id": "*4", "address": "192.168.88.1/24", "interface": "bridge",
                 "network": "192.168.88.0"},
                {".id": "*5", "address": "10.10.3.7/16", "interface": "mikromon",
                 "network": "10.10.0.0"}],
            ("interface", "list"): [{".id": "*6", "name": "LAN"},
                                    {".id": "*7", "name": "WAN"}],
            ("ip", "cloud"): [{"ddns-enabled": "no", "public-address": ""}],
            ("ip", "dns"): [{"allow-remote-requests": "yes"}],
            ("ip", "firewall", "filter"): [
                {".id": "*8", "chain": "input", "action": "drop",
                 "in-interface-list": "!LAN"}],
            ("system", "scheduler"): [],
        }


class FakeDevice:
    def __init__(self, router):
        self.router = router
        self.api = None

    def reachable(self, timeout=None, attempts=None):
        return True

    def connect(self):
        self.api = types.SimpleNamespace(path=lambda *s: FakePath(self.router, s))
        return self.api

    def ping(self, address, count=2):
        return 0

    def close(self):
        pass


ROUTER = FakeRouter()
_orig_rw = push_pkg.rw_device
push_pkg.rw_device = lambda cfg: FakeDevice(ROUTER)

print("planning")
cfg = types.SimpleNamespace(
    name="R1", wan=types.SimpleNamespace(links=[types.SimpleNamespace(
        interface="ether1", name="Vumatel")]))
fd = FakeDevice(ROUTER)
fd.connect()
pusher = types.SimpleNamespace(api=push_pkg.api.PushApi(fd))
cur = vu.read(pusher, cfg)
check("the site's own networks are offered, not the WAN, the management "
      "tunnel or ours", cur["lan_subnets"] == ["192.168.88.0/24"])
check("the management tunnel's port is taken, so remote users get the next "
      "one", vu._port(cur) == 13232)
r = vu.reachability(cur)
check("a router with a public address on its main line is reachable there",
      r["ok"] and r["endpoint"] == "41.1.2.3")
cg = FakeRouter(wan_ip="100.64.10.20/10")
fd2 = FakeDevice(cg)
fd2.connect()
cur_cg = vu.read(types.SimpleNamespace(api=push_pkg.api.PushApi(fd2)), cfg)
r = vu.reachability(cur_cg, hub_seen_ip="102.1.1.1")
check("a router behind CGNAT is called out, with the port somebody would "
      "have to forward", not r["ok"] and "CGNAT" in r["why"] and "13232" in r["why"])
check("the remote-user subnet skips one another router already has",
      vu.pick_users_subnet(cur, {"10.11.0.0/24"}) == "10.11.1.0/24")
try:
    vu.plan(pusher, cfg, {"vu_label": "Laptop", "vu_pubkey": "nope"},
            {"vu_net": ["192.168.88.0/24"]})
    refused = ""
except PlanRefused as exc:
    refused = str(exc)
check("a pasted private key or a typo is refused with what to copy instead",
      refused.startswith("Nothing was sent") and "Public key" in refused)
conf = vu.client_config(private_key="", address="10.11.0.2/32",
                        router_pubkey="RPUB", endpoint="x.example", port=13232,
                        allowed=["192.168.88.0/24", "10.11.0.0/24"],
                        label="Laptop")
check("a device that made its own keys gets no PrivateKey line to overwrite "
      "its own with", "PrivateKey" not in conf and "Endpoint = x.example:13232"
      in conf and "PersistentKeepalive = 25" in conf)

# ---- through the dashboard --------------------------------------------------
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "u",
           "password": "p", "wan": {"links": [{"name": "Vumatel",
                                               "interface": "ether1"}]}},
          DEFAULT_THRESHOLDS, org_id=org)
ds.close()
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS)))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None, multi=None):
    if multi is not None:
        body = urllib.parse.urlencode(multi, doseq=True).encode()
    else:
        body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    req("/login", {"email": "owner@alpha.test",
                   "password": "a-password-for-the-test"})
    st, page = req("/device?name=R1&tab=tunnel")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("the VPN tab has a Remote users box with an add form",
          st == 200 and "Remote users" in page and 'name="vu_pubkey"' in page
          and "41.1.2.3:13232" in page)

    laptop_priv, laptop_pub = keypair()
    form = {"csrf": tok, "device": "R1", "feature": "vpnusers", "view": "tunnel",
            "vpnuser_action": "add", "vu_label": "Thandi's laptop",
            "vu_type": "windows", "vu_keys": "own", "vu_pubkey": laptop_pub,
            "vu_net": ["192.168.88.0/24"], "vu_dns": "1", "vu_ddns": "1"}
    st, prev = req("/device/push", multi=form)
    check("Preview shows what would go to the router, and sends nothing",
          st == 200 and "Dry run" in prev
          and "create WireGuard interface &#x27;mikromon-users&#x27;" in prev
          and "add remote user &#x27;Thandi&#x27;s laptop&#x27; at 10.11.0.2" in prev
          and not any(e[0] == "add" for e in ROUTER.log))
    st, done = req("/device/push", multi={**form, "apply": "1",
                                          "safe_revert": "1"})
    adds = [e for e in ROUTER.log if e[0] == "add"]
    i_timer = next(i for i, e in enumerate(adds)
                   if e[1] == ("system", "scheduler"))
    i_peer = next(i for i, e in enumerate(adds)
                  if e[1] == ("interface", "wireguard", "peers"))
    check("Safe mode's timer went on the router before anything else",
          i_timer < i_peer and i_timer == min(
              i for i, e in enumerate(adds)
              if e[1] != ("system", "scheduler")) - 1)
    peers = [p for p in ROUTER.tables[("interface", "wireguard", "peers")]
             if p.get("comment", "").startswith("mikromon:vpnuser:")]
    check("the laptop is a peer on its own interface, with one address",
          len(peers) == 1 and peers[0]["interface"] == "mikromon-users"
          and peers[0]["allowed-address"] == "10.11.0.2/32"
          and peers[0]["public-key"] == laptop_pub)
    check("the management tunnel's own rows were not touched",
          all(e[1] != ("interface", "wireguard") or e[2].get("name") != "mikromon"
              for e in ROUTER.log if e[0] in ("set", "remove")))
    rules = {r.get("comment") for r in ROUTER.tables[("ip", "firewall", "filter")]}
    check("the handshake port is let in and the site is reachable both ways",
          {"mikromon:vpnusers:in", "mikromon:vpnusers:fwd-in",
           "mikromon:vpnusers:fwd-out"} <= rules)
    check("connected devices count as LAN for the default firewall",
          any(m.get("comment") == "mikromon:vpnusers:lan"
              for m in ROUTER.tables[("interface", "list", "member")]))
    check("MikroTik's DDNS name was switched on as asked",
          ROUTER.tables[("ip", "cloud")][0].get("ddns-enabled") == "yes")
    check("the settings page names the device and the router",
          st == 200 and "Thandi&#x27;s laptop can connect to R1" in done)
    check("...with the router's key, the device's address and the endpoint",
          f"PublicKey = {ROUTER.iface_pub}" in done
          and "Address = 10.11.0.2/32" in done
          and "Endpoint = 41.1.2.3:13232" in done)
    check("...only the site's network and the remote-user subnet, so the "
          "laptop's own internet is untouched",
          "AllowedIPs = 192.168.88.0/24, 10.11.0.0/24" in done
          and "DNS = 10.11.0.1" in done)
    check("...and no private key anywhere: the laptop keeps its own",
          not re.search(r"PrivateKey = [A-Za-z0-9+/]{43}=", done)
          and laptop_priv not in done)
    with open(os.path.join(tmp, "hub.json")) as fh:
        hub = json.load(fh)
    check("the subnet is recorded so no other router is given it",
          hub.get("vpn_user_subnets", {}).get("R1") == "10.11.0.0/24")

    form2 = {**form, "vu_label": "Sipho phone", "vu_type": "android",
             "vu_keys": "make", "vu_pubkey": "", "vu_full": "1"}
    st, done2 = req("/device/push", multi={**form2, "apply": "1",
                                           "safe_revert": "1"})
    m = re.search(r"PrivateKey = (\S+)", done2)
    peer2 = [p for p in ROUTER.tables[("interface", "wireguard", "peers")]
             if p.get("comment") == "mikromon:vpnuser:Sipho phone"]
    check("when the dashboard makes the keys, the file carries the private "
          "key -- shown once, with a download",
          m is not None and "download=" in done2 and "only time" in done2)
    check("...and the router only ever received its public half",
          m is not None and peer2 and peer2[0]["public-key"] == public_key(m.group(1))
          and not any(m.group(1) in json.dumps(e) for e in ROUTER.log))
    check("all traffic through the site: every route, the site's DNS, and a "
          "masquerade so the site's line carries it",
          "AllowedIPs = 0.0.0.0/0" in done2 and "DNS = 10.11.0.1" in done2
          and any(r.get("comment") == "mikromon:vpnusers:nat"
                  for r in ROUTER.tables.get(("ip", "firewall", "nat"), [])))
    check("the second device gets the next address",
          peer2 and peer2[0]["allowed-address"] == "10.11.0.3/32")

    st, page = req("/device?name=R1&tab=tunnel")
    check("both devices are listed on the VPN tab",
          "Thandi&#x27;s laptop" in page and "Sipho phone" in page)
    pid = peers[0][".id"]
    req("/device/push", multi={"csrf": tok, "device": "R1", "feature": "vpnusers",
                               "view": "tunnel", "vpnuser_action": "remove",
                               "peer_id": pid, "apply": "1"})
    check("removing one device takes away only that one",
          not any(p[".id"] == pid for p in
                  ROUTER.tables[("interface", "wireguard", "peers")])
          and any(p.get("comment") == "mikromon:vpnuser:Sipho phone" for p in
                  ROUTER.tables[("interface", "wireguard", "peers")]))
    req("/device/push", multi={"csrf": tok, "device": "R1", "feature": "vpnusers",
                               "view": "tunnel", "vpnuser_action": "off",
                               "apply": "1"})
    left = [r for t in ROUTER.tables.values() for r in t
            if str(r.get("comment", "")).startswith("mikromon:vpnuser")]
    check("switching it off removes everything it added and nothing else",
          not left and any(i.get("name") == "mikromon" for i in
                           ROUTER.tables[("interface", "wireguard")]))
finally:
    srv.shutdown()
    srv.server_close()
    push_pkg.rw_device = _orig_rw

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL REMOTE USER TESTS PASSED")
