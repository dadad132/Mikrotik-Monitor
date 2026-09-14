"""Tell the three tunnel failures apart, instead of calling them all "offline".

Every dead end this week came from one blind spot. We could see what mikromon
INTENDED (hub.json) and what it WROTE (wg-peers.conf), but never what the hub
was actually running, nor whether a single packet had arrived. So these three
presented identically, and each was diagnosed by guesswork over days:

  * a peer the hub never loaded  -> our fault, fixed from the dashboard
  * a router whose key differs   -> fixed with set_router_key.py, no visit
  * a site blocking outbound UDP -> not fixable from here at all

They need completely different actions. These tests pin down that the table
separates them.

Run:  ./.venv/Scripts/python.exe tests/tunnel_health_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.web as web
from mikromon.web import _tunnel_health_rows, _write_wg_peers

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


NOW = time.time()

HUB = {"leases_meta": {
    "Healthy Branch":         {"ip": "10.10.1.1", "pubkey": "AAAA="},
    "Mobilis Geely Edenvale": {"ip": "10.10.157.167", "pubkey": "QTCW="},
    "Never Loaded":           {"ip": "10.10.3.3", "pubkey": "CCCC="},
    "Stale":                  {"ip": "10.10.4.4", "pubkey": "DDDD="},
    "Never Provisioned":      {"ip": "10.10.5.5", "pubkey": ""},
}}

d = tempfile.mkdtemp()
peers = os.path.join(d, "wg-peers.conf")
_write_wg_peers(peers, {n: {"ip": m["ip"], "pubkey": m["pubkey"], "extra": []}
                        for n, m in HUB["leases_meta"].items()})


def with_live(live, err=""):
    web._wg_dump = lambda iface="wg0": (live, err)
    rows, _ = _tunnel_health_rows(HUB, peers)
    return rows


_real_dump = web._wg_dump

LIVE = {
    "AAAA=": {"endpoint": "1.2.3.4:51820", "allowed": "10.10.1.1/32",
              "handshake": int(NOW - 20), "rx": 900000, "tx": 800000},
    # Loaded, but the router has never completed a handshake: exactly
    # Edenvale, whose own key is a different one entirely.
    "QTCW=": {"endpoint": "(none)", "allowed": "10.10.157.167/32",
              "handshake": 0, "rx": 0, "tx": 0},
    "DDDD=": {"endpoint": "5.6.7.8:51820", "allowed": "10.10.4.4/32",
              "handshake": int(NOW - 3600), "rx": 500, "tx": 900},
}

try:
    rows = {r["name"]: r for r in with_live(LIVE)}

    print("\nTelling the three failures apart")

    r = rows["Healthy Branch"]
    check("a working tunnel reads as up, with how long ago it last shook",
          r["ok"] and "handshake" in r["verdict"])

    r = rows["Mobilis Geely Edenvale"]
    # Edenvale exactly: loaded, correct key, and a BLANK endpoint. WireGuard
    # fills the endpoint in from any packet that decrypts with the peer's
    # key, so blank is proof that nothing belonging to this router has ever
    # arrived. Separating that from "arrives and is rejected" took days by
    # hand; it is one field.
    check("a peer loaded but never heard from, with no endpoint, is called "
          "out as nothing ever arriving -- not as a key problem, because "
          "the two need opposite fixes",
          not r["ok"] and "nothing has EVER arrived" in r["verdict"]
          and "site's link" in r["verdict"]
          and r["in_file"] and r["loaded"])

    rows_ep = {x["name"]: x for x in with_live(dict(
        LIVE, **{"QTCW=": {"endpoint": "196.1.2.3:13231",
                           "allowed": "10.10.157.167/32",
                           "handshake": 0, "rx": 0, "tx": 0}}))}
    check("...whereas a peer WITH an endpoint and no handshake is the "
          "opposite case: packets arrive and are rejected, so the key is "
          "wrong and set_router_key.py is the fix",
          "packets ARRIVE" in rows_ep["Mobilis Geely Edenvale"]["verdict"]
          and "196.1.2.3:13231" in rows_ep["Mobilis Geely Edenvale"]["verdict"])

    r = rows["Never Loaded"]
    check("a peer that IS in the file but was never applied is called out as "
          "the hub's own fault -- this is the failure that cost the week, "
          "and it was invisible",
          not r["ok"] and "NOT LOADED" in r["verdict"] and r["in_file"])

    r = rows["Stale"]
    check("a tunnel that shook an hour ago is flagged as stopped, not as up",
          not r["ok"] and "stopped" in r["verdict"])

    r = rows["Never Provisioned"]
    check("a router with no key registered is not blamed on the tunnel",
          not r["ok"] and "never provisioned" in r["verdict"])

    print("\nWithout the running state, it refuses to guess")

    rows2 = {r["name"]: r for r in with_live({}, err="Operation not permitted")}
    check("when wg cannot be read, no router is declared healthy -- "
          "reporting the fleet as fine on missing evidence is how this went "
          "unnoticed for a week",
          not any(r["ok"] for r in rows2.values()))
    check("...and it says so rather than blaming the routers",
          all("cannot read" in r["verdict"] for r in rows2.values()
              if r["pubkey"]))

    print("\nA peer missing from the file is distinguished from one not loaded")

    half = os.path.join(d, "half.conf")
    _write_wg_peers(half, {"Healthy Branch": {"ip": "10.10.1.1",
                                              "pubkey": "AAAA=", "extra": []}})
    web._wg_dump = lambda iface="wg0": (LIVE, "")
    rows3 = {r["name"]: r for r in _tunnel_health_rows(HUB, half)[0]}
    check("a router mikromon never wrote out is told to press Reload, which "
          "is the one action that fixes it",
          "Reload hub peers" in rows3["Never Loaded"]["verdict"]
          and not rows3["Never Loaded"]["in_file"])
finally:
    web._wg_dump = _real_dump

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL TUNNEL-HEALTH TESTS PASSED")
