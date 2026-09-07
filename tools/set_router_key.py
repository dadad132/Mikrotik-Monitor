#!/usr/bin/env python3
"""Register the WireGuard public key a router ALREADY has, instead of forcing
a new one on it.

Provisioning mints a fresh keypair every run and assumes the router will
accept the private half. When that does not take — the `private-key=` line is
refused, or the paste is cut short — the router keeps its old key, the hub
keeps expecting the new one, and every handshake is discarded in silence. The
router looks perfectly configured and reports rx=0 while tx climbs. Running
the script again only mints a third key and makes it worse.

This is the way out: read the key off the router, tell the hub to trust that
one. Nothing changes on the router at all.

  On the router:
      /interface/wireguard/print detail where name=mikromon
    copy the public-key= value.

  On this server:
      python tools/set_router_key.py "Mobilis Geely Edenvale" sThRTq...=

It writes hub.json (the source of truth), regenerates wg-peers.conf from it
using the application's own writer, and asks systemd to apply it. Editing
wg-peers.conf by hand does NOT work: it is regenerated from hub.json the next
time anything touches the hub, which silently restores the broken key.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_DEFAULT_CFGS = ("config.yaml", "/opt/mikromon/config.yaml",
                 "/etc/mikromon/config.yaml")
# WireGuard keys are 32 bytes, base64: 43 characters then '='.
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$")


def _devices_db_from(cfg_path: str) -> str:
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line.startswith("devices_db:"):
                    return line.split(":", 1)[1].strip().strip("'\"")
    except OSError as exc:
        sys.exit(f"could not read {cfg_path}: {exc}")
    sys.exit(f"no devices_db: line in {cfg_path}")


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        sys.exit(__doc__.strip() + "\n\nUsage: set_router_key.py "
                 '"<device name>" <public-key>')
    name, pubkey = args[0], args[1].strip().strip('"')

    if not _KEY_RE.match(pubkey):
        sys.exit(f"{pubkey!r} is not a WireGuard public key (expected 44 "
                 f"base64 characters ending in '='). Copy the public-key= "
                 f"value from /interface/wireguard/print detail — not the "
                 f"peer's key, which is the hub's.")

    cfg = next((c for c in _DEFAULT_CFGS if os.path.exists(c)), None)
    if not cfg:
        sys.exit("no config.yaml found. Pass one:  "
                 "python tools/set_router_key.py ... --config /path/config.yaml")
    devices_db = _devices_db_from(cfg)

    from mikromon.web import (_hub_path, _hub_load, _hub_save,
                              _hub_wg_leases, _write_wg_peers,
                              _WG_PEERS_DEFAULT)

    hub_file = _hub_path(devices_db)
    hub = _hub_load(hub_file)
    if not hub:
        sys.exit(f"no hub.json at {hub_file} — is the WireGuard hub set up?")

    leases = hub.setdefault("leases_meta", {})
    if name not in leases:
        known = "\n  ".join(sorted(leases)) or "(none)"
        sys.exit(f"no router called {name!r} is registered on the hub.\n"
                 f"Names are case- and space-sensitive. Registered:\n  {known}")

    old = leases[name].get("pubkey") or "(none)"
    ip = leases[name].get("ip") or "(none)"
    if old == pubkey:
        print(f"{name}: the hub already expects this key. Nothing to change.")
        print("If it is still unreachable the fault is elsewhere — check the "
              "router's own rx counter.")
    leases[name]["pubkey"] = pubkey

    print(f"config      {cfg}")
    print(f"hub.json    {hub_file}")
    print(f"router      {name}   tunnel ip {ip}")
    print(f"  was       {old}")
    print(f"  now       {pubkey}")

    _hub_save(hub_file, hub)
    peers_path = hub.get("wg_peers") or _WG_PEERS_DEFAULT
    ok, err = _write_wg_peers(peers_path, _hub_wg_leases(hub))
    if not ok:
        sys.exit(f"\nhub.json was updated, but {peers_path} could not be "
                 f"written: {err}\nRe-run this with sudo.")
    print(f"\nwrote {peers_path}")

    # The path unit watches the peers file and runs `wg syncconf`, but nudge
    # it directly too: a file written with identical mtime granularity has
    # been seen not to trigger, and a peer that is in the file but not in the
    # running interface looks exactly like no fix at all.
    # Never let this stage undo the work above: hub.json and the peers file
    # are already correct by now, and exiting non-zero here would read as a
    # failure and invite someone to "fix" it by re-provisioning -- which is
    # what breaks the key in the first place.
    try:
        r = subprocess.run(["systemctl", "start", "mikromon-wg-reload.service"],
                           capture_output=True, text=True)
        rc, err = r.returncode, (r.stderr or "").strip()
    except (FileNotFoundError, OSError) as exc:
        rc, err = 1, str(exc)
    if rc == 0:
        print("applied to the running interface (mikromon-wg-reload).")
    else:
        print(f"NOT applied to the running interface yet: {err}")
        print("The files are correct. Apply them with:")
        print("  sudo systemctl start mikromon-wg-reload.service")

    print("\nNow check the ROUTER — this is the only thing that proves it:")
    print('  /interface/wireguard/peers/print detail '
          'where comment="mikromon:tunnel:hub"')
    print("  rx moving off 0 means the handshake completed.")
    print("\nDo NOT re-run the provisioning script on this router: it would "
          "mint another new key and undo this.")


if __name__ == "__main__":
    main()
