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
    """The devices DB a config points at, as an ABSOLUTE path.

    config.yaml normally says `devices_db: ./devices.db`, and that "." means
    the directory the service runs in -- not whichever directory somebody
    happened to be standing in when they ran this. Resolving it against the
    caller's shell sent this tool looking for hub.json in the wrong place and
    told the operator the hub was not set up, which was alarming and wrong.
    """
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line.startswith("devices_db:"):
                    val = line.split(":", 1)[1].strip().strip("'\"")
                    if not val:
                        break
                    if os.path.isabs(val):
                        return val
                    return os.path.normpath(
                        os.path.join(os.path.dirname(os.path.abspath(cfg_path)),
                                     val))
    except OSError as exc:
        sys.exit(f"could not read {cfg_path}: {exc}")
    sys.exit(f"no devices_db: line in {cfg_path}")


def _opt(name: str) -> str:
    """Read --name=value or --name value from argv. Returns "" if absent.

    This existed only in the usage text before: the argument parser dropped
    anything starting with "--" and then counted the VALUE as a positional,
    so the documented escape hatch broke the command it was meant to rescue.
    """
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == f"--{name}" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
    return ""


def main() -> None:
    argv = sys.argv[1:]
    args, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a.startswith("--"):
            # "--config /path" consumes the path; "--config=/path" does not.
            skip = ("=" not in a and i + 1 < len(argv)
                    and not argv[i + 1].startswith("--"))
            continue
        args.append(a)
    if len(args) != 2:
        sys.exit(__doc__.strip() + "\n\nUsage: set_router_key.py "
                 '"<device name>" <public-key>')
    name, pubkey = args[0], args[1].strip().strip('"')

    if not _KEY_RE.match(pubkey):
        sys.exit(f"{pubkey!r} is not a WireGuard public key (expected 44 "
                 f"base64 characters ending in '='). Copy the public-key= "
                 f"value from /interface/wireguard/print detail — not the "
                 f"peer's key, which is the hub's.")

    cfg = _opt("config")
    if cfg and not os.path.exists(cfg):
        sys.exit(f"no config at {cfg}")
    if not cfg:
        # The repo this script lives in is a likely home too: somebody who
        # has just run git pull is standing in it.
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = list(_DEFAULT_CFGS) + [os.path.join(here, "config.yaml")]
        cfg = next((c for c in candidates if os.path.exists(c)), None)
    if not cfg:
        sys.exit("no config.yaml found. Looked in:\n  "
                 + "\n  ".join(candidates)
                 + "\n\nPass one:  python tools/set_router_key.py "
                   '"<device>" <key> --config /path/config.yaml')
    devices_db = _opt("devices-db") or _devices_db_from(cfg)

    from mikromon.web import (_hub_path, _hub_load, _hub_save,
                              _hub_wg_leases, _write_wg_peers,
                              _WG_PEERS_DEFAULT)

    hub_file = _opt("hub") or _hub_path(devices_db)
    hub = _hub_load(hub_file)
    if not hub:
        sys.exit(f"no hub.json at {hub_file}\n"
                 f"  (from {cfg}, devices_db={devices_db})\n\n"
                 f"If the hub lives elsewhere, point at it directly:\n"
                 f"  python tools/set_router_key.py \"<device>\" <key> "
                 f"--hub /path/to/hub.json")

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
