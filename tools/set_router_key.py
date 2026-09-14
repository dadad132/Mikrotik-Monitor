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


def _extract_key(text: str) -> str:
    """A public key from a bare key, or from pasted print-detail output.

    RouterOS prints `public-key="..."` alongside `private-key` and the peer's
    own key, so the labelled one is preferred and a bare 44-character token
    is only used when there is no label to go on. Reading the wrong one --
    the peer's, which is the HUB's key -- registers the hub against itself
    and nothing works.
    """
    text = (text or "").strip().strip('"')
    m = re.search(r'public-key\s*[:=]\s*"?([A-Za-z0-9+/]{42,43}=)"?', text)
    if m:
        return m.group(1)
    if _KEY_RE.match(text):
        return text
    m = re.search(r'\b([A-Za-z0-9+/]{42,43}=)\b', text)
    return m.group(1) if m else text


def _handshook(pubkey: str, iface: str = "wg0") -> bool:
    """Whether the hub has completed a handshake with this key.

    The only evidence that actually proves the tunnel came up. Everything
    else -- the file being correct, the service exiting 0, the peer being
    loaded -- has been true at some point this week while nothing worked.
    """
    import subprocess
    for cmd in (["wg", "show", iface, "dump"],
                ["sudo", "-n", "wg", "show", iface, "dump"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        except Exception:  # noqa: BLE001
            return False
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 5 and f[0] == pubkey:
                try:
                    return int(f[4] or 0) > 0
                except ValueError:
                    return False
        return False
    return False


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
    name, pubkey = args[0], _extract_key(args[1])

    if not _KEY_RE.match(pubkey):
        sys.exit(f"{args[1]!r} does not contain a WireGuard public key "
                 f"(44 base64 characters ending in '=').\n\n"
                 f"Rather than retyping it, paste the whole line from the "
                 f"router:\n"
                 f"  /interface/wireguard/print detail where name=mikromon\n"
                 f"and pass the output, quoted. One mistyped character "
                 f"fails exactly like a\nwrong key -- the hub discards it "
                 f"in silence -- so do not read it by eye.")

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

    # Watch for a real handshake rather than printing instructions and
    # leaving the operator to find out later. Every other signal -- the file
    # being right, the service exiting 0, the peer being loaded -- has been
    # true at some point this week while nothing actually worked.
    import time as _t
    print("\nwaiting up to 60s for the router to hand-shake ...", flush=True)
    deadline = _t.time() + 60
    up = False
    while _t.time() < deadline:
        if _handshook(pubkey):
            up = True
            break
        _t.sleep(3)

    if up:
        print(f"\nTUNNEL UP - {name} has hand-shaken with the hub.")
        print("It should show online on the dashboard within a minute.")
        print("\nDo NOT re-run the provisioning script on this router: it "
              "would mint another new key and undo this.")
        return

    print("\nNO HANDSHAKE after 60s. The hub is now expecting:")
    print(f"  {pubkey}")
    print("\nTwo causes, and they need opposite fixes:")
    print("  1. That is not the router's real key. ONE mistyped character")
    print("     fails exactly like a wrong key, in silence. Do not read it")
    print("     by eye -- on the router run:")
    print("       /interface/wireguard/print detail where name=mikromon")
    print("     and pass the WHOLE output to this tool, quoted:")
    print(f'       python tools/set_router_key.py "{name}" "<paste output>"')
    print("  2. The key is right and the packets never arrive: the site is")
    print("     blocking outbound UDP to the hub. Check Tunnel health on")
    print("     Platform admin -- 'loaded but never handshaked' is this one.")


if __name__ == "__main__":
    main()
