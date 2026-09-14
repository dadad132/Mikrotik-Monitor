#!/usr/bin/env python3
"""Point a device back at the tunnel address its router actually answers on.

The failure this repairs, end to end:

  A device is renamed. Everything about a router is filed under its NAME --
  the tunnel lease and key in hub.json included -- and only the devices row
  used to move, so the lease was left behind under the old name. The tunnel
  itself kept working (the peers file matches on public key, not on the
  comment), but the dashboard now saw no lease and said the router had never
  been set up. Somebody pressed Provision to fix that, which minted a SECOND
  tunnel address and a SECOND key. The router was never re-pasted, so it
  still holds the first key and still answers on the first address -- while
  mikromon had started probing the second. Result: reported UNREACHABLE while
  somebody is logged into it.

  In a diagnostics report this shows up as two near-identical peer names
  holding separate keys, or as a device with no peer at all.

This tool does not touch the router. It probes every tunnel address the hub
knows, finds the one this router is really on, and points the device back at
it -- so the fix costs a site visit of nothing.

    python tools/fix_tunnel_duplicates.py                  # report only
    python tools/fix_tunnel_duplicates.py --apply          # make the changes
    python tools/fix_tunnel_duplicates.py --apply --keep-dead-leases

Run it on the server, as the user that owns the databases. Restart the
service afterwards so the engine picks the addresses up.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

API_PORT = 8728
PROBE_TIMEOUT = 3.0


def answers(host: str, port: int = API_PORT, timeout: float = PROBE_TIMEOUT):
    """(reachable, milliseconds). The same TCP probe the monitor itself uses."""
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.monotonic() - started) * 1000, 1)
    except OSError:
        return False, None


def load_devices(db_path: str) -> list:
    db = sqlite3.connect(db_path)
    try:
        rows = db.execute("SELECT name, config FROM devices ORDER BY name")
        out = []
        for name, blob in rows.fetchall():
            try:
                out.append((name, json.loads(blob)))
            except (TypeError, ValueError):
                continue
        return out
    finally:
        db.close()


def set_host(db_path: str, name: str, host: str) -> None:
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT config FROM devices WHERE name = ?",
                         (name,)).fetchone()
        if not row:
            return
        cfg = json.loads(row[0])
        cfg["host"] = host
        db.execute("UPDATE devices SET config = ?, updated = ? WHERE name = ?",
                   (json.dumps(cfg), time.time(), name))
        db.commit()
    finally:
        db.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--devices-db", default="./devices.db")
    ap.add_argument("--hub", default="./hub.json")
    ap.add_argument("--apply", action="store_true",
                    help="make the changes (default is to report only)")
    ap.add_argument("--keep-dead-leases", action="store_true",
                    help="leave the abandoned lease in hub.json. Keeping it "
                         "is harmless but it keeps showing up as a duplicate "
                         "in the diagnostics report.")
    args = ap.parse_args()

    for path in (args.devices_db, args.hub):
        if not os.path.exists(path):
            print(f"not found: {path}", file=sys.stderr)
            return 2

    hub = json.load(open(args.hub, encoding="utf-8"))
    meta = hub.get("leases_meta") or {}
    devices = load_devices(args.devices_db)
    if not meta:
        print("The hub holds no router leases; nothing to repair.")
        return 0

    print(f"{len(devices)} device(s), {len(meta)} registered lease(s).")
    print("Probing every tunnel address on port "
          f"{API_PORT} (this takes a moment) ...\n")

    # Probe each distinct address once, not once per device that names it.
    addresses = {(m or {}).get("ip") for m in meta.values()}
    addresses |= {(d.get("host") or "") for _, d in devices}
    addresses.discard("")
    alive = {}
    for ip in sorted(addresses):
        ok, ms = answers(ip)
        alive[ip] = ok
        print(f"  {ip:<16} {'answers  ' + str(ms) + 'ms' if ok else 'no answer'}")

    fixes, notes = [], []
    for name, cfg in devices:
        host = cfg.get("host") or ""
        if not host or alive.get(host):
            continue                      # already fine, or not on the tunnel
        # This device is being polled at an address nothing answers on. Is the
        # router sitting on one of the OTHER leases -- the one it kept?
        candidates = [(other, (m or {}).get("ip"))
                      for other, m in meta.items()
                      if other != name and alive.get((m or {}).get("ip"))]
        # Only leases no LIVE device is already using. Repointing a device at
        # an address another router answers on would be a much worse bug than
        # the one being fixed.
        claimed = {d.get("host") for n, d in devices if n != name}
        free = [(o, ip) for o, ip in candidates if ip not in claimed]
        if len(free) == 1:
            fixes.append((name, host, free[0][1], free[0][0]))
        elif len(free) > 1:
            notes.append(f"  {name}: unreachable at {host}, and MORE THAN ONE "
                         f"spare lease answers ({', '.join(ip for _, ip in free)}). "
                         f"Not guessing -- check which is this router by hand.")
        else:
            notes.append(f"  {name}: unreachable at {host}, and no other "
                         f"registered address answers either. This one really "
                         f"is offline, or its tunnel is down.")

    print()
    if not fixes and not notes:
        print("Every device answers at the address it is being polled at. "
              "Nothing to repair.")
        return 0

    if fixes:
        print("These devices are being polled at a dead address while the "
              "router answers on another one it still holds:\n")
        for name, old, new, lease in fixes:
            print(f"  {name}")
            print(f"      polled at : {old}   (nothing answers)")
            print(f"      router is : {new}   (registered as \"{lease}\")")
    if notes:
        print("\nNot repaired automatically:")
        print("\n".join(notes))

    if not args.apply:
        print("\nThis was a dry run. Re-run with --apply to make the changes.")
        return 0

    for name, old, new, lease in fixes:
        set_host(args.devices_db, name, new)
        # Move the working lease onto the device's current name, so the
        # dashboard stops calling it unprovisioned and nobody is tempted to
        # press Provision again -- which is what caused this in the first
        # place.
        if lease in meta:
            meta[name] = meta.pop(lease)
        leases = hub.setdefault("leases", {})
        if lease in leases:
            leases[name] = leases.pop(lease)
        if not args.keep_dead_leases:
            meta.pop(f"{name}__dead", None)
        print(f"fixed: {name} -> {new}")

    hub["leases_meta"] = meta
    tmp = args.hub + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(hub, fh, indent=2)
    os.replace(tmp, args.hub)
    print(f"\nUpdated {args.hub} and {args.devices_db}.")
    print("Restart the mikromon service so the engine picks up the new "
          "addresses.")
    print("The peers file is rebuilt by the dashboard on its next hub change; "
          "to force it now, open Platform admin and press Reload peers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
