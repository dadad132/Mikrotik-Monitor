#!/usr/bin/env python3
"""Print who may manage which router, and why not when they may not.

Run this on the server when someone gets "Not allowed" (or the old bare
"forbidden") pressing a button they believe they are entitled to press:

    python tools/check_access.py                 # reads ./config.yaml
    python tools/check_access.py /etc/mikromon/config.yaml

Every device-management gate in the dashboard comes down to one comparison —
the company that owns the router against the company the person is signed in
to — plus, for members, whether that router is in their allocation. Both live
in the databases and neither is visible from the web UI, which is why a
refusal was so hard to account for from a screenshot.

Read-only. It opens both databases, prints a table, and changes nothing.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys


def _load_paths(cfg_path: str):
    """auth_db and devices_db out of config.yaml, without needing PyYAML."""
    auth_db = devices_db = ""
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line.startswith("auth_db:"):
                    auth_db = line.split(":", 1)[1].strip().strip("'\"")
                elif line.startswith("devices_db:"):
                    devices_db = line.split(":", 1)[1].strip().strip("'\"")
    except OSError as exc:
        sys.exit(f"could not read {cfg_path}: {exc}\n"
                 f"Pass the path explicitly, e.g.\n"
                 f"    python tools/check_access.py /opt/mikromon/config.yaml")
    return auth_db, devices_db


def _rows(db_path: str, sql: str):
    if not db_path or not os.path.exists(db_path):
        sys.exit(f"database not found: {db_path or '(not set in config.yaml)'}")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def main() -> None:
    # The installer puts it in /opt/mikromon, which is not where you are
    # standing when you clone the repo to run this.
    _DEFAULTS = ("config.yaml", "/opt/mikromon/config.yaml",
                 "/etc/mikromon/config.yaml")
    if len(sys.argv) > 1:
        cfg_path = sys.argv[1]
    else:
        cfg_path = next((c for c in _DEFAULTS if os.path.exists(c)),
                        _DEFAULTS[0])
    auth_db, devices_db = _load_paths(cfg_path)
    print(f"config      {cfg_path}")
    print(f"auth_db     {auth_db}")
    print(f"devices_db  {devices_db}\n")

    orgs = {r[0]: r[1] for r in _rows(auth_db, "SELECT id, name FROM orgs")}
    users = _rows(auth_db,
                  "SELECT COALESCE(email, username), role, org_id, devices, "
                  "is_superadmin FROM users ORDER BY org_id, role DESC")
    devices = _rows(devices_db, "SELECT name, org_id FROM devices ORDER BY name")

    print("PEOPLE")
    print(f"  {'login':32} {'role':7} {'org':>4}  company               allocation")
    for login, role, org_id, devs_raw, is_sa in users:
        try:
            devs = json.loads(devs_raw) if devs_raw != "*" else "*"
        except (json.JSONDecodeError, TypeError):
            devs = devs_raw
        alloc = ("every router in the company" if role == "owner"
                 else "all" if devs == "*"
                 else (", ".join(devs) if devs else "NOTHING ALLOCATED"))
        tag = " [platform admin]" if is_sa else ""
        print(f"  {str(login)[:32]:32} {role:7} {org_id:>4}  "
              f"{str(orgs.get(org_id, '?'))[:20]:20}  {alloc}{tag}")

    print("\nROUTERS")
    print(f"  {'name':32} {'org':>4}  company")
    for name, org_id in devices:
        flag = "" if org_id in orgs else "   <-- owned by a company that does not exist"
        print(f"  {str(name)[:32]:32} {org_id:>4}  "
              f"{str(orgs.get(org_id, '?'))[:20]:20}{flag}")

    print("\nWHO CAN PRESS THE BUTTONS")
    problems = 0
    for name, dev_org in devices:
        allowed = []
        for login, role, org_id, devs_raw, _is_sa in users:
            if org_id != dev_org:
                continue          # different company: no access, by design
            if role == "owner":
                allowed.append(str(login))
                continue
            try:
                devs = json.loads(devs_raw) if devs_raw != "*" else "*"
            except (json.JSONDecodeError, TypeError):
                devs = []
            if devs == "*" or (isinstance(devs, list) and name in devs):
                allowed.append(str(login))
        if allowed:
            print(f"  {str(name)[:32]:32} {', '.join(allowed)}")
        else:
            problems += 1
            print(f"  {str(name)[:32]:32} NOBODY — every login is in another "
                  f"company, or is a member without it allocated")

    print()
    if problems:
        print(f"{problems} router(s) nobody can manage. The usual cause is a "
              f"router stamped with a\ncompany id that no longer matches the "
              f"person using it — routers imported from\nconfig.yaml default "
              f"to company 1, which is not always the company you sign in as.")
    else:
        print("Every router has at least one login that can manage it. If "
              "someone is still\nrefused, check the server log for a line "
              "starting 'denied management of'.")


if __name__ == "__main__":
    main()
