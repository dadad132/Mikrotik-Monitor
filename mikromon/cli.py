"""Command-line interface for mikromon."""
from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .checks import ALL_CHECKS
from .config import ConfigError, load_config
from .device import Device, DeviceError
from .engine import Engine
from .notify import build_notifiers
from .util import as_int, human_duration, uptime_to_seconds

log = logging.getLogger("mikromon")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mikromon",
        description="Monitor MikroTik routers and email the IT admin when "
                    "something happens (WAN failover, internet down, reboots, "
                    "resource exhaustion, suspicious logins, config changes).",
    )
    p.add_argument("command", nargs="?", default="run",
                   choices=["run", "once", "demo", "dashboard",
                            "test-connection", "test-email", "list-checks",
                            "useradd", "userlist", "userdel", "passwd",
                            "set-devices"],
                   help="run | once | demo | dashboard | test-connection | "
                        "test-email | list-checks | useradd | userlist | "
                        "userdel | passwd | set-devices")
    p.add_argument("-c", "--config", default="config.yaml",
                   help="path to config file (default: config.yaml)")
    p.add_argument("--dry-run", action="store_true",
                   help="run checks but print alerts instead of sending them")
    p.add_argument("--interval", type=float, default=1.5,
                   help="seconds between polls in demo mode (default: 1.5)")
    p.add_argument("--serve", action="store_true",
                   help="in demo mode, serve the dashboard after the scenario")
    p.add_argument("--port", type=int, default=None,
                   help="web dashboard port (default: 8080)")
    # user-management arguments
    p.add_argument("--user", help="username (useradd/userdel/passwd/set-devices)")
    p.add_argument("--password", help="password (useradd/passwd)")
    p.add_argument("--role", choices=["admin", "user"], default="user",
                   help="role for useradd (default: user)")
    p.add_argument("--devices", default="",
                   help="comma-separated device names this user may see, or '*' "
                        "for all (useradd/set-devices)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="enable DEBUG logging")
    p.add_argument("--version", action="version", version=f"mikromon {__version__}")
    return p


def main(argv=None) -> int:
    # Make Unicode (σ, — , °C) printable on legacy Windows code pages.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)

    # `demo` is self-contained — it needs no config file or real router.
    if args.command == "demo":
        _setup_logging("DEBUG" if args.verbose else "INFO")
        return _cmd_demo(args)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    _setup_logging("DEBUG" if args.verbose else config.log_level)

    if args.command in ("useradd", "userlist", "userdel", "passwd",
                        "set-devices"):
        return _cmd_users(args, config)

    if args.command == "dashboard":
        from . import web

        if not config.metrics_db:
            print("Set 'metrics_db:' in the config to enable the dashboard.",
                  file=sys.stderr)
            return 2
        web.serve(config.metrics_db, config.state_file, config.web_host,
                  args.port or config.web_port, auth_db=config.auth_db,
                  secure_cookies=config.web_secure_cookies,
                  metrics_token=config.metrics_token,
                  devices_db=config.devices_db, defaults=config.defaults)
        return 0

    if args.command == "list-checks":
        return _cmd_list_checks(config)
    if args.command == "test-connection":
        return _cmd_test_connection(config)
    if args.command == "test-email":
        return _cmd_test_email(config)

    engine = Engine(config, dry_run=args.dry_run)
    if args.command == "once":
        # A single poll — suitable for cron. Sends real alerts unless --dry-run.
        # State persists in state.json, so `confirmations` still applies across
        # successive cron invocations.
        alerts = engine.run_once()
        print(f"Cycle complete: {len(alerts)} alert(s).")
        for a in alerts:
            print("  " + a.one_line())
        return 0

    try:
        engine.run()
    except KeyboardInterrupt:
        pass
    return 0


# ----- sub-commands ---------------------------------------------------------
def _cmd_list_checks(config) -> int:
    print("Available checks:")
    for cls in ALL_CHECKS:
        print(f"  {cls.name:12s} flags={','.join(cls.flags)} "
              f"requires={','.join(cls.requires)}")
    print("\nPer-device enablement:")
    for dev in config.devices:
        on = [cls.name for cls in ALL_CHECKS if cls.is_enabled(dev)]
        extra = []
        if dev.check_enabled("reachability"):
            extra.append("reachability")
        print(f"  {dev.name}: {', '.join(extra + on) or '(none)'}")
    return 0


def _cmd_test_connection(config) -> int:
    rc = 0
    for cfg in config.devices:
        dev = Device(cfg)
        print(f"\n== {cfg.name} ({cfg.host}:{cfg.api_port}) ==")
        if not dev.reachable():
            print("  UNREACHABLE (no TCP response on the API port)")
            rc = 1
            continue
        try:
            dev.connect()
            snap = dev.fetch(["resource"])
            res = snap.resource
            print(f"  OK  board={res.get('board-name', '?')} "
                  f"version={res.get('version', '?')}")
            print(f"      uptime={human_duration(uptime_to_seconds(res.get('uptime')))} "
                  f"cpu={as_int(res.get('cpu-load'))}% "
                  f"free-mem={res.get('free-memory', '?')}")
        except DeviceError as exc:
            print(f"  CONNECT FAILED: {exc}")
            rc = 1
        finally:
            dev.close()
    return rc


def _cmd_users(args, config) -> int:
    from .auth import AuthError, AuthStore

    if not config.auth_db:
        print("Set 'auth_db:' in the config first (e.g. auth_db: ./auth.db).",
              file=sys.stderr)
        return 2
    store = AuthStore(config.auth_db)
    try:
        if args.command == "userlist":
            users = store.list_users()
            if not users:
                print("(no users yet)")
            for u in users:
                devs = "*" if u["devices"] == "*" else ",".join(u["devices"]) or "-"
                print(f"  {u['username']:20} role={u['role']:5} devices={devs}")
            return 0
        if not args.user:
            print("--user is required for this command.", file=sys.stderr)
            return 2
        if args.command == "useradd":
            if not args.password:
                print("--password is required for useradd.", file=sys.stderr)
                return 2
            store.add_user(args.user, args.password, role=args.role,
                           devices=args.devices or None)
            print(f"Created {args.role} '{args.user}'.")
        elif args.command == "passwd":
            if not args.password:
                print("--password is required for passwd.", file=sys.stderr)
                return 2
            store.set_password(args.user, args.password)
            print(f"Password updated for '{args.user}'.")
        elif args.command == "set-devices":
            store.set_devices(args.user, args.devices or None)
            print(f"Devices for '{args.user}' set to: {args.devices or '(none)'}")
        elif args.command == "userdel":
            store.delete_user(args.user)
            print(f"Deleted '{args.user}'.")
        return 0
    except AuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()


def _cmd_demo(args) -> int:
    import os
    import time

    from .mock import demo_config, demo_devices, seed_demo_users
    from .notify import build_notifiers

    config = demo_config()
    for path in (config.state_file, config.metrics_db, config.auth_db,
                 config.devices_db):
        if path and os.path.exists(path):
            os.unlink(path)  # start the story (and accounts/devices) fresh
    devices = demo_devices(config)
    engine = Engine(config, devices=devices, notifiers=build_notifiers(config))
    frames = devices[0].frames

    # Deterministic simulated clock: each poll is exactly poll_interval apart,
    # so throughput rates are realistic no matter how fast the demo is displayed.
    sim = {"t": time.time()}
    engine.now_fn = lambda: sim["t"]

    print("=" * 70)
    print("mikromon DEMO — simulating a MikroTik (no real router needed)")
    print(f"Alert emails are written to ./{config.outbox_dir}/ as .eml + .html")
    print("=" * 70)
    total_alerts = 0
    for i, frame in enumerate(frames):
        sim["t"] += config.poll_interval
        print(f"\n--- poll {i + 1}/{len(frames)}: {frame['note']} ---")
        alerts = engine.run_once()
        total_alerts += len(alerts)
        if not alerts:
            print("   (all healthy)")
        for a in alerts:
            print("   " + a.one_line())
            if a.cause:
                print(f"        why: {a.cause}")
        time.sleep(max(0.0, args.interval))
    print(f"\nDemo complete: {total_alerts} alert(s) raised. "
          f"Open the digests in ./{config.outbox_dir}/")
    if args.serve:
        from . import web
        from .devices_store import DevicesStore

        seed_demo_users(config.auth_db)
        ds = DevicesStore(config.devices_db)  # populate the /devices page
        ds.seed_from(config.devices, config.defaults)
        ds.close()
        port = args.port or config.web_port
        print(f"\nServing the dashboard with the demo data on "
              f"http://127.0.0.1:{port}  (Ctrl-C to stop)")
        print("  Log in as  admin/admin123   (sees both routers; Devices + Admin)")
        print("         or  branch/branch123 (sees only DEMO-Router-Branch)")
        print("  As admin, use the Devices page to add/edit/test routers, and")
        print("  Admin to create users and choose which devices each one sees.")
        web.serve(config.metrics_db, config.state_file, "127.0.0.1", port,
                  auth_db=config.auth_db, devices_db=config.devices_db,
                  defaults=config.defaults)
    else:
        print("Tip: re-run with --serve to view this data in the web dashboard "
              "(with login + per-user device access).")
    return 0


def _cmd_test_email(config) -> int:
    notifiers = build_notifiers(config)
    if not notifiers:
        print("No notifiers configured (add an 'smtp:' section).",
              file=sys.stderr)
        return 2
    for n in notifiers:
        print(f"Sending test via '{n.name}'...")
        n.send_test()
    print("Done. Check the inbox(es) listed in smtp.to_addrs.")
    return 0
