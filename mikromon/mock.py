"""A simulated MikroTik for local demos — no real router, no network needed.

`MockDevice` mimics the parts of `Device` the engine uses, returning scripted
data that evolves over a series of polls so you can watch real alerts fire:
healthy baseline -> CPU spike -> WAN failover -> traffic/client spikes ->
internet outage -> recovery -> device unreachable -> back online.

Used by `python -m mikromon demo`.
"""
from __future__ import annotations

from .config import (AppConfig, DeviceConfig, WanConfig, WanEndpoint)
from .device import Snapshot

# --- byte deltas applied per poll (cumulative counters are built from these) --
_RX_NORMAL = 2_000_000
_RX_SPIKE = 250_000_000
_Q_NORMAL = 8_000_000
_Q_SPIKE = 250_000_000

_BASE_MACS = [f"AA:BB:CC:00:00:{i:02X}" for i in range(10)]
_BASE11 = _BASE_MACS + ["AA:BB:CC:00:00:0A"]
_SPIKE_MACS = [f"AA:BB:CC:00:01:{i:02X}" for i in range(35)]

_BASE_LOG = [
    {"time": "08:00:01", "topics": "system,info", "message": "router started"},
    {"time": "08:00:02", "topics": "system,info,account",
     "message": "user admin logged in from 192.168.88.50 via winbox"},
]
_FAILED_LOGIN = {"time": "09:14:33", "topics": "system,error,account",
                 "message": "login failure for user admin from 203.0.113.77 via ssh"}
_CONFIG_CHANGE = {"action": "changed ip firewall filter rule", "by": "admin",
                  "message": "rule disabled"}
_SESSION = [{"name": "admin", "address": "192.168.88.50", "via": "winbox",
             "when": "jan/01 08:00:02"}]


def _routes(state: str):
    prim_up = state == "primary"
    back_up = state in ("primary", "backup")  # backup link itself is alive
    prim = {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
            "active": "true" if prim_up else "false",
            "gateway-status": "1.1.1.1 reachable via ether1" if prim_up
            else "1.1.1.1 unreachable"}
    back = {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
            "active": "true" if state == "backup" else "false",
            "gateway-status": "10.0.0.1 reachable via lte1" if back_up
            else "10.0.0.1 unreachable"}
    return [prim, back]


def _ifaces(rx: int):
    return [
        {"name": "ether1", "type": "ether", "running": "true", "disabled": "false",
         "rx-byte": str(rx), "tx-byte": "500000", "link-downs": "0",
         "comment": "Primary WAN"},
        {"name": "lte1", "type": "lte", "running": "true", "disabled": "false",
         "rx-byte": "1000000", "tx-byte": "1000000", "link-downs": "0",
         "comment": "LTE backup"},
    ]


def _resource(cpu: int, tick: int):
    return [{"cpu-load": str(cpu), "uptime": f"{3600 + tick * 60}s",
             "version": "7.15.3", "board-name": "RB5009", "cpu-count": "4",
             "total-memory": "1073741824", "free-memory": "805306368",
             "total-hdd-space": "1073741824", "free-hdd-space": "805306368"}]


def _leases(macs):
    return [{"status": "bound", "mac-address": m,
             "address": f"192.168.88.{i + 10}", "host-name": f"client-{i}"}
            for i, m in enumerate(macs)]


_CALM_PLAN = [(8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [],
               "healthy") for _ in range(12)]


def build_frames(incident: bool = True):
    """The scripted story. Each frame is one poll."""
    plan = ([
        # (cpu, route, macs, reachable, rx_delta, q_delta, logs, history, note)
        (8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [], "healthy baseline"),
        (8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [], "healthy"),
        (8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [], "healthy (learning normal)"),
        (8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [], "healthy (learning normal)"),
        (8, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [], "healthy (baseline warm)"),
        (97, "primary", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [_FAILED_LOGIN], [],
         "CPU spike + failed SSH login from a public IP"),
        (8, "backup", _BASE_MACS, True, _RX_NORMAL, _Q_NORMAL, [], [_CONFIG_CHANGE],
         "primary WAN fails -> failover to LTE backup; a config change is logged"),
        (12, "backup", _SPIKE_MACS, True, _RX_SPIKE, _Q_SPIKE, [], [],
         "traffic spike on WAN + 35 devices online + a top-talker"),
        (10, "down", _BASE11, True, 0, _Q_NORMAL, [], [], "both WANs down -> internet outage"),
        (8, "primary", _BASE11, True, _RX_NORMAL, _Q_NORMAL, [], [], "recovery: back on primary, all normal"),
        (0, "primary", _BASE11, False, 0, 0, [], [], "router stops responding (unreachable)"),
        (8, "primary", _BASE11, True, _RX_NORMAL, _Q_NORMAL, [], [], "router back online"),
    ] if incident else _CALM_PLAN)
    frames = []
    rx_total, q_total = 0, 0
    for tick, (cpu, route, macs, reachable, rxd, qd, logs, hist, note) in enumerate(plan):
        rx_total += rxd
        q_total += qd
        frames.append({
            "reachable": reachable,
            "note": note,
            "resource": _resource(cpu, tick),
            "health": [{"name": "temperature", "value": "42"}],
            "route": _routes(route),
            "interface": _ifaces(rx_total),
            "dhcp_lease": _leases(macs),
            "queue_simple": [{"name": "pc-reception", "target": "192.168.88.10",
                              "bytes": f"0/{q_total}"}],
            "kid_control": [],
            "log": _BASE_LOG + logs,
            "history": hist,
            "active": _SESSION,
        })
    return frames


class MockDevice:
    def __init__(self, cfg, frames, board="RB5009", version="7.15.3", serial=""):
        self.cfg = cfg
        self.frames = frames
        self.tick = -1
        self.board = board
        self.version = version
        self.serial = serial or ("MT" + format(abs(hash(cfg.name)) % 10**10, "010d"))

    @property
    def name(self):
        return self.cfg.name

    def reachable(self, timeout=None):
        # Advances the scenario once per poll (engine calls this first).
        self.tick = min(self.tick + 1, len(self.frames) - 1)
        return bool(self.frames[self.tick].get("reachable", True))

    def connect(self):
        return None

    def close(self):
        pass

    def _frame(self):
        return self.frames[max(self.tick, 0)]

    def fetch(self, datasets) -> Snapshot:
        snap = Snapshot(handle=self)
        frame = self._frame()
        for name in datasets:
            snap.data[name] = list(frame.get(name, []))
        # Synthesize per-device inventory metadata so the demo populates the
        # device table + RouterOS version stats with realistic variety.
        if snap.data.get("resource"):
            res = dict(snap.data["resource"][0])
            res["version"] = self.version
            res["board-name"] = self.board
            res["architecture-name"] = "arm64"
            snap.data["resource"] = [res]
        if "identity" in datasets:
            snap.data["identity"] = [{"name": self.cfg.name}]
        if "routerboard" in datasets:
            snap.data["routerboard"] = [{
                "model": self.board, "serial-number": self.serial,
                "current-firmware": self.version}]
        return snap

    def ping(self, address, count=3):
        return 100 if self._frame().get("note", "").find("outage") >= 0 else 0


def _demo_device(name: str) -> DeviceConfig:
    return DeviceConfig(
        name=name, host="mock", lan_subnets=["192.168.88.0/24"],
        wan=WanConfig(links=[WanEndpoint(interface="ether1", name="Fibre"),
                             WanEndpoint(interface="lte1", name="LTE")]),
        client_count_sources=["dhcp"], traffic_interfaces=["ether1"],
        checks={"reachability": True, "wan_failover": True, "internet_down": True,
                "resources": True, "interfaces": True, "security": True,
                "dhcp_new_clients": False, "client_count": True,
                "wan_traffic": True, "client_usage": True},
        thresholds={
            "cpu_warn": 80, "cpu_crit": 95, "mem_free_warn_pct": 15,
            "mem_free_crit_pct": 7, "disk_free_warn_pct": 15,
            "disk_free_crit_pct": 5, "temp_warn_c": 60, "temp_crit_c": 75,
            "flap_window_s": 600, "flap_threshold": 4,
            "baseline_alpha": 0.3, "baseline_warmup": 3, "baseline_z": 2.0,
            "baseline_buckets": "global", "client_min_count": 5,
            "client_count_ratio": 1.5, "traffic_floor_mbit": 1,
            "traffic_ratio": 1.5, "client_floor_mbit": 1, "client_usage_ratio": 2.0,
        },
    )


def demo_config(outbox_dir: str = "outbox") -> AppConfig:
    """A self-contained config for the demo (fast, sensitive, fresh state).

    Two devices so per-user access control is demonstrable: HQ has the incident,
    Branch stays healthy.
    """
    return AppConfig(
        poll_interval=2, state_file="./demo-state.json", confirmations=1,
        smtp=None, outbox_dir=outbox_dir, metrics_db="./demo-metrics.db",
        auth_db="./demo-auth.db", devices_db="./demo-devices.db",
        devices=[_demo_device("DEMO-Router-HQ"), _demo_device("DEMO-Router-Branch")])


def demo_devices(config):
    # HQ gets the incident scenario; Branch stays calm. Different hardware +
    # RouterOS versions so the inventory + version-breakdown look realistic
    # (the Branch runs an older v6 that the UI flags for upgrade).
    incident = build_frames(incident=True)
    calm = build_frames(incident=False)
    out = []
    for cfg in config.devices:
        if "HQ" in cfg.name:
            out.append(MockDevice(cfg, incident, board="RB5009", version="7.15.3"))
        else:
            out.append(MockDevice(cfg, calm, board="hAP ac2", version="6.49.10"))
    return out


def seed_demo_users(auth_db: str):
    """Create demo accounts so the login + per-user scoping can be shown.

    admin/admin123   -> sees both devices, can manage users.
    branch/branch123 -> sees only DEMO-Router-Branch.
    """
    from .auth import AuthStore

    store = AuthStore(auth_db)
    try:
        if not store.get_user("admin"):
            store.add_user("admin", "admin123", role="admin", devices="*")
        if not store.get_user("branch"):
            store.add_user("branch", "branch123", role="user",
                           devices=["DEMO-Router-Branch"])
    finally:
        store.close()
