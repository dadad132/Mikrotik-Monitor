"""Configuration loading and validation.

Reads a YAML file into typed dataclasses, merges global `defaults:` thresholds
into each device, and fails loudly with a helpful message when something
required is missing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .alert import Severity

DEFAULT_THRESHOLDS = {
    "cpu_warn": 80,
    "cpu_crit": 95,
    "mem_free_warn_pct": 15,
    "mem_free_crit_pct": 7,
    "disk_free_warn_pct": 15,
    "disk_free_crit_pct": 5,
    "temp_warn_c": 60,
    "temp_crit_c": 75,
    "flap_window_s": 600,
    "flap_threshold": 4,
    # --- learned-baseline tuning (shared by the anomaly checks) ---
    "baseline_alpha": 0.05,     # EWMA learning rate (lower = steadier / longer memory)
    "baseline_warmup": 168,     # ~7 days of data before a bucket starts alerting
    "baseline_z": 3.0,          # std-devs above normal to count as abnormal
    "baseline_buckets": "hourweek",  # hour | hourweek | global
    # device-count anomaly
    "client_min_count": 5,      # ignore networks smaller than this
    "client_count_ratio": 1.5,  # must be >=1.5x the typical count to alert
    # WAN throughput anomaly
    "traffic_floor_mbit": 1,    # ignore links quieter than this
    "traffic_ratio": 1.5,       # must be >=1.5x typical throughput to alert
    # per-client usage anomaly
    "client_floor_mbit": 5,     # ignore clients using less than this
    "client_usage_ratio": 2.0,  # must be >=2x that client's own typical use
}

DEFAULT_CHECKS = {
    "reachability": True,
    "wan_failover": True,
    "internet_down": True,
    "resources": True,
    "interfaces": True,
    "security": True,
    "dhcp_new_clients": False,
    "client_count": False,      # abnormally many connected devices
    "wan_traffic": True,        # throughput sampling + abnormal-traffic alerts
    "client_usage": False,      # per-client top-talkers
}


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""


@dataclass
class SmtpConfig:
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    from_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject_prefix: str = "[MikroMon]"
    min_severity: Severity = Severity.INFO


@dataclass
class WanEndpoint:
    interface: str = ""
    gateway: str = ""
    name: str = ""  # friendly ISP label, e.g. "Vodacom"

    @property
    def configured(self) -> bool:
        return bool(self.interface or self.gateway)

    def label(self, idx: int = 0) -> str:
        return self.name or self.interface or self.gateway or f"WAN{idx + 1}"


@dataclass
class WanConfig:
    # Uplinks in priority order (highest priority first). Supports 2, 3, 4+.
    links: list = field(default_factory=list)
    ping_targets: list = field(default_factory=list)

    @property
    def primary(self) -> WanEndpoint:
        return self.links[0] if self.links else WanEndpoint()

    @property
    def backup(self) -> WanEndpoint:
        return self.links[1] if len(self.links) > 1 else WanEndpoint()

    @property
    def configured(self) -> bool:
        return any(ep.configured for ep in self.links)


@dataclass
class DeviceConfig:
    name: str
    host: str
    api_port: int = 8728
    username: str = ""
    password: str = ""
    use_ssl: bool = False
    verify_ssl: bool = False
    timeout: int = 60
    # Optional SEPARATE read-write credentials for config-push (provisioning,
    # backups, firewall/QoS). The monitor user above should stay read-only;
    # pushes use these when set, otherwise fall back to the monitor user.
    push_username: str = ""
    push_password: str = ""
    lan_subnets: list = field(default_factory=list)
    wan: WanConfig = field(default_factory=WanConfig)
    monitor_interfaces: list = field(default_factory=list)
    # which sources to count for device-count anomaly: dhcp|wireless|arp|hotspot
    client_count_sources: list = field(
        default_factory=lambda: ["bridge", "wireless"])
    # interfaces to track for WAN throughput ([] = auto: the WAN uplinks)
    traffic_interfaces: list = field(default_factory=list)
    checks: dict = field(default_factory=lambda: dict(DEFAULT_CHECKS))
    thresholds: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))

    def check_enabled(self, name: str) -> bool:
        return bool(self.checks.get(name, DEFAULT_CHECKS.get(name, False)))

    def th(self, name: str):
        return self.thresholds.get(name, DEFAULT_THRESHOLDS.get(name))


@dataclass
class AppConfig:
    poll_interval: int = 60
    state_file: str = "./state.json"
    log_level: str = "INFO"
    confirmations: int = 2
    smtp: SmtpConfig | None = None
    outbox_dir: str | None = None  # if set, also write alert digests as .eml/.html
    metrics_db: str | None = None  # if set, record time-series to this SQLite file
    metrics_retention_days: int = 30
    web_host: str = "127.0.0.1"
    web_port: int = 8080
    auth_db: str | None = None      # if set, the dashboard requires login
    web_secure_cookies: bool = False  # set True when serving behind HTTPS
    metrics_token: str | None = None  # bearer/query token for Prometheus scraping
    devices_db: str | None = None   # if set, devices are managed in the dashboard
    push_log_db: str | None = None  # if set, config-push actions are logged here
    access: dict | None = None      # on-demand WebFig/Winbox-through-hub settings
    billing: dict | None = None     # Stripe billing config (db, stripe_secret, etc.)
    defaults: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    devices: list = field(default_factory=list)


def _require(d: dict, key: str, where: str):
    if key not in d or d[key] in (None, ""):
        raise ConfigError(f"Missing required '{key}' in {where}")
    return d[key]


def _endpoint(d) -> WanEndpoint:
    d = d or {}
    return WanEndpoint(interface=str(d.get("interface", "")),
                       gateway=str(d.get("gateway", "")),
                       name=str(d.get("name", "")))


def _wan_links(wan_raw: dict) -> list:
    """Priority-ordered uplinks. Accepts the new `links:` list, or the legacy
    `primary:`/`backup:` pair for back-compat."""
    links_raw = wan_raw.get("links")
    if links_raw:
        return [_endpoint(x) for x in links_raw if x]
    out = []
    for key in ("primary", "backup"):
        ep = _endpoint(wan_raw.get(key))
        if ep.configured:
            out.append(ep)
    return out


def load_config(path: str) -> AppConfig:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        raise ConfigError(
            f"Config file not found: {path}\n"
            f"Copy config.example.yaml to {path} and edit it."
        )
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse YAML in {path}: {exc}")

    if not isinstance(raw, dict):
        raise ConfigError(f"Top level of {path} must be a mapping/object.")

    defaults = {**DEFAULT_THRESHOLDS, **(raw.get("defaults") or {})}

    smtp_raw = raw.get("smtp")
    smtp = None
    if smtp_raw:
        smtp = SmtpConfig(
            host=_require(smtp_raw, "host", "smtp"),
            port=int(smtp_raw.get("port", 587)),
            username=smtp_raw.get("username", ""),
            password=smtp_raw.get("password", ""),
            use_tls=bool(smtp_raw.get("use_tls", True)),
            use_ssl=bool(smtp_raw.get("use_ssl", False)),
            from_addr=smtp_raw.get("from_addr") or smtp_raw.get("username", ""),
            to_addrs=list(smtp_raw.get("to_addrs") or []),
            subject_prefix=smtp_raw.get("subject_prefix", "[MikroMon]"),
            min_severity=Severity.parse(smtp_raw.get("min_severity", "INFO"),
                                        Severity.INFO),
        )
        # to_addrs may be empty in multi-tenant mode — each org has its own list.

    devices_db = raw.get("devices_db") or None
    devices = []
    raw_devices = raw.get("devices") or []
    if not raw_devices and not devices_db:
        raise ConfigError("No devices configured under 'devices:' (and no "
                          "'devices_db:' set for web-managed devices).")
    seen = set()
    for i, d in enumerate(raw_devices):
        dev = build_device(d, defaults, where=f"devices[{i}]")
        if dev.name in seen:
            raise ConfigError(f"Duplicate device name: {dev.name!r}")
        seen.add(dev.name)
        devices.append(dev)

    return AppConfig(
        poll_interval=int(raw.get("poll_interval", 60)),
        state_file=str(raw.get("state_file", "./state.json")),
        log_level=str(raw.get("log_level", "INFO")).upper(),
        confirmations=int(raw.get("confirmations", 2)),
        smtp=smtp,
        outbox_dir=raw.get("outbox_dir") or None,
        metrics_db=raw.get("metrics_db") or None,
        metrics_retention_days=int(raw.get("metrics_retention_days", 30)),
        web_host=str((raw.get("web") or {}).get("host", "127.0.0.1")),
        web_port=int((raw.get("web") or {}).get("port", 8080)),
        web_secure_cookies=bool((raw.get("web") or {}).get("secure_cookies", False)),
        metrics_token=(raw.get("web") or {}).get("metrics_token") or None,
        auth_db=raw.get("auth_db") or None,
        devices_db=devices_db,
        push_log_db=raw.get("push_log_db") or None,
        access=(raw.get("access") or None),
        billing=(raw.get("billing") or None),
        defaults=defaults,
        devices=devices,
    )


def build_device(d: dict, defaults: dict, where: str = "device") -> DeviceConfig:
    """Construct a validated DeviceConfig from a raw dict (YAML or the DB)."""
    if not isinstance(d, dict):
        raise ConfigError(f"{where}: device entry must be a mapping.")
    wan_raw = d.get("wan") or {}
    return DeviceConfig(
        name=str(_require(d, "name", where)),
        host=str(_require(d, "host", where)),
        api_port=int(d.get("api_port", 8728) or 8728),
        username=str(d.get("username", "")),
        password=str(d.get("password", "")),
        use_ssl=bool(d.get("use_ssl", False)),
        verify_ssl=bool(d.get("verify_ssl", False)),
        timeout=int(d.get("timeout", 60) or 60),
        push_username=str(d.get("push_username", "")),
        push_password=str(d.get("push_password", "")),
        lan_subnets=list(d.get("lan_subnets") or []),
        wan=WanConfig(
            links=_wan_links(wan_raw),
            ping_targets=[str(t) for t in (wan_raw.get("ping_targets") or [])],
        ),
        monitor_interfaces=[str(x) for x in (d.get("monitor_interfaces") or [])],
        client_count_sources=[str(x).lower() for x in
                              (d.get("client_count_sources")
                               or ["dhcp", "wireless"])],
        traffic_interfaces=[str(x) for x in (d.get("traffic_interfaces") or [])],
        checks={**DEFAULT_CHECKS, **(d.get("checks") or {})},
        thresholds={**defaults, **(d.get("thresholds") or {})},
    )


def device_to_dict(cfg: DeviceConfig) -> dict:
    """Serialize a DeviceConfig back to a plain dict (for storage / edit forms)."""
    return {
        "name": cfg.name, "host": cfg.host, "api_port": cfg.api_port,
        "username": cfg.username, "password": cfg.password,
        "push_username": cfg.push_username, "push_password": cfg.push_password,
        "use_ssl": cfg.use_ssl, "verify_ssl": cfg.verify_ssl,
        "timeout": cfg.timeout, "lan_subnets": list(cfg.lan_subnets),
        "wan": {
            "links": [{"name": ep.name, "interface": ep.interface,
                       "gateway": ep.gateway} for ep in cfg.wan.links],
            "ping_targets": list(cfg.wan.ping_targets),
        },
        "monitor_interfaces": list(cfg.monitor_interfaces),
        "client_count_sources": list(cfg.client_count_sources),
        "traffic_interfaces": list(cfg.traffic_interfaces),
        # Only persist checks that differ from the current default so that
        # raising a default from False→True automatically applies to all devices.
        "checks": {k: v for k, v in cfg.checks.items()
                   if v != DEFAULT_CHECKS.get(k)},
        "thresholds": dict(cfg.thresholds),
    }
