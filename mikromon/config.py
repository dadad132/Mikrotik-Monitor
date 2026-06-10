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
    "baseline_alpha": 0.1,      # EWMA learning rate (lower = steadier)
    "baseline_warmup": 24,      # samples a time-bucket needs before it can alert
    "baseline_z": 3.0,          # std-devs above normal to count as abnormal
    "baseline_buckets": "hour",  # hour | hourweek | global
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
    "wan_traffic": False,       # abnormal WAN throughput / data usage
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


@dataclass
class WanConfig:
    primary: WanEndpoint = field(default_factory=WanEndpoint)
    backup: WanEndpoint = field(default_factory=WanEndpoint)
    ping_targets: list = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return bool(self.primary.interface or self.primary.gateway)


@dataclass
class DeviceConfig:
    name: str
    host: str
    api_port: int = 8728
    username: str = ""
    password: str = ""
    use_ssl: bool = False
    verify_ssl: bool = False
    timeout: int = 10
    lan_subnets: list = field(default_factory=list)
    wan: WanConfig = field(default_factory=WanConfig)
    monitor_interfaces: list = field(default_factory=list)
    # which sources to count for device-count anomaly: dhcp|wireless|arp|hotspot
    client_count_sources: list = field(
        default_factory=lambda: ["dhcp", "wireless"])
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
    devices: list = field(default_factory=list)


def _require(d: dict, key: str, where: str):
    if key not in d or d[key] in (None, ""):
        raise ConfigError(f"Missing required '{key}' in {where}")
    return d[key]


def _endpoint(d) -> WanEndpoint:
    d = d or {}
    return WanEndpoint(interface=str(d.get("interface", "")),
                       gateway=str(d.get("gateway", "")))


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
        if not smtp.to_addrs:
            raise ConfigError("smtp.to_addrs must list at least one recipient.")

    devices = []
    raw_devices = raw.get("devices") or []
    if not raw_devices:
        raise ConfigError("No devices configured under 'devices:'.")
    seen = set()
    for i, d in enumerate(raw_devices):
        where = f"devices[{i}]"
        name = _require(d, "name", where)
        if name in seen:
            raise ConfigError(f"Duplicate device name: {name!r}")
        seen.add(name)
        wan_raw = d.get("wan") or {}
        devices.append(DeviceConfig(
            name=str(name),
            host=str(_require(d, "host", where)),
            api_port=int(d.get("api_port", 8728)),
            username=str(d.get("username", "")),
            password=str(d.get("password", "")),
            use_ssl=bool(d.get("use_ssl", False)),
            verify_ssl=bool(d.get("verify_ssl", False)),
            timeout=int(d.get("timeout", 10)),
            lan_subnets=list(d.get("lan_subnets") or []),
            wan=WanConfig(
                primary=_endpoint(wan_raw.get("primary")),
                backup=_endpoint(wan_raw.get("backup")),
                ping_targets=[str(t) for t in (wan_raw.get("ping_targets") or [])],
            ),
            monitor_interfaces=[str(x) for x in (d.get("monitor_interfaces") or [])],
            client_count_sources=[str(x).lower() for x in
                                  (d.get("client_count_sources")
                                   or ["dhcp", "wireless"])],
            traffic_interfaces=[str(x) for x in (d.get("traffic_interfaces") or [])],
            checks={**DEFAULT_CHECKS, **(d.get("checks") or {})},
            thresholds={**defaults, **(d.get("thresholds") or {})},
        ))

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
        devices=devices,
    )
