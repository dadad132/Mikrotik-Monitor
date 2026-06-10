"""Check registry.

Each check is a small class that inspects a Snapshot and reports observations
through a CheckContext. Checks declare:
  * `key`           — config flag(s) under `devices[].checks` that enable it,
  * `requires`      — which datasets the engine must fetch for it to run.
"""
from __future__ import annotations

from .wan import WanCheck
from .wan_traffic import WanTrafficCheck
from .resources import ResourceCheck
from .interfaces import InterfaceCheck
from .security import SecurityCheck
from .dhcp import DhcpCheck
from .clients import ClientCountCheck
from .client_usage import ClientUsageCheck

# Order is the order alerts are produced within a poll.
ALL_CHECKS = [
    WanCheck,
    WanTrafficCheck,
    ResourceCheck,
    InterfaceCheck,
    SecurityCheck,
    DhcpCheck,
    ClientCountCheck,
    ClientUsageCheck,
]


def enabled_checks(device_cfg):
    """Instantiate the checks enabled for a given device."""
    return [cls() for cls in ALL_CHECKS if cls.is_enabled(device_cfg)]


def required_datasets(device_cfg):
    """Union of datasets needed by the device's enabled checks."""
    needed = set()
    for cls in ALL_CHECKS:
        if cls.is_enabled(device_cfg):
            needed.update(cls.datasets(device_cfg))
    return needed
