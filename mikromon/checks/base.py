"""Base class for checks."""
from __future__ import annotations


class Check:
    #: config flags (any one enabled -> the check runs)
    flags: tuple = ()
    #: datasets the engine must fetch for this check
    requires: tuple = ()
    #: stable name (for logging / --list-checks)
    name: str = "check"

    @classmethod
    def is_enabled(cls, device_cfg) -> bool:
        return any(device_cfg.check_enabled(f) for f in cls.flags)

    @classmethod
    def datasets(cls, device_cfg) -> set:
        """Datasets to fetch for this device. Override for per-device choices."""
        return set(cls.requires)

    def run(self, snap, dev, ctx) -> None:
        """Inspect `snap` for device config `dev`, reporting via `ctx`."""
        raise NotImplementedError
