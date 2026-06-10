"""System health: CPU, memory, storage, temperature, reboots, firmware changes."""
from __future__ import annotations

from ..alert import Severity
from ..util import as_float, as_int, human_bytes, human_duration, uptime_to_seconds
from .base import Check


def _temperature(health_rows, resource):
    """Extract a board temperature (°C) from /system/health across RouterOS versions."""
    # v7 returns name/value rows: {'name': 'temperature', 'value': '45'}
    for row in health_rows:
        if str(row.get("name", "")).lower() in ("temperature", "cpu-temperature",
                                                 "board-temperature"):
            return as_float(row.get("value"))
    # v6 returns a single dict with a 'temperature' key.
    for row in health_rows:
        if "temperature" in row:
            return as_float(row.get("temperature"))
    if "temperature" in (resource or {}):
        return as_float(resource.get("temperature"))
    return None


class ResourceCheck(Check):
    flags = ("resources",)
    requires = ("resource", "health")
    name = "resources"

    def run(self, snap, dev, ctx) -> None:
        res = snap.resource
        if not res:
            return
        mem = ctx.memory("resources")

        # ---- reboot detection (uptime went backwards) ---------------------
        uptime_s = uptime_to_seconds(res.get("uptime"))
        prev_uptime = mem.get("uptime_s")
        if prev_uptime is not None and uptime_s is not None and uptime_s < prev_uptime:
            ctx.event(
                "reboot", Severity.CRITICAL,
                "Router rebooted",
                detail=f"Uptime reset to {human_duration(uptime_s)} "
                       f"(was {human_duration(prev_uptime)}).",
                cause="Uptime counter went backwards, indicating a reboot — "
                      "power loss, watchdog, crash, or a manual/scheduled restart.",
                facts={"uptime_s": uptime_s, "previous_uptime_s": prev_uptime},
            )
        if uptime_s is not None:
            mem["uptime_s"] = uptime_s

        # ---- firmware/version change --------------------------------------
        version = str(res.get("version", ""))
        prev_version = mem.get("version")
        if prev_version and version and version != prev_version:
            ctx.event(
                "version_change", Severity.WARNING,
                f"RouterOS version changed: {prev_version} → {version}",
                cause="Firmware was upgraded or downgraded. If this was not "
                      "planned, investigate who changed it.",
            )
        if version:
            mem["version"] = version

        # ---- CPU ----------------------------------------------------------
        cpu = as_int(res.get("cpu-load"))
        ctx.sample("cpu", cpu)
        ctx.threshold("cpu", cpu, warn=dev.th("cpu_warn"), crit=dev.th("cpu_crit"),
                      what="CPU load", unit="%",
                      cause="Sustained high CPU can indicate a traffic spike, an "
                            "attack, a runaway script, or an undersized device.")

        # ---- memory (alert on LOW free %) ---------------------------------
        total_mem = as_int(res.get("total-memory"))
        free_mem = as_int(res.get("free-memory"))
        if total_mem > 0:
            free_pct = round(free_mem / total_mem * 100, 1)
            ctx.sample("mem_free_pct", free_pct)
            ctx.threshold(
                "memory", free_pct,
                warn=dev.th("mem_free_warn_pct"), crit=dev.th("mem_free_crit_pct"),
                what="Free RAM", unit="%", higher_is_bad=False,
                fmt=lambda v: f"{v:g}% ({human_bytes(free_mem)} free)",
                cause="Low free memory can cause dropped connections and instability.")

        # ---- storage (alert on LOW free %) --------------------------------
        total_hdd = as_int(res.get("total-hdd-space"))
        free_hdd = as_int(res.get("free-hdd-space"))
        if total_hdd > 0:
            free_pct = round(free_hdd / total_hdd * 100, 1)
            ctx.threshold(
                "storage", free_pct,
                warn=dev.th("disk_free_warn_pct"), crit=dev.th("disk_free_crit_pct"),
                what="Free storage", unit="%", higher_is_bad=False,
                fmt=lambda v: f"{v:g}% ({human_bytes(free_hdd)} free)",
                cause="Low storage can prevent logging, backups and upgrades.")

        # ---- temperature --------------------------------------------------
        temp = _temperature(snap.rows("health"), res)
        if temp:
            ctx.sample("temp_c", temp)
            ctx.threshold(
                "temperature", temp,
                warn=dev.th("temp_warn_c"), crit=dev.th("temp_crit_c"),
                what="Temperature", unit="°C",
                cause="High temperature shortens hardware life — check airflow, "
                      "fan, and ambient conditions.")
