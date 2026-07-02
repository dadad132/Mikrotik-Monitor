"""System health: CPU, memory, storage, temperature, reboots, firmware changes."""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, sigma_str
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
        # Hard threshold — absolute safety net regardless of learned baseline.
        ctx.threshold("cpu", cpu, warn=dev.th("cpu_warn"), crit=dev.th("cpu_crit"),
                      what="CPU load", unit="%",
                      cause="Sustained high CPU can indicate a traffic spike, an "
                            "attack, a runaway script, or an undersized device.")
        # Learned-baseline anomaly — fires once the device's normal pattern is
        # established (warmup). Adapts as the device's load changes over time.
        if cpu is not None:
            bl = Baseline(mem.setdefault("cpu_bl", {}),
                          alpha=dev.th("baseline_alpha"),
                          warmup=dev.th("baseline_warmup"),
                          scheme=dev.th("baseline_buckets"))
            s = bl.score(cpu, ctx.now)
            high = is_high(s, float(cpu), floor=10.0,
                           min_ratio=1.3, z=dev.th("baseline_z"))
            if not high:
                bl.update(cpu, ctx.now)
            ctx.transition(
                "cpu_anomaly", healthy=not high,
                severity=Severity.WARNING,
                title=(f"CPU unusually high: {cpu:g}% "
                       f"(normal ~{s['mean']:.0f}% at this time)"),
                cause=(f"CPU is {sigma_str(s['z'])} above the learned baseline "
                       f"for this time of day. Possible cause: traffic spike, "
                       f"scripting job, or attack."),
                recovery_title="CPU returned to normal levels",
            )

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
            # Learned-baseline: alert when memory usage is anomalously high
            # (free_pct anomalously LOW) vs this device's normal pattern.
            used_pct = round(100.0 - free_pct, 1)
            bl_mem = Baseline(mem.setdefault("mem_bl", {}),
                              alpha=dev.th("baseline_alpha"),
                              warmup=dev.th("baseline_warmup"),
                              scheme=dev.th("baseline_buckets"))
            s_mem = bl_mem.score(used_pct, ctx.now)
            mem_high = is_high(s_mem, used_pct, floor=50.0,
                               min_ratio=1.15, z=dev.th("baseline_z"))
            if not mem_high:
                bl_mem.update(used_pct, ctx.now)
            ctx.transition(
                "memory_anomaly", healthy=not mem_high,
                severity=Severity.WARNING,
                title=(f"Memory usage unusually high: {used_pct:.0f}% used "
                       f"(normal ~{s_mem['mean']:.0f}% at this time)"),
                cause=(f"Memory consumption is {sigma_str(s_mem['z'])} above the "
                       f"learned baseline. Possible leak, runaway process, "
                       f"or unusual traffic."),
                recovery_title="Memory usage returned to normal",
            )

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
