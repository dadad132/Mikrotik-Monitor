"""The monitoring engine: poll every device, run its checks, dispatch alerts."""
from __future__ import annotations

import logging
import signal
import threading
import time

from .alert import Severity
from .checks import enabled_checks, required_datasets
from .context import CheckContext
from .device import Device, DeviceError
from .metrics import MetricsStore
from .notify import build_notifiers
from .state import StateStore

log = logging.getLogger(__name__)


class Engine:
    def __init__(self, config, dry_run: bool = False, devices=None,
                 notifiers=None):
        self.config = config
        self.dry_run = dry_run
        self.state = StateStore(config.state_file).load()
        # `devices`/`notifiers` can be injected (used by the demo and tests).
        self.notifiers = (notifiers if notifiers is not None
                          else build_notifiers(config))
        # Device source: injected > web-managed store (devices_db) > YAML.
        self.devices_store = None
        if devices is not None:
            self.devices = devices
        elif getattr(config, "devices_db", None):
            from .devices_store import DevicesStore

            self.devices_store = DevicesStore(config.devices_db)
            seeded = self.devices_store.seed_from(config.devices, config.defaults)
            if seeded:
                log.info("Seeded %d device(s) from YAML into %s",
                         seeded, config.devices_db)
            self.devices = self._devices_from_store()
        else:
            self.devices = [Device(d) for d in config.devices]
        # Time source for checks (overridable so the demo can use a stable
        # simulated clock, making throughput math deterministic).
        self.now_fn = time.time
        self.metrics = None
        if getattr(config, "metrics_db", None):
            self.metrics = MetricsStore(config.metrics_db)
            self.metrics.prune(getattr(config, "metrics_retention_days", 30))
        self._stop = threading.Event()
        known = {d.name for d in self.devices}
        self.state.prune_unknown_devices(known)
        # Web-managed mode: the devices DB is the single source of truth, so
        # sweep metrics for any device no longer in it (orphans from deletes or
        # from older builds) — otherwise their stale series keep them on the
        # dashboard even though they're gone from the Devices tab.
        if self.devices_store is not None and self.metrics is not None:
            self.metrics.keep_only(known)

    def _devices_from_store(self):
        return [Device(c) for c in
                self.devices_store.list_configs(self.config.defaults)]

    def _record_facts(self, cfg, snap, now) -> None:
        """Persist a little inventory metadata (model, RouterOS version, serial,
        identity) so the dashboard can show a device table + version stats."""
        res = snap.resource
        rb = snap.first("routerboard")
        ident = snap.first("identity")
        facts = self.state.facts(cfg.name)
        model = rb.get("model") or rb.get("board-name") or res.get("board-name")
        wanted = {
            "model": model,
            "version": res.get("version"),
            "firmware": rb.get("current-firmware") or rb.get("upgrade-firmware"),
            "serial": rb.get("serial-number"),
            "identity": ident.get("name"),
            "uptime": res.get("uptime"),
            "arch": res.get("architecture-name"),
            "host": cfg.host,
            "wan_links": [ep.label(i) for i, ep in enumerate(cfg.wan.links)],
        }
        for key, val in wanted.items():
            if val not in (None, "", []):
                facts[key] = str(val) if isinstance(val, (str, int)) else val
        if any(v not in (None, "", []) for v in wanted.values()):
            facts["updated"] = now
        # Cache update availability (reads current router state, no network check).
        try:
            upd = snap.first("pkg_update")
            latest = str(upd.get("latest-version", "")).strip()
            installed = str(upd.get("installed-version", "")).strip()
            if latest and installed:
                facts["update_available"] = latest != installed
        except Exception:
            pass

    def _flush_metrics(self, ctx) -> None:
        if self.metrics and ctx.samples:
            self.metrics.record((ctx.now, ctx.device, m, lab, v)
                                for (m, v, lab) in ctx.samples)

    # ----- lifecycle --------------------------------------------------------
    def run(self) -> None:
        """Run forever (until SIGINT/SIGTERM), polling every poll_interval."""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: self._stop.set())
            except ValueError:
                pass  # not on the main thread (e.g. tests)
        log.info("mikromon started: %d device(s), polling every %ds%s",
                 len(self.devices), self.config.poll_interval,
                 " [DRY RUN]" if self.dry_run else "")
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 — never let the loop die
                log.exception("Unexpected error during poll cycle")
            self._stop.wait(self.config.poll_interval)
        log.info("mikromon stopping; saving state.")
        self.state.save()

    def run_once(self) -> list:
        """Poll all devices once, dispatch alerts, persist state. Returns alerts."""
        # Pick up devices added/edited/removed in the dashboard since last poll.
        if self.devices_store is not None:
            self.devices = self._devices_from_store()
            known = {d.name for d in self.devices}
            self.state.prune_unknown_devices(known)
            if self.metrics is not None:
                self.metrics.keep_only(known)
        batch = []
        for device in self.devices:
            batch.extend(self._poll_device(device))
        self.dispatch(batch)
        self.state.save()
        return batch

    # ----- per-device -------------------------------------------------------
    def _poll_device(self, device) -> list:
        cfg = device.cfg
        ctx = CheckContext(cfg.name, self.state, now=self.now_fn(),
                           default_confirm=self.config.confirmations)

        # 1) Is the device itself reachable on the API port?
        if cfg.check_enabled("reachability"):
            up = device.reachable()
            ctx.sample("up", 1 if up else 0)
            ctx.transition(
                "reachability", healthy=up, severity=Severity.CRITICAL,
                title="Device UNREACHABLE",
                cause=f"No TCP response from {cfg.host}:{cfg.api_port}. The "
                      "router is powered off, crashed, or cut off from the "
                      "network (or the API service/port is blocked).",
                recovery_title="Device reachable again",
            )
            if not up:
                log.warning("%s unreachable at %s:%s", cfg.name, cfg.host,
                            cfg.api_port)
                self._flush_metrics(ctx)
                return ctx.alerts

        # 2) Connect + pull the datasets the enabled checks need (plus a little
        #    inventory metadata for the dashboard's device list / version stats).
        datasets = set(required_datasets(cfg)) | {"resource", "identity",
                                                  "routerboard", "pkg_update"}
        try:
            device.connect()
            snap = device.fetch(datasets)
        except DeviceError as exc:
            if not cfg.check_enabled("reachability"):
                ctx.sample("up", 0)
            ctx.transition(
                "api_error", healthy=False, severity=Severity.CRITICAL,
                title="RouterOS API error",
                cause=str(exc) + " — check the monitor username/password, that "
                      "the API service is enabled, and the source IP is allowed.",
                recovery_title="RouterOS API reachable again",
            )
            device.close()
            self._flush_metrics(ctx)
            return ctx.alerts
        else:
            if not cfg.check_enabled("reachability"):
                ctx.sample("up", 1)
            ctx.transition("api_error", healthy=True, severity=Severity.CRITICAL,
                           title="RouterOS API error",
                           recovery_title="RouterOS API reachable again")

        self._record_facts(cfg, snap, ctx.now)

        # 3) Run each enabled check, isolating failures.
        for check in enabled_checks(cfg):
            try:
                check.run(snap, cfg, ctx)
            except Exception:  # noqa: BLE001
                log.exception("%s: check '%s' failed", cfg.name, check.name)
        device.close()

        if snap.errors:
            log.debug("%s: datasets unavailable: %s", cfg.name, snap.errors)
        self._flush_metrics(ctx)
        return ctx.alerts

    # ----- dispatch ---------------------------------------------------------
    def dispatch(self, alerts) -> None:
        if not alerts:
            return
        for a in alerts:
            log.info("ALERT %s", a.one_line())
        if self.dry_run:
            return
        if not self.notifiers:
            log.warning("%d alert(s) but no notifiers configured", len(alerts))
            return
        for notifier in self.notifiers:
            try:
                notifier.send(alerts)
            except Exception:  # noqa: BLE001
                log.exception("Notifier '%s' failed", notifier.name)
