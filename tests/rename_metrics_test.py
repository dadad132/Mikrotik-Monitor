"""Two faults found from a live diagnostics report, and the repairs for them.

1. A renamed device lost its identity. Everything about a router is filed
   under its NAME -- the tunnel lease and key, the metric history, the
   recorded conditions -- and only the devices row moved. The lease was
   orphaned, so the dashboard said the router had never been set up; somebody
   pressed Provision, which minted a SECOND tunnel address and key; the
   router was never re-pasted, so it kept answering on the first address
   while mikromon probed the second. Reported UNREACHABLE while a person was
   logged into it.

2. Reading "the latest value" GROUP BY'd the whole samples table, once per
   device per page load, on a table nothing pruned while the service ran.
   Measured at the shipped defaults (30 devices, 60s polling, 30 days) that
   was 25.7s to draw one dashboard.

Run:  ./.venv/Scripts/python.exe tests/rename_metrics_test.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.metrics import MetricsStore
from mikromon.web import _migrate_device_name, _adoptable_lease

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def tmpdb(suffix=".db"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    os.unlink(path)
    return path


# ------------------------------------------------------- the tunnel lease
print("\nRenaming a device carries its tunnel lease with it")

hub = {"leases": {"Geely Alberton": "10.10.61.88"},
       "leases_meta": {"Geely Alberton": {"ip": "10.10.61.88",
                                          "pubkey": "AAAA="}}}
check("the lease moves to the new name, so the router does not look like it "
      "has never been set up -- which is what makes somebody press Provision "
      "and mint a second key",
      _migrate_device_name(hub, "Geely Alberton", "Mobilis Geely Alberton")
      and hub["leases_meta"]["Mobilis Geely Alberton"]["pubkey"] == "AAAA=")

check("...and nothing is left behind under the old name",
      "Geely Alberton" not in hub["leases_meta"]
      and "Geely Alberton" not in hub["leases"])

check("the tunnel IP is unchanged, because the router is still on it",
      hub["leases"]["Mobilis Geely Alberton"] == "10.10.61.88")

check("a rename onto a name that already holds a lease is refused rather "
      "than overwriting somebody else's router",
      not _migrate_device_name(
          {"leases_meta": {"A": {"ip": "1"}, "B": {"ip": "2"}}}, "A", "B"))

check("renaming to the same name is a no-op", not _migrate_device_name(
    {"leases_meta": {"A": {"ip": "1"}}}, "A", "A"))

print("\nSpotting a lease that belongs to a device under its old name")

hub2 = {"leases_meta": {"Geely Alberton": {"ip": "10.10.61.88"},
                        "Howler": {"ip": "10.10.232.214"}}}
check("a lease whose address is the one this device is already polled at is "
      "this router, filed under the name it had before the rename",
      _adoptable_lease(hub2, "Mobilis Geely Alberton", "10.10.61.88")
      == "Geely Alberton")

check("a device that already has its own lease is left alone",
      _adoptable_lease(hub2, "Howler", "10.10.232.214") is None)

check("no address means no guess", _adoptable_lease(hub2, "New", "") is None)
check("an address nothing is registered at means no guess",
      _adoptable_lease(hub2, "New", "10.10.99.99") is None)


# ------------------------------------------------------------ the metrics
print("\nA renamed device keeps its history")

path = tmpdb()
store = MetricsStore(path)
try:
    now = time.time()
    store.record([(now - 60, "Old Name", "cpu", "", 10.0),
                  (now, "Old Name", "cpu", "", 20.0),
                  (now, "Old Name", "rx_bps", "ether1", 500.0),
                  (now, "Other", "cpu", "", 5.0)])
    check("the latest value per series is what was most recently recorded",
          store.latest("Old Name")[("cpu", "")]["value"] == 20.0)

    moved = store.rename_device("Old Name", "New Name")
    check(f"every sample moves across ({moved} of them), so the graphs do not "
          f"restart from nothing", moved == 3)
    check("...and the latest values move with them",
          store.latest("New Name")[("cpu", "")]["value"] == 20.0
          and store.latest("Old Name") == {})
    check("the labelled series survives too",
          store.latest("New Name")[("rx_bps", "ether1")]["value"] == 500.0)
    check("another device is untouched",
          store.latest("Other")[("cpu", "")]["value"] == 5.0)

    print("\nThe latest-value table stays true to the samples")

    store.record([(now + 60, "New Name", "cpu", "", 30.0)])
    check("a newer sample updates it",
          store.latest("New Name")[("cpu", "")]["value"] == 30.0)

    # A device polled twice concurrently, or a clock stepping back, must not
    # make an older reading the current one.
    store.record([(now - 3600, "New Name", "cpu", "", 99.0)])
    check("an OUT-OF-ORDER sample does not become the current value, so a "
          "clock step or a double poll cannot pin a stale reading on screen",
          store.latest("New Name")[("cpu", "")]["value"] == 30.0)

    check("all_latest agrees with latest, series for series",
          {(d, m, l): v for d, m, l, v, _ in store.all_latest()
           if d == "New Name"}
          == {("New Name", m, l): r["value"]
              for (m, l), r in store.latest("New Name").items()})

    check("devices() lists what has samples",
          set(store.devices()) == {"New Name", "Other"})

    print("\nDeleting and sweeping keep the two in step")

    store.delete_device("Other")
    check("deleting a device clears its latest values too, rather than "
          "leaving a ghost on the dashboard",
          store.latest("Other") == {} and "Other" not in store.devices())

    store.record([(now, "Gone", "cpu", "", 1.0)])
    removed = store.keep_only(["New Name"])
    check(f"keep_only sweeps a device that is no longer managed ({removed} "
          f"rows)", removed == 1 and store.latest("Gone") == {})
    check("...and reports nothing to do when everything is known, without "
          "scanning the samples table at all -- it used to full-scan every "
          "sample ever recorded, once per poll cycle",
          store.keep_only(["New Name"]) == 0)

    print("\nRetention is enforced while the service runs")

    store.record([(now - 40 * 86400, "New Name", "cpu", "", 7.0)])
    n = store.prune(30)
    check(f"samples past the retention window are removed ({n})", n == 1)
    check("...and the current value is untouched by pruning history",
          store.latest("New Name")[("cpu", "")]["value"] == 30.0)
finally:
    store.close()
    for ext in ("", "-wal", "-shm"):
        try:
            os.unlink(path + ext)
        except OSError:
            pass


print("\nUpgrading a database written before the latest-value table")

path = tmpdb()
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE samples (ts REAL NOT NULL, device TEXT NOT NULL,
  metric TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', value REAL NOT NULL);
""")
_now = time.time()
db.executemany("INSERT INTO samples VALUES (?,?,?,?,?)", [
    (_now - 120, "R1", "cpu", "", 1.0),
    (_now, "R1", "cpu", "", 42.0),
    (_now, "R1", "rx_bps", "eth1", 99.0),
    (_now, "R2", "cpu", "", 7.0)])
db.commit()
db.close()

store = MetricsStore(path)
try:
    check("opening an existing database backfills the latest values from the "
          "history it already has -- without this an upgraded server shows an "
          "empty dashboard for the whole fleet until the next poll",
          store.latest("R1")[("cpu", "")]["value"] == 42.0
          and store.latest("R2")[("cpu", "")]["value"] == 7.0)
    check("...including labelled series",
          store.latest("R1")[("rx_bps", "eth1")]["value"] == 99.0)
finally:
    store.close()

# Re-opening must not double up or re-do the work.
store = MetricsStore(path)
try:
    check("re-opening does not backfill again",
          len(store.all_latest()) == 3)
finally:
    store.close()
    for ext in ("", "-wal", "-shm"):
        try:
            os.unlink(path + ext)
        except OSError:
            pass

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL RENAME/METRICS TESTS PASSED")
