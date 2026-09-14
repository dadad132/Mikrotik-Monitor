"""The hub's peers file must never be observable half-written.

This is the bug that caused the whole saga, and it was mine.

open(path, "w") truncates FIRST and writes after. A systemd .path unit
watches that file and reloads WireGuard the moment it changes, so it fired on
the truncate -- and `wg syncconf` applied whatever it managed to read.
syncconf REMOVES every peer absent from the config it is handed, so peers
vanished from the running interface while the file on disk ended up perfectly
correct.

The symptoms all follow from that:

  * "[Errno 113] No route to host" reaching a router whose peer was plainly
    in the file. WireGuard routes by public key; with no LOADED peer owning
    that address there is nowhere for the packet to go, and the kernel says
    so immediately rather than timing out.
  * The router transmitting while the hub never answers -- its handshakes
    were being discarded by a hub that no longer knew its key.
  * Routers in DIFFERENT COMPANIES going offline and recovering at the same
    second: one racy reload dropped a batch of peers, the next clean one
    restored them together.
  * "It worked for a few minutes and then stopped."

Run:  ./.venv/Scripts/python.exe tests/atomic_peers_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.web import _atomic_write, _write_wg_peers

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


LEASES = {f"Branch {i:02d}": {"ip": f"10.10.{i}.1", "pubkey": f"KEY{i}="}
          for i in range(40)}


def peer_count(text):
    return text.count("[Peer]")


print("\nA reader can never see a partial file")

d = tempfile.mkdtemp()
path = os.path.join(d, "wg-peers.conf")

# Seed it, the way the hub always has a previous generation on disk.
ok, err = _write_wg_peers(path, LEASES)
check(f"the peers file is written ({peer_count(open(path).read())} peers)",
      ok and peer_count(open(path).read()) == 40)

# Hammer it while rewriting, the way the .path unit does. Every observation
# must be a COMPLETE generation -- never empty, never truncated.
observations = []
stop = threading.Event()


def watcher():
    while not stop.is_set():
        try:
            with open(path, encoding="utf-8") as fh:
                observations.append(peer_count(fh.read()))
        except FileNotFoundError:
            # The file vanishing IS the failure being tested for: syncconf
            # would apply an empty peer list and drop the whole fleet.
            observations.append(-1)
        except PermissionError:
            # Windows only, and not a partial read: it refuses to open a
            # file while a rename is in flight. On the Linux hub the reader
            # simply keeps seeing the old inode. Nothing observed.
            pass


t = threading.Thread(target=watcher, daemon=True)
t.start()
for _ in range(60):
    _write_wg_peers(path, LEASES)
time.sleep(0.05)
stop.set()
t.join(timeout=2)

bad = [n for n in observations if n != 40]
check(f"across {len(observations)} reads taken DURING {60} rewrites, every "
      f"one saw all 40 peers -- a single short read here is a fleet-wide "
      f"outage in production",
      not bad)
if bad:
    print(f"      saw peer counts: {sorted(set(bad))}")

check("the file is never momentarily missing either, which would make "
      "syncconf apply an empty peer list",
      -1 not in observations)

print("\nThe file still ends up correct")

final = open(path, encoding="utf-8").read()
check("every lease is present", peer_count(final) == 40)
check("...with its key and its address",
      "KEY7=" in final and "10.10.7.1/32" in final)

print("\n_atomic_write itself")

p2 = os.path.join(d, "thing.txt")
_atomic_write(p2, "hello")
check("it writes", open(p2).read() == "hello")
_atomic_write(p2, "replaced")
check("it replaces", open(p2).read() == "replaced")

check("no temporary files are left behind to accumulate in the hub's "
      "config directory",
      not [f for f in os.listdir(d) if f.startswith(".mikromon-")])

# A failed write must not destroy the good file that was already there.
try:
    _atomic_write(p2, None)  # type: ignore[arg-type]
except Exception:
    pass
check("a write that fails leaves the PREVIOUS contents intact, rather than "
      "truncating them and then falling over",
      open(p2).read() == "replaced")
check("...and still cleans up after itself",
      not [f for f in os.listdir(d) if f.startswith(".mikromon-")])

print("\nWhen the directory forbids creating a temp file")

# install.sh sets /etc/wireguard to 750 root:<service user>: readable and
# traversable, but NOT writable. mkstemp there raises EACCES -- which is how
# the first version of this left the peers file unwritable altogether.
import errno as _errno

_mk = tempfile.mkstemp


def _denied(*a, **kw):
    raise OSError(_errno.EACCES, "Permission denied")


p3 = os.path.join(d, "peers-ro-dir.conf")
_atomic_write(p3, "[Peer]\n# first\n")
tempfile.mkstemp = _denied
try:
    _atomic_write(p3, "[Peer]\n# second\n")
finally:
    tempfile.mkstemp = _mk
check("a directory that forbids new files no longer fails the write "
      "outright -- that regression left the hub unable to update its peers "
      "at all, which is worse than the race it was fixing",
      open(p3).read() == "[Peer]\n# second\n")

# The fallback must never empty the file: an empty peer list is exactly what
# wg syncconf turns into a fleet-wide outage.
LONG = "[Peer]\n" + "# padding\n" * 500
SHORT = "[Peer]\n# tiny\n"
_atomic_write(p3, LONG)
seen_empty = []
stop2 = threading.Event()


def watcher2():
    while not stop2.is_set():
        try:
            with open(p3, encoding="utf-8") as fh:
                if fh.read() == "":
                    seen_empty.append(1)
        except (FileNotFoundError, PermissionError):
            pass


t2 = threading.Thread(target=watcher2, daemon=True)
t2.start()
tempfile.mkstemp = _denied
try:
    for _ in range(40):
        _atomic_write(p3, LONG)
        _atomic_write(p3, SHORT)
finally:
    tempfile.mkstemp = _mk
    stop2.set()
    t2.join(timeout=2)

check("...and shrinking the file never leaves it momentarily EMPTY, which "
      "is the failure that actually matters: syncconf reading an empty peer "
      "list removes every peer on the hub",
      not seen_empty)
check("the shorter content fully replaces the longer one, with no tail of "
      "the old file left behind",
      open(p3).read() == SHORT)

print("\nThe temp file lands beside the target")

# os.replace is only atomic within one filesystem. Writing the temp file to
# /tmp and renaming onto /etc/wireguard would cross a mount boundary on a
# real hub and quietly reintroduce the race.
seen = []
_real = tempfile.mkstemp


def spy(*a, **kw):
    seen.append(kw.get("dir"))
    return _real(*a, **kw)


tempfile.mkstemp = spy
try:
    _atomic_write(p2, "x")
finally:
    tempfile.mkstemp = _real
check("the temp file is created in the target's own directory, so the "
      "rename stays on one filesystem and remains atomic",
      seen and os.path.abspath(seen[0]) == os.path.abspath(d))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ATOMIC-PEERS TESTS PASSED")
