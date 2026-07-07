"""Offline tests for the full-server backup archive: path selection, tar
contents, missing-file tolerance, and that a live (open, written-to) WAL-mode
SQLite DB is snapshotted correctly via the sqlite3 backup API rather than a
torn raw copy.

Run:  ./.venv/Scripts/python.exe tests/backup_test.py
"""
from __future__ import annotations

import io
import os
import sqlite3
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import backup

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()

print("backup_paths:")
paths = backup.backup_paths(
    config_path=os.path.join(tmp, "config.yaml"),
    auth_db=os.path.join(tmp, "auth.db"),
    devices_db=os.path.join(tmp, "sub", "devices.db"),
    metrics_db=None, push_log_db=None, billing_db=None,
    state_file=os.path.join(tmp, "state.json"), access_grants_file=None)
check("only configured paths are included",
      set(paths) == {"config.yaml", "auth.db", "devices.db", "hub.json",
                     "state.json"})
check("hub.json is derived alongside devices.db",
      paths["hub.json"] == os.path.join(tmp, "sub", "hub.json"))

print("build_archive — missing files are skipped, not fatal:")
data = backup.build_archive({"config.yaml": os.path.join(tmp, "nope.yaml")})
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
    check("archive is empty when nothing exists", tar.getnames() == [])

print("build_archive — plain files (config/json) are added verbatim:")
cfg_path = os.path.join(tmp, "config.yaml")
with open(cfg_path, "w") as fh:
    fh.write("poll_interval: 60\n")
state_path = os.path.join(tmp, "state.json")
with open(state_path, "w") as fh:
    fh.write('{"devices": {}}')
data = backup.build_archive({"config.yaml": cfg_path, "state.json": state_path})
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
    names = tar.getnames()
    check("both plain files present", set(names) == {"config.yaml", "state.json"})
    got = tar.extractfile("config.yaml").read().decode()
    check("plain file content round-trips", got == "poll_interval: 60\n")

print("build_archive — live WAL-mode SQLite DB is snapshotted consistently:")
db_path = os.path.join(tmp, "live.db")
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
conn.execute("INSERT INTO t (v) VALUES ('before-backup')")
conn.commit()
# Leave the connection OPEN (as the live server would) while we back it up,
# and make an uncommitted change in a second connection's WAL frame first.
conn2 = sqlite3.connect(db_path)
conn2.execute("INSERT INTO t (v) VALUES ('also-before-backup')")
conn2.commit()

data = backup.build_archive({"live.db": db_path})
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
    check("db appears in the archive", tar.getnames() == ["live.db"])
    member = tar.extractfile("live.db").read()
    snap_path = os.path.join(tmp, "restored.db")
    with open(snap_path, "wb") as fh:
        fh.write(member)
    restored = sqlite3.connect(snap_path)
    rows = [r[0] for r in restored.execute("SELECT v FROM t ORDER BY id")]
    restored.close()
    check("snapshot is a plain, directly-openable DB with both committed rows",
          rows == ["before-backup", "also-before-backup"])
conn.close()
conn2.close()

print("backup_filename:")
name = backup.backup_filename()
check("filename has the expected prefix/extension",
      name.startswith("mikromon-backup-") and name.endswith(".tar.gz"))

print("restore_archive — round-trips a backup onto a fresh install's paths:")
old_dir = os.path.join(tmp, "old")
new_dir = os.path.join(tmp, "new")
os.makedirs(old_dir)
os.makedirs(new_dir)
old_cfg = os.path.join(old_dir, "config.yaml")
with open(old_cfg, "w") as fh:
    fh.write("poll_interval: 60\n")
old_paths = backup.backup_paths(config_path=old_cfg, auth_db=db_path)
archive = backup.build_archive(old_paths)

# The "new server" has its own config at a different path — restoring must
# write to THIS install's configured destinations, not the old server's paths.
new_cfg = os.path.join(new_dir, "config.yaml")
new_auth_db = os.path.join(new_dir, "auth.db")
new_paths = backup.backup_paths(config_path=new_cfg, auth_db=new_auth_db)
written = backup.restore_archive(archive, new_paths)
check("restore writes to the new install's own paths, not the old one's",
      set(written) == {new_cfg, new_auth_db})
check("restored config content matches the backed-up file",
      open(new_cfg).read() == "poll_interval: 60\n")
restored = sqlite3.connect(new_auth_db)
rows = [r[0] for r in restored.execute("SELECT v FROM t ORDER BY id")]
restored.close()
check("restored db has the same rows as the live source it was backed up from",
      rows == ["before-backup", "also-before-backup"])

print("restore_archive — a member missing from the archive is left alone:")
untouched_path = os.path.join(new_dir, "metrics.db")
with open(untouched_path, "w") as fh:
    fh.write("pre-existing, not in the backup")
written2 = backup.restore_archive(
    archive, {**new_paths, "metrics.db": untouched_path})
check("only members actually present in the archive are written",
      "metrics.db" not in [os.path.basename(w) for w in written2]
      and open(untouched_path).read() == "pre-existing, not in the backup")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BACKUP TESTS PASSED")
