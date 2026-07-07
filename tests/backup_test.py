"""Offline tests for the full-server backup archive: path selection, tar
contents, missing-file tolerance, and that a live (open, written-to) WAL-mode
SQLite DB is snapshotted correctly via the sqlite3 backup API rather than a
torn raw copy.

Run:  ./.venv/Scripts/python.exe tests/backup_test.py
"""
from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import time

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
data = backup.build_archive({"config.yaml": os.path.join(tmp, "nope.yaml")},
                            tmp_dir=tmp)
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
    check("archive is empty when nothing exists", tar.getnames() == [])

print("build_archive — plain files (config/json) are added verbatim:")
cfg_path = os.path.join(tmp, "config.yaml")
with open(cfg_path, "w") as fh:
    fh.write("poll_interval: 60\n")
state_path = os.path.join(tmp, "state.json")
with open(state_path, "w") as fh:
    fh.write('{"devices": {}}')
data = backup.build_archive({"config.yaml": cfg_path, "state.json": state_path},
                            tmp_dir=tmp)
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
    names = tar.getnames()
    check("both plain files present", set(names) == {"config.yaml", "state.json"})
    got = tar.extractfile("config.yaml").read().decode()
    check("plain file content round-trips", got == "poll_interval: 60\n")

print("build_archive_to_file — an unreadable file is skipped, not fatal:")
readable_path = os.path.join(tmp, "readable.json")
with open(readable_path, "w") as fh:
    fh.write('{"grants": {}}')
unreadable_path = os.path.join(tmp, "unreadable.json")
with open(unreadable_path, "w") as fh:
    fh.write('{"grants": {}}')
os.chmod(unreadable_path, 0o000)
try:
    out_path = os.path.join(tmp, "partial.tar.gz")
    skipped = backup.build_archive_to_file(
        {"readable.json": readable_path, "unreadable.json": unreadable_path},
        out_path)
    check("the unreadable file is reported as skipped",
          len(skipped) == 1 and skipped[0][0] == "unreadable.json")
    with tarfile.open(out_path, mode="r:gz") as tar:
        check("the rest of the archive is still built successfully",
              tar.getnames() == ["readable.json"])
finally:
    os.chmod(unreadable_path, 0o644)  # so cleanup can remove tmp/ afterward

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

data = backup.build_archive({"live.db": db_path}, tmp_dir=tmp)
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
archive = backup.build_archive(old_paths, tmp_dir=tmp)

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

print("restore_archive — stale WAL/SHM sidecars from the OLD file are removed:")
stale_wal = new_auth_db + "-wal"
stale_shm = new_auth_db + "-shm"
with open(stale_wal, "w") as fh:
    fh.write("stale wal data from before the restore")
with open(stale_shm, "w") as fh:
    fh.write("stale shm data from before the restore")
backup.restore_archive(archive, new_paths)
check("stale -wal sidecar is removed on restore", not os.path.exists(stale_wal))
check("stale -shm sidecar is removed on restore", not os.path.exists(stale_shm))
check("the restored db itself still opens and reads correctly",
      [r[0] for r in sqlite3.connect(new_auth_db).execute(
          "SELECT v FROM t ORDER BY id")] == ["before-backup", "also-before-backup"])

print("restore_archive — a member missing from the archive is left alone:")
untouched_path = os.path.join(new_dir, "metrics.db")
with open(untouched_path, "w") as fh:
    fh.write("pre-existing, not in the backup")
written2 = backup.restore_archive(
    archive, {**new_paths, "metrics.db": untouched_path})
check("only members actually present in the archive are written",
      "metrics.db" not in [os.path.basename(w) for w in written2]
      and open(untouched_path).read() == "pre-existing, not in the backup")

print("backups_dir_for:")
check("anchored next to config.yaml",
      backup.backups_dir_for(config_path="/opt/mikromon/config.yaml")
      == os.path.join("/opt/mikromon", "backups-server"))
check("falls back to devices.db's directory when there's no config_path",
      backup.backups_dir_for(devices_db="/opt/mikromon/devices.db")
      == os.path.join("/opt/mikromon", "backups-server"))

print("is_safe_backup_name — rejects anything that could escape the dir:")
check("a normal generated name is accepted",
      backup.is_safe_backup_name("mikromon-backup-20260101-000000.tar.gz"))
check("path traversal is rejected", not backup.is_safe_backup_name("../../etc/passwd"))
check("an absolute path is rejected", not backup.is_safe_backup_name("/etc/passwd.tar.gz"))
check("a nested path is rejected", not backup.is_safe_backup_name("sub/dir.tar.gz"))
check("wrong extension is rejected", not backup.is_safe_backup_name("backup.zip"))
check("empty name is rejected", not backup.is_safe_backup_name(""))

print("list_backups + build_archive_to_file (the persisted, listable flow):")
backups_dir = os.path.join(tmp, "backups-server")
check("no directory yet -> empty list", backup.list_backups(backups_dir) == [])
# Explicit distinct names — backup_filename() only has second resolution,
# too coarse to reliably distinguish two backups made back-to-back in a test.
name1, name2 = "mikromon-backup-A.tar.gz", "mikromon-backup-B.tar.gz"
backup.build_archive_to_file(old_paths, os.path.join(backups_dir, name1))
os.utime(os.path.join(backups_dir, name1), (time.time() - 5, time.time() - 5))
backup.build_archive_to_file(old_paths, os.path.join(backups_dir, name2))
listed = backup.list_backups(backups_dir)
check("both created backups are listed",
      {b["name"] for b in listed} == {name1, name2})
check("listed newest first", listed[0]["name"] == name2)
check("sizes are non-zero (the config.yaml + db actually got written)",
      all(b["size"] > 0 for b in listed))
with open(os.path.join(backups_dir, "not-a-backup.txt"), "w") as fh:
    fh.write("ignore me")
check("a stray file in the backups dir is ignored by list_backups",
      len(backup.list_backups(backups_dir)) == 2)

print("restore_archive_from_path — restores directly from an on-disk archive:")
new_dir2 = os.path.join(tmp, "new2")
os.makedirs(new_dir2)
new_paths2 = backup.backup_paths(
    config_path=os.path.join(new_dir2, "config.yaml"),
    auth_db=os.path.join(new_dir2, "auth.db"))
written3 = backup.restore_archive_from_path(
    os.path.join(backups_dir, name1), new_paths2)
check("restore_archive_from_path writes both configured files",
      set(written3) == set(new_paths2.values()))
check("restored config content matches",
      open(new_paths2["config.yaml"]).read() == "poll_interval: 60\n")

print("restore — hub.json's hub_ip is stripped so the new server re-detects:")
# Unlike hub_pubkey/listen_port/subnet (refreshed by install.sh on every run),
# hub_ip is only ever set once, so a restored hub.json would otherwise pin
# every future provisioning screen to the OLD server's address forever, with
# no UI to fix it (the field is server-set, not user-editable).
old_dir3 = os.path.join(tmp, "old3")
new_dir3 = os.path.join(tmp, "new3")
os.makedirs(old_dir3)
os.makedirs(new_dir3)
old_devices_db = os.path.join(old_dir3, "devices.db")
with open(old_devices_db, "w") as fh:
    fh.write("fake devices db")
old_hub_json = os.path.join(old_dir3, "hub.json")
with open(old_hub_json, "w") as fh:
    json.dump({"hub_ip": "203.0.113.10", "hub_pubkey": "OLDKEY=",
              "leases": {"R1": "10.10.5.5"}}, fh)
old_paths3 = backup.backup_paths(devices_db=old_devices_db)
archive3 = backup.build_archive(old_paths3, tmp_dir=tmp)

new_devices_db = os.path.join(new_dir3, "devices.db")
new_paths3 = backup.backup_paths(devices_db=new_devices_db)
backup.restore_archive(archive3, new_paths3)
restored_hub = json.load(open(os.path.join(new_dir3, "hub.json")))
check("hub_ip is stripped from the restored hub.json",
      "hub_ip" not in restored_hub)
check("everything else in hub.json (pubkey, leases) is preserved",
      restored_hub.get("hub_pubkey") == "OLDKEY="
      and restored_hub.get("leases") == {"R1": "10.10.5.5"})

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BACKUP TESTS PASSED")
