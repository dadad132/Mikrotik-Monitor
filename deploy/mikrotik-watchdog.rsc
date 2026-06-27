# ============================================================
#  MikroMon Connectivity Watchdog + Auto-Restore
#  RouterOS Script Bundle
#  File: deploy/mikrotik-watchdog.rsc
# ============================================================
#
#  WHAT THIS DOES
#  --------------
#  mm-watchdog  (every 5 min)
#    - Pings 8.8.8.8, 1.1.1.1, and 9.9.9.9 to confirm internet access
#    - On failure: logs WHY (which interfaces are down, whether the
#      default route is missing, whether the WAN has an IP)
#    - After 3 consecutive failed checks (~15 min offline): restores
#      the last mm-autosave.backup and REBOOTS to undo the bad config
#
#  mm-backup  (daily at 03:00)
#    - Saves a fresh mm-autosave.backup ONLY when the router is confirmed
#      online — so a broken config never overwrites a good backup
#
#  HOW TO DEPLOY
#  -------------
#  Option A — MikroMon dashboard:
#    1. Open the device → Scripts tab
#    2. Create script "mm-watchdog", paste SCRIPT 1 source (section below)
#    3. Create script "mm-backup",   paste SCRIPT 2 source (section below)
#    4. SSH/WinBox terminal: paste the SETUP COMMANDS (section below)
#
#  Option B — WinBox terminal directly:
#    /import file-name=mikrotik-watchdog.rsc
#    (upload this file to the router first via WinBox Files)
#
#  AFTER INSTALL — save your first good-state backup:
#    /system script run mm-backup
#
#  VIEW LOGS:
#    /log print where topics~"script"
#
# ============================================================


# ============================================================
#  SCRIPT 1 SOURCE — mm-watchdog
#  Paste this as the "source" of a script named "mm-watchdog"
# ============================================================
#
# :global mmFail
# :if ([:typeof $mmFail] = "nothing") do={ :set mmFail 0 }
#
# # --- Probe three independent public DNS servers ---
# :local online false
# :if ([/ping address=8.8.8.8 count=3 interval=500ms] > 0) do={
#     :set online true
# }
# :if ($online = false) do={
#     :if ([/ping address=1.1.1.1 count=3 interval=500ms] > 0) do={
#         :set online true
#     }
# }
# :if ($online = false) do={
#     :if ([/ping address=9.9.9.9 count=3 interval=500ms] > 0) do={
#         :set online true
#     }
# }
#
# :if ($online = true) do={
#     :if ($mmFail > 0) do={
#         /log info message=("mm-watchdog: RECOVERED after " . $mmFail . " failed check(s)")
#     }
#     :set mmFail 0
# } else={
#     :set mmFail ($mmFail + 1)
#
#     # --- Collect diagnostics at time of failure ---
#     :local diag ""
#
#     # Which interfaces are not running?
#     :foreach i in=[/interface find where running=no] do={
#         :set diag ($diag . [/interface get $i name] . " down; ")
#     }
#
#     # Is there an active default route?
#     :local defRoute [/ip route find where dst-address="0.0.0.0/0" active=yes]
#     :if ([:len $defRoute] = 0) do={
#         :set diag ($diag . "no active default route; ")
#     }
#
#     # Does ether1 (WAN port) have an IP address?
#     :local wanIP [/ip address find where interface=ether1 invalid=no]
#     :if ([:len $wanIP] = 0) do={
#         :set diag ($diag . "no IP on ether1 (WAN); ")
#     }
#
#     :if ($diag = "") do={
#         :set diag "all interfaces up and route present — gateway/ISP unreachable"
#     }
#
#     /log warning message=("mm-watchdog: OFFLINE check " . $mmFail . "/3 — " . $diag)
#
#     # --- After 3 consecutive failures, restore the backup ---
#     :if ($mmFail >= 3) do={
#
#         # Try the known-good autosave first
#         :local bFile "mm-autosave.backup"
#         :local found [/file find where name="mm-autosave.backup"]
#
#         # Fall back to any .backup file on the router
#         :if ([:len $found] = 0) do={
#             :set bFile ""
#             :foreach f in=[/file find] do={
#                 :local fn [/file get $f name]
#                 :if ([:len $fn] > 7) do={
#                     :if ([:pick $fn ([:len $fn]-7) [:len $fn]] = ".backup") do={
#                         :set bFile $fn
#                     }
#                 }
#             }
#         }
#
#         :if ($bFile != "") do={
#             /log error message=("mm-watchdog: OFFLINE " . $mmFail . " checks — RESTORING " . $bFile . " — REBOOTING — last diag: " . $diag)
#             :delay 3s
#             /system backup load name=$bFile
#         } else={
#             /log error message=("mm-watchdog: OFFLINE " . $mmFail . " checks — NO BACKUP FILE FOUND on router — " . $diag)
#         }
#     }
# }
#
# ============================================================
#  END SCRIPT 1
# ============================================================


# ============================================================
#  SCRIPT 2 SOURCE — mm-backup
#  Paste this as the "source" of a script named "mm-backup"
# ============================================================
#
# :global mmFail
# :if ([:typeof $mmFail] = "nothing") do={ :set mmFail 0 }
#
# # Only save when confirmed online (never overwrite good backup with broken config)
# :if ($mmFail = 0) do={
#     /system backup save name="mm-autosave" dont-encrypt=yes
#     /log info message="mm-backup: saved mm-autosave.backup (router confirmed online)"
# } else={
#     /log warning message=("mm-backup: skipped — router not online (fail count: " . $mmFail . ")")
# }
#
# ============================================================
#  END SCRIPT 2
# ============================================================


# ============================================================
#  SETUP COMMANDS — run these ONCE in WinBox/SSH terminal
#  after you have added both scripts above
# ============================================================

# Remove old schedulers if any
/system scheduler remove [find name="mm-watchdog-sched"]
/system scheduler remove [find name="mm-backup-sched"]

# Schedule watchdog every 5 minutes
/system scheduler add \
    name="mm-watchdog-sched" \
    interval=5m \
    on-event="mm-watchdog" \
    policy=ftp,reboot,read,write,policy,test,password,sensitive,romon \
    comment="mikromon:watchdog-scheduler"

# Schedule daily backup at 03:00
/system scheduler add \
    name="mm-backup-sched" \
    interval=1d \
    start-time=03:00:00 \
    on-event="mm-backup" \
    policy=ftp,reboot,read,write,policy,test,password,sensitive,romon \
    comment="mikromon:backup-scheduler"

# Save the very first backup right now (initial known-good state)
/system backup save name="mm-autosave" dont-encrypt=yes
/log info message="mm-setup: initial backup saved — watchdog armed"

# ============================================================
#  VERIFY INSTALL
# ============================================================
# Check scripts exist:
#   /system script print where comment~"mikromon"
#
# Check schedulers:
#   /system scheduler print where comment~"mikromon"
#
# Check backup file saved:
#   /file print where name="mm-autosave.backup"
#
# Read the watchdog log:
#   /log print where topics~"script" proplist=time,message
#
# Run a manual backup now:
#   /system script run mm-backup
#
# Simulate a watchdog run (reads current connectivity):
#   /system script run mm-watchdog
#
# ============================================================
#  NOTES
# ============================================================
#  * The script checks ether1 for a WAN IP. If your WAN port
#    has a different name (e.g. ether2, sfp1, pppoe-out1),
#    change "ether1" in SCRIPT 1 to match.
#
#  * "dont-encrypt=yes" is RouterOS 7.x syntax. On RouterOS
#    6.x, remove that flag — backups are unencrypted by default.
#
#  * The 3-failure threshold means the router must be offline
#    for at least ~15 minutes before auto-restore fires.
#    Change "$mmFail >= 3" to a lower/higher number to adjust.
#
#  * If you make a config change from the dashboard and want
#    to PREVENT the watchdog from reverting it (because you
#    intentionally changed something), save a fresh backup
#    immediately after confirming the change works:
#      /system script run mm-backup
#
#  * The $mmFail global variable resets to 0 on router reboot.
#    If the router goes offline AND reboots (e.g. power cut),
#    the counter resets and the watchdog starts fresh — no
#    premature restore after a planned reboot.
# ============================================================
