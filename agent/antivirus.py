"""EasyMikroTik antivirus agent: watches one PC, and tells the support team.

This runs on the PC -- Windows, Linux or macOS -- never on the EasyMikroTik
server. It watches the folders malware usually arrives in, checks each new
file against known-bad hashes, YARA rules and an entropy heuristic, moves
clearly bad files into quarantine, and watches for Office or a web server
starting a shell. Everything it finds goes to EasyMikroTik, which emails
the support team and lists it under Antivirus on the dashboard.

Set up on a PC (the key comes from EasyMikroTik -> Antivirus -> Make a key):

    pip install -r requirements.txt
    python antivirus.py --install --url https://easymikrotik.com --key emk_...

--install checks the key, saves it, and starts the agent now and at every
sign-in (Windows: the user's Run key; Linux: a systemd user unit; macOS: a
LaunchAgent). --uninstall undoes that. --test sends one test alert, which
checks the key and that the support team's email arrives, without any
malware. Run with no options, it runs in the foreground until stopped.

On Windows there is no need for Python: EasyMikroTik-Antivirus-Setup.exe
(made by build_windows.py, downloaded from the Antivirus page) installs
this agent as a program of its own -- see windows_setup.py.

It runs as the signed-in user, so it watches that user's folders and can
only stop that user's processes. Without a key it still protects the PC,
and keeps its reports in ~/.easymikrotik_edr/outbox until one is set.

Needs Python 3.8 or newer.
"""
from __future__ import annotations

import getpass
import hashlib
import itertools
import json
import logging
import logging.handlers
import math
import os
import platform
import shutil
import signal
import socket
import sqlite3
import sys
import threading
import time
import uuid
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone

import psutil
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Optional YARA support (gracefully degrades if not installed yet)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

AGENT_VERSION = "1.1"

# =====================================================================
# 1. CONFIGURATION
# =====================================================================
STATE_DIR = os.path.join(os.path.expanduser("~"), ".easymikrotik_edr")
# What --install saves: the address and the key, for an agent started at
# sign-in, which has no environment variables to read them from.
SETTINGS_FILE = os.path.join(STATE_DIR, "agent.json")

CONFIG = {
    # Where to report, and this company's agent key (EasyMikroTik ->
    # Antivirus -> Make a key). Read at start-up from, in order: the
    # environment variables EASYMIKROTIK_URL and EASYMIKROTIK_AGENT_KEY,
    # what --install saved, then these two -- so one copy of this file
    # serves every company.
    "EASYMIKROTIK_URL": "https://easymikrotik.com",
    "AGENT_KEY": "",
    "OS_TYPE": platform.system(),  # 'Windows', 'Linux', or 'Darwin' (macOS)

    # Detection Thresholds
    "ENTROPY_THRESHOLD": 7.3,      # 0-8 scale; packed/encrypted code sits above it
    "MAX_FILE_SIZE_MB": 50,        # Skip huge ISOs/videos to save disk I/O
    # A file is scanned once it has stopped changing for this long, rather
    # than on every block written while it is still downloading.
    "SETTLE_SECONDS": 2.0,
    # Suspend Office when it starts a shell. Web servers are reported and
    # never suspended: see REPORT_ONLY_PARENTS.
    "SUSPEND_SUSPICIOUS_PROCESSES": True,
    "HEARTBEAT_MINUTES": 15,

    "QUARANTINE_DIR": os.path.join(STATE_DIR, "quarantine"),
    "OUTBOX_DIR": os.path.join(STATE_DIR, "outbox"),
    "DB_PATH": os.path.join(STATE_DIR, "signatures.db"),
    "LOG_PATH": os.path.join(STATE_DIR, "agent.log"),
}

# =====================================================================
# 2. OS-AWARE TARGET DIRECTORIES & SIGNATURES
# =====================================================================
def get_monitored_directories():
    """Returns high-risk directories based on whether the PC runs Windows, Linux, or macOS."""
    home = os.path.expanduser("~")
    os_type = CONFIG["OS_TYPE"]
    paths = [os.path.join(home, "Downloads")]

    if os_type == "Windows":
        paths.extend([
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            os.path.join(os.environ.get("APPDATA", ""), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        ])
    elif os_type == "Linux":
        paths.extend([
            "/tmp",
            "/dev/shm",  # Fileless malware & cryptominers love /dev/shm on Linux
            os.path.join(home, ".config/autostart"),
            os.path.join(home, ".ssh")
        ])
    elif os_type == "Darwin":  # macOS
        paths.extend([
            "/tmp",
            os.path.join(home, "Library/LaunchAgents")
        ])

    # Return only paths that actually exist on this machine
    return [p for p in paths if p and os.path.exists(p)]

# Suspicious parent -> child process spawns across platforms
_OFFICE_CHILDREN = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]
_WEB_CHILDREN = ["bash", "sh", "nc", "curl", "wget", "python3"]
SUSPICIOUS_PROCESS_CHAINS = {
    "Windows": {
        "winword.exe": _OFFICE_CHILDREN,
        "excel.exe": _OFFICE_CHILDREN,
        "powerpnt.exe": _OFFICE_CHILDREN,
        # Opening an attached .bat or .js runs it as Outlook's child.
        "outlook.exe": _OFFICE_CHILDREN,
    },
    "Linux": {
        "apache2": _WEB_CHILDREN,
        "httpd": _WEB_CHILDREN,
        "nginx": _WEB_CHILDREN,
    },
    "Darwin": {
        "Microsoft Word": ["sh", "bash", "zsh", "osascript", "curl"],
        "Microsoft Excel": ["sh", "bash", "zsh", "osascript", "curl"],
    }
}
# Web servers start shells for ordinary reasons -- PHP's mail() runs
# `sh -c sendmail` as apache2's child -- so suspending that shell breaks the
# website's email. These chains are reported and left running.
REPORT_ONLY_PARENTS = frozenset({"apache2", "httpd", "nginx"})

# The first bytes of a program: Windows (MZ), Linux (ELF) and macOS
# (Mach-O in both byte orders, and universal binaries). Only programs get
# the entropy test: zips, photos, PDFs and Office files all measure close to
# 8.0 as well, so testing everything flags nearly every download.
_EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
               b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Browsers download into these and rename the file when it is complete. The
# finished file is scanned when it appears under its real name.
_PARTIAL_EXTS = (".crdownload", ".part", ".partial", ".download")

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# The strings are written with \xNN escapes, which YARA decodes, so this file
# never contains what it hunts for. Otherwise a copy of the agent saved in
# Downloads is the first thing it quarantines.
_YARA_RULES = r"""
rule EICAR_Test_File {
    meta:
        description = "The EICAR test file: harmless, used to test that alerts arrive"
        severity = "HIGH"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR\x2dSTANDARD\x2dANTIVIRUS\x2dTEST\x2dFILE!$H+H*"
    condition:
        $eicar at 0
}

rule Reverse_Shell_Or_Hidden_PowerShell {
    meta:
        description = "A reverse shell, or PowerShell told to run an encoded command hidden"
        severity = "HIGH"
    strings:
        $ps = "powershell -nop -w hidden \x2denc" nocase ascii wide
        $shell = " -i >\x26 /dev/\x74cp/"
        $devtcp = "/dev/\x74cp/"
        $stdin = "0>\x261"
    condition:
        $ps or $shell or ($devtcp and $stdin)
}

rule Mac_Password_Prompt {
    meta:
        description = "AppleScript asking for a password in a hidden-answer dialog, as Mac stealers do"
        severity = "MEDIUM"
    strings:
        $dialog = "display di\x61log" nocase
        $hidden = "with hidden \x61nswer" nocase
    condition:
        $dialog and $hidden
}
"""

# =====================================================================
# 3. DETECTION ENGINE (SQLite Hashes + YARA + Shannon Entropy)
# =====================================================================
def _inside(path, folder):
    """Whether `path` is `folder` or anything under it."""
    p = os.path.normcase(os.path.abspath(path))
    f = os.path.normcase(os.path.abspath(folder))
    try:
        return os.path.commonpath([p, f]) == f
    except ValueError:  # different drives on Windows
        return False


def _own_program():
    """What runs this agent: the script, or, installed by the Windows setup,
    the program with Python inside it."""
    return sys.executable if getattr(sys, "frozen", False) else __file__


def _is_own_file(path):
    """The agent's own folder (quarantine, outbox, log) and its own script."""
    here = os.path.normcase(os.path.abspath(_own_program()))
    return (_inside(path, STATE_DIR)
            or os.path.normcase(os.path.abspath(path)) == here)


def is_executable(filepath):
    """Whether the file is a program, judged by its first bytes.

    Not os.access(path, X_OK): on Windows that is true of every file."""
    try:
        with open(filepath, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head.startswith(_EXEC_MAGIC)


class DetectionEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.yara_error = ""
        self._init_db()
        self.yara_rules = self._compile_default_yara()

    def _init_db(self):
        """Creates local SQLite signature DB and inserts the standard EICAR test hash."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS malware_hashes (
                    sha256 TEXT PRIMARY KEY,
                    threat_name TEXT,
                    severity TEXT
                )
            """)
            # Standard safe EICAR Antivirus Test File SHA-256 hash (the
            # 68-byte file exactly: one saved with a trailing newline hashes
            # differently, and only the YARA rule catches that one).
            eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            cur.execute(
                "INSERT OR IGNORE INTO malware_hashes VALUES (?, ?, ?)",
                (eicar_sha256, "EICAR-Standard-Antivirus-Test-File", "HIGH")
            )
            conn.commit()

    def _compile_default_yara(self):
        """Compiles built-in cross-platform YARA rules."""
        if not YARA_AVAILABLE:
            logging.warning("yara-python not installed. Running with SHA-256 + Entropy only.")
            return None
        try:
            return yara.compile(source=_YARA_RULES)
        except Exception as e:  # a broken rule must not stop the hash checks
            self.yara_error = f"YARA rules did not compile: {e}"
            logging.error(self.yara_error)
            return None

    def known_hash(self, file_hash):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT threat_name, severity FROM malware_hashes WHERE sha256 = ?",
                (file_hash,)).fetchone()

    @staticmethod
    def calculate_sha256(filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def calculate_entropy(filepath):
        """Calculates Shannon Entropy (0.0 to 8.0) to spot packed/encrypted binaries."""
        with open(filepath, "rb") as f:
            data = f.read(2 * 1024 * 1024)  # Sample first 2MB for speed
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def scan_file(self, filepath):
        """Runs multi-stage analysis on a single file.

        Returns None, or what was found: reason, severity, sha256, and the
        stage that found it ("hash", "yara" or "entropy")."""
        if not os.path.isfile(filepath) or _is_own_file(filepath):
            return None

        try:
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if size_mb > CONFIG["MAX_FILE_SIZE_MB"] or size_mb == 0:
                return None

            # Stage 1: Fast SHA-256 Hash Lookup
            file_hash = self.calculate_sha256(filepath)
            row = self.known_hash(file_hash)
            if row:
                return {"stage": "hash", "reason": f"Known malware hash ({row[0]})",
                        "severity": row[1] or "HIGH", "sha256": file_hash}

            # Stage 2: YARA Pattern Matching
            if self.yara_rules:
                matches = self.yara_rules.match(filepath)
                if matches:
                    rule_names = ", ".join(m.rule for m in matches)
                    severity = max((m.meta.get("severity", "HIGH") for m in matches),
                                   key=lambda s: _SEVERITY_RANK.get(s, 3))
                    return {"stage": "yara", "reason": f"YARA rule match ({rule_names})",
                            "severity": severity, "sha256": file_hash}

            # Stage 3: Entropy of programs only. A packed program is often a
            # normal installer, so this is reported, never quarantined.
            if is_executable(filepath):
                entropy = self.calculate_entropy(filepath)
                if entropy >= CONFIG["ENTROPY_THRESHOLD"]:
                    return {"stage": "entropy",
                            "reason": f"Packed or encrypted program (entropy {entropy:.2f}/8.0)",
                            "severity": "LOW", "sha256": file_hash}

        except OSError:
            pass  # gone, locked or unreadable: nothing to scan
        except Exception as e:
            logging.debug(f"Scan error on {filepath}: {e}")

        return None

# =====================================================================
# 4. REPORTING TO EASYMIKROTIK
# =====================================================================
def local_ip():
    """The address this PC uses to reach the internet, which is the one its
    router sees. (A UDP connect sends nothing.)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def mac_for(ip):
    """The network card behind `ip`: the router's DHCP leases list PCs by it."""
    try:
        for addrs in psutil.net_if_addrs().values():
            if any(a.family == socket.AF_INET and a.address == ip for a in addrs):
                for a in addrs:
                    if a.family == psutil.AF_LINK:
                        return a.address.replace("-", ":").upper()
    except Exception:
        pass
    return ""


def agent_id():
    """This install's own id, kept across restarts. Not the PC's name: two
    PCs can share a name, and a renamed PC is still the same install."""
    path = os.path.join(STATE_DIR, "agent_id")
    try:
        with open(path, encoding="utf-8") as fh:
            value = fh.read().strip()
        if value:
            return value
    except OSError:
        pass
    value = uuid.uuid4().hex
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value)
    except OSError:
        pass
    return value


def identity():
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    return {"agent_id": agent_id(), "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}".strip(),
            "user": user, "version": AGENT_VERSION}


def settings():
    """(address, key) to report with: the environment first, then what
    --install saved, then CONFIG."""
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    url = (os.environ.get("EASYMIKROTIK_URL") or saved.get("url")
           or CONFIG["EASYMIKROTIK_URL"])
    key = (os.environ.get("EASYMIKROTIK_AGENT_KEY") or saved.get("key")
           or CONFIG["AGENT_KEY"])
    return str(url).strip(), str(key).strip()


class Reporter:
    """Gets every event to EasyMikroTik, including ones from while it was offline.

    Each event is written to the outbox folder first and deleted only once
    the server has taken it, so a PC that is offline, a server being
    updated, or the agent restarting loses nothing: the support team hears
    late rather than never."""

    MAX_OUTBOX = 500

    def __init__(self, url, key, outbox_dir, ident):
        url = (url or "").strip().rstrip("/")
        if url and "://" not in url:
            url = "https://" + url   # "easymikrotik.com" as typed
        self.url = url + "/api/v1/edr/alerts" if url else ""
        self.key = (key or "").strip()
        self.outbox = outbox_dir
        self.identity = ident
        self.last_error = ""
        self.last_status = None   # the server's HTTP answer, None if none
        self._seq = itertools.count()
        self._wake = threading.Event()
        # The sender thread and a stopping agent both flush; one at a time,
        # or the same report goes twice.
        self._flushing = threading.Lock()

    def _event(self, event_type, severity, target="", reason="", action="",
               sha256="", details=None):
        ip = local_ip()
        return {**self.identity, "local_ip": ip, "mac": mac_for(ip),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type, "severity": severity,
                "target": target, "reason": reason, "action": action,
                "sha256": sha256, "details": details or {}}

    def report(self, event_type, severity, target="", reason="", action="",
               sha256="", details=None):
        """Queue one event for the server. Never raises."""
        event = self._event(event_type, severity, target, reason, action,
                            sha256, details)
        # Sorted by name when sent: the clock first, then a counter for two
        # reports in the same tick.
        name = (f"{time.time_ns():020d}-{next(self._seq):08d}-"
                f"{uuid.uuid4().hex[:8]}.json")
        tmp = os.path.join(self.outbox, name + ".tmp")
        try:
            os.makedirs(self.outbox, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(event, fh)
            os.replace(tmp, os.path.join(self.outbox, name))
        except OSError as e:
            logging.error(f"Could not queue the {event_type} report: {e}")
            return
        self._trim()
        self._wake.set()

    def _pending(self):
        try:
            return sorted(f for f in os.listdir(self.outbox) if f.endswith(".json"))
        except OSError:
            return []

    def _trim(self):
        """Oldest first, past MAX_OUTBOX: a PC offline for weeks must not
        fill its disk with reports."""
        files = self._pending()
        for name in files[:max(0, len(files) - self.MAX_OUTBOX)]:
            try:
                os.remove(os.path.join(self.outbox, name))
            except OSError:
                pass

    def post(self, event):
        """Send one event: "sent", "retry" (keep it and try later) or "drop".
        Why it did not go is left in last_error."""
        self.last_error = ""
        self.last_status = None
        if not (self.url and self.key):
            self.last_error = "No EasyMikroTik address or agent key is set"
            return "retry"
        try:
            resp = requests.post(self.url, json=event, timeout=10,
                                 headers={"Authorization": f"Bearer {self.key}"})
        except requests.RequestException as e:
            self.last_error = f"EasyMikroTik not reachable: {e}"
            logging.debug(self.last_error)
            return "retry"
        self.last_status = resp.status_code
        if 200 <= resp.status_code < 300:
            return "sent"
        self.last_error = f"EasyMikroTik answered {resp.status_code}: {resp.text[:200]}"
        if resp.status_code in (400, 413):
            # Sending it again will not make it acceptable.
            logging.error(f"EasyMikroTik refused a report: {self.last_error}")
            return "drop"
        if resp.status_code == 401:
            self.last_error = "EasyMikroTik does not know this agent key"
            logging.error(f"{self.last_error}; reports wait in {self.outbox} "
                          f"until it is set right")
        return "retry"

    def flush(self):
        """Send what is waiting, oldest first. False if the server did not
        take something, which then stays for the next try."""
        with self._flushing:
            for name in self._pending():
                path = os.path.join(self.outbox, name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        event = json.load(fh)
                except (OSError, ValueError):
                    event = None
                if event is not None and self.post(event) == "retry":
                    return False
                try:
                    os.remove(path)
                except OSError:
                    pass
            return True

    def heartbeat(self):
        """Tells the server this agent is still running. Not queued: an old
        heartbeat says nothing."""
        self.post(self._event("HEARTBEAT", "LOW"))

    def run(self):
        backoff = 5
        next_beat = 0.0
        while True:
            self._wake.clear()
            try:
                sent = self.flush()
                if sent and time.monotonic() >= next_beat:
                    self.heartbeat()
                    next_beat = time.monotonic() + CONFIG["HEARTBEAT_MINUTES"] * 60
            except Exception:
                # If this thread died, nothing would ever be reported again.
                logging.exception("Reporting to EasyMikroTik failed")
                sent = False
            if sent:
                backoff = 5
                self._wake.wait(60)
            else:
                self._wake.wait(backoff)  # a new event still wakes it at once
                backoff = min(backoff * 2, 300)

# =====================================================================
# 5. RESPONSE (Quarantine)
# =====================================================================
def quarantine_file(filepath, detection_info, reporter):
    """Moves a malicious file into the Quarantine directory, and reports it.

    A file that could not be moved is reported too: it is still on the PC,
    which is exactly when the support team most needs to hear about it."""
    common = {"target": filepath, "reason": detection_info["reason"],
              "sha256": detection_info.get("sha256", "")}
    try:
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        q_name = f"{timestamp}_{uuid.uuid4().hex[:6]}_{filename}.quarantined"
        q_path = os.path.join(CONFIG["QUARANTINE_DIR"], q_name)

        shutil.move(filepath, q_path)
        # Read-only after the move, not before: Windows will not delete a
        # read-only file, and a move between drives is a copy and a delete.
        try:
            os.chmod(q_path, 0o400)
        except OSError:
            pass
        # Where it came from, so a false alarm can be put back by hand.
        with open(q_path + ".json", "w", encoding="utf-8") as fh:
            json.dump({"original_path": filepath, **detection_info,
                       "quarantined": datetime.now(timezone.utc).isoformat()}, fh)
    except Exception as e:
        logging.error(f"Failed to quarantine {filepath}: {e}")
        reporter.report("THREAT_DETECTED", detection_info["severity"],
                        action=f"Could NOT quarantine it ({e}); the file is still in place",
                        **common)
        return False

    logging.warning(f"[QUARANTINED] {filepath} -> {q_path} | Reason: {detection_info['reason']}")
    reporter.report("FILE_QUARANTINED", detection_info["severity"],
                    action=f"Moved to quarantine: {q_path}", **common)
    return True


def handle_file(engine, reporter, filepath):
    """Scan one settled file, and act on what was found."""
    result = engine.scan_file(filepath)
    if not result:
        return
    if result["stage"] == "entropy":
        logging.warning(f"[SUSPICIOUS] {filepath} | {result['reason']}")
        reporter.report("SUSPICIOUS_FILE", result["severity"], target=filepath,
                        reason=result["reason"], sha256=result["sha256"],
                        action="Reported only; packed programs are often normal installers")
        return
    logging.critical(f"[THREAT DETECTED] {filepath} | {result['reason']}")
    quarantine_file(filepath, result, reporter)

# =====================================================================
# 6. REAL-TIME WATCHERS (File System + Process Monitor)
# =====================================================================
class ScanQueue:
    """Files wait here until they have stopped changing, then are scanned once.

    A download fires a "modified" event for every block written. Scanning on
    each one hashed the same growing file hundreds of times, and judged it
    before it was complete."""

    MAX_PENDING = 20000

    def __init__(self, handle, settle):
        self._handle = handle
        self._settle = settle
        self._due = {}
        self._lock = threading.Lock()

    def add(self, path):
        if path.lower().endswith(_PARTIAL_EXTS):
            return
        with self._lock:
            if path in self._due or len(self._due) < self.MAX_PENDING:
                self._due[path] = time.monotonic() + self._settle

    def ready(self, now=None):
        """The paths quiet for long enough, taken off the queue."""
        now = time.monotonic() if now is None else now
        with self._lock:
            done = [p for p, due in self._due.items() if due <= now]
            for p in done:
                del self._due[p]
        return done

    def run(self):
        while True:
            time.sleep(0.5)
            for path in self.ready():
                try:
                    self._handle(path)
                except Exception:
                    logging.exception(f"Scan failed: {path}")


class RealTimeFileHandler(FileSystemEventHandler):
    def __init__(self, scan_queue):
        self.queue = scan_queue

    def on_created(self, event):
        if not event.is_directory:
            self.queue.add(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.queue.add(event.src_path)

    def on_moved(self, event):
        # Browsers finish a download by renaming it, so the finished file
        # only ever shows up here.
        if not event.is_directory:
            self.queue.add(event.dest_path)


def check_processes(rules, seen, reporter, suspend=True):
    """One look at the process list. Returns what it flagged.

    `seen` holds (pid, start time) of processes already looked at. A pid
    alone is not enough: Windows hands pids out again within minutes, and a
    new process given an old number would never be checked."""
    bad = {p.lower(): {c.lower() for c in kids} for p, kids in rules.items()}
    watched_children = set().union(*bad.values()) if bad else set()
    flagged = []
    alive = set()
    for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "create_time"]):
        info = proc.info
        pid = info["pid"]
        key = (pid, info.get("create_time"))
        alive.add(key)
        if key in seen:
            continue
        seen.add(key)

        proc_name = (info.get("name") or "").lower()
        ppid = info.get("ppid")
        # Only a child we watch for is worth looking its parent up.
        if not ppid or proc_name not in watched_children:
            continue
        try:
            parent_name = psutil.Process(ppid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if proc_name not in bad.get(parent_name, ()):
            continue

        cmd = " ".join(info.get("cmdline") or [])[:1000]
        report_only = parent_name in REPORT_ONLY_PARENTS
        if report_only:
            action = "Reported only: web servers start shells for normal reasons"
        elif suspend:
            # Suspend process immediately so a human or rule can inspect it
            try:
                proc.suspend()
                action = "Suspended the process so it can be inspected"
            except psutil.Error as e:
                action = f"Could NOT suspend it ({type(e).__name__}); it may still be running"
        else:
            action = "Reported only (suspending is switched off)"
        logging.critical(
            f"[BEHAVIORAL ALERT] Suspicious spawn: {parent_name} (PID {ppid}) -> {proc_name} (PID {pid}) | CMD: {cmd}"
        )
        severity = "MEDIUM" if report_only else "HIGH"
        reporter.report("SUSPICIOUS_PROCESS", severity,
                        target=f"{parent_name} -> {proc_name}",
                        reason=f"{parent_name} started {proc_name}",
                        action=action,
                        details={"pid": pid, "parent_pid": ppid, "cmdline": cmd})
        flagged.append({"pid": pid, "parent": parent_name, "child": proc_name,
                        "action": action})
    seen.intersection_update(alive)  # forget processes that have exited
    return flagged


def monitor_processes(reporter):
    """Background thread polling process trees for abnormal parent-child spawns."""
    rules = SUSPICIOUS_PROCESS_CHAINS.get(CONFIG["OS_TYPE"], {})
    seen = set()
    while True:
        try:
            check_processes(rules, seen, reporter,
                            CONFIG["SUSPEND_SUSPICIOUS_PROCESSES"])
        except Exception as e:
            logging.debug(f"Process monitor error: {e}")
        time.sleep(2)

# =====================================================================
# 7. MAIN ENTRYPOINT
# =====================================================================
def send_test(url=None, key=None):
    """`python antivirus.py --test`: one alert straight to EasyMikroTik, to
    check the key and the email path without any malware on the PC."""
    if url is None or key is None:
        url, key = settings()
    os.makedirs(STATE_DIR, exist_ok=True)
    reporter = Reporter(url, key, CONFIG["OUTBOX_DIR"], identity())
    result = reporter.post(reporter._event(
        "AGENT_TEST", "MEDIUM", reason="Test alert sent with --test",
        action="Nothing to do: this checks that alerts reach the support team"))
    if result == "sent":
        print(f"Sent to {reporter.url}. The support team should get a "
              f"'Test alert' email within a minute.")
        return 0
    print(f"Not sent: {reporter.last_error}")
    return 1


def single_instance():
    """A lock held for as long as this agent runs, or None if another copy
    already holds it. Started at sign-in and again by hand, two agents
    would each quarantine and report the same file."""
    fh = open(os.path.join(STATE_DIR, "agent.lock"), "a+")
    try:
        fh.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def main(url=None, key=None):
    if url is None or key is None:
        url, key = settings()
    for folder in (STATE_DIR, CONFIG["QUARANTINE_DIR"], CONFIG["OUTBOX_DIR"]):
        os.makedirs(folder, exist_ok=True)
    lock = single_instance()
    if lock is None:
        print("The agent is already running for this user on this PC.")
        return
    handlers = [logging.handlers.RotatingFileHandler(
        CONFIG["LOG_PATH"], maxBytes=1_000_000, backupCount=3,
        encoding="utf-8")]
    if sys.stdout is not None:   # None when started windowless (pythonw)
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )
    logging.info(f"Starting EasyMikroTik Cross-Platform EDR Agent on {CONFIG['OS_TYPE']} ({socket.gethostname()})")

    reporter = Reporter(url, key, CONFIG["OUTBOX_DIR"], identity())
    if not reporter.key:
        logging.warning("No agent key (run with --install --key ...): "
                        f"reports are kept in {CONFIG['OUTBOX_DIR']} until "
                        f"one is set.")
    threading.Thread(target=reporter.run, name="reporter", daemon=True).start()

    engine = DetectionEngine(CONFIG["DB_PATH"])
    if engine.yara_error:
        reporter.report("AGENT_ERROR", "MEDIUM", reason=engine.yara_error,
                        action="Running on hash and entropy checks only")
    scans = ScanQueue(lambda path: handle_file(engine, reporter, path),
                      CONFIG["SETTLE_SECONDS"])
    threading.Thread(target=scans.run, name="scanner", daemon=True).start()

    # 1. Start Real-Time File Watcher
    observer = Observer()
    handler = RealTimeFileHandler(scans)
    watched_dirs = []
    for directory in get_monitored_directories():
        try:
            observer.schedule(handler, directory, recursive=True)
        except Exception as e:  # permissions, or the OS's watch limit
            logging.error(f"Cannot watch {directory}: {e}")
            reporter.report("AGENT_ERROR", "MEDIUM", target=directory,
                            reason=f"Cannot watch this folder: {e}",
                            action="Files arriving in this folder are not checked")
            continue
        watched_dirs.append(directory)
        logging.info(f"Watching directory: {directory}")

    observer.start()

    # 2. Start Behavioral Process Monitor Thread
    proc_thread = threading.Thread(target=monitor_processes, args=(reporter,),
                                   name="processes", daemon=True)
    proc_thread.start()
    logging.info("Behavioral Process Monitor started.")
    reporter.report("AGENT_STARTED", "LOW",
                    reason=f"Watching {len(watched_dirs)} folder(s)"
                           + ("" if engine.yara_rules else
                              "; YARA rules off (yara-python not installed)"),
                    details={"folders": watched_dirs,
                             "yara": bool(engine.yara_rules)})

    # A service manager stops the agent with SIGTERM; treat it like Ctrl+C
    # so the stop is reported.
    if hasattr(signal, "SIGTERM"):
        def _stop(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, _stop)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping EDR Agent...")
        reporter.report("AGENT_STOPPED", "LOW", reason="The agent was stopped on this PC")
        reporter.flush()
        observer.stop()
    observer.join()
    lock.close()

# =====================================================================
# 8. STARTING BY ITSELF (--install / --uninstall)
# =====================================================================
# At sign-in, as the signed-in user: not a Windows service or a root daemon.
# Those run as SYSTEM or root, whose home folder is not the user's, so they
# would watch the wrong Downloads folder.
AUTOSTART_NAME = "EasyMikroTik Antivirus"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_UNIT = "easymikrotik-antivirus.service"
_PLIST = "com.easymikrotik.antivirus"


def _command():
    """How the agent is started: this Python and this file. On Windows the
    windowless pythonw.exe beside it, so sign-in does not open a console.
    The Windows setup's program needs nothing but itself."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    exe = sys.executable
    if os.name == "nt":
        windowless = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(windowless):
            exe = windowless
    return [exe, os.path.abspath(__file__)]


def _unit_text(cmd):
    """A systemd user unit. Each argument double-quoted, with systemd's own
    specials (% and $) doubled so a path cannot be read as one."""
    def q(arg):
        arg = arg.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + arg.replace("%", "%%").replace("$", "$$") + '"'
    return ("[Unit]\nDescription=EasyMikroTik antivirus agent\n"
            "After=network-online.target\n\n"
            "[Service]\n"
            f"ExecStart={' '.join(q(c) for c in cmd)}\n"
            "Restart=on-failure\nRestartSec=30\n\n"
            "[Install]\nWantedBy=default.target\n")


def _plist_bytes(cmd):
    import plistlib
    return plistlib.dumps({
        "Label": _PLIST,
        "ProgramArguments": cmd,
        "RunAtLoad": True,
        # Started again if it dies, but not after a clean stop.
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
    })


def _save_settings(url, key):
    """Readable by this user only, from the moment it exists: it holds the
    company's key."""
    os.makedirs(STATE_DIR, exist_ok=True)
    fd = os.open(SETTINGS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"url": url, "key": key}, fh)
    if os.name != "nt":
        os.chmod(SETTINGS_FILE, 0o600)   # one left by an older install


def _run(args):
    """A system command; returns its error text, or "" when it worked."""
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return str(e)
    return "" if r.returncode == 0 else (r.stderr or r.stdout or
                                         f"exit {r.returncode}").strip()


def _stop_running(program=None):
    """Stop any other copy of the agent this user is running, however it
    was started -- by full path at sign-in, or as `python antivirus.py`
    from its own folder. `program` is another copy's file, for the Windows
    setup replacing the one it installed."""
    me = os.path.normcase(os.path.abspath(program or _own_program()))
    stopped = 0
    for proc in psutil.process_iter(["pid", "cmdline", "cwd"]):
        if proc.info["pid"] == os.getpid():
            continue
        cwd = proc.info.get("cwd") or ""
        # The script is an argument to Python; a program is the command.
        cmd = [os.path.normcase(os.path.abspath(os.path.join(cwd, str(a))))
               for a in (proc.info.get("cmdline") or [])[:3]]
        if me in cmd:
            try:
                proc.terminate()
                stopped += 1
            except psutil.Error:
                pass
    return stopped


def install(url, key, os_type=None):
    """Save the address and key, and start the agent at every sign-in from
    now on -- and now. Returns the exit code."""
    os_type = os_type or CONFIG["OS_TYPE"]
    url, key = (url or "").strip(), (key or "").strip()
    if not key:
        print("No agent key. Give it with --key (EasyMikroTik -> Antivirus -> "
              "Make a key).")
        return 1
    if not url:
        print("No EasyMikroTik address. Give it with --url, e.g. "
              "--url https://easymikrotik.com")
        return 1
    os.makedirs(STATE_DIR, exist_ok=True)
    # A heartbeat, not a test alert: installing on fifty PCs should not
    # send the support team fifty emails.
    check = Reporter(url, key, CONFIG["OUTBOX_DIR"], identity())
    if check.post(check._event("HEARTBEAT", "LOW")) != "sent":
        if check.last_status in (401, 404):
            print(f"Not installed: {check.last_error}.")
            return 1
        print(f"Warning: {check.last_error}. Installing anyway; the agent "
              f"keeps its reports until it can send them.")
    _save_settings(url, key)
    cmd = _command()
    if os_type == "Windows":
        import subprocess
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as k:
            winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ,
                              subprocess.list2cmdline(cmd))
        subprocess.Popen(cmd, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                         | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        where = "at every Windows sign-in"
    elif os_type == "Linux":
        units = os.path.join(os.path.expanduser("~"), ".config", "systemd",
                             "user")
        os.makedirs(units, exist_ok=True)
        with open(os.path.join(units, _UNIT), "w", encoding="utf-8") as fh:
            fh.write(_unit_text(cmd))
        error = (_run(["systemctl", "--user", "daemon-reload"])
                 or _run(["systemctl", "--user", "enable", "--now", _UNIT]))
        if error:
            print(f"Saved the key, but systemd would not start the agent: "
                  f"{error}")
            return 1
        where = ("whenever this user is signed in (to keep it running when "
                 "nobody is: sudo loginctl enable-linger " +
                 (identity().get("user") or "USER") + ")")
    elif os_type == "Darwin":
        agents = os.path.join(os.path.expanduser("~"), "Library",
                              "LaunchAgents")
        os.makedirs(agents, exist_ok=True)
        path = os.path.join(agents, _PLIST + ".plist")
        with open(path, "wb") as fh:
            fh.write(_plist_bytes(cmd))
        domain = f"gui/{os.getuid()}"
        _run(["launchctl", "bootout", domain, path])   # an older copy, if any
        error = _run(["launchctl", "bootstrap", domain, path])
        if error:
            print(f"Saved the key, but launchd would not start the agent: "
                  f"{error}")
            return 1
        where = "at every sign-in to this Mac"
    else:
        print(f"Starting by itself is not supported on {os_type}; the key is "
              f"saved, so running antivirus.py by hand uses it.")
        return 1
    print(f"Installed. The agent is running, and starts {where}. It reports "
          f"to {check.url}.")
    return 0


def uninstall(os_type=None):
    """Stop starting at sign-in, and stop the running agent. The quarantine
    folder stays: it may hold the only copy of a file somebody wants back."""
    os_type = os_type or CONFIG["OS_TYPE"]
    if os_type == "Windows":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, AUTOSTART_NAME)
        except FileNotFoundError:
            pass
    elif os_type == "Linux":
        _run(["systemctl", "--user", "disable", "--now", _UNIT])
        unit = os.path.join(os.path.expanduser("~"), ".config", "systemd",
                            "user", _UNIT)
        if os.path.exists(unit):
            os.remove(unit)
        _run(["systemctl", "--user", "daemon-reload"])
    elif os_type == "Darwin":
        path = os.path.join(os.path.expanduser("~"), "Library",
                            "LaunchAgents", _PLIST + ".plist")
        _run(["launchctl", "bootout", f"gui/{os.getuid()}", path])
        if os.path.exists(path):
            os.remove(path)
    stopped = _stop_running()
    url, key = settings()
    if key:
        r = Reporter(url, key, CONFIG["OUTBOX_DIR"], identity())
        r.post(r._event("AGENT_STOPPED", "LOW",
                        reason="Uninstalled from this PC"))
    copies = f"{stopped} running cop{'y' if stopped == 1 else 'ies'}"
    print(f"Uninstalled{f'; stopped {copies}' if stopped else ''}. The "
          f"quarantine folder is kept: {CONFIG['QUARANTINE_DIR']}")
    return 0


def cli(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        description="EasyMikroTik antivirus agent. With no options it runs "
                    "until stopped.")
    what = p.add_mutually_exclusive_group()
    what.add_argument("--test", action="store_true",
                      help="send one test alert to the support team, and stop")
    what.add_argument("--install", action="store_true",
                      help="save the address and key, and start the agent at "
                           "every sign-in")
    what.add_argument("--uninstall", action="store_true",
                      help="stop starting at sign-in, and stop the agent")
    p.add_argument("--url", help="the EasyMikroTik address")
    p.add_argument("--key", help="this company's agent key")
    a = p.parse_args(argv)
    url, key = settings()
    url, key = (a.url or url), (a.key or key)
    if a.test:
        return send_test(url, key)
    if a.install:
        return install(url, key)
    if a.uninstall:
        return uninstall()
    main(url, key)
    return 0


if __name__ == "__main__":
    sys.exit(cli())
