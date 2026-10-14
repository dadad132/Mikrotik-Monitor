"""The antivirus agent (agent/antivirus.py), checked without installing it.

The agent runs on customers' PCs with psutil, watchdog and requests. None of
them is a server dependency, so stand-ins take their place here and the
agent's own logic is what gets exercised: what it scans and when, what it
quarantines, what it reports, and that a report outlives the server being
away.

Run:  ./.venv/Scripts/python.exe tests/agent_test.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import types
import zipfile

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "agent", "antivirus.py")
HOME = tempfile.mkdtemp()
# expanduser reads USERPROFILE on Windows and HOME elsewhere.
os.environ["HOME"] = os.environ["USERPROFILE"] = HOME
os.environ.pop("EASYMIKROTIK_AGENT_KEY", None)

# ---- stand-ins for the PC-side libraries ----------------------------------
psutil = types.ModuleType("psutil")


class Error(Exception):
    pass


class NoSuchProcess(Error):
    pass


class AccessDenied(Error):
    pass


psutil.Error, psutil.NoSuchProcess, psutil.AccessDenied = (
    Error, NoSuchProcess, AccessDenied)
psutil.AF_LINK = -1
psutil.net_if_addrs = lambda: {}
PROCS: list = []
NAMES: dict = {}


class FakeProc:
    def __init__(self, pid, name, ppid, created=1.0, cmdline=None,
                 suspend_error=None, cwd=""):
        self.info = {"pid": pid, "name": name, "ppid": ppid,
                     "cmdline": cmdline or [name], "create_time": created,
                     "cwd": cwd}
        self.suspended = False
        self.terminated = False
        self._err = suspend_error

    def suspend(self):
        if self._err:
            raise self._err
        self.suspended = True

    def terminate(self):
        self.terminated = True


class FakeParent:
    def __init__(self, pid):
        if pid not in NAMES:
            raise NoSuchProcess(pid)
        self._pid = pid

    def name(self):
        return NAMES[self._pid]


psutil.process_iter = lambda attrs=None: list(PROCS)
psutil.Process = FakeParent

requests = types.ModuleType("requests")


class RequestException(Exception):
    pass


class Resp:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


POSTS: list = []
RESPONSES: list = []


def fake_post(url, json=None, timeout=None, headers=None):
    POSTS.append({"url": url, "json": json, "headers": headers})
    r = RESPONSES.pop(0) if RESPONSES else Resp(200)
    if isinstance(r, Exception):
        raise r
    return r


requests.RequestException = RequestException
requests.post = fake_post

watchdog = types.ModuleType("watchdog")
wd_events = types.ModuleType("watchdog.events")
wd_observers = types.ModuleType("watchdog.observers")
wd_events.FileSystemEventHandler = type("FileSystemEventHandler", (), {})
wd_observers.Observer = object
sys.modules.update({"psutil": psutil, "requests": requests,
                    "watchdog": watchdog, "watchdog.events": wd_events,
                    "watchdog.observers": wd_observers,
                    "yara": None})       # None: "import yara" fails, as uninstalled

spec = importlib.util.spec_from_file_location("antivirus", AGENT)
av = importlib.util.module_from_spec(spec)
spec.loader.exec_module(av)

print("importing:")
check("importing the agent creates no folders and no log file",
      not os.path.exists(av.STATE_DIR))
check("its state lives in the user's home folder",
      av.STATE_DIR == os.path.join(HOME, ".easymikrotik_edr"))
QDIR, OUT = av.CONFIG["QUARANTINE_DIR"], av.CONFIG["OUTBOX_DIR"]
for d in (QDIR, OUT):
    os.makedirs(d)

print("the YARA rules never match the agent itself:")
src = open(AGENT, encoding="utf-8").read()


def yara_text(s: str) -> str:
    """What YARA reads a text string as: \\xNN, \\\\ and \\" decoded."""
    return re.sub(r'\\(x[0-9a-fA-F]{2}|\\|")',
                  lambda m: (chr(int(m.group(1)[1:], 16))
                             if m.group(1)[0] == "x" else m.group(1)), s)


strings = [yara_text(s) for s in
           re.findall(r'\$\w+\s*=\s*"((?:[^"\\]|\\.)*)"', av._YARA_RULES)]
check("the rules have their strings", len(strings) >= 6)
check("the agent's own source contains none of them, so a copy of it in "
      "Downloads is not quarantined",
      not [s for s in strings if s.lower() in src.lower()])
eicar = [s for s in strings if s.startswith("X5O")]
check("the escaped EICAR string still decodes to the real one",
      len(eicar) == 1 and hashlib.sha256(eicar[0].encode()).hexdigest()
      == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

print("what counts as a program:")
DL = os.path.join(HOME, "Downloads")
os.makedirs(DL)


def write(name, data, folder=DL):
    p = os.path.join(folder, name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


noise = os.urandom(300_000)
pe = write("setup.exe", b"MZ" + noise)
elf = write("tool", b"\x7fELF" + noise)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
    z.writestr("photo.jpg", noise)
zipped = write("photos.zip", buf.getvalue())
txt = write("notes.txt", b"hello world " * 100)
check("Windows and Linux programs are recognised by their first bytes",
      av.is_executable(pe) and av.is_executable(elf))
check("a zip and a text file are not programs, whatever os.access says",
      not av.is_executable(zipped) and not av.is_executable(txt))

print("scanning:")
eng = av.DetectionEngine(av.CONFIG["DB_PATH"])
check("without yara-python it still starts, on hashes and entropy",
      eng.yara_rules is None and not eng.yara_error)
check("a zip (entropy near 8) is not flagged", eng.scan_file(zipped) is None)
found = eng.scan_file(pe)
check("a packed program is reported LOW by the entropy stage",
      found and found["stage"] == "entropy" and found["severity"] == "LOW")
check("an ordinary text file is clean", eng.scan_file(txt) is None)
bad = write("invoice.pdf.exe", b"pretend this is malware " * 10)
bad_hash = hashlib.sha256(open(bad, "rb").read()).hexdigest()
with sqlite3.connect(av.CONFIG["DB_PATH"]) as db:
    db.execute("INSERT INTO malware_hashes VALUES (?, ?, ?)",
               (bad_hash, "Test.Trojan", "HIGH"))
found = eng.scan_file(bad)
check("a known-bad hash is found, with its name and severity",
      found and found["stage"] == "hash" and "Test.Trojan" in found["reason"]
      and found["severity"] == "HIGH" and found["sha256"] == bad_hash)
own = write("old.quarantined", open(bad, "rb").read(), QDIR)
check("files in the agent's own folder are never scanned",
      eng.scan_file(own) is None)
check("an empty file is skipped", eng.scan_file(write("e.exe", b"")) is None)

print("quarantine:")
rep = av.Reporter("https://easymikrotik.test/", "emk_testkey", OUT,
                  {"agent_id": "a1", "hostname": "PC1", "os": "Windows 11",
                   "user": "thandi", "version": av.AGENT_VERSION})


def last_event():
    names = rep._pending()
    with open(os.path.join(OUT, names[-1]), encoding="utf-8") as fh:
        return json.load(fh)


moved = av.quarantine_file(bad, found, rep)
qfiles = os.listdir(QDIR)
check("the bad file leaves Downloads for the quarantine folder",
      moved and not os.path.exists(bad)
      and any(f.endswith("_invoice.pdf.exe.quarantined") for f in qfiles))
notes = [f for f in qfiles if f.endswith(".quarantined.json")]
check("...beside a note of where it came from, to put a false alarm back",
      len(notes) == 1 and json.load(open(os.path.join(QDIR, notes[0])))
      ["original_path"] == bad)
ev = last_event()
check("and a FILE_QUARANTINED report is queued for EasyMikroTik",
      ev["event_type"] == "FILE_QUARANTINED" and ev["target"] == bad
      and ev["sha256"] == bad_hash and ev["severity"] == "HIGH"
      and ev["action"].startswith("Moved to quarantine"))
check("the report says which PC and person it came from",
      ev["agent_id"] == "a1" and ev["hostname"] == "PC1"
      and ev["user"] == "thandi" and ev["timestamp"].endswith("+00:00"))
gone = os.path.join(DL, "vanished.exe")
moved = av.quarantine_file(gone, {"reason": "Known malware hash (X)",
                                  "severity": "HIGH", "sha256": ""}, rep)
ev = last_event()
check("a file that cannot be moved is still reported -- as NOT quarantined",
      not moved and ev["event_type"] == "THREAT_DETECTED"
      and "Could NOT quarantine" in ev["action"])
av.handle_file(eng, rep, pe)
ev = last_event()
check("a packed program is reported, and left where it is",
      os.path.exists(pe) and ev["event_type"] == "SUSPICIOUS_FILE"
      and ev["severity"] == "LOW")

print("getting reports to EasyMikroTik:")
waiting = rep._pending()
order = []
for n in waiting:
    with open(os.path.join(OUT, n), encoding="utf-8") as fh:
        order.append(json.load(fh)["event_type"])
RESPONSES[:] = [Resp(503)]
check("server down: nothing is lost",
      rep.flush() is False and rep._pending() == waiting)
POSTS.clear()
check("server back: everything goes, oldest first, and leaves the outbox",
      rep.flush() and rep._pending() == []
      and [p["json"]["event_type"] for p in POSTS] == order)
check("to the alerts endpoint, with the company key as a bearer token",
      all(p["url"] == "https://easymikrotik.test/api/v1/edr/alerts"
          and p["headers"]["Authorization"] == "Bearer emk_testkey"
          for p in POSTS))
rep.report("AGENT_ERROR", "MEDIUM", reason="x")
RESPONSES[:] = [Resp(400, "bad_event")]
check("a report the server calls malformed is dropped, not retried for ever",
      rep.flush() and rep._pending() == [])
rep.report("AGENT_ERROR", "MEDIUM", reason="x")
RESPONSES[:] = [Resp(401)]
check("an unknown key keeps the report until the key is put right",
      rep.flush() is False and len(rep._pending()) == 1
      and "does not know this agent key" in rep.last_error)
RESPONSES[:] = [RequestException("no route to host")]
check("so does no network at all",
      rep.flush() is False and len(rep._pending()) == 1)
nokey = av.Reporter("https://easymikrotik.test", "", OUT, {"agent_id": "a1"})
check("with no key set, reports wait in the outbox",
      nokey.flush() is False and len(nokey._pending()) == 1)
rep.MAX_OUTBOX = 5
for i in range(9):
    rep.report("AGENT_ERROR", "MEDIUM", reason=f"#{i}")
kept = []
for n in rep._pending():
    with open(os.path.join(OUT, n), encoding="utf-8") as fh:
        kept.append(json.load(fh)["reason"])
check("an offline PC keeps at most MAX_OUTBOX reports, dropping the oldest",
      kept == ["#4", "#5", "#6", "#7", "#8"])
RESPONSES[:] = []
rep.flush()

print("waiting for files to settle:")
handled: list = []
q = av.ScanQueue(handled.append, settle=2.0)
q.add("a.exe")
q.add("b.exe.crdownload")
q.add("a.exe")
t = time.monotonic()
check("nothing is scanned while the file is still changing",
      q.ready(now=t + 1) == [])
check("it is scanned once when it settles; partial downloads are skipped",
      q.ready(now=t + 3) == ["a.exe"] and q.ready(now=t + 10) == [])
handler = av.RealTimeFileHandler(q)
moved_ev = types.SimpleNamespace(is_directory=False, src_path="x.crdownload",
                                 dest_path=os.path.join(DL, "x.exe"))
handler.on_moved(moved_ev)
check("a download renamed to its final name is scanned under that name",
      q.ready(now=time.monotonic() + 5) == [moved_ev.dest_path])
handler.on_created(types.SimpleNamespace(is_directory=True, src_path=DL))
check("folders are ignored", q.ready(now=time.monotonic() + 5) == [])

print("processes:")
rep2 = av.Reporter("https://easymikrotik.test", "emk_k",
                   os.path.join(HOME, "out2"), {"agent_id": "a2"})
os.makedirs(rep2.outbox)


def last2():
    with open(os.path.join(rep2.outbox, rep2._pending()[-1]),
              encoding="utf-8") as fh:
        return json.load(fh)


win = av.SUSPICIOUS_PROCESS_CHAINS["Windows"]
NAMES.update({100: "WINWORD.EXE", 200: "explorer.exe", 300: "apache2"})
word_ps = FakeProc(101, "powershell.exe", 100, created=5.0,
                   cmdline=["powershell.exe", "-e", "SQBFAFgA"])
normal = FakeProc(201, "powershell.exe", 200)
PROCS[:] = [word_ps, normal]
seen: set = set()
flagged = av.check_processes(win, seen, rep2)
check("Word starting PowerShell is caught and suspended",
      [f["pid"] for f in flagged] == [101] and word_ps.suspended)
check("PowerShell started from Explorer is left alone", not normal.suspended)
ev = last2()
check("...and reported HIGH, with its command line",
      ev["event_type"] == "SUSPICIOUS_PROCESS" and ev["severity"] == "HIGH"
      and "SQBFAFgA" in ev["details"]["cmdline"])
check("the same process is not reported twice",
      av.check_processes(win, seen, rep2) == [])
reused = FakeProc(101, "cmd.exe", 100, created=9.0)
PROCS[:] = [reused]
check("a new process given an old pid is checked (Windows reuses pids)",
      len(av.check_processes(win, seen, rep2)) == 1 and reused.suspended)
check("processes that have exited are forgotten", (101, 5.0) not in seen)
denied = FakeProc(102, "cmd.exe", 100, created=3.0,
                  suspend_error=AccessDenied())
PROCS[:] = [denied]
flagged = av.check_processes(win, seen, rep2)
check("one that cannot be suspended is still reported, saying so",
      flagged and "Could NOT suspend" in last2()["action"])
sh = FakeProc(301, "sh", 300)
PROCS[:] = [sh]
flagged = av.check_processes(av.SUSPICIOUS_PROCESS_CHAINS["Linux"], set(),
                             rep2)
check("a web server starting a shell is reported MEDIUM and never suspended "
      "(PHP's mail() does exactly that)",
      flagged and not sh.suspended and last2()["severity"] == "MEDIUM")

print("identity and --test:")
first, again = av.agent_id(), av.agent_id()
check("the agent's id is kept across restarts", first == again
      and len(first) == 32)
av.CONFIG["AGENT_KEY"] = ""
check("--test without a key says so", av.send_test() == 1)
av.CONFIG["AGENT_KEY"] = "emk_k"
POSTS.clear()
RESPONSES[:] = [Resp(200)]
check("--test sends one AGENT_TEST alert straight away",
      av.send_test() == 0 and POSTS[-1]["json"]["event_type"] == "AGENT_TEST"
      and POSTS[-1]["json"]["severity"] == "MEDIUM")
av.CONFIG["AGENT_KEY"] = ""

print("where the address and key come from:")
check("with nothing saved, the defaults in the file",
      av.settings() == ("https://easymikrotik.com", ""))
with open(av.SETTINGS_FILE, "w") as fh:
    json.dump({"url": "https://saved.test", "key": "emk_saved"}, fh)
check("what --install saved comes next",
      av.settings() == ("https://saved.test", "emk_saved"))
os.environ["EASYMIKROTIK_AGENT_KEY"] = "emk_env"
check("and the environment wins over both",
      av.settings() == ("https://saved.test", "emk_env"))
del os.environ["EASYMIKROTIK_AGENT_KEY"]
os.remove(av.SETTINGS_FILE)

print("one copy at a time:")
first = av.single_instance()
check("the first copy gets the lock", first is not None)
check("a second copy does not", av.single_instance() is None)
first.close()
again = av.single_instance()
check("once the first has stopped, a new one can start", again is not None)
again.close()

print("starting by itself -- Windows:")
RUN: dict = {}


class _Key:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


winreg = types.ModuleType("winreg")
winreg.HKEY_CURRENT_USER, winreg.REG_SZ, winreg.KEY_SET_VALUE = 1, 1, 2
winreg.CreateKey = lambda root, path: _Key()
winreg.OpenKey = lambda root, path, res=0, access=0: _Key()
winreg.SetValueEx = lambda k, name, res, kind, value: RUN.__setitem__(name,
                                                                      value)


def _delete_value(k, name):
    if name not in RUN:
        raise FileNotFoundError(name)
    del RUN[name]


winreg.DeleteValue = _delete_value
sys.modules["winreg"] = winreg
import subprocess  # noqa: E402

STARTED: list = []
real_popen = subprocess.Popen
subprocess.Popen = lambda cmd, **kw: STARTED.append(cmd)
try:
    cmd = av._command()
    check("it runs this Python on this file",
          os.path.basename(cmd[1]) == "antivirus.py"
          and os.path.isabs(cmd[1]) and os.path.isfile(cmd[0]))
    RESPONSES[:] = [Resp(401)]
    check("a key the server does not know is refused, and nothing installed",
          av.install("https://em.test", "emk_wrong", os_type="Windows") == 1
          and RUN == {} and not os.path.exists(av.SETTINGS_FILE))
    check("no key at all is refused too",
          av.install("https://em.test", "", os_type="Windows") == 1)
    check("and no address",
          av.install("", "emk_good", os_type="Windows") == 1)
    check("an address typed without https:// still reaches the alerts "
          "endpoint", av.Reporter("easymikrotik.com/", "k", OUT, {}).url
          == "https://easymikrotik.com/api/v1/edr/alerts")
    POSTS.clear()
    RESPONSES[:] = [Resp(200)]
    check("a good key installs",
          av.install("https://em.test", "emk_good", os_type="Windows") == 0)
    check("...checking it with a heartbeat, not a test alert that would "
          "email the support team for every PC installed",
          [p["json"]["event_type"] for p in POSTS] == ["HEARTBEAT"])
    check("...starting at every sign-in from the user's Run key",
          RUN.get(av.AUTOSTART_NAME) == subprocess.list2cmdline(cmd))
    check("...and starting now", STARTED == [cmd])
    check("...with the address and key saved for when it starts by itself",
          av.settings() == ("https://em.test", "emk_good"))
    RESPONSES[:] = [RequestException("offline")]
    check("offline, it installs anyway: the agent sends its reports later",
          av.install("https://em.test", "emk_good", os_type="Windows") == 0)
    running = FakeProc(900, "pythonw.exe", 1, cmdline=cmd)
    by_hand = FakeProc(901, "python.exe", 1,
                       cmdline=["python", "antivirus.py"],
                       cwd=os.path.dirname(cmd[1]))
    other = FakeProc(902, "python.exe", 1, cmdline=["python", "other.py"])
    PROCS[:] = [running, by_hand, other]
    POSTS.clear()
    check("--uninstall removes the sign-in entry",
          av.uninstall(os_type="Windows") == 0 and RUN == {})
    check("...stops the running agent, however it was started",
          running.terminated and by_hand.terminated and not other.terminated)
    check("...tells the server it was uninstalled",
          POSTS and POSTS[-1]["json"]["event_type"] == "AGENT_STOPPED")
    check("...and keeps the quarantine folder", os.path.isdir(QDIR))
finally:
    subprocess.Popen = real_popen
    del sys.modules["winreg"]

print("starting by itself -- Linux and macOS:")
RAN: list = []
real_run = av._run
av._run = lambda args: RAN.append(args) or ""
had_getuid = hasattr(os, "getuid")
if not had_getuid:
    os.getuid = lambda: 501
try:
    RESPONSES[:] = []
    check("Linux installs", av.install("https://em.test", "emk_good",
                                       os_type="Linux") == 0)
    unit = os.path.join(HOME, ".config", "systemd", "user", av._UNIT)
    text = open(unit, encoding="utf-8").read()
    exec_line = [ln for ln in text.splitlines() if ln.startswith("ExecStart=")]
    check("...as a systemd user unit that runs this file and restarts it if "
          "it dies", len(exec_line) == 1
          and exec_line[0].endswith('antivirus.py"')
          and exec_line[0].count('"') == 4
          and "Restart=on-failure" in text
          and "WantedBy=default.target" in text)
    check("...enabled and started", ["systemctl", "--user", "enable", "--now",
                                     av._UNIT] in RAN)
    odd = av._unit_text(["/usr/bin/python3", '/home/a b/50%/$x/"q".py'])
    check("a path with spaces, %, $ or quotes cannot be misread by systemd",
          'ExecStart="/usr/bin/python3" "/home/a b/50%%/$$x/\\"q\\".py"' in odd)
    RAN.clear()
    check("--uninstall disables it and removes the unit",
          av.uninstall(os_type="Linux") == 0 and not os.path.exists(unit)
          and ["systemctl", "--user", "disable", "--now", av._UNIT] in RAN)
    RAN.clear()
    check("macOS installs", av.install("https://em.test", "emk_good",
                                       os_type="Darwin") == 0)
    import plistlib  # noqa: E402
    plist = os.path.join(HOME, "Library", "LaunchAgents",
                         av._PLIST + ".plist")
    data = plistlib.loads(open(plist, "rb").read())
    check("...as a LaunchAgent that runs at sign-in and comes back if it dies",
          data["ProgramArguments"] == cmd and data["RunAtLoad"] is True
          and data["KeepAlive"] == {"SuccessfulExit": False})
    check("...loaded for this user",
          ["launchctl", "bootstrap", f"gui/{os.getuid()}", plist] in RAN)
    check("--uninstall unloads and removes it",
          av.uninstall(os_type="Darwin") == 0 and not os.path.exists(plist))
finally:
    av._run = real_run
    if not had_getuid:
        del os.getuid

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL AGENT TESTS PASSED")
