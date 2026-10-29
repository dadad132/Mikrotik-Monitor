"""The Windows setup for the antivirus agent (agent/windows_setup.py),
checked without installing anything.

The setup is what a customer's PC runs: it checks the company key, unpacks
the agent program, makes it start at every sign-in, lists it under
Settings -> Apps, and takes all of that off again on uninstall. The
registry, the process list and EasyMikroTik are stood in for here, so the
setup's own decisions are what get exercised. The built .exe is tested end
to end on a real PC before it ships (see agent/build_windows.py).

Run:  ./.venv/Scripts/python.exe tests/windows_setup_test.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import zipfile

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_DIR = os.path.join(ROOT, "agent")
TMP = tempfile.mkdtemp()
for var, sub in (("USERPROFILE", "home"), ("HOME", "home"),
                 ("LOCALAPPDATA", "local"), ("APPDATA", "appdata")):
    os.environ[var] = os.path.join(TMP, sub)
    os.makedirs(os.environ[var], exist_ok=True)
os.environ.pop("EASYMIKROTIK_AGENT_KEY", None)
os.environ.pop("EASYMIKROTIK_URL", None)

# ---- stand-ins: the PC's libraries, its processes, its registry ------------
psutil = types.ModuleType("psutil")
psutil.Error = type("Error", (Exception,), {})
psutil.AF_LINK = -1
psutil.net_if_addrs = lambda: {}
PROCS: list = []


class Proc:
    def __init__(self, pid, cmdline):
        self.info = {"pid": pid, "cmdline": cmdline, "cwd": ""}
        self.terminated = False

    def terminate(self):
        self.terminated = True


psutil.process_iter = lambda attrs=None: list(PROCS)

requests = types.ModuleType("requests")
requests.RequestException = type("RequestException", (Exception,), {})


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


requests.post = fake_post
watchdog = types.ModuleType("watchdog")
wd_events = types.ModuleType("watchdog.events")
wd_observers = types.ModuleType("watchdog.observers")
wd_events.FileSystemEventHandler = type("FileSystemEventHandler", (), {})
wd_observers.Observer = object

REG: dict = {}


class _Key:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _open(root, path, res=0, access=0):
    if path not in REG:
        raise FileNotFoundError(path)
    return _Key(path)


def _create(root, path):
    REG.setdefault(path, {})
    return _Key(path)


def _set(k, name, res, kind, value):
    REG[k.path][name] = (kind, value)


def _delete_value(k, name):
    if name not in REG[k.path]:
        raise FileNotFoundError(name)
    del REG[k.path][name]


def _delete_key(root, path):
    if path not in REG:
        raise FileNotFoundError(path)
    del REG[path]


winreg = types.ModuleType("winreg")
winreg.HKEY_CURRENT_USER, winreg.KEY_SET_VALUE = 1, 2
winreg.REG_SZ, winreg.REG_DWORD = "REG_SZ", "REG_DWORD"
winreg.CreateKey, winreg.OpenKey, winreg.SetValueEx = _create, _open, _set
winreg.DeleteValue, winreg.DeleteKey = _delete_value, _delete_key

sys.modules.update({"psutil": psutil, "requests": requests,
                    "watchdog": watchdog, "watchdog.events": wd_events,
                    "watchdog.observers": wd_observers, "yara": None,
                    "winreg": winreg})


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(AGENT_DIR, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


av = load("antivirus")
ws = load("windows_setup")

STARTED: list = []
real_popen = subprocess.Popen
subprocess.Popen = lambda cmd, **kw: STARTED.append(cmd)


def payload(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


GOOD = payload(os.path.join(TMP, "agent.zip"), {
    ws.EXE_NAME: b"MZ agent", "_internal/python312.dll": b"MZ dll"})
RUN = av._RUN_KEY
UNINST = ws._UNINSTALL_KEY
URL, KEY = "https://em.test", "emk_good"

try:
    print("Checking the key")
    check("no key: refused before anything is sent",
          ws.check_key(URL, "")[0] == "refused" and POSTS == [])
    RESPONSES[:] = [Resp(401, "unknown key")]
    verdict, why = ws.check_key(URL, "emk_wrong")
    check("a key EasyMikroTik does not know is refused, saying so",
          verdict == "refused" and "did not accept this key" in why)
    RESPONSES[:] = [Resp(404)]
    verdict, why = ws.check_key("https://wrong.test", KEY)
    check("an address that is not EasyMikroTik with antivirus on is refused",
          verdict == "refused" and "Check the address" in why)
    RESPONSES[:] = [requests.RequestException("no route")]
    verdict, why = ws.check_key(URL, KEY)
    check("a PC that cannot reach EasyMikroTik yet still installs, and is "
          "told the reports wait", verdict == "offline"
          and "Installed anyway" in why)
    POSTS.clear()
    check("a good key: ok", ws.check_key(URL, KEY) == ("ok", ""))
    check("...checked with a heartbeat, not a test alert: setting up fifty "
          "PCs must not send fifty emails",
          POSTS[-1]["json"]["event_type"] == "HEARTBEAT"
          and POSTS[-1]["headers"]["Authorization"] == f"Bearer {KEY}")

    print("\nInstalling")
    dest = ws.install_dir()
    check("into the user's own programs folder: no administrator needed",
          dest == os.path.join(os.environ["LOCALAPPDATA"], "Programs",
                               "EasyMikroTik Antivirus"))
    exe = ws.install(URL, KEY, payload=GOOD)
    check("the agent program is unpacked there",
          exe == os.path.join(dest, ws.EXE_NAME) and os.path.isfile(exe)
          and os.path.isfile(os.path.join(dest, "_internal", "python312.dll")))
    check("...starts at every sign-in, from the Run key",
          REG[RUN][av.AUTOSTART_NAME] == ("REG_SZ", f'"{exe}"'))
    entry = REG.get(UNINST, {})
    check("...is listed under Settings -> Apps, by name and version",
          entry.get("DisplayName", (0, ""))[1] == "EasyMikroTik Antivirus"
          and entry.get("DisplayVersion", (0, ""))[1] == av.AGENT_VERSION
          and entry.get("Publisher", (0, ""))[1] == "EasyMikroTik")
    check("...which uninstalls it with the program itself, quietly or not",
          entry["UninstallString"][1] == f'"{exe}" --uninstall'
          and entry["QuietUninstallString"][1].endswith("--uninstall --quiet")
          and entry["NoModify"] == ("REG_DWORD", 1))
    check("...saves the address and key for the agent started at sign-in",
          json.load(open(av.SETTINGS_FILE)) == {"url": URL, "key": KEY})
    check("...and starts it now", STARTED == [[exe]])
    check("no Start menu entry where pywin32 is missing is not a failure: "
          "it installed all the same", not os.path.exists(ws.shortcut_path()))

    print("\nInstalling again (an update)")
    with open(os.path.join(dest, "_internal", "old.pyd"), "wb") as fh:
        fh.write(b"MZ old")
    running_agent = Proc(4242, [exe])
    other = Proc(4343, [r"C:\Program Files\Other\other.exe"])
    me = Proc(os.getpid(), [exe])
    PROCS[:] = [running_agent, other, me]
    ws.install(URL, KEY, payload=GOOD, start=False)
    check("stops the running agent so its files can be replaced",
          running_agent.terminated and not other.terminated
          and not me.terminated)
    check("...and leaves none of the old version's files behind",
          not os.path.exists(os.path.join(dest, "_internal", "old.pyd")))
    PROCS.clear()

    stranger = os.path.join(TMP, "someone-elses")
    os.makedirs(stranger)
    with open(os.path.join(stranger, "notes.txt"), "w") as fh:
        fh.write("mine")
    try:
        ws.put_files(stranger, GOOD)
        refused = False
    except RuntimeError:
        refused = True
    check("a folder that is not its own is never emptied",
          refused and os.path.isfile(os.path.join(stranger, "notes.txt")))
    broken = payload(os.path.join(TMP, "broken.zip"), {"readme.txt": b"x"})
    try:
        ws.put_files(os.path.join(TMP, "fresh"), broken)
        said = ""
    except RuntimeError as exc:
        said = str(exc)
    check("a damaged setup says to download it again", "Download it again"
          in said)

    print("\nRunning")
    check("not running when nothing holds the agent's lock",
          ws.running() is False)
    held = av.single_instance()
    check("running while an agent holds it", ws.running() is True)
    held.close()
    POSTS.clear()
    sent, said = ws.send_test_alert()
    check("the test button sends a test alert with the saved key",
          sent and POSTS[-1]["json"]["event_type"] == "AGENT_TEST"
          and POSTS[-1]["headers"]["Authorization"] == f"Bearer {KEY}")

    print("\nThe installed program")
    sys.frozen = True
    try:
        check("starts as itself, with no Python and no script",
              av._command() == [sys.executable])
        check("never scans itself", av._is_own_file(sys.executable))
    finally:
        del sys.frozen

    print("\nUninstalling")
    q = av.CONFIG["QUARANTINE_DIR"]
    os.makedirs(q, exist_ok=True)
    with open(os.path.join(q, "x.quarantined"), "wb") as fh:
        fh.write(b"bad")
    POSTS.clear()
    STARTED.clear()
    ws.uninstall()
    check("no longer starts at sign-in", av.AUTOSTART_NAME not in REG[RUN])
    check("...gone from Settings -> Apps", UNINST not in REG)
    check("...EasyMikroTik is told it was uninstalled",
          POSTS and POSTS[-1]["json"]["event_type"] == "AGENT_STOPPED"
          and "Uninstalled" in POSTS[-1]["json"]["reason"])
    check("...the company's key is not left on the PC",
          not os.path.exists(av.SETTINGS_FILE))
    check("...the program is removed",
          not os.path.exists(dest) and STARTED == [])
    check("...and the quarantine kept: it may hold a file somebody wants "
          "back", os.path.isfile(os.path.join(q, "x.quarantined")))

    ws.install(URL, KEY, payload=GOOD, start=False)
    real_exe = sys.executable
    sys.executable = os.path.join(dest, ws.EXE_NAME)
    try:
        ws.uninstall()
    finally:
        sys.executable = real_exe
    check("run from its own folder (Settings -> Apps), the folder is "
          "removed just after it closes, by a separate command",
          os.path.isdir(dest) and STARTED
          and "rmdir /s /q" in STARTED[-1] and f'"{dest}"' in STARTED[-1])

    print("\nWithout the window")
    RESPONSES[:] = [Resp(401)]
    check("--quiet with a refused key exits 1",
          ws.main(["--quiet", "--url", URL, "--key", "emk_wrong"]) == 1)
    ws.payload_path = lambda: GOOD
    check("--quiet with a good key installs, exit 0",
          ws.main(["--quiet", "--url", URL, "--key", KEY]) == 0
          and REG[RUN].get(av.AUTOSTART_NAME))

    print("\nThe build and the server agree")
    sys.path.insert(0, AGENT_DIR)
    import build_windows as bw  # noqa: E402
    sys.path.insert(0, ROOT)
    from mikromon import edr  # noqa: E402
    check("the build reads the names and version the setup uses",
          (bw.VERSION, bw.APP_NAME, bw.EXE_NAME, bw.SETUP_NAME, bw.PAYLOAD)
          == (av.AGENT_VERSION, ws.APP_NAME, ws.EXE_NAME, ws.SETUP_NAME,
              ws.PAYLOAD))
    check("the dashboard offers the file the build makes",
          edr.SETUP_NAME == ws.SETUP_NAME
          and os.path.normpath(os.path.dirname(edr.SETUP_FILE))
          == os.path.normpath(bw.OUT))
finally:
    subprocess.Popen = real_popen

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL WINDOWS SETUP TESTS PASSED")
