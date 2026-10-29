"""Windows setup for the EasyMikroTik antivirus agent: no Python needed.

build_windows.py turns this into EasyMikroTik-Antivirus-Setup.exe, which
carries the agent program (Python inside it) as agent.zip. Run, the setup
asks for the EasyMikroTik address and the company's agent key, checks the
key, and installs for the signed-in user, with no administrator needed:

  * the agent program into %LOCALAPPDATA%\\Programs\\EasyMikroTik Antivirus
  * started now, and at every sign-in (the user's Run key, as --install)
  * listed under Settings -> Apps, which is where it is uninstalled
  * a Start menu entry that says whether it is running, and sends a test
    alert

Per user on purpose, like antivirus.py --install: the agent watches the
signed-in user's Downloads and temp folders, which a service running as
SYSTEM would not see.

For many PCs at once, without the window:
    EasyMikroTik-Antivirus-Setup.exe --url https://easymikrotik.com --key emk_... --quiet

The installed program (windows_app.py) is the agent when started with no
options, --status for the Start menu entry and --uninstall for Settings.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
import zipfile

import antivirus as av

APP_NAME = av.AUTOSTART_NAME          # "EasyMikroTik Antivirus"
EXE_NAME = "EasyMikroTikAntivirus.exe"
SETUP_NAME = "EasyMikroTik-Antivirus-Setup.exe"
PAYLOAD = "agent.zip"
PUBLISHER = "EasyMikroTik"
_UNINSTALL_KEY = (r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
                  r"\EasyMikroTikAntivirus")
DEFAULT_URL = av.CONFIG["EASYMIKROTIK_URL"]


# ---------------------------------------------------------------------------
# Where things go
# ---------------------------------------------------------------------------
def install_dir() -> str:
    base = (os.environ.get("LOCALAPPDATA")
            or os.path.join(os.path.expanduser("~"), "AppData", "Local"))
    return os.path.join(base, "Programs", APP_NAME)


def shortcut_path() -> str:
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                        "Start Menu", "Programs", APP_NAME + ".lnk")


def payload_path() -> str:
    """The agent program carried inside this setup."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, PAYLOAD)


# ---------------------------------------------------------------------------
# Installing
# ---------------------------------------------------------------------------
def check_key(url: str, key: str) -> tuple:
    """("ok" | "refused" | "offline", why). A heartbeat, not a test alert,
    as --install sends: setting up fifty PCs should not send the support
    team fifty emails. Refused only when EasyMikroTik answered and said no;
    a PC that cannot reach it yet installs anyway and sends later."""
    url, key = (url or "").strip(), (key or "").strip()
    if not key:
        return "refused", ("Paste the company's agent key (EasyMikroTik → "
                           "Antivirus → Make a key).")
    if not url:
        return "refused", "Fill in the EasyMikroTik address."
    os.makedirs(av.STATE_DIR, exist_ok=True)
    r = av.Reporter(url, key, av.CONFIG["OUTBOX_DIR"], av.identity())
    if r.post(r._event("HEARTBEAT", "LOW")) == "sent":
        return "ok", ""
    if r.last_status == 401:
        return "refused", ("EasyMikroTik did not accept this key. Check it "
                           "was copied whole, and has not been replaced "
                           "since.")
    if r.last_status == 404:
        return "refused", (f"{url} did not answer as EasyMikroTik with "
                           f"antivirus switched on. Check the address.")
    return "offline", (f"{r.last_error}. Installed anyway: the agent keeps "
                       f"its reports until it can send them.")


def _ours(folder: str) -> bool:
    return os.path.isfile(os.path.join(folder, EXE_NAME))


def _remove_folder(folder: str, tries: int = 20) -> None:
    """A program that was just stopped can hold its files for a moment."""
    for i in range(tries):
        try:
            shutil.rmtree(folder)
            return
        except FileNotFoundError:
            return
        except OSError:
            if i == tries - 1:
                raise
            time.sleep(0.25)


def put_files(dest: str, payload: str) -> str:
    """Unpack the agent program into `dest`, replacing an older copy, and
    return the program's path. Refuses a folder that is not its own: it
    deletes what is there first."""
    exe = os.path.join(dest, EXE_NAME)
    if os.path.exists(dest):
        if not _ours(dest):
            raise RuntimeError(f"{dest} is there already and is not an "
                               f"EasyMikroTik Antivirus install; nothing "
                               f"was changed.")
        av._stop_running(exe)
        _remove_folder(dest)
    with zipfile.ZipFile(payload) as z:
        z.extractall(dest)
    if not _ours(dest):
        raise RuntimeError("The setup file is incomplete. Download it again.")
    return exe


def _folder_kb(folder: str) -> int:
    total = 0
    for root, _, files in os.walk(folder):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total // 1024


def register(exe: str) -> None:
    """Start at every sign-in, and be listed under Settings -> Apps."""
    import winreg
    dest = os.path.dirname(exe)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, av._RUN_KEY) as k:
        winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ,
                          subprocess.list2cmdline([exe]))
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _UNINSTALL_KEY) as k:
        for name, value in (
                ("DisplayName", APP_NAME),
                ("DisplayVersion", av.AGENT_VERSION),
                ("Publisher", PUBLISHER),
                ("InstallLocation", dest),
                ("DisplayIcon", exe),
                ("UninstallString",
                 subprocess.list2cmdline([exe, "--uninstall"])),
                ("QuietUninstallString",
                 subprocess.list2cmdline([exe, "--uninstall", "--quiet"]))):
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        for name, value in (("NoModify", 1), ("NoRepair", 1),
                            ("EstimatedSize", _folder_kb(dest))):
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)


def add_shortcut(exe: str) -> bool:
    """The Start menu entry: opens the status window. Nothing depends on
    it, so a PC that will not make one still installs."""
    try:
        from win32com.client import Dispatch
        link = Dispatch("WScript.Shell").CreateShortCut(shortcut_path())
        link.TargetPath = exe
        link.Arguments = "--status"
        link.WorkingDirectory = os.path.dirname(exe)
        link.IconLocation = exe
        link.Description = "Whether the antivirus is running; send a test alert"
        link.save()
        return True
    except Exception:  # noqa: BLE001 -- pywin32 missing, or COM refused
        return False


def start_agent(exe: str) -> None:
    subprocess.Popen([exe], cwd=os.path.dirname(exe), close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                     | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def install(url: str, key: str, *, dest: str | None = None,
            payload: str | None = None, start: bool = True) -> str:
    """Everything after the key check. Returns the installed program."""
    exe = put_files(dest or install_dir(), payload or payload_path())
    av._save_settings(url.strip(), key.strip())
    register(exe)
    add_shortcut(exe)
    if start:
        start_agent(exe)
    return exe


# ---------------------------------------------------------------------------
# Uninstalling (run by the installed program, from Settings -> Apps)
# ---------------------------------------------------------------------------
def unregister() -> None:
    import winreg
    for path, value in ((av._RUN_KEY, APP_NAME), (_UNINSTALL_KEY, None)):
        try:
            if value is None:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            else:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, value)
        except FileNotFoundError:
            pass
    try:
        os.remove(shortcut_path())
    except OSError:
        pass


def _remove_after_exit(folder: str) -> None:
    """The uninstaller runs from the folder it removes, so a separate
    command finishes the job a few seconds after it has closed."""
    subprocess.Popen(
        f'cmd.exe /d /c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{folder}"',
        cwd=os.path.dirname(folder), close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0))


def uninstall(dest: str | None = None) -> int:
    """Stop it, stop it starting, tell EasyMikroTik, and remove the program
    and its saved key. The quarantine folder stays: it may hold the only
    copy of a file somebody wants back. Returns how many copies were
    stopped."""
    dest = dest or install_dir()
    exe = os.path.join(dest, EXE_NAME)
    unregister()
    stopped = av._stop_running(exe)
    url, key = av.settings()
    if key:
        r = av.Reporter(url, key, av.CONFIG["OUTBOX_DIR"], av.identity())
        r.post(r._event("AGENT_STOPPED", "LOW",
                        reason="Uninstalled from this PC"))
    try:
        os.remove(av.SETTINGS_FILE)
    except OSError:
        pass
    if _ours(dest):
        running_from = os.path.normcase(os.path.abspath(sys.executable))
        if av._inside(running_from, dest):
            _remove_after_exit(dest)
        else:
            _remove_folder(dest)
    return stopped


# ---------------------------------------------------------------------------
# Is it running?
# ---------------------------------------------------------------------------
def running() -> bool:
    """Whether an agent holds this user's lock. Taken and let go at once if
    nothing does."""
    os.makedirs(av.STATE_DIR, exist_ok=True)
    lock = av.single_instance()
    if lock is None:
        return True
    lock.close()
    return False


def send_test_alert() -> tuple:
    """(sent, message) for the window's test button."""
    url, key = av.settings()
    os.makedirs(av.STATE_DIR, exist_ok=True)
    r = av.Reporter(url, key, av.CONFIG["OUTBOX_DIR"], av.identity())
    result = r.post(r._event(
        "AGENT_TEST", "MEDIUM", reason="Test alert sent from this PC",
        action="Nothing to do: this checks that alerts reach the support "
               "team"))
    if result == "sent":
        return True, ("Sent. The support team should get a 'Test alert' "
                      "email within a minute, and this PC shows on the "
                      "Antivirus page.")
    return False, f"Not sent: {r.last_error}"


# ---------------------------------------------------------------------------
# The windows
# ---------------------------------------------------------------------------
def _sharp_text() -> None:
    """Without this, Windows scales the window up as a blurry bitmap on a
    high-resolution screen."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 -- older Windows; only looks softer
        pass


class _Window:
    def __init__(self, title: str):
        import tkinter as tk
        from tkinter import ttk
        _sharp_text()
        self.tk, self.ttk = tk, ttk
        self.root = tk.Tk()
        self.root.title(title)
        self.root.resizable(False, False)
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.grid(sticky="nsew")
        self.row = 0

    def text(self, value, *, bold=False, wrap=460, color=None):
        style = {"font": ("Segoe UI", 12, "bold")} if bold else {}
        lab = self.ttk.Label(self.frame, text=value, wraplength=wrap,
                             justify="left", **style)
        if color:
            lab.configure(foreground=color)
        lab.grid(row=self.row, column=0, columnspan=2, sticky="w",
                 pady=(0, 10))
        self.row += 1
        return lab

    def field(self, label, value="", show=None):
        self.ttk.Label(self.frame, text=label).grid(
            row=self.row, column=0, sticky="w", pady=4, padx=(0, 10))
        var = self.tk.StringVar(value=value)
        entry = self.ttk.Entry(self.frame, textvariable=var, width=46,
                               show=show or "")
        entry.grid(row=self.row, column=1, sticky="we", pady=4)
        self.row += 1
        return var, entry

    def buttons(self, *specs):
        bar = self.ttk.Frame(self.frame)
        bar.grid(row=self.row, column=0, columnspan=2, sticky="e",
                 pady=(14, 0))
        self.row += 1
        made = []
        for text, command in specs:
            b = self.ttk.Button(bar, text=text, command=command)
            b.pack(side="left", padx=(8, 0))
            made.append(b)
        return made

    def later(self, fn, *args):
        """Run `fn` from a worker thread on the window's own thread."""
        self.root.after(0, fn, *args)


def setup_window() -> int:
    saved_url, saved_key = av.settings()
    w = _Window(f"{APP_NAME} Setup")
    w.text(f"Install {APP_NAME}", bold=True)
    w.text(f"For {os.environ.get('USERNAME') or 'this user'} on this PC. It "
           f"watches Downloads, temp and start-up folders, quarantines "
           f"what is clearly malware, and tells your support team. It "
           f"starts now and each time you sign in.")
    url_var, _ = w.field("EasyMikroTik address", saved_url or DEFAULT_URL)
    key_var, key_entry = w.field("Agent key", saved_key)
    status = w.text("", wrap=520)
    result = {"code": 1}

    def say(message, color=None):
        status.configure(text=message, foreground=color or "")

    def done(exe, note):
        for child in w.frame.winfo_children():
            child.destroy()
        w.row = 0
        w.text(f"{APP_NAME} is installed and running", bold=True)
        w.text("It starts each time you sign in to this PC. To remove it: "
               "Settings → Apps → " + APP_NAME + ". The Start menu entry "
               "shows whether it is running.")
        if note:
            w.text(note, color="#b45309")
        outcome = w.text("Send a test alert to check the support team's "
                         "email arrives.")

        def test():
            outcome.configure(text="Sending...")
            threading.Thread(target=lambda: w.later(
                lambda r: outcome.configure(text=r[1]), send_test_alert()),
                daemon=True).start()
        w.buttons(("Send a test alert", test), ("Close", w.root.destroy))
        result["code"] = 0

    def work(url, key):
        verdict, why = check_key(url, key)
        if verdict == "refused":
            return w.later(failed, why)
        try:
            exe = install(url, key)
        except Exception as exc:  # noqa: BLE001 -- said in the window
            return w.later(failed, f"Not installed: {exc}")
        w.later(done, exe, why if verdict == "offline" else "")

    def failed(message):
        say(message, "#b91c1c")
        install_btn.configure(state="normal")

    def go():
        install_btn.configure(state="disabled")
        say("Checking the key and installing...")
        threading.Thread(target=work, args=(url_var.get(), key_var.get()),
                         daemon=True).start()

    install_btn, _ = w.buttons(("Install", go), ("Cancel", w.root.destroy))
    key_entry.focus_set()
    w.root.mainloop()
    return result["code"]


def status_window() -> int:
    url, key = av.settings()
    w = _Window(APP_NAME)
    w.text(APP_NAME, bold=True)
    on = running()
    w.text("Running, and starts each time you sign in." if on else
           "Not running at the moment. It starts at the next sign-in, or "
           "now with Start it.", color=None if on else "#b45309")
    w.text(f"Reports to: {url or '(not set)'}\n"
           f"Agent key: {(key[:10] + '...') if key else '(not set)'}\n"
           f"Quarantine: {av.CONFIG['QUARANTINE_DIR']}\n"
           f"Log: {av.CONFIG['LOG_PATH']}", wrap=560)
    outcome = w.text("")

    def test():
        outcome.configure(text="Sending...")
        threading.Thread(target=lambda: w.later(
            lambda r: outcome.configure(text=r[1]), send_test_alert()),
            daemon=True).start()

    def start():
        start_agent(sys.executable)
        outcome.configure(text="Started.")
    specs = [("Send a test alert", test)]
    if not on and getattr(sys, "frozen", False):
        specs.append(("Start it", start))
    w.buttons(*specs, ("Close", w.root.destroy))
    w.root.mainloop()
    return 0


def uninstall_window(quiet: bool = False) -> int:
    if quiet:
        uninstall()
        return 0
    from tkinter import Tk, messagebox
    _sharp_text()
    root = Tk()
    root.withdraw()
    if not messagebox.askyesno(
            f"Uninstall {APP_NAME}",
            f"Remove {APP_NAME} from this PC? It stops protecting it, and "
            f"your support team is told it was uninstalled."):
        return 1
    try:
        uninstall()
    except Exception as exc:  # noqa: BLE001 -- said in the window
        messagebox.showerror(APP_NAME, f"Not fully removed: {exc}")
        return 1
    messagebox.showinfo(APP_NAME, f"{APP_NAME} is removed. Anything it "
                                  f"quarantined is kept in "
                                  f"{av.CONFIG['QUARANTINE_DIR']}")
    return 0


def quiet_install(url: str, key: str) -> int:
    """--quiet: no window, for setting up many PCs. The exit code says how
    it went: 0 installed, 1 the key or address was refused, 2 failed."""
    verdict, why = check_key(url, key)
    if verdict == "refused":
        av.logging.error(why)
        return 1
    try:
        install(url, key)
    except Exception:  # noqa: BLE001
        return 2
    return 0


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog=SETUP_NAME)
    p.add_argument("--url")
    p.add_argument("--key")
    p.add_argument("--quiet", action="store_true")
    a, _ = p.parse_known_args(argv)
    if a.quiet:
        saved_url, saved_key = av.settings()
        return quiet_install(a.url or saved_url or DEFAULT_URL,
                             a.key or saved_key)
    return setup_window()


if __name__ == "__main__":
    sys.exit(main())
