"""Build EasyMikroTik-Antivirus-Setup.exe. Run on Windows, from anywhere:

    py -3.12 agent\\build_windows.py

1. A build environment in agent/build/venv: PyInstaller, the agent's
   libraries, yara-python (the pattern rules) and pywin32 (the Start menu
   entry). Made once, reused after.
2. The agent program, windows_app.py, as a folder with Python inside it.
   A folder, not one file: a one-file program unpacks itself into %TEMP%
   at every start, and leaves a copy there each time Windows shuts down
   with it running.
3. That folder zipped into the setup, windows_setup.py, built as one file.
4. The setup copied to mikromon/downloads/, which the dashboard's
   Antivirus page offers for download.

Not code-signed: Windows SmartScreen asks before the first run of it on
each PC (More info -> Run anyway) until it is.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
VENV = os.path.join(BUILD, "venv")
PY = os.path.join(VENV, "Scripts", "python.exe")
OUT = os.path.join(ROOT, "mikromon", "downloads")
NEEDS = ["pyinstaller", "psutil", "requests", "watchdog", "yara-python",
         "pywin32"]


def _constants(filename) -> dict:
    """The plain string settings at the top of an agent file, read without
    importing it: that would need the agent's libraries in this Python."""
    with open(os.path.join(HERE, filename), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    out = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out[node.targets[0].id] = node.value.value
    return out


_AGENT = _constants("antivirus.py")
_SETUP = _constants("windows_setup.py")
VERSION = _AGENT["AGENT_VERSION"]
APP_NAME = _AGENT["AUTOSTART_NAME"]
EXE_NAME, SETUP_NAME = _SETUP["EXE_NAME"], _SETUP["SETUP_NAME"]
PAYLOAD, PUBLISHER = _SETUP["PAYLOAD"], _SETUP["PUBLISHER"]


def run(*args):
    print(">", " ".join(args), flush=True)
    subprocess.run(args, check=True)


def version_file(name: str, description: str) -> str:
    """The Details tab of the file's Properties: who made it, what it is."""
    nums = [int(x) for x in (VERSION.split(".") + ["0"] * 4)[:4]]
    path = os.path.join(BUILD, f"{name}-version.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tuple(nums)}, prodvers={tuple(nums)},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', '{PUBLISHER}'),
      StringStruct('FileDescription', '{description}'),
      StringStruct('FileVersion', '{VERSION}'),
      StringStruct('InternalName', '{name}'),
      StringStruct('OriginalFilename', '{name}.exe'),
      StringStruct('ProductName', '{APP_NAME}'),
      StringStruct('ProductVersion', '{VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""")
    return path


def pyinstaller(script, name, *extra):
    run(PY, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed",
        "--name", name, "--distpath", os.path.join(BUILD, "dist"),
        "--workpath", os.path.join(BUILD, "work"),
        "--specpath", BUILD, "--paths", HERE,
        *extra, os.path.join(HERE, script))


def main() -> int:
    if os.name != "nt":
        print("Build this on Windows: the setup is a Windows program.")
        return 1
    if not os.path.isfile(PY):
        run(sys.executable, "-m", "venv", VENV)
    run(PY, "-m", "pip", "install", "--quiet", "--upgrade", *NEEDS)

    agent_name = EXE_NAME[:-4]
    pyinstaller("windows_app.py", agent_name, "--onedir",
                "--hidden-import", "win32com.client",
                "--version-file", version_file(
                    agent_name, f"{APP_NAME} agent"))
    folder = os.path.join(BUILD, "dist", agent_name)
    payload = os.path.join(BUILD, PAYLOAD)
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _, files in os.walk(folder):
            for f in files:
                full = os.path.join(base, f)
                z.write(full, os.path.relpath(full, folder))

    setup_name = SETUP_NAME[:-4]
    pyinstaller("windows_setup.py", setup_name, "--onefile",
                "--hidden-import", "win32com.client",
                "--add-data", f"{payload}{os.pathsep}.",
                "--version-file", version_file(
                    setup_name, f"{APP_NAME} Setup"))
    os.makedirs(OUT, exist_ok=True)
    built = os.path.join(BUILD, "dist", SETUP_NAME)
    shutil.copy2(built, os.path.join(OUT, SETUP_NAME))
    size = os.path.getsize(built) / 1e6
    print(f"\nBuilt {SETUP_NAME} ({size:.1f} MB), version "
          f"{VERSION}, copied to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
