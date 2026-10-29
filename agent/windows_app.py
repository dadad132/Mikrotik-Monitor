"""EasyMikroTik Antivirus on Windows: the program the setup installs.

Built by build_windows.py into EasyMikroTikAntivirus.exe, with Python
inside it. With no options it is the agent (antivirus.main), which is how
sign-in starts it. The Start menu entry passes --status, and Settings ->
Apps passes --uninstall. --test sends a test alert, as the script's does.
"""
from __future__ import annotations

import sys

import antivirus as av
import windows_setup as ws


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--uninstall" in argv:
        return ws.uninstall_window(quiet="--quiet" in argv)
    if "--status" in argv:
        return ws.status_window()
    if "--test" in argv:
        sent, _ = ws.send_test_alert()
        return 0 if sent else 1
    av.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
