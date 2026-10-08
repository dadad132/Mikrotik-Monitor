"""No function reads a module-level name its module does not define.

Removing code leaves callers behind, and Python only notices when the line
runs. "Change now" on the Billing page called a function that went out with
the Zoho invoicing code, and failed for weeks as a bare 502; the WireGuard
report's DevicesStore was never imported, so every peer read as orphaned.
This reads every module's symbol table and fails on any such name.

Run:  ./.venv/Scripts/python.exe tests/undefined_names_test.py
"""
from __future__ import annotations

import builtins
import importlib
import os
import pkgutil
import symtable
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon  # noqa: E402

problems = []
for info in pkgutil.walk_packages(mikromon.__path__, "mikromon."):
    mod = importlib.import_module(info.name)
    path = getattr(mod, "__file__", "") or ""
    if not path.endswith(".py"):
        continue
    with open(path, encoding="utf-8") as fh:
        table = symtable.symtable(fh.read(), path, "exec")
    known = set(vars(mod)) | set(dir(builtins))

    def walk(t, where=""):
        for child in t.get_children():
            here = f"{where}.{child.get_name()}" if where else child.get_name()
            for s in child.get_symbols():
                name = s.get_name()
                if (s.is_referenced() and s.is_global()
                        and not s.is_assigned() and name not in known
                        and not name.startswith("__")):
                    problems.append(f"{info.name}: {here}() uses '{name}'")
            walk(child, here)

    walk(table)

for p in problems:
    print("  [FAIL]", p)
if problems:
    print(f"\nFAILED: {len(problems)} undefined name(s)")
    sys.exit(1)
print("  [ok  ] every module-level name a function uses is defined")
print("\nALL UNDEFINED-NAME TESTS PASSED")
