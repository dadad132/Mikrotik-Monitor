"""No page script is broken by a Python escape.

The Queues tab's script builder joined its lines with '\\n' -- written in a
Python string as '\n', which Python turns into a real line break inside the
JavaScript string, and a JavaScript string cannot hold one. The browser
refused the whole script, so the builder never filled in and its buttons did
nothing, with nothing on the page to say why. Found by loading every tab in
a real browser.

This checks every script this code writes into a page for that mistake: a
quote, a bare line break, and the same quote again.

Run:  ./.venv/Scripts/python.exe tests/inline_js_test.py
"""
from __future__ import annotations

import importlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


# A one-character JS string that is only a line break: '\n' as Python wrote
# it, not as JavaScript needs it.
BROKEN = re.compile(r"(['\"])\r?\n\1")
SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)

modules = ["mikromon.web", "mikromon.web_auth", "mikromon.web_shared",
           "mikromon.web_landing", "mikromon.web_ai", "mikromon.web_edr",
           "mikromon.web_terms", "mikromon.web_vpnusers"]
found, scripts = [], 0
for name in modules:
    mod = importlib.import_module(name)
    for attr, value in vars(mod).items():
        if not isinstance(value, str) or "<script" not in value.lower():
            continue
        for body in SCRIPT.findall(value):
            scripts += 1
            for m in BROKEN.finditer(body):
                line = body[:m.start()].count("\n") + 1
                found.append(f"{name}.{attr}, line {line} of its script")

print(f"Checked {scripts} scripts")
check("no script has a bare line break inside a one-character string",
      not found)
for f in found:
    print("   ", f)

from mikromon import web  # noqa: E402

check("the Queues tab's builder joins its lines with a JavaScript \\n",
      "L.join('\\n')" in web._QUEUE_BUILDER_JS)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL INLINE JS TESTS PASSED")
