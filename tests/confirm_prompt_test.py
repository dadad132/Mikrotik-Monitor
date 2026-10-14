"""Every "are you sure?" prompt actually asks.

A browser decodes an onclick/onsubmit attribute before running it as
script. A message put inside confirm('...') with an apostrophe in it --
"Joe's Shop", an o'brien@ address, or simply "every company's current
data" -- ends the quoted string early; the handler then does not parse,
never runs, and the button does its job WITHOUT asking. The server-backup
Restore button on Platform admin did exactly that.

So every prompt goes through web_shared.confirm_attr(), and this test holds
it there: it reads the source of every module for a confirm( opened with a
quote, and checks the prompts that carry names a person typed.

Run:  ./.venv/Scripts/python.exe tests/confirm_prompt_test.py
"""
from __future__ import annotations

import ast
import html
import json
import os
import pkgutil
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon  # noqa: E402
from mikromon import web, web_auth  # noqa: E402
from mikromon.web_shared import confirm_attr  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


_HANDLER = re.compile(r'on(?:click|submit)="return confirm\((.*?)\)"')


def _message(raw: str):
    """One prompt's argument as the browser runs it -- the attribute decoded
    -- read as string literals joined by + to a form's own values
    (this.email.value). None if it would not parse."""
    parts = []
    for part in html.unescape(raw).split(" + "):
        part = part.strip()
        if re.fullmatch(r"this(\.\w+)+", part):
            parts.append("{" + part + "}")
            continue
        try:
            value = json.loads(part)
        except ValueError:
            return None
        if not isinstance(value, str):
            return None
        parts.append(value)
    return "".join(parts)


def asked(page: str) -> list:
    """The message of every confirm prompt on a page; None for one that
    would not parse, and so would never ask."""
    return [_message(raw) for raw in _HANDLER.findall(page)]


print("the helper:")
for text in ("Remove Joe's Shop?", 'Say "yes"', "o'brien@example.com",
             "</script><b>&amp;", "line one\nline two", "Reboot — ~1–2 min"):
    attr = confirm_attr(text)
    js = html.unescape(attr)
    check(f"{text!r} survives the attribute and reads back the same",
          '"' not in attr and "'" not in attr
          and js.startswith("return confirm(") and js.endswith(")")
          and json.loads(js[len("return confirm("):-1]) == text)

print("no prompt is written the old way:")
# Read from the parsed source, so only the text a prompt is built from is
# looked at: the quote that closes a Python string after "confirm(" is not
# one, and an apostrophe hidden as \' or &#39; still is.
_OLD = re.compile(r"confirm\(\s*(?:'|&#39;|&#x27;)")
bad = []
for info in pkgutil.walk_packages(mikromon.__path__, "mikromon."):
    mod = __import__(info.name, fromlist=["_"])
    path = getattr(mod, "__file__", "") or ""
    if not path.endswith(".py"):
        continue
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            text = "".join(v.value if isinstance(v, ast.Constant) else "{}"
                           for v in node.values)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        else:
            continue
        if _OLD.search(text):
            bad.append(f"{os.path.basename(path)}:{node.lineno}")
check("every confirm() takes its message from confirm_attr (or a data- "
      "attribute)" + (f" -- not: {', '.join(sorted(set(bad)))}" if bad else ""),
      not bad)

print("the prompts that went through without asking:")
page = web_auth._render_superadmin(
    {"role": "owner", "is_superadmin": True, "email": "boss@x.test"}, [],
    [{"name": "server-20261014.tar.gz", "size": 1000, "mtime": 0}], csrf="c")
msgs = asked(page)
check("Platform admin's server-backup Restore button asks, apostrophe and all",
      any(m and m.startswith("Restore server-20261014.tar.gz?")
          and "every company's current data" in m for m in msgs))
check("...and so does restoring from an uploaded file",
      any(m and m.startswith("Restore from this file?") for m in msgs))
check("...and resetting someone's two-factor names the account typed in",
      "Reset two-factor sign-in for {this.email.value}?" in msgs)
check("no prompt on that page fails to parse", msgs and None not in msgs)

row = web._mini_form("/devices/delete", "c", "Joe's Shop", "Delete", "btn red",
                     "Joe's Shop")
check("deleting a device named Joe's Shop asks first",
      asked(row) == ["Delete Joe's Shop?"])

hostile = 'x" onmouseover="alert(1)'
page = web._render_device_backups(
    "Joe's Shop", {"role": "owner"}, {}, "c",
    backups=[{"name": f"{hostile}.backup", "size": 10, "time": ""}])
check("a router file name with a quote in it stays inside its prompt",
      any(m and m.startswith(f"Restore {hostile}.backup?") for m in asked(page))
      and 'onmouseover="alert(1)' not in page)
check("rebooting Joe's Shop asks first",
      any(m and m.startswith("Reboot Joe's Shop now?") for m in asked(page)))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL CONFIRM-PROMPT TESTS PASSED")
