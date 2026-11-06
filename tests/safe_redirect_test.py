"""Redirects stay on this site (web.safe_location).

Browsers drop tabs and line breaks from a Location header and read a
backslash as a slash, so each of those is a way to send someone from a link
on this site to another one. Only Yoco's payment page, whose address its own
API returned, may leave the site, and only over https.

Run: python tests/safe_redirect_test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mikromon.web import safe_location as f  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


B, TAB, DEL = chr(92), chr(9), chr(127)
for label, loc in (("another site", "https://evil.example/"),
                   ("a protocol-relative address", "//evil.example"),
                   ("a backslash", "/" + B + "evil.example"),
                   ("a tab the browser would drop", "/" + TAB + "/evil.example"),
                   ("a line break starting a header", "/ok\r\nSet-Cookie: s=1"),
                   ("a space", "/ /evil.example"),
                   ("a control character", "/a" + DEL),
                   ("a script", "javascript:alert(1)"),
                   ("no slash", "evil.example")):
    check(f"{label} goes to the home page instead", f(loc) == "/")
for loc in ("/billing?ok=Saved%20it.", "/device?name=a%20b", "/superadmin#offsite", "/"):
    check(f"a page of this site is kept: {loc}", f(loc) == loc)
check("Yoco's https payment page is allowed when asked for",
      f("https://c.yoco.com/checkout/x", external=True) == "https://c.yoco.com/checkout/x")
check("...but not over plain http", f("http://c.yoco.com/x", external=True) == "/")
check("...nor a script", f("javascript:alert(1)", external=True) == "/")
check("...nor with a line break in it", f("https://c.yoco.com/x\r\nA: b", external=True) == "/")
check("nothing at all is the home page", f("") == "/" and f(None) == "/")
print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL SAFE REDIRECT TESTS PASSED")
sys.exit(1 if FAILS else 0)
