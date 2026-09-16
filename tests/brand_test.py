"""The logo, on every page and in every tab.

There were four separate head templates and none of them linked an icon, so
every browser tab showed a blank page. And the "logo" was a diamond character
copied into four places, which meant changing it meant finding all four.

So what is tested here is mostly coverage: that no page was missed, and that
adding a fifth page cannot quietly go without one.

Run:  python tests/brand_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import brand, web_auth, web_landing, web_shared

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


USER = {"role": "admin", "org_name": "Acme", "email": "a@b.c", "name": "A"}

print("\nEvery page that renders a <head> links an icon")

PAGES = {
    "the landing page": web_landing.render_landing(),
    "the login page": web_auth._auth_page("Sign in", "<p>x</p>"),
    "every authenticated page": web_shared._page("Devices", "<p>x</p>"),
}
for name, html in PAGES.items():
    check(f"{name} has a favicon", 'rel="icon"' in html)
    check(f"...and points at an SVG, which covers every size from one file",
          "/favicon.svg" in html)

check("the .ico fallback is there too, for browsers that ask for it whatever "
      "the page says",
      all("/favicon.ico" in h for h in PAGES.values()))

print("\nThe mark itself appears where a person looks for it")

check("the landing page nav and footer both carry it",
      web_landing.render_landing().count("brand-mark") >= 2)
check("the login page carries it above the form",
      "brand-mark" in web_auth._auth_page("Sign in", "<p>x</p>"))
check("the sidebar on every authenticated page carries it",
      "brand-mark" in web_shared._header(USER, "/dashboard"))
check("the sidebar of a signed-out shell still carries it, rather than "
      "collapsing to nothing", "brand-mark" in web_shared._header(None, "/"))

print("\nNo page is still drawing the old placeholder")

for name, html in PAGES.items():
    # The landing page uses the same glyph as a FEATURE bullet, which is not
    # a logo; what must be gone is the one sitting next to the brand name.
    check(f"{name} no longer puts a diamond next to the brand name",
          "&#9670;" + "easymikrotik" not in html.replace(" ", "")
          and '<span class="dot">&#9670;</span>' not in html)

print("\nWhat the routes serve")

ctype, blob = brand.favicon_bytes()
check("the favicon is an SVG", ctype == "image/svg+xml" and blob.startswith(b"<svg"))
check("...small enough to be inlined without a second thought",
      len(blob) < 4096)
check("...and carries the brand name for a screen reader",
      b"EasyMikroTik" in blob)

ctype, blob = brand.logo_bytes(tempfile.mkdtemp())
check("with no custom file, /logo serves the built-in mark",
      ctype == "image/svg+xml" and blob.startswith(b"<svg"))

print("\nReplacing the logo without touching any code")

d = tempfile.mkdtemp()
open(os.path.join(d, "logo.svg"), "w").write('<svg id="theirs"></svg>')
ctype, blob = brand.logo_bytes(d)
check("a logo.svg dropped into the app directory is served instead -- the "
      "whole point, because a logo is replaced by somebody in a hurry who "
      "should not need a code change to do it",
      b'id="theirs"' in blob)

check("...and the page then REFERENCES it rather than inlining the built-in "
      "one, so the browser caches it",
      '<img' in brand.logo_img(26, d) and "/logo" in brand.logo_img(26, d))

open(os.path.join(d, "logo.svg"), "w").close()
os.remove(os.path.join(d, "logo.svg"))
open(os.path.join(d, "logo.png"), "wb").write(b"\x89PNG\r\n\x1a\n")
ctype, blob = brand.logo_bytes(d)
check("a PNG works too, served as a PNG rather than mislabelled",
      ctype == "image/png" and blob.startswith(b"\x89PNG"))

check("the built-in mark is inlined when there is no custom file, costing "
      "no extra request", "<svg" in brand.logo_img(26, tempfile.mkdtemp()))

print("\nThe mark scales, because a tab is 16px and a sidebar is not")

for size in (16, 26, 64, 256):
    svg = brand.mark_svg(size)
    check(f"at {size}px it is one drawing scaled, not a separate asset",
          f'width="{size}"' in svg and 'viewBox="0 0 128 128"' in svg)

check("the wordmark version exists for where the name is not already written "
      "in text beside it", "EasyMikroTik" in brand.lockup_svg(40)
      or "MikroTik" in brand.lockup_svg(40))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BRAND TESTS PASSED")
