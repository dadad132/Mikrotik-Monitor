"""The EasyMikroTik mark, in one place.

Every page drew its own logo before this: a diamond character and the brand
name, repeated in four templates, and no favicon at all -- which is why every
browser tab showed a blank page icon.

The mark is drawn as SVG rather than shipped as an image because it has to
work at 16px in a tab and at 40px in a sidebar, on a cream background and a
dark one, without shipping four PNGs and without a binary in the repository.

It can be replaced without touching any code: drop `logo.svg` (or `logo.png`)
into the application directory and it is served instead, everywhere, on the
next request. `_custom_logo` is what looks.
"""
from __future__ import annotations

import os

BRAND = "EasyMikroTik"

# Brand colours, sampled from the artwork. The bottom layer is a warm grey
# fill with a navy outline, which is what lets the mark sit on both the light
# and the dark theme without a second version of it.
INK = "#16324f"          # navy — outline of the base layer, and the wordmark
SLAB = "#a8a29e"         # warm grey — the base layer's face
MID_LINE = "#3f6f9f"     # steel blue — the middle layer
MID_FACE = "#93b4d6"
TEAL = "#2bbfc0"         # the grid layer
CABLE = "#1f8fb0"        # the line draped over the stack

# Three stacked layers seen in isometric, a 3x3 grid on the top one, and a
# cable running over them and away to the right: what the product does, which
# is sit above a stack of sites and reach out to them.
_MARK = (
    '<path d="M64 78 L104 98 L64 118 L24 98 Z" fill="{slab}" stroke="{ink}" '
    'stroke-width="7" stroke-linejoin="round"/>'
    '<path d="M64 54 L104 74 L64 94 L24 74 Z" fill="{mid_face}" '
    'fill-opacity=".72" stroke="{mid_line}" stroke-width="7" '
    'stroke-linejoin="round"/>'
    '<g stroke="{teal}" stroke-width="6" stroke-linejoin="round" '
    'stroke-linecap="round" fill="none">'
    '<path d="M64 30 L96 46 L64 62 L32 46 Z"/>'
    '<path d="M42.7 40.7 L74.7 56.7"/><path d="M53.3 35.3 L85.3 51.3"/>'
    '<path d="M74.7 35.3 L42.7 51.3"/><path d="M85.3 40.7 L53.3 56.7"/>'
    '</g>'
    '<path d="M26 50 C 28 24, 52 15, 71 20 C 87 25, 92 34, 105 36 L 122 36" '
    'fill="none" stroke="{cable}" stroke-width="7" stroke-linecap="round" '
    'stroke-linejoin="round"/>'
).format(ink=INK, slab=SLAB, mid_line=MID_LINE, mid_face=MID_FACE,
         teal=TEAL, cable=CABLE)


def mark_svg(size: int = 128, title: str = "") -> str:
    """The mark on its own, no wordmark. Used in the sidebar and the tab."""
    t = f"<title>{title}</title>" if title else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" '
            f'width="{size}" height="{size}" role="img" '
            f'aria-label="{BRAND}">{t}{_MARK}</svg>')


def _custom_logo(app_dir: str = "") -> str:
    """A replacement logo dropped in by hand, or "".

    Checked on every request rather than cached: replacing a logo is a thing
    somebody does once, in a hurry, and then expects to see. Restarting the
    service to find out whether the file was in the right place is exactly
    the sort of small unnecessary loop this codebase keeps tripping over.
    """
    root = app_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("logo.svg", "logo.png"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            return p
    return ""


def logo_img(size: int = 26, app_dir: str = "", cls: str = "brand-mark") -> str:
    """The mark as page markup.

    A custom file is referenced by URL so the browser caches it; the built-in
    mark is inlined so it costs no request and inherits nothing it should not.
    """
    if _custom_logo(app_dir):
        return (f'<img class="{cls}" src="/logo" width="{size}" '
                f'height="{size}" alt="{BRAND}">')
    return mark_svg(size).replace(
        "<svg ", f'<svg class="{cls}" ', 1)


def favicon_tags() -> str:
    """What goes in <head> so the browser tab is not blank.

    One SVG covers every modern browser at every size. The .ico line is for
    the browsers that ask for /favicon.ico regardless of what the page says;
    that route answers with the same drawing.
    """
    return ('<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
            '<link rel="alternate icon" href="/favicon.ico">'
            '<link rel="apple-touch-icon" href="/logo">')


def favicon_bytes() -> tuple:
    """(content_type, bytes) for the favicon route."""
    return ("image/svg+xml", mark_svg(64, BRAND).encode("utf-8"))


def logo_bytes(app_dir: str = "") -> tuple:
    """(content_type, bytes) for /logo — the custom file if there is one."""
    custom = _custom_logo(app_dir)
    if custom:
        ctype = ("image/svg+xml" if custom.endswith(".svg") else "image/png")
        try:
            with open(custom, "rb") as f:
                return (ctype, f.read())
        except OSError:
            pass
    return ("image/svg+xml", mark_svg(256, BRAND).encode("utf-8"))


# The mark plus the wordmark, for the landing page and anywhere the name is
# not already written next to it in text.
def lockup_svg(height: int = 40) -> str:
    w = int(height * 4.6)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 590 128" '
            f'width="{w}" height="{height}" role="img" aria-label="{BRAND}">'
            f'{_MARK}'
            f'<text x="150" y="82" font-family="Segoe UI,Inter,system-ui,'
            f'sans-serif" font-size="58" fill="{INK}">'
            f'<tspan font-weight="400">Easy</tspan>'
            f'<tspan font-weight="700">MikroTik</tspan></text></svg>')
