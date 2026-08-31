"""Inline SVG diagrams for the Guide tab.

Drawn rather than screenshotted, deliberately. A screenshot of this dashboard
goes stale the first time a button moves, and nobody notices until a customer
follows a picture that no longer matches. These show the *mechanism* — which
way a tunnel dials, what happens between Preview and Apply, why a line with
distance 10 wins — and that does not change when the UI is restyled.

They are inline SVG (not files) so they need no static-file route, no extra
request, and no cache busting: the guide page carries its own pictures. Every
colour is a CSS custom property from the shared theme, so they follow light
and dark mode without a second copy.

Written as plain strings, never f-strings: SVG path data is full of braces and
percent signs that an f-string would try to interpret.
"""
from __future__ import annotations

import itertools

# Shared bits. `currentColor` is avoided in favour of explicit tokens so a
# diagram reads the same whether it sits in a box or a warning panel.
_C_TEXT = "var(--text)"
_C_MUTED = "var(--text-muted)"
_C_FAINT = "var(--text-faint)"
_C_LINE = "var(--border)"
_C_ACCENT = "var(--accent)"
_C_OK = "var(--success)"
_C_WARN = "var(--warning)"
_C_BAD = "var(--danger)"
_C_SURF = "var(--surface)"


_uid = itertools.count(1)


def _arrow_defs(prefix: str, colour: str):
    """An arrowhead marker, and the url() that points at it.

    SVG markers resolve against the whole document, not the svg they sit in,
    so a fixed id breaks two ways: two different diagrams on one page silently
    share whichever was defined first (and the second inherits the first's
    colour), and the same diagram used twice emits a duplicate id. The counter
    makes every call unique, so a figure can be reused in as many sections as
    it earns a place in.
    """
    mid = prefix + str(next(_uid))
    defs = ('<defs><marker id="' + mid + '" markerWidth="9" markerHeight="9"'
            ' refX="8" refY="3" orient="auto">'
            '<path d="M0,0 L8,3 L0,6 z" fill="' + colour + '"/>'
            '</marker></defs>')
    return defs, "url(#" + mid + ")"


def _fig(svg: str, caption: str) -> str:
    return ('<figure class="gfig">' + svg
            + '<figcaption>' + caption + '</figcaption></figure>')


def dial_home() -> str:
    """Why a router behind CGNAT is still reachable: it dials out, we never
    dial in. This is the single most common source of "but my router has no
    public IP" confusion, and one picture settles it."""
    _dh_defs, _dh_ar = _arrow_defs("dh", _C_ACCENT)
    svg = (
        '<svg viewBox="0 0 660 250" role="img" '
        'aria-label="Three routers behind NAT each open an outbound WireGuard '
        'tunnel to the easymikrotik hub server, which the dashboard then uses '
        'to reach them">'
        + _dh_defs +
        # hub
        '<rect x="255" y="20" width="150" height="58" rx="10" fill="'
        + _C_SURF + '" stroke="' + _C_ACCENT + '" stroke-width="2"/>'
        '<text x="330" y="44" text-anchor="middle" font-size="14"'
        ' font-weight="700" fill="' + _C_TEXT + '">easymikrotik</text>'
        '<text x="330" y="62" text-anchor="middle" font-size="11" fill="'
        + _C_MUTED + '">hub server (public IP)</text>'
        # routers
        + "".join(
            '<rect x="' + str(x) + '" y="170" width="150" height="56" rx="10"'
            ' fill="' + _C_SURF + '" stroke="' + _C_LINE + '" stroke-width="2"/>'
            '<text x="' + str(x + 75) + '" y="194" text-anchor="middle"'
            ' font-size="13" font-weight="600" fill="' + _C_TEXT + '">'
            + label + '</text>'
            '<text x="' + str(x + 75) + '" y="212" text-anchor="middle"'
            ' font-size="10" fill="' + _C_FAINT + '">' + sub + '</text>'
            for x, label, sub in (
                (15, "Branch router", "behind CGNAT"),
                (255, "Branch router", "dynamic IP"),
                (495, "Branch router", "LTE / no port forward")))
        # arrows: routers -> hub (outbound only)
        + '<path d="M90,168 C90,120 250,110 275,80" fill="none" stroke="'
        + _C_ACCENT + '" stroke-width="2" marker-end="' + _dh_ar + '"/>'
        '<path d="M330,168 L330,84" fill="none" stroke="' + _C_ACCENT
        + '" stroke-width="2" marker-end="' + _dh_ar + '"/>'
        '<path d="M570,168 C570,120 410,110 385,80" fill="none" stroke="'
        + _C_ACCENT + '" stroke-width="2" marker-end="' + _dh_ar + '"/>'
        '<text x="330" y="130" text-anchor="middle" font-size="11"'
        ' font-weight="600" fill="' + _C_ACCENT + '">outbound only &#8594;'
        '</text>'
        '</svg>')
    return _fig(svg,
                "Every router opens the tunnel <b>outwards</b> to the hub and "
                "keeps it open. Nothing ever dials in, so no public IP, no "
                "port forward and no firewall hole is needed at the site — "
                "which is why CGNAT and LTE lines work fine.")


def preview_apply() -> str:
    """The safety story, which is the thing most worth trusting and least
    obvious from the buttons alone."""
    _pa_defs, _pa_ar = _arrow_defs("pa", _C_FAINT)
    svg = (
        '<svg viewBox="0 0 660 210" role="img" '
        'aria-label="Preview shows the exact commands, Apply pushes them after '
        'taking a backup, then the router checks itself and auto-restores the '
        'backup if it can no longer reach the hub">'
        + _pa_defs
        + "".join(
            '<rect x="' + str(x) + '" y="18" width="150" height="62" rx="10"'
            ' fill="' + _C_SURF + '" stroke="' + col + '" stroke-width="2"/>'
            '<text x="' + str(x + 75) + '" y="42" text-anchor="middle"'
            ' font-size="13" font-weight="700" fill="' + col + '">' + t + '</text>'
            '<text x="' + str(x + 75) + '" y="62" text-anchor="middle"'
            ' font-size="10" fill="' + _C_MUTED + '">' + sub + '</text>'
            for x, t, sub, col in (
                (15, "1 &#183; Preview", "see the exact commands", _C_ACCENT),
                (255, "2 &#183; Apply", "backup taken first", _C_ACCENT),
                (495, "3 &#183; Self-check", "router tests itself", _C_WARN)))
        + '<path d="M170,49 L250,49" stroke="' + _C_FAINT + '" stroke-width="2"'
        ' marker-end="' + _pa_ar + '"/>'
        '<path d="M410,49 L490,49" stroke="' + _C_FAINT + '" stroke-width="2"'
        ' marker-end="' + _pa_ar + '"/>'
        # the two outcomes
        '<path d="M540,82 L540,120" stroke="' + _C_OK + '" stroke-width="2"/>'
        '<path d="M615,82 L615,120" stroke="' + _C_BAD + '" stroke-width="2"/>'
        '<rect x="330" y="122" width="210" height="56" rx="9" fill="'
        + _C_SURF + '" stroke="' + _C_OK + '" stroke-width="2"/>'
        '<text x="435" y="144" text-anchor="middle" font-size="12"'
        ' font-weight="700" fill="' + _C_OK + '">Hub still reachable</text>'
        '<text x="435" y="163" text-anchor="middle" font-size="10" fill="'
        + _C_MUTED + '">change is kept</text>'
        '<rect x="556" y="122" width="94" height="56" rx="9" fill="'
        + _C_SURF + '" stroke="' + _C_BAD + '" stroke-width="2"/>'
        '<text x="603" y="144" text-anchor="middle" font-size="12"'
        ' font-weight="700" fill="' + _C_BAD + '">Cut off</text>'
        '<text x="603" y="163" text-anchor="middle" font-size="10" fill="'
        + _C_MUTED + '">auto-restores</text>'
        '</svg>')
    return _fig(svg,
                "Nothing reaches a router without you seeing it first. The "
                "self-check runs <b>on the router</b>, so a change that cuts "
                "it off still gets undone — no site visit.")


def failover_distance() -> str:
    """Distance is the one number people get wrong, and the ordering is
    counter-intuitive: lower wins, so the *smaller* number is the better
    line."""
    def line(y, label, dist, col, dashed, note):
        dash = ' stroke-dasharray="7 5"' if dashed else ""
        return (
            '<rect x="15" y="' + str(y) + '" width="152" height="50" rx="9"'
            ' fill="' + _C_SURF + '" stroke="' + col + '" stroke-width="2"/>'
            '<text x="91" y="' + str(y + 21) + '" text-anchor="middle"'
            ' font-size="12" font-weight="600" fill="' + _C_TEXT + '">'
            + label + '</text>'
            '<text x="91" y="' + str(y + 38) + '" text-anchor="middle"'
            ' font-size="11" font-weight="700" fill="' + col + '">distance '
            + dist + '</text>'
            '<path d="M172,' + str(y + 25) + ' L470,' + str(y + 25) + '"'
            ' stroke="' + col + '" stroke-width="2.5"' + dash + '/>'
            '<text x="321" y="' + str(y + 17) + '" text-anchor="middle"'
            ' font-size="11" font-weight="600" fill="' + col + '">' + note
            + '</text>')

    svg = (
        '<svg viewBox="0 0 660 190" role="img" '
        'aria-label="Two internet lines at distance 10 and 11. RouterOS sends '
        'traffic over distance 10 while it is up, and switches to 11 only when '
        '10 goes down">'
        + line(18, "Fibre", "10", _C_OK, False, "carrying traffic")
        + line(112, "LTE backup", "11", _C_FAINT, True, "idle standby")
        + '<rect x="478" y="52" width="166" height="70" rx="10" fill="'
        + _C_SURF + '" stroke="' + _C_LINE + '" stroke-width="2"/>'
        '<text x="561" y="80" text-anchor="middle" font-size="13"'
        ' font-weight="700" fill="' + _C_TEXT + '">Internet</text>'
        '<text x="561" y="100" text-anchor="middle" font-size="10" fill="'
        + _C_MUTED + '">lowest distance wins</text>'
        '</svg>')
    return _fig(svg,
                "<b>Lower wins.</b> The line with the smallest distance "
                "carries everything; the others wait. If fibre drops, RouterOS "
                "moves to 11 on its own and moves back when fibre returns — "
                "no ping test, no script.")


def tunnel_sites() -> str:
    """Site-to-site is routinely confused with the dial-home tunnel; showing
    both on one picture is the quickest way to separate them."""
    svg = (
        '<svg viewBox="0 0 660 200" role="img" '
        'aria-label="Two branch LANs reach each other across the hub through '
        'the tunnels their routers already hold open">'
        '<rect x="15" y="60" width="160" height="76" rx="10" fill="' + _C_SURF
        + '" stroke="' + _C_LINE + '" stroke-width="2"/>'
        '<text x="95" y="86" text-anchor="middle" font-size="13"'
        ' font-weight="600" fill="' + _C_TEXT + '">Head office</text>'
        '<text x="95" y="106" text-anchor="middle" font-size="11" fill="'
        + _C_MUTED + '">192.168.1.0/24</text>'
        '<text x="95" y="124" text-anchor="middle" font-size="10" fill="'
        + _C_FAINT + '">printers, NAS, PCs</text>'
        '<rect x="485" y="60" width="160" height="76" rx="10" fill="' + _C_SURF
        + '" stroke="' + _C_LINE + '" stroke-width="2"/>'
        '<text x="565" y="86" text-anchor="middle" font-size="13"'
        ' font-weight="600" fill="' + _C_TEXT + '">Branch</text>'
        '<text x="565" y="106" text-anchor="middle" font-size="11" fill="'
        + _C_MUTED + '">192.168.9.0/24</text>'
        '<text x="565" y="124" text-anchor="middle" font-size="10" fill="'
        + _C_FAINT + '">tills, cameras</text>'
        '<rect x="255" y="18" width="150" height="52" rx="10" fill="' + _C_SURF
        + '" stroke="' + _C_ACCENT + '" stroke-width="2"/>'
        '<text x="330" y="40" text-anchor="middle" font-size="12"'
        ' font-weight="700" fill="' + _C_TEXT + '">hub</text>'
        '<text x="330" y="58" text-anchor="middle" font-size="10" fill="'
        + _C_MUTED + '">already connected</text>'
        '<path d="M175,92 C220,92 240,70 258,60" fill="none" stroke="'
        + _C_ACCENT + '" stroke-width="2.5"/>'
        '<path d="M485,92 C440,92 420,70 402,60" fill="none" stroke="'
        + _C_ACCENT + '" stroke-width="2.5"/>'
        '<path d="M175,118 L485,118" stroke="' + _C_OK + '" stroke-width="2.5"'
        ' stroke-dasharray="8 5"/>'
        '<text x="330" y="140" text-anchor="middle" font-size="11"'
        ' font-weight="600" fill="' + _C_OK + '">'
        'each side reaches the other&#39;s LAN</text>'
        '</svg>')
    return _fig(svg,
                "Site-to-site rides the tunnels the routers already hold open. "
                "You are not building a new VPN — you are telling two existing "
                "ones which LANs to let through.")
