"""VPN remote users on the page: the box on a router's VPN tab, and the
page that hands over a device's WireGuard settings once.

Rendering only; push/vpnusers.py decides what goes to the router.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote

from .web_shared import _BRAND, esc

DEVICE_TYPES = [("windows", "Windows laptop"), ("mac", "Mac"),
                ("iphone", "iPhone / iPad"), ("android", "Android phone"),
                ("linux", "Linux")]
_DESKTOP = ("windows", "mac", "linux")


def _where_public_key(kind: str) -> str:
    if kind in ("iphone", "android"):
        return ("In the WireGuard app tap <b>+</b>, then <b>Create from "
                "scratch</b>, then <b>Generate keypair</b>. Copy the "
                "<b>Public key</b>. Leave that screen open.")
    return ("In WireGuard choose <b>Add Tunnel → Add empty tunnel…</b>. The "
            "window shows a <b>Public key</b>: copy it. Leave the window open.")


def _reach_line(reach: dict, port: int) -> str:
    if reach.get("ok"):
        return (f'<p style="margin:0 0 12px"><span style="color:var(--success);'
                f'font-weight:700">&#10003;</span> Remote devices will connect '
                f'to <code>{esc(reach["endpoint"])}:{port}</code>. '
                f'<span class="muted">{esc(reach.get("why", ""))}</span></p>')
    return (f'<div class="fwarn" style="margin:0 0 12px;font-size:13px">'
            f'<b>A remote device may not be able to reach this router.</b> '
            f'{esc(reach.get("why", ""))}</div>')


def users_box(name: str, csrf: str, cur: dict, reach: dict, port: int,
              can_manage: bool = True) -> str:
    """The "Remote users" box on the VPN tab."""
    if cur.get("unsupported"):
        return (f'<div class="box"><h2>Remote users</h2><p class="muted">'
                f'Remote users need WireGuard, which arrived in RouterOS 7.1; '
                f'this router runs {esc(cur.get("version", "?"))}.</p></div>')
    peers = cur.get("peers") or []
    rows = ""
    for p in peers:
        hs = str(p.get("last-handshake") or "")
        seen = (f"{hs} ago" if hs and hs not in ("never", "0s") else "never")
        frm = str(p.get("current-endpoint-address") or "")
        rm = ""
        if can_manage:
            rm = (f'<form method="POST" action="/device/push" class="inline" '
                  f'onsubmit="return confirm(\'Remove {esc(p["label"])}? It '
                  f'will stop connecting straight away.\')">'
                  f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                  f'<input type="hidden" name="device" value="{esc(name)}">'
                  f'<input type="hidden" name="feature" value="vpnusers">'
                  f'<input type="hidden" name="view" value="tunnel">'
                  f'<input type="hidden" name="vpnuser_action" value="remove">'
                  f'<input type="hidden" name="peer_id" value="{esc(p.get(".id", ""))}">'
                  f'<button class="btn red" type="submit" '
                  f'style="padding:4px 10px;font-size:12px">Remove</button></form>')
        rows += (f'<tr><td><b>{esc(p["label"])}</b></td>'
                 f'<td><code>{esc(str(p.get("allowed-address", "")).split("/")[0])}'
                 f'</code></td><td>{esc(seen)}'
                 + (f' <span class="muted">from {esc(frm)}</span>' if frm else "")
                 + f'</td><td>{rm}</td></tr>')
    table = (f'<table style="margin:0 0 14px"><tr><th>Device</th><th>Address'
             f'</th><th>Last connected</th><th></th></tr>{rows}</table>'
             if peers else
             '<p class="muted" style="margin:0 0 14px">No remote users yet.</p>')
    if not can_manage:
        return (f'<div class="box" id="vpnusers"><h2>Remote users</h2>'
                f'{_reach_line(reach, port)}{table}</div>')
    nets = "".join(
        f'<label class="chk"><input type="checkbox" name="vu_net" '
        f'value="{esc(n)}" checked> {esc(n)}</label>'
        for n in (cur.get("lan_subnets") or []))
    types = "".join(f'<option value="{k}">{esc(v)}</option>'
                    for k, v in DEVICE_TYPES)
    ddns = ("" if (cur.get("cloud") or {}).get("ddns") else
            '<label class="chk" style="display:flex;margin:6px 0 0">'
            '<input type="checkbox" name="vu_ddns" value="1" checked> Use '
            'MikroTik\'s free DDNS name, so devices still find this router if '
            'the ISP changes its address</label>')
    dns = ('<label class="chk" style="display:flex;margin:6px 0 0">'
           '<input type="checkbox" name="vu_dns" value="1" checked> Use the '
           'site\'s DNS, so local names resolve</label>'
           if cur.get("router_dns") else "")
    off = ""
    if cur.get("iface") is not None:
        off = (f'<form method="POST" action="/device/push" style="margin-top:12px" '
               f'onsubmit="return confirm(\'Switch remote users off on this '
               f'router? Every remote device stops connecting.\')">'
               f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
               f'<input type="hidden" name="device" value="{esc(name)}">'
               f'<input type="hidden" name="feature" value="vpnusers">'
               f'<input type="hidden" name="view" value="tunnel">'
               f'<input type="hidden" name="vpnuser_action" value="off">'
               f'<button class="btn ghost" type="submit">Switch remote users '
               f'off on this router</button></form>')
    form = (
        f'<form method="POST" action="/device/push" id="vuform">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="hidden" name="device" value="{esc(name)}">'
        f'<input type="hidden" name="feature" value="vpnusers">'
        f'<input type="hidden" name="view" value="tunnel">'
        f'<input type="hidden" name="vpnuser_action" value="add">'
        f'<h3 style="margin:0 0 8px">Add a remote user</h3>'
        f'<div class="fields">'
        f'<label class="f">Device name<input name="vu_label" maxlength="40" '
        f'placeholder="e.g. Thandi\'s laptop" required style="width:100%">'
        f'</label>'
        f'<label class="f">What it is<select name="vu_type" id="vutype" '
        f'style="width:100%" onchange="mmVuHelp()">{types}</select></label>'
        f'</div>'
        f'<div style="margin:12px 0 0">'
        f'<label class="chk" style="display:flex"><input type="radio" '
        f'name="vu_keys" value="own" checked onchange="mmVuKeys()"> '
        f'<span><b>Use the device\'s own key</b> (recommended: its private key '
        f'never leaves it)</span></label>'
        f'<div id="vuown" style="margin:6px 0 0 26px">'
        f'<p class="muted" id="vuhelp" style="margin:0 0 6px;font-size:12.5px">'
        f'{_where_public_key("windows")}</p>'
        f'<input name="vu_pubkey" id="vupub" maxlength="60" '
        f'placeholder="Public key, 44 characters ending in =" '
        f'style="width:100%;font-family:Consolas,Menlo,monospace"></div>'
        f'<label class="chk" style="display:flex;margin-top:8px"><input '
        f'type="radio" name="vu_keys" value="make" onchange="mmVuKeys()"> '
        f'<span><b>Make the keys for me</b> (you get a file to import; it '
        f'holds the private key, so treat it like a password)</span></label>'
        f'</div>'
        f'<p style="margin:14px 0 4px;font-size:13.5px"><b>What it may '
        f'reach</b></p>'
        f'<div class="chkrow">{nets or "<span class=muted>No site networks found.</span>"}</div>'
        f'<label class="chk" style="display:flex;margin:6px 0 0">'
        f'<input type="checkbox" name="vu_full" value="1"> Send ALL its internet '
        f'traffic through this site (it then browses from the site\'s internet '
        f'line)</label>'
        f'{dns}{ddns}'
        f'<label style="display:block;margin:12px 0 0">Connect to '
        f'<span class="muted" style="font-weight:400">(optional: a hostname '
        f'or address of your own; blank uses the one above)</span><br>'
        f'<input name="vu_endpoint" maxlength="120" '
        f'placeholder="{esc(reach.get("endpoint") or "vpn.example.com")}" '
        f'style="width:100%;max-width:420px"></label>'
        f'<div style="margin-top:14px"><button class="btn" type="submit">'
        f'Preview</button></div></form>')
    js = """<script>
function mmVuKeys(){var own=document.querySelector('input[name=vu_keys][value=own]');
 var on=own&&own.checked; var b=document.getElementById('vuown');
 if(b)b.style.display=on?'':'none'; var k=document.getElementById('vupub');
 if(k)k.required=on;}
var MM_VU_HELP=%s;
function mmVuHelp(){var t=document.getElementById('vutype');
 var h=document.getElementById('vuhelp'); if(t&&h)h.innerHTML=MM_VU_HELP[t.value]||'';}
mmVuKeys();
</script>""" % (json.dumps({k: _where_public_key(k)
                             for k, _ in DEVICE_TYPES})
                 .replace("</", "<\\/"))
    return (f'<div class="box" id="vpnusers"><h2>Remote users</h2>'
            f'<p class="muted" style="margin:0 0 10px">Let a laptop or phone '
            f'connect straight to this site over WireGuard and reach its '
            f'network, from home, a hotel, anywhere. Each device gets its own '
            f'key and address, and can be removed on its own.</p>'
            f'{_reach_line(reach, port)}{table}{form}{off}</div>{js}')


def _steps(kind: str, made_keys: bool) -> str:
    phone = kind in ("iphone", "android")
    store = ("the App Store" if kind == "iphone" else "Google Play"
             if kind == "android" else "wireguard.com/install")
    if made_keys:
        if phone:
            how = ("Send the file to the phone (email it to yourself, say), "
                   "then in WireGuard tap <b>+</b> → <b>Create from file or "
                   "archive</b> and pick it.")
        else:
            how = ("In WireGuard choose <b>Import tunnel(s) from file</b> and "
                   "pick the downloaded file.")
        items = [f"Install WireGuard from {store} if it is not there yet.", how,
                 "Tap or click <b>Activate</b>. That is it."]
    else:
        where = ("the screen you created it on" if phone else
                 "the window you created it in")
        items = [f"Go back to {where} (the one showing the Public key you "
                 f"pasted here).",
                 "Below its <b>PrivateKey = …</b> line, paste the lines shown "
                 "here. Keep the PrivateKey line the app made: it pairs with "
                 "the public key you gave.",
                 "Give it a name, save it, and <b>Activate</b>."]
    return "<ol>" + "".join(f"<li>{i}</li>" for i in items) + "</ol>"


def config_page_inner(name: str, label: str, conf: str, *, made_keys: bool,
                      kind: str, reach: dict, safe_note: bool) -> str:
    """The body of the page shown once after a remote user is added."""
    q = quote(name)
    warn = ("" if reach.get("ok") else
            f'<div class="fwarn" style="margin:0 0 12px"><b>Before you test:'
            f'</b> {esc(reach.get("why", ""))}</div>')
    if made_keys:
        b64 = base64.b64encode(conf.encode("utf-8")).decode("ascii")
        fname = "".join(c if c.isalnum() else "-" for c in label)[:30] or "vpn"
        head = (f'<p><b>Save this file now.</b> It holds the device\'s private '
                f'key, which {esc(_BRAND)} does not keep: this is the only time '
                f'it is shown. If it is lost, remove this user and add it '
                f'again.</p>'
                f'<p><a class="btn" download="{esc(fname)}.conf" '
                f'href="data:text/plain;charset=utf-8;base64,{b64}">Download '
                f'{esc(fname)}.conf</a></p>')
        shown = conf
    else:
        head = ('<p>The device made its own keys, so nothing secret is on '
                'this page. Add these lines to the tunnel you started in the '
                'WireGuard app:</p>')
        shown = "\n".join(line for line in conf.splitlines()
                          if not line.startswith("#"))
    safe = ('<p class="muted" style="font-size:12.5px">Safe mode is checking '
            'the change on the router in the background (about a minute). '
            'If it had cut the router off, it would put itself back and you '
            'would be told.</p>' if safe_note else "")
    return (
        f'<div class="wrap" style="max-width:760px">'
        f'<div class="box" style="border-left:4px solid var(--success)">'
        f'<h1 style="margin-top:0">{esc(label)} can connect to {esc(name)}</h1>'
        f'{warn}{head}'
        f'<pre style="background:var(--surface-2);border:1px solid '
        f'var(--border);border-radius:8px;padding:12px;white-space:pre-wrap;'
        f'font-size:13px">{esc(shown)}</pre>'
        f'<p style="margin:12px 0 4px"><b>On the device</b></p>'
        f'{_steps(kind, made_keys)}{safe}'
        f'<a class="btn ghost" href="/device?name={q}&tab=tunnel#vpnusers">'
        f'Back to the VPN tab</a></div></div>')
