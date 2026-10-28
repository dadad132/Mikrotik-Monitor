"""The site's security headers, as the nginx config install.sh writes them.

A domain health scan scored the site's web headers 16/27: no
Content-Security-Policy, no Permissions-Policy, and the nginx version in the
Server header. This pins what fixed them, and what the policy deliberately
leaves out because the site needs it:
  * inline script is allowed -- every page carries its own -- but no script
    can come from anywhere else, nothing can be embedded, no <base> hijack,
    and no other site may frame these pages
  * no form-action: paying posts a form that redirects to Yoco
  * the remote WebFig proxy hides the nginx version too, and gets no CSP,
    since WebFig runs scripts of its own

Run:  ./.venv/Scripts/python.exe tests/security_headers_test.py
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mikromon import access  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


src = open(os.path.join(ROOT, "deploy", "install.sh"), encoding="utf-8").read()
site = src[src.index("write_site() {"):src.index("    write_site\n")]
https = site[site.index("# HTTPS dashboard proxy"):]
plain = site[site.index("# HTTP → HTTPS redirect"):site.index("# HTTPS dashboard proxy")]
csp = re.search(r'add_header Content-Security-Policy "([^"]+)" always;', https)
csp = csp.group(1) if csp else ""
directives = {d.split()[0]: d.split()[1:] for d in
              (p.strip() for p in csp.split(";")) if d}

print("The HTTPS site")
check("sends a Content-Security-Policy, on error pages too", bool(csp))
check("...scripts only from this site (inline allowed: every page has its "
      "own), never from another host",
      directives.get("script-src") == ["'self'", "'unsafe-inline'"])
check("...nothing embedded, no <base> hijack, no framing by other sites",
      directives.get("object-src") == ["'none'"]
      and directives.get("base-uri") == ["'self'"]
      and directives.get("frame-ancestors") == ["'self'"]
      and directives.get("default-src") == ["'self'"])
check("...and no form-action, which would stop a payment redirecting to "
      "Yoco", "form-action" not in directives)
check("sends a Permissions-Policy switching off what the site never uses",
      re.search(r'add_header Permissions-Policy\s+"[^"]*camera=\(\)[^"]*'
                r'microphone=\(\)[^"]*geolocation=\(\)[^"]*" always;', https)
      is not None)
check("keeps the headers that already passed, now on every response",
      all(re.search(rf"add_header {h}\s+\S+ always;", https) for h in
          ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy")))
check("hides the nginx version, on HTTPS and on the HTTP redirect",
      "server_tokens off;" in https and "server_tokens off;" in plain)
check("...per server, not http-wide, where a server_tokens line already in "
      "nginx.conf would make nginx refuse the whole file",
      "server_tokens" not in site[:site.index("server {")])

print("\nThe remote WebFig proxy")
conf = access.render_nginx_http(
    [{"kind": "webfig", "device": "R1", "expires": 0, "port": 20001,
      "tunnel_ip": "10.10.0.5", "router_port": 80}],
    "/etc/ssl/c.pem", "/etc/ssl/k.pem")
check("hides the nginx version too", "server_tokens off;" in conf)
check("...and sets no CSP, which would break WebFig's own scripts",
      "Content-Security-Policy" not in conf)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SECURITY HEADER TESTS PASSED")
