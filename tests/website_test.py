"""What the website's pages promise a visitor, a keyboard and a crawler.

Run: python tests/website_test.py
"""
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mikromon import auth as auth_mod, web, web_auth, web_landing, web_seo, web_shared  # noqa: E402
from mikromon.web_shared import _link_labels, _page, _theme_colours, _with_main  # noqa: E402

FAILS = []


def check(name, ok, extra=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f"  ({extra})" if extra and not ok else ""))
    if not ok:
        FAILS.append(name)


print("Every label is tied to its field")
html = _link_labels('<label>Name</label><input name="n">')
m = re.search(r'<label for="(\w+)">Name</label><input id="(\w+)"', html)
check("a label and the field after it are tied together",
      bool(m) and m[1] == m[2], html)
html = _link_labels('<label class="f">Host</label>\n  <select name="h">')
check("...across a line break, keeping the label's own class",
      'class="f"' in html and "<select id=" in html, html)
html = _link_labels('<label>A</label><input name="a"><label>B</label><input name="b">')
check("...each with an id of its own",
      len(set(re.findall(r'<input id="(\w+)"', html))) == 2, html)
html = _link_labels('<label>A</label><input id="mine" name="a">')
check("...using an id the field already has", 'for="mine"' in html, html)
html = _link_labels('<label>A</label><input data-id="9" name="a">')
check("...and not mistaking data-id for one", 'data-id="9"' in html
      and re.search(r'<input id="fld\d+" data-id', html) is not None, html)
same = '<label class="x"><input type="checkbox" name="c"> On</label><input name="n">'
check("a field inside its label is left alone", _link_labels(same) == same)
same = '<label>T</label><input type="hidden" name="h">'
check("a hidden field is never a label's target", _link_labels(same) == same)
same = """<script>var t="<label>A</label><input name='a'>";</script>"""
check("a label written inside a script is left alone",
      _link_labels(same) == same)
html = _link_labels(same + '<label>B</label><input name="b">')
check("...while the form after that script is still tied up",
      'for="fld1"' in html and html.startswith(same), html)
same = '<label for="z">A</label><input name="a">'
check("a label already tied to something stays as it is",
      _link_labels(same) == same)

print("The page's structure")
aside = '<aside class="dash-side">nav</aside>'
html = _with_main(aside + "<p>body</p>")
check("the nav stays outside <main>",
      html == aside + '<main id="main" tabindex="-1"><p>body</p></main>', html)
html = _with_main("<p>body</p>")
check("a page with no nav is all <main>",
      html == '<main id="main" tabindex="-1"><p>body</p></main>', html)
page = _page("Devices", aside + "<p>x</p>")
check("<html> says what language it is in", '<html lang="en">' in page)
check("a keyboard user can skip the nav", 'href="#main"' in page
      and page.index("skip-link") < page.index('class="dash-side"'))
check("every page has a description", 'name="description"' in page)
check("the tab says which site it is",
      "<title>Devices &middot; easymikrotik</title>" in page, page[:400])
page = _page("Smith & Sons", aside)
check("a name with an ampersand is escaped once, not twice",
      "<title>Smith &amp; Sons" in page and "&amp;amp;" not in page, page[:400])

print("Colours that follow the theme")
check("a status colour in a page's markup is the theme's",
      _theme_colours('<b style="color:#dc2626">x</b>')
      == '<b style="color:var(--danger-text)">x</b>')
check("...but a router script shown on the page reads as it does on the router",
      _theme_colours('<pre>:put "color:#dc2626"</pre>')
      == '<pre>:put "color:#dc2626"</pre>')
check("...and a fill or a border is not touched",
      _theme_colours('<i style="background-color:#dc2626;border-color:#dc2626">')
      == '<i style="background-color:#dc2626;border-color:#dc2626">')
check("...nor a longer colour that starts the same",
      _theme_colours('color:#16a34a00') == 'color:#16a34a00')
for token in ("--success-text", "--warning-text", "--danger-text", "--accent-fill"):
    check(f"{token} is set in light and both dark blocks",
          web_shared._THEME_VARS.count(token + ":") == 3)

print("Emails and invoices keep their colours")
code = open(web.__file__, encoding="utf-8").read()
emails = code[code.index("def _renewal_email("):code.index("def _email_renewal(")]
check("nothing that builds an email leans on the site's stylesheet",
      "var(--" not in emails)
source = open(web_auth.__file__, encoding="utf-8").read()
fields = source[source.index("def _invoice_money("):source.index("def _invoice_actions(")]
check("an invoice's text keeps its own colours",
      "var(--text" not in fields and "-text)" not in fields)

print("The landing page")
page = web_landing.render_landing(base="https://easymikrotik.com")
check("one <main>", page.count("<main") == 1 and page.count("</main>") == 1)
check("the canonical address is the home page",
      '<link rel="canonical" href="https://easymikrotik.com/">' in page)
check("a shared link gets a title, a text and a picture",
      'property="og:title"' in page and 'property="og:description"' in page
      and 'content="https://easymikrotik.com/og.jpg"' in page)
check("the description fits in a search result",
      120 <= len(web_landing._DESCRIPTION) <= 160, len(web_landing._DESCRIPTION))
check("the FAQ's structured data is the FAQ on the page",
      all(q in page for q, _a in web_landing._FAQ) and '"FAQPage"' in page)
page = web_landing.render_landing()
check("with no address set, nothing is built from a guess",
      "canonical" not in page and "og:url" not in page and "og:image" not in page)
faq = [("Q?", 'A </script><script>alert(1)</script>')]
check("an answer cannot break out of the structured data",
      "</script><script>" not in web_seo._json_ld("T", "D", faq, "t"))
check("the antivirus is not advertised in what crawlers read",
      not re.search("antivirus", web_seo.llms_txt("https://x", "b"), re.I)
      and not re.search("antivirus", web_landing._DESCRIPTION, re.I))

print("The dashboard")
dash = open(web.__file__, encoding="utf-8").read()
check("no page-wide <meta refresh> while scripts run",
      '<meta http-equiv="refresh"' not in dash.replace(
          '<noscript><meta http-equiv="refresh" content="10"></noscript>', ""))
check("it refreshes only if the server answers, and not over someone typing",
      "fetch('/health'" in dash and "function busy()" in dash)
check("...though a cursor left in the search box cannot hold it off for ever",
      "Date.now()-touched>30000" in dash)
check("what is typed in the search box survives the refresh", "'mm-q'" in dash)

print("The real server")
d = tempfile.mkdtemp()
auth_db = os.path.join(d, "auth.db")
store = auth_mod.AuthStore(auth_db)
store.signup("owner@example.com", "password1", "Acme")
store.close()
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    os.path.join(d, "m.db"), os.path.join(d, "s.json"),
    auth_mod.AuthStore(auth_db), web.SessionManager(),
    devices_db=os.path.join(d, "d.db")))
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


opener = urllib.request.build_opener(NoRedirect)


def get(path, method="GET", headers=None):
    req = urllib.request.Request(base + path, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


status, body, headers = get("/robots.txt")
text = body.decode()
check("robots.txt answers with no session", status == 200, status)
check("...keeps crawlers out of the private pages", all(
    f"Disallow: {p}" in text for p in ("/dashboard", "/superadmin", "/pay")))
check("...and names the sitemap", "/sitemap.xml" in text)
status, body, headers = get("/sitemap.xml")
check("the sitemap lists the public pages", status == 200 and all(
    f"{base}{p}</loc>" in body.decode() for p in ("/", "/terms", "/signup")))
check("...and is XML", "xml" in headers.get("Content-Type", ""))
status, body, _h = get("/llms.txt")
check("llms.txt answers", status == 200 and body.startswith(b"# "))
status, body, headers = get("/og.jpg")
check("the preview image is served", status == 200
      and headers.get("Content-Type") == "image/jpeg" and body[:2] == b"\xff\xd8")
check("...small enough for WhatsApp to show it", len(body) < 300 * 1024, len(body))

status, body, headers = get("/login", method="HEAD")
check("HEAD is answered, not refused", status == 200, status)
check("...with no body", body == b"", len(body))
check("...and the length a GET would send",
      int(headers.get("Content-Length", 0)) == len(get("/login")[1]))
status, body, headers = get("/logo.svg", method="HEAD")
check("HEAD on the artwork has no body either", status == 200 and body == b"")
check("the Server header gives no Python version",
      "Python" not in headers.get("Server", ""), headers.get("Server"))

real, web_seo.OG_IMAGE_FILE = web_seo.OG_IMAGE_FILE, os.path.join(d, "gone.jpg")
status, _b, _h = get("/og.jpg")
web_seo.OG_IMAGE_FILE = real
check("a missing preview image is a 404, not a dropped connection",
      status == 404, status)

status, _b, _h = get("/nothing-here")
check("an unknown page, signed out, goes to sign in", status in (302, 303), status)
srv.shutdown()

print()
print("FAILED: " + ", ".join(FAILS) if FAILS else "All checks passed.")
sys.exit(1 if FAILS else 0)
