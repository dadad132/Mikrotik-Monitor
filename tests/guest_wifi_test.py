"""Branded guest Wi-Fi: capture the lead, then let the router do its job.

The front door of a guest network is a marketing surface as much as a network
one, and a badly escaped splash page turns it into an XSS vector. The back door
is the router: five Hotspot menus have to agree, and half-applied changes are
worse than none. This suite covers both halves plus the SQLite store they sit
on, with a fake router that records every operation.

Run:  .venv/bin/python tests/guest_wifi_test.py
"""
from __future__ import annotations

import csv
import io
import os
import sqlite3
import sys
import tempfile
import threading
import time
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import guest_wifi as W  # noqa: E402
from mikromon.push import Pusher  # noqa: E402
from mikromon.push.api import PushError  # noqa: E402
from mikromon.push.plan import Plan  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def refuses(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False, ""
    except W.GuestWifiError as exc:
        return True, str(exc)


TMP = tempfile.mkdtemp(prefix="guest-wifi-")
DB = os.path.join(TMP, "guest.db")
store = W.GuestWifiStore(DB)

BASE = {
    "slug": "acme-guest",
    "brand_name": "Acme Guest",
    "headline": "Welcome, guests!",
    "logo_url": "https://example.test/logo.png?a=1&b=2",
    "accent_color": "#3B82F6",
    "bg_color": "#0F172A",
    "guest_password": "welcome2026",
    "shared_secret": "radius-shared-secret",
    "hotspot_iface": "vlan-guest",
    "vlan_id": 22,
    "down_mbps": 10,
    "up_mbps": 5,
    "session_minutes": 120,
    "require_phone": 1,
}

print("Portals: what is stored, and what comes back")

p = store.upsert_portal(1, BASE)
check("a portal is created with the stated defaults and a real id",
      p["id"] > 0 and p["headline"] == "Welcome, guests!"
      and p["subheadline"] == "Sign in below to get online."
      and p["device"] == "" and p["enabled"] == 1
      and p["redirect_url"] == "" and p["require_email"] == 1)
check("colours are normalised to #rrggbb",
      p["accent_color"] == "#3b82f6" and p["bg_color"] == "#0f172a")
check("the guest password and shared secret come back in plain form",
      p["guest_password"] == "welcome2026"
      and p["shared_secret"] == "radius-shared-secret")

raw = sqlite3.connect(DB).execute(
    "SELECT guest_password, shared_secret FROM guest_portals WHERE id=?",
    (p["id"],)).fetchone()
check("...but are sealed in the database, so a copied db leaks neither",
      str(raw[0]).startswith("enc1:") and str(raw[1]).startswith("enc1:"))

check("a portal can be read back by id, by slug, or for a device",
      store.get_portal(1, portal_id=p["id"])["id"] == p["id"]
      and store.get_portal_by_slug("acme-guest")["id"] == p["id"])
public = store.get_portal_by_slug("acme-guest")
check("the public slug lookup never hands out the RADIUS shared secret",
      "shared_secret" not in public
      and public["guest_password"] == "welcome2026")

same = store.upsert_portal(1, {"slug": "acme-guest", "headline": "New headline"})
check("upsert by slug updates rather than colliding with itself",
      same["id"] == p["id"] and same["headline"] == "New headline"
      and same["brand_name"] == "Acme Guest")
by_id = store.upsert_portal(1, {"id": p["id"], "subheadline": "Get online."})
check("...and an explicit id updates only that portal",
      by_id["id"] == p["id"] and by_id["subheadline"] == "Get online.")

print("\nValidation: a bad portal must never reach the router or the database")

count_before = len(store.list_portals(1))
bad_cases = [
    ("accent", dict(BASE, slug="bad-color", accent_color="red; background:url(javascript:evil)")),
    ("bg", dict(BASE, slug="bad-bg", bg_color="#12345")),
    ("logo javascript", dict(BASE, slug="bad-logo", logo_url="javascript:alert(1)")),
    ("logo data", dict(BASE, slug="bad-data", logo_url="data:text/html;base64,xxx")),
    ("logo with newline", dict(BASE, slug="bad-nl", logo_url="https://ok.test/a\nSet-Cookie: x")),
    ("redirect ftp", dict(BASE, slug="bad-redirect", redirect_url="ftp://files.test")),
    ("slow speed", dict(BASE, slug="bad-slow", down_mbps=0.1)),
    ("fast speed", dict(BASE, slug="bad-fast", up_mbps=10001)),
    ("short session", dict(BASE, slug="bad-short", session_minutes=4)),
    ("long session", dict(BASE, slug="bad-long", session_minutes=10081)),
    ("vlan 1", dict(BASE, slug="bad-vlan1", vlan_id=1)),
    ("vlan 4095", dict(BASE, slug="bad-vlan4095", vlan_id=4095)),
    ("unsafe slug", dict(BASE, slug="Not A Slug!")),
    ("no brand", dict(BASE, slug="no-brand", brand_name="  ")),
    ("public subnet", dict(BASE, slug="public-subnet", subnet="8.8.8.0/24")),
    ("very long URL", dict(BASE, slug="long-url",
                           logo_url="https://ok.test/" + "a" * 3000)),
]
for label, data in bad_cases:
    bad, why = refuses(store.upsert_portal, 1, data)
    check(f"refuses {label} with a reason", bad and len(why) > 10)
check("none of the refusals left a row behind",
      len(store.list_portals(1)) == count_before)

check("a path under /static/ or /assets/ is an allowed local logo",
      store.upsert_portal(1, dict(BASE, slug="local-logo",
                                  logo_url="/assets/logo.svg"))["logo_url"]
      == "/assets/logo.svg")

other = store.upsert_portal(2, dict(BASE, slug="other-guest", brand_name="Other"))
bad, why = refuses(store.upsert_portal, 3, dict(BASE, slug="other-guest"))
check("a slug already owned by another organisation is refused", bad and "use" in why)
check("another organisation cannot see or delete this portal",
      store.get_portal(2, portal_id=p["id"]) is None
      and store.delete_portal(2, p["id"]) is False
      and store.get_portal(2)["id"] == other["id"])

forged = store.upsert_portal(1, dict(BASE, slug="forged-guest", org_id=2))
moved = store.upsert_portal(1, {"id": forged["id"], "org_id": 2,
                                "headline": "Still mine"})
check("a forged org_id in the submitted data cannot create or move a portal "
      "into another organisation",
      forged["org_id"] == 1 and moved["org_id"] == 1
      and moved["headline"] == "Still mine"
      and store.get_portal(2, portal_id=forged["id"]) is None)

default = store.upsert_portal(1, dict(BASE, slug="default-guest", device="",
                                      brand_name="Default"))
specific = store.upsert_portal(1, dict(BASE, slug="r1-guest", device="R1",
                                       brand_name="R1 Guest"))
check("a named router gets its own portal, and other routers the default",
      store.get_portal(1, device="R1")["id"] == specific["id"]
      and store.get_portal(1, device="R2")["id"] == default["id"]
      and store.get_portal(1)["id"] == default["id"])
check("an explicit portal id wins over device selection",
      store.get_portal(1, portal_id=specific["id"], device="R2")["id"]
      == specific["id"])
bad, why = refuses(store.upsert_portal, 1,
                   {"id": p["id"], "slug": "renamed-guest"})
check("a slug cannot be renamed, which would strand the router's tagged "
      "entries", bad and "slug" in why.lower())

check("deleting with the wrong org id changes nothing",
      store.delete_portal(99, specific["id"]) is False
      and store.get_portal(1, portal_id=specific["id"]) is not None)
check("deleting with the right org id removes it",
      store.delete_portal(1, specific["id"]) is True
      and store.get_portal(1, portal_id=specific["id"]) is None)

dup_a = store.upsert_portal(1, dict(BASE, slug="dup-a-guest", device="R2",
                                    brand_name="Dup A"))
bad, why = refuses(store.upsert_portal, 1, dict(BASE, slug="dup-b-guest",
                                                device="R2", brand_name="Dup B"))
check("two portals on one named router cannot share the guest user name",
      bad and "dup-a-guest" in why and "R2" in why)
dup_c = store.upsert_portal(1, dict(BASE, slug="dup-c-guest", device="R2",
                                    brand_name="Dup C", guest_username="guest-c"))
check("a distinct guest user makes a second portal on that router valid",
      dup_c["guest_username"] == "guest-c")
bad, why = refuses(store.upsert_portal, 1,
                   {"id": dup_a["id"], "guest_username": "guest-c"})
check("an update cannot create the same router user collision", bad)

print("\nLead capture: validate, normalise, and keep each org to itself")

lead_portal = store.upsert_portal(1, dict(BASE, slug="leads-guest",
                                          require_name=1, require_email=1,
                                          require_phone=1, require_company=0,
                                          show_marketing_optin=1))
for label, kw in [
        ("missing name", {"name": "", "email": "a@b.test", "phone": "1"}),
        ("missing email", {"name": "A", "email": "", "phone": "1"}),
        ("missing phone", {"name": "A", "email": "a@b.test", "phone": ""}),
        ("bad email", {"name": "A", "email": "not-an-email", "phone": "1"})]:
    bad, why = refuses(store.record_lead, lead_portal, **kw)
    check(f"lead capture refuses {label}", bad and len(why) > 5)

lead = store.record_lead(
    lead_portal, name=" Alice ", email=" Alice@Example.test ",
    phone="+27 82 123 4567", marketing_optin=True,
    client_mac="AA-BB-CC-DD-EE-FF", client_ip="10.99.0.23")
check("an accepted lead is normalised (trimmed, lowercase MAC/IP)",
      lead["name"] == "Alice" and lead["email"] == "alice@example.test"
      and lead["client_mac"] == "aa:bb:cc:dd:ee:ff"
      and lead["client_ip"] == "10.99.0.23" and lead["marketing_optin"] == 1)
check("Cisco-style MACs normalise the same way",
      store.record_lead(lead_portal, name="Bob", email="bob@example.test",
                        phone="1", client_mac="aabb.ccdd.eeff")["client_mac"]
      == "aa:bb:cc:dd:ee:ff")
bad, why = refuses(store.record_lead, lead_portal, name="Eve",
                   email="eve@example.test", phone="1",
                   client_mac="not-a-mac")
check("a nonsense MAC is refused instead of being written as-is", bad)
bad, why = refuses(store.record_lead, dict(lead_portal, enabled=0),
                   name="Hidden", email="hidden@x.test", phone="1")
check("a disabled portal collects no PII", bad and "disabled" in why)

leads = store.list_leads(1, portal_id=lead_portal["id"])
check("leads are listed by portal and searchable by email, case-insensitively",
      len(leads) == 2
      and len(store.list_leads(1, search="ALICE@")) == 1
      and store.list_leads(2) == [])
check("a search string is a parameter, not SQL",
      store.list_leads(1, search="' OR 1=1 --") == [])
check("limit and offset page the list",
      [r["id"] for r in store.list_leads(
          1, portal_id=lead_portal["id"], limit=1, offset=1)]
      == [leads[1]["id"]])

stats_org = 700
stats_portal = store.upsert_portal(stats_org, dict(BASE, slug="stats-guest"))
for days, optin in ((0, True), (3, True), (12, False)):
    row = store.record_lead(stats_portal, name="S", email=f"s{days}@x.test",
                            phone="1", marketing_optin=optin)
    store.db.execute("UPDATE guest_leads SET created_at=? WHERE id=?",
                     (time.time() - days * 86400, row["id"]))
store.db.commit()
st = store.lead_stats(stats_org)
check("lead stats split by 24h/7d/30d and count opt-ins",
      st["total"] == 3 and st["last_24h"] == 1 and st["last_7d"] == 2
      and st["last_30d"] == 3 and st["optin_count"] == 2
      and abs(st["optin_pct"] - 66.7) < 0.01)

csv_portal = store.upsert_portal(1, dict(BASE, slug="csv-guest"))
store.record_lead(csv_portal, name='=HYPERLINK("http://evil.test")',
                  email="-sender@evil.test", phone="+123456",
                  company="@evil", client_mac="aa:bb:cc:dd:ee:00")
store.record_lead(csv_portal, name="Normal Person", email="normal@x.test",
                  phone="1")
rows = list(csv.reader(io.StringIO(store.export_leads_csv(1, portal_id=csv_portal["id"]))))
check("CSV export has a header and one row per lead", len(rows) == 3 and rows[0][0] == "id")
danger = next(row for row in rows[1:] if row[4].startswith("'="))
check("CSV formula injection is neutralised in every dangerous cell",
      all(not cell.startswith(("=", "+", "-", "@", "\t", "\r"))
          for row in rows[1:] for cell in row)
      and danger[5].startswith("'-") and danger[6].startswith("'+")
      and danger[7].startswith("'@"))
check("CSV export honours the portal filter",
      len(list(csv.reader(io.StringIO(store.export_leads_csv(1))))) > len(rows))

print("\nThe public splash page: branding, fields, and escaping")

page_portal = dict(lead_portal)
page_portal.update({
    "brand_name": "<script>evil()</script> Acme",
    "headline": "Free & <b>Fast</b> Wi-Fi",
    "subheadline": "Sign in <i>below</i>",
    "terms_text": '<img src=x onerror="evil()"> used',
    "accent_color": "#ab12cd",
    "bg_color": "#010203",
})
html = W.render_splash_html(
    page_portal, link_login_only="http://10.10.0.1/cgi-bin/hotspot/login?a=1&b=2",
    link_orig="http://example.test/welcome", client_mac="aa:bb:cc:dd:ee:ff",
    client_ip="10.99.0.4", error='<svg onload="evil()">',
    values={"name": '"><script>x</script>', "email": "a@b.test"})
check("all portal text is escaped, so a brand name cannot run script",
      "<script>evil()" not in html and "&lt;script&gt;evil()" in html
      and "&lt;img src=x onerror=" in html and "&lt;b&gt;Fast&lt;/b&gt;" in html)
check("prefilled values and the error message are escaped too",
      '&quot;&gt;&lt;script&gt;x' in html
      and "&lt;svg onload=" in html and "onmouseover=" not in html)
check("branding colours are applied", "#ab12cd" in html and "#010203" in html)
check("brand, headline, logo and terms are shown",
      "Acme" in html and "Free &amp; &lt;b&gt;Fast&lt;/b&gt;" in html
      and "https://example.test/logo.png?a=1&amp;b=2" in html
      and "used" in html)
check("required fields, checkbox, opt-in and hidden hotspot params render",
      all(f'name="{n}"' in html for n in
          ("name", "email", "phone", "terms", "marketing_optin",
           "link-login-only", "link-orig", "mac", "ip"))
      and 'type="email"' in html and 'type="tel"' in html)
check("the page is a mobile-ready standalone HTML document",
      html.lstrip().lower().startswith("<!doctype html>")
      and "viewport" in html and "<style>" in html and "</html>" in html)

plain = W.render_splash_html(dict(page_portal, require_phone=0,
                                  require_name=0, show_marketing_optin=0))
check("turning a requirement off removes that field",
      'name="phone"' not in plain and 'name="name"' not in plain
      and 'name="marketing_optin"' not in plain)
check("a hostile colour from a hand-built portal cannot inject CSS",
      "javascript:" not in W.render_splash_html(
          dict(page_portal, accent_color="red;background:url(javascript:evil)")))
check("a disabled portal shows no capture form at all",
      "unavailable" in W.render_splash_html(dict(page_portal, enabled=0))
      and "Connect to Wi-Fi" not in
      W.render_splash_html(dict(page_portal, enabled=0))
      and "unavailable" in W.render_splash_html(dict(page_portal, enabled="0")))

print("\nHandoff to the router: only safe login URLs are auto-submitted")

good = W.render_connected_html(
    page_portal, link_login_only="http://10.10.0.1/cgi-bin/hotspot/login?dst=x&popup=true",
    link_orig="http://example.test/welcome")
check("a private hotspot gateway gets a real auto-submit form",
      'action="http://10.10.0.1/cgi-bin/hotspot/login?dst=x&amp;popup=true"' in good
      and 'name="username" value="guest"' in good
      and 'name="password" value="welcome2026"' in good
      and 'name="dst" value="http://example.test/welcome"' in good
      and ".submit()" in good)
check("a gateway given as a valid hostname is accepted",
      ".submit()" in W.render_connected_html(
          page_portal, link_login_only="https://hotspot.acme.test/login"))
for label, url in [
        ("javascript", "javascript:alert(1)"),
        ("data", "data:text/html,<script>evil()</script>"),
        ("public ip", "http://8.8.8.8/login"),
        ("crlf", "http://10.0.0.1/\r\nSet-Cookie: evil=1"),
        ("no host", "http:///login"),
        ("bad port", "http://10.0.0.1:99999/login")]:
    bad = W.render_connected_html(page_portal, link_login_only=url)
    check(f"rejects {label} login URL and shows the preview card instead",
          "You're connected!" in bad and "<form" not in bad
          and "javascript:" not in bad and "data:text/html" not in bad
          and "Set-Cookie" not in bad)
preview = W.render_connected_html(page_portal, link_orig="javascript:alert(1)")
check("standalone preview has a redirect button but never a script URL",
      "You're connected!" in preview and "javascript:" not in preview
      and "Continue" in preview)
with_creds = W.render_connected_html(
    page_portal, link_orig="https://user:pass@evil.test/")
check("login credentials in link-orig are dropped rather than echoed",
      "user:pass" not in with_creds and "href=\"https://user" not in with_creds)
check("a web route can pin the login action and redirect to known hosts",
      ".submit()" not in W.render_connected_html(
          page_portal, link_login_only="https://attacker.test/login",
          allowed_hosts=["10.0.0.1"])
      and "evil.test" not in W.render_connected_html(
          page_portal, link_orig="http://evil.test/phish",
          allowed_origins=["example.test"]))
disabled_connected = W.render_connected_html(
    dict(page_portal, enabled=0),
    link_login_only="http://10.0.0.1/login")
check("a disabled portal never hands credentials to the router",
      "unavailable" in disabled_connected and "<form" not in disabled_connected)

snippet = W.hotspot_login_html_snippet(
    "https://portal.acme.test/guest/acme-guest?theme=dark")
check("the hotspot login snippet forwards all four RouterOS variables",
      all(v in snippet for v in ("$(link-login-only)", "$(link-orig)",
                                 "$(mac)", "$(ip)"))
      and "https://portal.acme.test/guest/acme-guest?theme=dark&amp;" in snippet)
bad, why = refuses(W.hotspot_login_html_snippet, "javascript:alert(1)")
check("a hostile portal URL cannot be written into login.html", bad)

print("\nRouterOS provisioning: five menus, idempotent, fully reversible")


class FakeApi:
    """Router tables in memory, with the fetch/execute shape Pusher expects."""

    def __init__(self, state=None, fail_desc=None):
        self.state = state if state is not None else {}
        self.fail_desc = fail_desc
        self.executed = []
        self._n = 100

    def fetch(self, path):
        return [dict(r) for r in self.state.get(tuple(path), [])]

    def execute(self, op):
        if self.fail_desc and op.desc == self.fail_desc:
            raise PushError("simulated failure: " + op.desc)
        self.executed.append(op)
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self._n += 1
            rid = f"*{self._n}"
            rows.append({**{k: str(v) for k, v in op.params.items()}, ".id": rid})
            return rid
        if op.action == "set":
            for row in rows:
                if row.get(".id") == str(op.params.get(".id")):
                    row.update({k: str(v) for k, v in op.params.items()
                                if k != ".id"})
            return None
        if op.action == "remove":
            self.state[tuple(op.path)] = [
                r for r in rows if r.get(".id") != str(op.params.get(".id"))]
            return None
        raise PushError("unknown action " + op.action)


cfg = types.SimpleNamespace(name="R1")
plan_portal = dict(BASE)
plan_portal["guest_password"] = "welcome2026"
state = {}
pusher = Pusher(cfg, FakeApi(state), dry_run=True)
plan = W.build_hotspot_plan(pusher, cfg, plan_portal, "portal.acme.test")
check("the planner returns a Plan for the device", isinstance(plan, Plan)
      and plan.device == "R1" and len(plan.ops) == 5)

paths = [(tuple(op.path), op.params) for op in plan.ops]
menus = [p for p, _ in paths]
check("all five RouterOS menus are provisioned",
      menus == [("ip", "hotspot", "user", "profile"),
                ("ip", "hotspot", "profile"),
                ("ip", "hotspot"),
                ("ip", "hotspot", "user"),
                ("ip", "hotspot", "walled-garden")])
uprof, hprof, hotspot, user, garden = [p for _, p in paths]
check("the user profile carries rate limit and session timeout",
      uprof["name"] == "mm-guest-acme-guest"
      and uprof["rate-limit"] == "5M/10M"
      and uprof["session-timeout"] == "120m"
      and uprof["shared-users"] == "unlimited")
check("the hotspot profile allows the two HTTP login methods",
      hprof["login-by"] == "http-chap,http-pap" and hprof["name"] == uprof["name"])
check("the hotspot is enabled on the guest interface and uses that profile",
      hotspot["interface"] == "vlan-guest" and hotspot["profile"] == uprof["name"]
      and hotspot["disabled"] == "no")
check("the guest user is created on that profile",
      user["name"] == "guest" and user["password"] == "welcome2026"
      and user["profile"] == uprof["name"])
check("walled garden lets unauthenticated guests reach the branded portal",
      garden["dst-host"] == "portal.acme.test" and garden["action"] == "allow")
check("every entry is tagged with its own mikromon comment",
      [p["comment"] for p in (uprof, hprof, hotspot, user, garden)]
      == [W.TAG + x + ":acme-guest" for x in
          ("uprof", "hprof", "hs", "user", "wg")])
check("every operation has a rollback inverse",
      all(op.inverse is not None for op in plan.ops))

apply_api = FakeApi(state)
applier = Pusher(cfg, apply_api, dry_run=False)
applier.apply(plan)
check("applying writes all five entries",
      all(len(state.get(path, [])) == 1 for path in menus))
second = W.build_hotspot_plan(Pusher(cfg, FakeApi(state), dry_run=True), cfg,
                              plan_portal, "portal.acme.test")
check("a second run is a no-op: nothing is re-added or re-set",
      second.empty and len(second.ops) == 0)

bool_state = {
    ("ip", "hotspot", "user", "profile"): [{
        ".id": "*1", "name": "mm-guest-acme-guest", "rate-limit": "5M/10M",
        "session-timeout": "120m", "shared-users": "unlimited",
        "comment": W.TAG + "uprof:acme-guest"}],
    ("ip", "hotspot", "profile"): [{
        ".id": "*2", "name": "mm-guest-acme-guest",
        "login-by": "http-chap,http-pap",
        "comment": W.TAG + "hprof:acme-guest"}],
    ("ip", "hotspot"): [{
        ".id": "*3", "name": "mm-guest-acme-guest", "interface": "vlan-guest",
        "profile": "mm-guest-acme-guest", "disabled": False,
        "comment": W.TAG + "hs:acme-guest"}],
    ("ip", "hotspot", "user"): [{
        ".id": "*4", "name": "guest", "password": "welcome2026",
        "profile": "mm-guest-acme-guest",
        "comment": W.TAG + "user:acme-guest"}],
    ("ip", "hotspot", "walled-garden"): [{
        ".id": "*5", "dst-host": "portal.acme.test", "action": "allow",
        "comment": W.TAG + "wg:acme-guest"}],
}
bool_plan = W.build_hotspot_plan(
    Pusher(cfg, FakeApi(bool_state), dry_run=True), cfg, plan_portal,
    "portal.acme.test")
check("RouterOS reading disabled back as false does not cause endless sets",
      bool_plan.empty)

leak_state = {("ip", "hotspot", "user"): [{
    ".id": "*9", "name": "guest", "password": "old-password",
    "profile": "mm-guest-acme-guest",
    "comment": W.TAG + "user:acme-guest"}]}
leak_plan = W.build_hotspot_plan(
    Pusher(cfg, FakeApi(leak_state), dry_run=True), cfg,
    dict(plan_portal, guest_password="newsecret"), "portal.acme.test")
check("a changed guest password is sent to the router but redacted from the "
      "audit-log description",
      "newsecret" not in leak_plan.diff_text()
      and "password=" not in leak_plan.diff_text()
      and any(op.params.get("password") == "newsecret" for op in leak_plan.ops))
odd_plan = W.build_hotspot_plan(
    Pusher(cfg, FakeApi(leak_state), dry_run=True), cfg,
    dict(plan_portal, guest_password="secret, extra, tail"),
    "portal.acme.test")
check("a password containing comma-space still leaves no fragment in the log",
      all(word not in odd_plan.diff_text()
          for word in ("secret", "extra", "tail", "password=")))

disabled_plan = W.build_hotspot_plan(
    pusher, cfg, dict(plan_portal, enabled=0), "portal.acme.test")
check("a disabled portal makes no router changes, however enabled was typed",
      disabled_plan.empty and "disabled" in disabled_plan.summary
      and W.build_hotspot_plan(
          pusher, cfg, dict(plan_portal, enabled="0"),
          "portal.acme.test").empty)


class SharedFetchApi(FakeApi):
    def fetch(self, path):
        return self.state.get(tuple(path), [])  # the same row objects


shared_state = {("ip", "hotspot"): [{
    ".id": "*7", "name": "mm-guest-acme-guest", "interface": "vlan-guest",
    "profile": "mm-guest-acme-guest", "disabled": False,
    "comment": W.TAG + "hs:acme-guest"}]}
W.build_hotspot_plan(Pusher(cfg, SharedFetchApi(shared_state), dry_run=True),
                     cfg, plan_portal, "portal.acme.test")
check("planning never mutates the router rows handed back by fetch",
      shared_state[("ip", "hotspot")][0]["disabled"] is False)

rollback_state = {}
rollback_api = FakeApi(rollback_state,
                       fail_desc=plan.ops[3].desc)  # fail on the guest user
try:
    Pusher(cfg, rollback_api, dry_run=False).apply(
        W.build_hotspot_plan(Pusher(cfg, FakeApi(rollback_state), dry_run=True),
                             cfg, plan_portal, "portal.acme.test"))
    rolled = False
except PushError:
    rolled = True
check("a failed apply rolls every completed entry back",
      rolled and all(not rollback_state.get(path) for path in menus))

bad, why = refuses(W.build_hotspot_plan, pusher, cfg, plan_portal,
                   "javascript:alert(1)")
check("a hostile walled-garden host is refused before a plan exists", bad)

unmanaged = {("ip", "hotspot", "user"): [
    {".id": "*1", "name": "guest", "comment": "made by a human"}]}
plan2 = W.build_hotspot_plan(Pusher(cfg, FakeApi(unmanaged), dry_run=True),
                             cfg, plan_portal, "portal.acme.test")
check("an unmanaged lookalike row is never updated or removed",
      all(op.params.get(".id") != "*1" for op in plan2.ops))

print("\nConcurrent writes from web threads")

errors = []


def write_lead(index):
    try:
        store.record_lead(csv_portal, name=f"Thread {index}",
                          email=f"thread{index}@x.test", phone="1")
    except Exception as exc:  # noqa: BLE001
        errors.append(exc)


threads = [threading.Thread(target=write_lead, args=(i,)) for i in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
check("eight simultaneous lead writes all land, none raise 'database "
      "is locked'", not errors
      and len(store.list_leads(1, portal_id=csv_portal["id"])) == 10)

store.close()
print("\n" + ("ALL PASS" if not FAILS else f"{len(FAILS)} FAILURE(S): " + "; ".join(FAILS)))
sys.exit(1 if FAILS else 0)
