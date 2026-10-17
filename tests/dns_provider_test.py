"""The DNS tab has one DNS provider on at a time, and NextDNS is one of them.

NextDNS sat in a box of its own beside the provider switches, and nothing
tied the two together. Switching Cloudflare on while NextDNS was on changed
only the router's plain DNS servers -- which RouterOS does not use while
NextDNS's DNS-over-HTTPS server is set -- so Cloudflare showed on, NextDNS
showed on, and NextDNS was still the one in use. A switch could also light
for a server the ISP hands out: Google, on a router switched to Cloudflare,
because the line's ISP gives out 8.8.8.8. Now:
  * NextDNS is in the list of providers, and only one of them is ever on
  * switching another on while NextDNS is on asks first: Cancel changes
    nothing, OK deletes this router's NextDNS profile and uses the one picked
  * the one that is on stays on -- it is changed by switching another on
  * the server will not remove NextDNS without that yes, and keeps it when
    the router cannot be reached

The switches' own script is run in Node when it is installed, so what is
checked is what a browser does with the page, not what the page says.

Run:  ./.venv/Scripts/python.exe tests/dns_provider_test.py
"""
from __future__ import annotations

import html
import http.cookiejar
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.push as push_pkg  # noqa: E402
from mikromon import nextdns, web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, build_device  # noqa: E402
from mikromon.device import DeviceError  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import features as F  # noqa: E402
from mikromon.webguard import GuardedHTTPServer  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DNS = ("ip", "dns")
DOH = "https://dns.nextdns.io/"


class FakePath:
    def __init__(self, router, segs):
        self.r, self.segs = router, segs

    def __iter__(self):
        return iter([dict(x) for x in self.r.tables.setdefault(self.segs, [])])

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        self.r.tables.setdefault(self.segs, []).append(
            {".id": nid, **{k: str(v) for k, v in params.items()}})
        self.r.log.append(("add", self.segs, dict(params)))
        return nid

    def update(self, **params):
        for x in self.r.tables.setdefault(self.segs, []):
            if x.get(".id") == params.get(".id"):
                x.update({k: str(v) for k, v in params.items()})
        self.r.log.append(("set", self.segs, dict(params)))

    def remove(self, rid):
        rows = self.r.tables.setdefault(self.segs, [])
        self.r.tables[self.segs] = [x for x in rows if x.get(".id") != rid]
        self.r.log.append(("remove", self.segs, rid))

    def __call__(self, cmd, **params):
        self.r.log.append(("run", self.segs, cmd))
        return iter([])


class FakeRouter:
    def __init__(self):
        self.ids = itertools.count(100)
        self.log = []
        self.down = False
        self.tables = {
            ("system", "resource"): [{"version": "7.16.2", "uptime": "3d"}],
            # Switched to Cloudflare, on a line whose ISP hands out Google.
            DNS: [{".id": "*0", "servers": "1.1.1.1,1.0.0.1",
                   "dynamic-servers": "8.8.8.8", "use-doh-server": "",
                   "verify-doh-cert": "no", "allow-remote-requests": "true"}],
            ("ip", "dhcp-server", "network"): [
                {".id": "*1", "address": "192.168.88.0/24",
                 "gateway": "192.168.88.1", "dns-server": ""}],
            ("ip", "address"): [{".id": "*2", "address": "192.168.88.1/24",
                                 "interface": "bridge"}],
        }

    def dns(self):
        return self.tables[DNS][0]

    def writes(self, since):
        return [e for e in self.log[since:] if e[0] != "run"]


class FakeDevice:
    def __init__(self, router):
        self.router = router
        self.api = None

    def reachable(self, timeout=None, attempts=None):
        return not self.router.down

    def connect(self):
        if self.router.down:
            raise DeviceError("router unreachable (test)")
        self.api = types.SimpleNamespace(
            path=lambda *s: FakePath(self.router, s), close=lambda: None)
        return self.api

    def close(self):
        pass


# NextDNS's own API, faked: profiles made, profiles deleted.
ND = {"made": [], "deleted": [], "fail_delete": False}
_nd_ids = itertools.count(1)


def _nd_create(api_key, name):
    pid = f"nd{next(_nd_ids)}"
    ND["made"].append(pid)
    return pid


def _nd_delete(api_key, pid):
    if ND["fail_delete"]:
        raise nextdns.NextDnsError("simulated: NextDNS is down")
    ND["deleted"].append(pid)


def _nd_get(api_key, pid, max_age=0):
    return {"denylist": [], "allowlist": [], "security": {},
            "parentalControl": {}, "privacy": {}}


nextdns.create_profile = _nd_create
nextdns.delete_profile = _nd_delete
nextdns.get_profile = _nd_get

ROUTER = FakeRouter()
push_pkg.rw_device = lambda cfg: FakeDevice(ROUTER)

tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.set_nextdns({"api_key": "test-nextdns-key"})
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "u", "password": "p"},
          DEFAULT_THRESHOLDS, org_id=org)
ds.close()
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    """The page as sent: attributes still escaped, scripts as they run."""
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def text(page):
    return html.unescape(page)


def stored():
    s = DevicesStore(ddb)
    try:
        return s.raw("R1") or {}
    finally:
        s.close()


class _Switches(HTMLParser):
    """The DNS form's switches, with what a browser would read off them."""

    def __init__(self):
        super().__init__()
        self.found = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag != "input" or a.get("name") not in ("dns_preset", "opt"):
            return
        self.found.append({
            "name": a["name"], "value": a.get("value") or "",
            "checked": "checked" in a,
            "attrs": {k: v or "" for k, v in a.items()
                      if k.startswith("data-")}})


def switches(page):
    p = _Switches()
    p.feed(page)
    return p.found


def lit(page):
    return [s["value"] for s in switches(page)
            if s["name"] == "dns_preset" and s["checked"]]


def asks(page):
    return {s["value"]: s["attrs"].get("data-mm-ask")
            for s in switches(page) if s["name"] == "dns_preset"}


# A browser, as far as these switches need one: the page's own script, run
# against stand-ins for its switches and their form.
_HARNESS = r"""
const t = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const asked = [], ready = [], answers = t.answers.slice();
global.confirm = (m) => { asked.push(m); return answers.shift(); };
const form = {
  dataset: {mmInstantForm: '1'}, extra: [], sent: null,
  querySelector(sel) {
    return this.extra.find(e => sel === 'input[name=apply]'
                                && e.name === 'apply') || null;
  },
  appendChild(e) { this.extra.push(e); },
  requestSubmit() {
    this.sent = inputs.filter(i => i.checked).map(i => [i.name, i.value])
      .concat(this.extra.map(e => [e.name, e.value]));
  },
};
const label = {appendChild() {}};
const inputs = t.inputs.map(d => ({
  name: d.name, value: d.value, checked: d.checked, attrs: d.attrs,
  listeners: [], form: form,
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
  addEventListener(type, fn) { if (type === 'change') this.listeners.push(fn); },
  closest(sel) { return sel === 'form' ? form : sel === 'label' ? label : null; },
}));
global.document = {
  addEventListener(type, fn) { if (type === 'DOMContentLoaded') ready.push(fn); },
  createElement() { return {style: {}, dataset: {}}; },
  querySelectorAll(sel) {
    if (sel === 'input[data-exclusive]')
      return inputs.filter(i => 'data-exclusive' in i.attrs);
    const m = sel.match(/^input\[data-exclusive="(.*)"\]$/);
    if (m) return inputs.filter(i => i.attrs['data-exclusive'] === m[1]);
    if (sel === 'input.switch[data-mm-instant]')
      return inputs.filter(i => 'data-mm-instant' in i.attrs);
    return [];
  },
};
eval(t.script);
ready.forEach(f => f());
const el = inputs.find(i => i.value === t.click);
el.checked = !el.checked;
let stopped = false;
const ev = {stopImmediatePropagation() { stopped = true; }};
for (const fn of el.listeners) { fn.call(el, ev); if (stopped) break; }
process.stdout.write(JSON.stringify({
  on: inputs.filter(i => i.checked && i.name === 'dns_preset').map(i => i.value),
  sent: form.sent, asked: asked}));
"""
NODE = shutil.which("node")


def flip(page, value, answers=()):
    """Flip one switch the way a click does. Returns what is on afterwards,
    what was sent ([name, value] pairs, or None), and what was asked."""
    script = re.search(r"<script>((?:(?!</script>).)*function mmExclusive"
                       r"(?:(?!</script>).)*)</script>", page, re.S).group(1)
    out = subprocess.run(
        [NODE, "-e", _HARNESS], capture_output=True, text=True, timeout=60,
        input=json.dumps({"script": script, "inputs": switches(page),
                          "click": value, "answers": list(answers)}))
    if out.returncode:
        print(out.stderr)
        return {"on": None, "sent": "error", "asked": []}
    return json.loads(out.stdout)


def picked(sent):
    return [v for k, v in (sent or []) if k == "dns_preset"]


try:
    print("The rule: what counts as the provider in use")
    check("the servers set on the router decide, not the ones the ISP hands "
          "out -- Cloudflare set, the ISP giving 8.8.8.8, is Cloudflare",
          F._active_preset({"servers": "1.1.1.1,1.0.0.1",
                            "dynamic-servers": "8.8.8.8"}) == "cloudflare")
    check("...while a router with none set still shows the one its ISP "
          "hands out", F._active_preset(
              {"servers": "", "dynamic-servers": "8.8.8.8"}) == "google")
    check("no provider is the one in use while DNS-over-HTTPS is set: the "
          "plain servers then only look up the DoH server's name",
          F._active_preset({"servers": "1.1.1.1",
                            "use-doh-server": DOH + "abc"}) == "")
    plain = build_device({"name": "R9", "host": "10.0.0.9"}, DEFAULT_THRESHOLDS)
    check("NextDNS is not offered where the platform cannot make a profile",
          not any(f.get("value") == "nextdns" for f in
                  F.nextdns_form({"dns": {}}, plain)))

    st, page = req("/login", {"email": "owner@alpha.test",
                              "password": "a-password-for-the-test"})

    print("\nBefore NextDNS: one provider on, the one the router is set to")
    st, page = req("/device?name=R1&tab=nextdns")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("the tab opens", st == 200)
    check("Cloudflare is the one on -- not Google, though the ISP hands out "
          "8.8.8.8", lit(page) == ["cloudflare"])
    check("NextDNS is in the same list of providers, off",
          [s["value"] for s in switches(page) if s["name"] == "dns_preset"]
          [:1] == ["nextdns"] and "nextdns" not in lit(page))
    check("nothing asks before switching while NextDNS is off",
          not any(asks(page).values()))
    check("the two client options sit under their own heading, apart from "
          "the providers", "Making the network use it" in text(page)
          and "These are not DNS providers" in text(page))

    if NODE:
        r = flip(page, "google")
        check("switching Google on turns Cloudflare off and sends Google "
              "alone, without asking", r["on"] == ["google"]
              and picked(r["sent"]) == ["google"] and not r["asked"]
              and ["apply", "1"] in r["sent"])
        r = flip(page, "cloudflare")
        check("switching off the one that is on leaves it on and sends "
              "nothing -- one is on at all times",
              r["on"] == ["cloudflare"] and r["sent"] is None)
        r = flip(page, "force_dns")
        check("the client options still apply as they are flipped, sending "
              "the provider that is on with them",
              ["opt", "force_dns"] in (r["sent"] or [])
              and picked(r["sent"]) == ["cloudflare"])
    else:
        print("  [skip] node is not installed: the switches' script was not "
              "run")

    print("\nSwitching NextDNS on")
    base = {"csrf": tok, "device": "R1", "feature": "nextdns", "bypass": "",
            "opt": ["allow_remote"], "apply": "1", "instant": "1"}
    st, page = req("/device/push", {**base, "dns_preset": "nextdns"})
    check("it makes this router its own NextDNS profile, and says so",
          ND["made"] == ["nd1"]
          and "NextDNS enabled for this router" in text(page))
    check("the router resolves through it",
          ROUTER.dns()["use-doh-server"] == DOH + "nd1")
    ROUTER.dns()["dynamic-servers"] = "1.1.1.1,1.0.0.1"
    st, page = req("/device?name=R1&tab=nextdns")
    check("NextDNS is the only one on -- not Cloudflare beside it, though "
          "the ISP now hands out 1.1.1.1", lit(page) == ["nextdns"])
    ask = asks(page)
    check("every other provider asks before it is switched on",
          all(ask[k] for k in F._DNS_PRESET_SERVERS) and not ask["nextdns"])
    check("...naming the one picked, saying the profile is deleted for "
          "good, and that Cancel keeps NextDNS", ask["cloudflare"].startswith(
              "Stop using NextDNS and switch this router to Cloudflare — "
              "fast & private?")
          and "deletes this router's NextDNS profile" in ask["cloudflare"]
          and "cannot be undone" in ask["cloudflare"]
          and "Cancel keeps NextDNS exactly as it is" in ask["cloudflare"])
    check("OK sends remove_nextdns", all(
        s["attrs"].get("data-mm-ask-send") == "remove_nextdns"
        for s in switches(page)
        if s["name"] == "dns_preset" and s["value"] != "nextdns"))

    if NODE:
        r = flip(page, "cloudflare", answers=[False])
        check("Cancel: nothing is sent, and NextDNS is still the one on",
              r["sent"] is None and r["on"] == ["nextdns"]
              and len(r["asked"]) == 1
              and r["asked"][0].startswith("Stop using NextDNS and switch "
                                           "this router to Cloudflare"))
        r = flip(page, "cloudflare", answers=[True])
        check("OK: NextDNS goes off, and Cloudflare alone is sent with the "
              "yes", r["on"] == ["cloudflare"]
              and picked(r["sent"]) == ["cloudflare"]
              and ["remove_nextdns", "1"] in r["sent"]
              and ["apply", "1"] in r["sent"])
        r = flip(page, "nextdns")
        check("NextDNS cannot be switched off on its own, leaving no "
              "provider: nothing is asked or sent", r["on"] == ["nextdns"]
              and r["sent"] is None and not r["asked"])

    print("\nThe server does not remove NextDNS without the yes")
    n = len(ROUTER.log)
    st, page = req("/device/push", {**base, "dns_preset": "cloudflare"})
    check("Cloudflare sent without it: nothing is changed, and the page "
          "says how to be asked", "Nothing was changed: this router still "
          "uses NextDNS" in text(page) and not ROUTER.writes(n)
          and not ND["deleted"] and stored().get("nextdns_enabled"))
    st, page = req("/device/push", {**base,
                                    "dns_preset": ["nextdns", "cloudflare"]})
    check("NextDNS and Cloudflare both sent (no script in the browser): "
          "NextDNS wins, and its DNS is left alone",
          ROUTER.dns()["use-doh-server"] == DOH + "nd1"
          and ROUTER.dns()["servers"] == "9.9.9.9,149.112.112.112"
          and not ND["deleted"])

    print("\nA router that cannot be reached keeps NextDNS")
    ROUTER.down = True
    st, page = req("/device/push", {**base, "dns_preset": "cloudflare",
                                    "remove_nextdns": "1"})
    ROUTER.down = False
    check("the switch fails with the reason, and the profile is not deleted",
          "router unreachable (test)" in text(page) and not ND["deleted"]
          and stored().get("nextdns_profile_id") == "nd1")

    print("\nSaying yes")
    st, page = req("/device/push", {**base, "dns_preset": "cloudflare",
                                    "remove_nextdns": "1",
                                    "opt": ["allow_remote", "force_dns"]})
    check("the router resolves through Cloudflare: NextDNS's DoH server is "
          "cleared, not left in front of it",
          ROUTER.dns()["use-doh-server"] == ""
          and ROUTER.dns()["servers"] == "1.1.1.1,1.0.0.1")
    check("this router's NextDNS profile is deleted, and the dashboard has "
          "it off NextDNS", ND["deleted"] == ["nd1"]
          and not stored().get("nextdns_enabled")
          and not stored().get("nextdns_profile_id")
          and not stored().get("nextdns_dns_snapshot"))
    check("the page says what happened",
          "Switched from NextDNS to Cloudflare — fast & private, and deleted "
          "this router's NextDNS profile." in text(page))
    check("Cloudflare is the only one on, and nothing asks any more",
          lit(page) == ["cloudflare"] and not any(asks(page).values()))

    print("\nA profile NextDNS will not delete is said, not hidden")
    req("/device/push", {**base, "dns_preset": "nextdns"})
    ND["fail_delete"] = True
    st, page = req("/device/push", {**base, "dns_preset": "google",
                                    "remove_nextdns": "1"})
    ND["fail_delete"] = False
    check("the router still moves to Google and off NextDNS",
          ROUTER.dns()["servers"] == "8.8.8.8,8.8.4.4"
          and ROUTER.dns()["use-doh-server"] == ""
          and not stored().get("nextdns_enabled"))
    check("...and the page names the profile to remove by hand",
          "could not delete the NextDNS profile nd2 (simulated: NextDNS is "
          "down) - remove it on NextDNS by hand" in text(page))

    print("\nThe NextDNS box's own Disable & delete")
    req("/device/push", {**base, "dns_preset": "nextdns"})
    st, page = req("/device?name=R1&tab=nextdns")
    m = re.search(r'action="/device/nextdns" onsubmit="return confirm\('
                  r'([^"]*)\)"', page)
    check("asks before it deletes the profile",
          m is not None and json.loads(html.unescape(m.group(1))).startswith(
              "Turn NextDNS off for R1 and delete its profile?"))
    st, page = req("/device/nextdns", {"csrf": tok, "device": "R1",
                                       "enable": "0"})
    check("...and, said yes to, deletes it and puts back the DNS the router "
          "had before NextDNS: one provider on again", "nd3" in ND["deleted"]
          and ROUTER.dns()["use-doh-server"] == ""
          and lit(page) == ["google"])
finally:
    srv.shutdown()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DNS PROVIDER TESTS PASSED")
