"""Two-factor sign-in (TOTP, as every authenticator app makes).

A stolen password is no longer enough: signing in also takes the 6-digit
code the person's phone shows. Platform admins must use it; a company owner
can require it for everyone in the company. Recovery codes cover a lost
phone; an owner (for their team) or the platform admin can reset it, and the
person is emailed when that happens.

Run:  ./.venv/Scripts/python.exe tests/twofactor_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mikromon import totp, web, webguard
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.metrics import MetricsStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("The codes themselves")
check("RFC 6238 test vector (T=59)",
      totp.code_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59 // 30) == "287082")
check("RFC 6238 test vector (T=1111111109)",
      totp.code_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                   1111111109 // 30) == "081804")
_s = totp.new_secret()
_step = int(time.time() // 30)
check("a code from a phone whose clock is 30 seconds out still works",
      totp.verify(_s, totp.code_at(_s, _step - 1)) == _step - 1)
check("...but not one from two minutes ago",
      totp.verify(_s, totp.code_at(_s, _step - 4)) == 0)
check("a code already used is refused (seen over a shoulder, it is spent)",
      totp.verify(_s, totp.code_at(_s, _step), last_step=_step) == 0)
check("the login and set-up code checks are rate limited like passwords",
      {"/login/2fa", "/account/2fa"} <= webguard._LOGIN_PATHS)

DEF = dict(DEFAULT_THRESHOLDS)
tmp = tempfile.mkdtemp()
mdb, sfile, adb = (os.path.join(tmp, x) for x in ("m.db", "s.json", "a.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)

auth = AuthStore(adb)
plat = auth.signup("boss@platform.test", "secret123", "Platform")
auth.set_superadmin("boss@platform.test", True)
auth.add_member(plat, "co@platform.test", "secret123", role="owner")
acme = auth.signup("owner@acme.test", "secret123", "Acme")
auth.add_member(acme, "staff@acme.test", "secret123", role="member")

MAIL = []
sessions = web.SessionManager()
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, sessions, secure_cookies=False, defaults=DEF))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
# Notices go through the handler's background mailer; capture them.
_handler = srv.RequestHandlerClass
_handler._mail_bg = lambda self, to, subject, text: MAIL.append(
    (list(to or []), subject, text))


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return (r.status, r.read().decode("utf-8", "replace"), r.geturl(),
                r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), "", e.headers


def csrf_of(page):
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


def pending_of(page):
    m = re.search(r'name="pending" value="([^"]+)"', page)
    return m.group(1) if m else ""


def codes_of(page):
    """The recovery codes in the list (they are in the download link too)."""
    m = re.search(r"<pre[^>]*>(.*?)</pre>", page, re.S)
    return re.findall(r"\b[a-z2-9]{4}-[a-z2-9]{4}\b", m.group(1) if m else "")


def now_code(secret, ahead=0):
    return totp.code_at(secret, int(time.time() // 30) + ahead)


def reset_step(email):
    """Let the next test use the current code again (the replay guard is
    tested on its own)."""
    auth._update(auth.get_user(email)["id"], totp_step=0)


def set_up(op):
    """Walk the set-up page; returns (secret, recovery codes)."""
    st, page, url, hdr = req(op, "/account/2fa")
    key = re.search(r'user-select:all">([A-Z2-7 ]+)</code>', page)
    secret = key.group(1).replace(" ", "") if key else ""
    st, page, url, hdr = req(op, "/account/2fa",
                             {"csrf": csrf_of(page), "code": now_code(secret)})
    return secret, codes_of(page), page, hdr


try:
    print("\nA platform admin has to set it up first")
    boss = opener()
    st, page, url, _ = req(boss, "/login", {"email": "boss@platform.test",
                                            "password": "secret123"})
    check("signing in with only a password lands on the set-up page, not "
          "the dashboard", url.endswith("/account/2fa")
          and "Platform admins must use two-factor sign-in" in page)
    check("...which shows a square to scan, and the key to type instead",
          "<svg" in page and re.search(r'user-select:all">[A-Z2-7 ]{20,}',
                                       page))
    st, page, url, _ = req(boss, "/superadmin")
    check("every other page sends them back to set it up",
          url.endswith("/account/2fa"))
    st, body, _, _ = req(boss, "/api/devices")
    check("...and the API answers 403, not a page of HTML",
          st == 403 and "two_factor_setup_required" in body)
    st, page, url, _ = req(boss, "/superadmin/reset-2fa",
                           {"csrf": csrf_of(page), "email": "x"})
    check("posts are refused too", url.endswith("/account/2fa"))

    st, page, _, _ = req(boss, "/account/2fa")
    st, page, _, _ = req(boss, "/account/2fa",
                         {"csrf": csrf_of(page), "code": "000000"})
    check("a wrong code does not turn it on",
          "not right" in page and not auth.get_user(
              "boss@platform.test")["totp_on"])
    secret, codes, page, hdr = set_up(boss)
    check("the right code turns it on and shows ten recovery codes once",
          auth.get_user("boss@platform.test")["totp_on"] and len(codes) == 10
          and "not shown again" in page)
    check("...on a page the browser is told not to keep",
          "no-store" in (hdr.get("Cache-Control") or ""))
    row = auth.db.execute("SELECT totp_secret, totp_recovery FROM users "
                          "WHERE lower(email) = 'boss@platform.test'"
                          ).fetchone()
    check("the secret is stored sealed, the recovery codes only as hashes",
          row[0].startswith("enc1:") and codes[0] not in row[1]
          and secret not in row[0])
    st, page, url, _ = req(boss, "/superadmin")
    check("now the platform pages open", st == 200
          and url.endswith("/superadmin"))

    print("\nSigning in takes the code too")
    reset_step("boss@platform.test")
    b2 = opener()
    st, page, url, hdr = req(b2, "/login", {"email": "boss@platform.test",
                                            "password": "secret123"})
    pending = pending_of(page)
    check("the right password alone gets the code page, not a session",
          "Enter your code" in page and pending)
    st, _, url, _ = req(b2, "/dashboard")
    check("...and nothing behind the sign-in opens yet",
          url.endswith("/login"))
    st, page, url, _ = req(b2, "/login/2fa",
                           {"pending": pending, "code": "123456"})
    check("a wrong code says so and lets them try again",
          "not right" in page and pending_of(page) == pending)
    code = now_code(secret)
    st, page, url, _ = req(b2, "/login/2fa", {"pending": pending,
                                              "code": code})
    check("the right code signs them in", url.endswith("/dashboard"))
    b3 = opener()
    _, page, _, _ = req(b3, "/login", {"email": "boss@platform.test",
                                       "password": "secret123"})
    _, page, url, _ = req(b3, "/login/2fa", {"pending": pending_of(page),
                                             "code": code})
    check("the same code cannot be used twice",
          "not right" in page and not url.endswith("/dashboard"))

    b4 = opener()
    _, page, _, _ = req(b4, "/login", {"email": "boss@platform.test",
                                       "password": "secret123"})
    p4 = pending_of(page)
    for _ in range(5):
        _, page, url, _ = req(b4, "/login/2fa", {"pending": p4,
                                                 "code": "000000"})
    check("five wrong codes and it is back to the password",
          "Too many wrong codes" in page)
    reset_step("boss@platform.test")
    _, page, url, _ = req(b4, "/login/2fa", {"pending": p4,
                                             "code": now_code(secret)})
    check("...and that half-finished sign-in is dead, even with a right code",
          not url.endswith("/dashboard"))

    b5 = opener()
    _, page, _, _ = req(b5, "/login", {"email": "boss@platform.test",
                                       "password": "secret123"})
    p5 = pending_of(page)
    sessions._p[p5]["expires"] = time.time() - 1
    _, page, url, _ = req(b5, "/login/2fa", {"pending": p5,
                                             "code": now_code(secret)})
    check("one left waiting more than five minutes has to start again",
          "took too long" in page)

    print("\nRecovery codes")
    b6 = opener()
    _, page, _, _ = req(b6, "/login", {"email": "boss@platform.test",
                                       "password": "secret123"})
    _, page, url, _ = req(b6, "/login/2fa", {"pending": pending_of(page),
                                             "code": codes[0].upper()})
    check("a recovery code signs in in place of the phone, and says how "
          "many are left", "/account" in url and "9 left" in page)
    b7 = opener()
    _, page, _, _ = req(b7, "/login", {"email": "boss@platform.test",
                                       "password": "secret123"})
    _, page, url, _ = req(b7, "/login/2fa", {"pending": pending_of(page),
                                             "code": codes[0]})
    check("...once only", "not right" in page)
    _, page, _, _ = req(boss, "/account")
    check("My account shows it on, the codes left, and that a platform admin "
          "cannot turn it off", 'id="twofa"' in page and "9 recovery codes"
          in page and "cannot be turned off" in page
          and 'value="2fa_off"' not in page)
    reset_step("boss@platform.test")
    _, page, _, hdr = req(boss, "/account", {
        "csrf": csrf_of(page), "action": "2fa_codes",
        "code": now_code(secret)})
    new_codes = codes_of(page)
    check("new recovery codes can be made (with a code), and the old ones "
          "stop working", len(new_codes) == 10
          and auth.totp_recovery_left("boss@platform.test") == 10
          and not auth.totp_check("boss@platform.test", codes[1]))

    print("\nA company that requires it")
    own = opener()
    _, page, url, _ = req(own, "/login", {"email": "owner@acme.test",
                                          "password": "secret123"})
    check("an ordinary owner is not forced to use it",
          url.endswith("/dashboard"))
    _, page, _, _ = req(own, "/account")
    check("...and My account offers to set it up, and to require it for the "
          "company", "Set up two-factor sign-in" in page
          and 'name="require_2fa"' in page)
    _, page, url, _ = req(own, "/account", {"csrf": csrf_of(page),
                                            "action": "2fa_require",
                                            "require_2fa": "1"})
    check("requiring it is refused until the owner has it themselves",
          "for yourself first" in page and not auth.org_requires_2fa(acme))
    osecret, ocodes, page, _ = set_up(own)
    _, page, _, _ = req(own, "/account")
    _, page, _, _ = req(own, "/account", {"csrf": csrf_of(page),
                                          "action": "2fa_require",
                                          "require_2fa": "1"})
    check("then it can be required", auth.org_requires_2fa(acme)
          and "now required" in page)
    staff = opener()
    _, page, url, _ = req(staff, "/login", {"email": "staff@acme.test",
                                            "password": "secret123"})
    check("a member without it is taken to set it up, told why",
          url.endswith("/account/2fa")
          and "Your company asks everyone" in page)
    ssecret, scodes, page, _ = set_up(staff)
    _, page, _, _ = req(staff, "/account")
    check("...and cannot turn it off while the company requires it",
          "cannot be turned off" in page)

    print("\nResetting someone who lost their phone")
    _, page, _, _ = req(own, "/admin")
    check("the owner's Team page shows who has it, with a Reset button",
          "two-factor on" in page and 'action="/admin/reset-2fa"' in page)
    MAIL.clear()
    st, page, url, _ = req(own, "/admin/reset-2fa", {
        "csrf": csrf_of(page), "account": "staff@acme.test"})
    check("the owner resets a member's two-factor sign-in",
          not auth.get_user("staff@acme.test")["totp_on"])
    check("...and the member is emailed that it happened",
          MAIL and MAIL[-1][0] == ["staff@acme.test"]
          and "turned off by owner@acme.test" in MAIL[-1][2])
    _, page, url, _ = req(staff, "/dashboard")
    check("...so, as the company requires it, they set it up again at once",
          url.endswith("/account/2fa"))

    co = opener()
    _, page, url, _ = req(co, "/login", {"email": "co@platform.test",
                                         "password": "secret123"})
    _, page, _, _ = req(co, "/admin")
    check("a co-owner is not offered a reset for the platform admin",
          "boss@platform.test" in page
          and page.count('action="/admin/reset-2fa"') == 0)
    st, body, _, _ = req(co, "/admin/reset-2fa", {
        "csrf": csrf_of(page), "account": "boss@platform.test"})
    check("...and posting it anyway is refused",
          st == 403 and auth.get_user("boss@platform.test")["totp_on"])

    _, page, _, _ = req(boss, "/superadmin")
    check("the Platform page has a reset form", 'id="twofa-reset"' in page)
    MAIL.clear()
    _, page, url, _ = req(boss, "/superadmin/reset-2fa", {
        "csrf": csrf_of(page), "email": "owner@acme.test"})
    check("the platform admin can reset anyone's",
          not auth.get_user("owner@acme.test")["totp_on"]
          and "reset for owner@acme.test" in page and MAIL)
    _, page, url, _ = req(boss, "/superadmin/reset-2fa", {
        "csrf": csrf_of(page), "email": "boss@platform.test"})
    check("...except their own (another admin, or the server, does that)",
          "your own account" in page
          and auth.get_user("boss@platform.test")["totp_on"])

    print("\nTurning it off where it is optional")
    auth.set_require_2fa(acme, False)
    _, page, _, _ = req(own, "/account")
    osecret, ocodes, page, _ = set_up(own)
    _, page, _, _ = req(own, "/account")
    check("off is offered when nothing requires it",
          'value="2fa_off"' in page)
    _, page, _, _ = req(own, "/account", {"csrf": csrf_of(page),
                                          "action": "2fa_off",
                                          "password": "wrong-pass",
                                          "code": now_code(osecret, 1)})
    check("it needs the password AND a code",
          auth.get_user("owner@acme.test")["totp_on"]
          and "still on" in page)
    reset_step("owner@acme.test")
    MAIL.clear()
    _, page, _, _ = req(own, "/account", {"csrf": csrf_of(page),
                                          "action": "2fa_off",
                                          "password": "secret123",
                                          "code": now_code(osecret)})
    check("with both it goes off, and the person is emailed",
          not auth.get_user("owner@acme.test")["totp_on"]
          and "turned off by you" in (MAIL[-1][2] if MAIL else ""))

    print("\nFrom the server")
    cfg = os.path.join(tmp, "config.yaml")
    with open(cfg, "w") as fh:
        fh.write(f"auth_db: {adb}\ndevices_db: {os.path.join(tmp, 'd.db')}\n"
                 f"metrics_db: {mdb}\n")
    r = subprocess.run([sys.executable, "-m", "mikromon", "reset-2fa", "-c",
                        cfg, "--user", "boss@platform.test"],
                       capture_output=True, text=True, cwd=ROOT)
    fresh = AuthStore(adb)
    check("`python -m mikromon reset-2fa --user` resets the platform admin "
          "who lost everything", r.returncode == 0
          and not fresh.get_user("boss@platform.test")["totp_on"])
    fresh.close()
finally:
    srv.shutdown()

print("")
if FAILS:
    print(f"FAILED: {len(FAILS)}: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL TWO-FACTOR TESTS PASSED")
