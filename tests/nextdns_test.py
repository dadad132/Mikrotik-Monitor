"""Offline tests for the NextDNS.io API client (mikromon/nextdns.py).

No real network calls are made — every call to the NextDNS API is exercised
by monkeypatching urllib.request.urlopen, same approach as billing_test.py's
PayFast client tests.

Run:  ./.venv/Scripts/python.exe tests/nextdns_test.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import nextdns

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class _FakeResponse:
    def __init__(self, body: dict):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(behavior):
    """behavior: a callable(req) -> _FakeResponse, or an Exception instance
    to raise (simulating the NextDNS API being unreachable/erroring)."""
    import urllib.request as ur
    original = ur.urlopen

    def fake(req, timeout=None):
        if isinstance(behavior, Exception):
            raise behavior
        return behavior(req)

    ur.urlopen = fake
    return original


def _unpatch_urlopen(original):
    import urllib.request as ur
    ur.urlopen = original


print("create_profile:")
seen_requests = []


def _capture(req):
    seen_requests.append(req)
    return _FakeResponse({"data": {"id": "abc123"}})


orig = _patch_urlopen(_capture)
pid = nextdns.create_profile("sekret-key", "R1")
_unpatch_urlopen(orig)
check("returns the new profile id from the API response", pid == "abc123")
check("posts to /profiles", seen_requests[-1].full_url == "https://api.nextdns.io/profiles")
check("sends the api key in the X-Api-Key header",
      seen_requests[-1].get_header("X-api-key") == "sekret-key")
check("request body carries the profile name",
      json.loads(seen_requests[-1].data.decode()) == {"name": "R1"})

seen_requests.clear()
orig = _patch_urlopen(_capture)
nextdns.create_profile("sekret-key", "R2")
_unpatch_urlopen(orig)
check("NEVER sends a ?clone= query param — confirmed live, NextDNS rejects it "
      "outright with HTTP 400 {\"code\":\"extraneous\",\"source\":"
      "{\"parameter\":\"clone\"}}, i.e. it does not know that parameter at "
      "all, so no value would have worked. Callers wanting a copy create a "
      "blank profile here and copy the settings across afterwards",
      seen_requests[-1].full_url == "https://api.nextdns.io/profiles"
      and "clone" not in seen_requests[-1].full_url)
try:
    nextdns.create_profile("k", "R2b", clone_from="template99")
    check("create_profile no longer accepts clone_from at all, so the broken "
          "call shape cannot come back by accident", False)
except TypeError:
    check("create_profile no longer accepts clone_from at all, so the broken "
          "call shape cannot come back by accident", True)

orig = _patch_urlopen(lambda req: _FakeResponse({"id": "flat456"}))
check("also accepts a flat (non-nested) {id: ...} response shape",
      nextdns.create_profile("k", "R3") == "flat456")
_unpatch_urlopen(orig)

orig = _patch_urlopen(lambda req: _FakeResponse({}))
try:
    nextdns.create_profile("k", "R4")
    check("a response with no id raises NextDnsError", False)
except nextdns.NextDnsError:
    check("a response with no id raises NextDnsError", True)
_unpatch_urlopen(orig)

print("error handling (network failures never crash the caller with a raw "
      "urllib exception):")
orig = _patch_urlopen(urllib.error.URLError("unreachable"))
try:
    nextdns.create_profile("k", "R5")
    check("unreachable API raises NextDnsError, not URLError", False)
except nextdns.NextDnsError:
    check("unreachable API raises NextDnsError, not URLError", True)
_unpatch_urlopen(orig)


class _FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code, body=b'{"error":"invalid key"}'):
        super().__init__("https://api.nextdns.io/profiles", code, "err", {}, None)
        self._body = body

    def read(self):
        return self._body


orig = _patch_urlopen(_FakeHTTPError(401))
try:
    nextdns.create_profile("bad-key", "R6")
    check("a 401 from the API raises NextDnsError with the status code in it", False)
except nextdns.NextDnsError as exc:
    check("a 401 from the API raises NextDnsError with the status code in it",
          "401" in str(exc) and "invalid key" in str(exc))
_unpatch_urlopen(orig)

print("delete_profile:")
seen_requests.clear()
orig = _patch_urlopen(_capture)
nextdns.delete_profile("sekret-key", "abc123")
_unpatch_urlopen(orig)
check("DELETEs the specific profile id",
      seen_requests[-1].full_url == "https://api.nextdns.io/profiles/abc123"
      and seen_requests[-1].get_method() == "DELETE")

orig = _patch_urlopen(_FakeHTTPError(404))
try:
    nextdns.delete_profile("k", "already-gone")
    check("deleting an already-gone profile raises (caller decides to ignore it)", False)
except nextdns.NextDnsError:
    check("deleting an already-gone profile raises (caller decides to ignore it)", True)
_unpatch_urlopen(orig)

print("rename_profile (keeps a per-WAN profile's name tracking its uplink's "
      "label without losing its query history to a recreate):")
seen_requests.clear()
orig = _patch_urlopen(_capture)
nextdns.rename_profile("sekret-key", "abc123", "R1 - Telkom")
_unpatch_urlopen(orig)
check("PATCHes the profile itself",
      seen_requests[-1].full_url == "https://api.nextdns.io/profiles/abc123"
      and seen_requests[-1].get_method() == "PATCH")
check("sends only the new name",
      json.loads(seen_requests[-1].data.decode()) == {"name": "R1 - Telkom"})

orig = _patch_urlopen(_FakeHTTPError(404))
try:
    nextdns.rename_profile("k", "gone", "whatever")
    check("renaming a profile that no longer exists raises NextDnsError "
          "(the caller decides whether that is fatal)", False)
except nextdns.NextDnsError:
    check("renaming a profile that no longer exists raises NextDnsError "
          "(the caller decides whether that is fatal)", True)
_unpatch_urlopen(orig)

print("URL helpers:")
check("doh_url embeds the profile id for RouterOS's use-doh-server field",
      nextdns.doh_url("abc123") == "https://dns.nextdns.io/abc123")
check("setup_url points at that profile's own NextDNS dashboard page",
      nextdns.setup_url("abc123") == "https://my.nextdns.io/abc123/setup")

print("")
print("Reading the profile without being rate limited off the page:")

# Opening the DNS tab reads the whole profile. Nothing cached it, so every
# page load, every redirect after saving a toggle, and every mirror of the
# template settings was a fresh call -- and NextDNS answers 429 well before
# that feels excessive, because the panel is read several times for every
# time it is changed. What the customer saw was "Could not load this
# profile's settings", which reads like NextDNS being broken rather than
# like us asking too often.
_calls = []
_real_request = nextdns._request


def _fake(method, path, api_key, body=None, _retried=False):
    _calls.append((method, path))
    return {"data": {"security": {"threatIntelligenceFeeds": True},
                     "denylist": [], "allowlist": []}}


nextdns._request = _fake
try:
    nextdns.invalidate()
    for _ in range(3):
        nextdns.get_profile("KEY", "83f58f")
    check("three page loads of the DNS tab cost ONE call, not three",
          len(_calls) == 1)

    _n = len(_calls)
    nextdns.get_profile("KEY", "OTHER")
    check("a different profile is not served another router's cached copy",
          len(_calls) == _n + 1)

    _n = len(_calls)
    nextdns.update_section("KEY", "83f58f", "security", {"x": True})
    nextdns.get_profile("KEY", "83f58f")
    check("saving a setting invalidates the cache, so the page straight "
          "after a save shows what was saved -- a stale panel there reads "
          "exactly like the save having failed",
          len(_calls) == _n + 2)

    for writer, args in ((nextdns.add_list_entry, ("KEY", "83f58f", "denylist", "x.com")),
                         (nextdns.remove_list_entry, ("KEY", "83f58f", "denylist", "x.com")),
                         (nextdns.rename_profile, ("KEY", "83f58f", "New name"))):
        nextdns.get_profile("KEY", "83f58f")
        _n = len(_calls)
        writer(*args)
        nextdns.get_profile("KEY", "83f58f")
        check(f"{writer.__name__} invalidates too", len(_calls) > _n + 1)

    _n = len(_calls)
    nextdns.get_profile("KEY", "83f58f", max_age=0)
    check("max_age=0 forces a fresh read, for the places that must not "
          "guess", len(_calls) == _n + 1)
finally:
    nextdns._request = _real_request
    nextdns.invalidate()

print("")
print("When NextDNS does say no:")

_attempts = []


def _rate_limited(method, path, api_key, body=None, _retried=False):
    _attempts.append(_retried)
    import urllib.error
    raise urllib.error.HTTPError(path, 429, "Too Many Requests",
                                 {"Retry-After": "0"}, None)


_real_urlopen = nextdns.urllib.request.urlopen


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_seq = []


def _fake_urlopen(req, timeout=None):
    import urllib.error
    if _seq and _seq.pop(0) == 429:
        raise urllib.error.HTTPError(
            req.full_url, 429, "Too Many Requests",
            {"Retry-After": "0"}, None)
    return _Resp(b'{"data":{"security":{}}}')


nextdns.urllib.request.urlopen = _fake_urlopen
try:
    nextdns.invalidate()
    _seq[:] = [429]
    got = nextdns.get_profile("KEY", "retry-me")
    check("a single 429 is retried rather than failing the page -- the first "
          "one almost always means 'wait a moment', and losing the whole "
          "panel for a second's patience is a poor trade",
          isinstance(got, dict))

    nextdns.invalidate()
    _seq[:] = [429, 429]
    try:
        nextdns.get_profile("KEY", "still-limited")
        check("two 429s in a row raises", False)
    except nextdns.NextDnsError as exc:
        check("a second 429 gives up rather than hammering",
              True)
        check("...and says the settings are fine and we asked too often, "
              "rather than implying NextDNS is broken",
              "asked once too often" in str(exc))
finally:
    nextdns.urllib.request.urlopen = _real_urlopen
    nextdns.invalidate()

print("")
print("A switch does the thing when you click it:")

from mikromon.web import (_nextdns_security_box, _nextdns_parental_box,
                          _nextdns_privacy_box, _nextdns_list_box)

for _fn, _label in ((_nextdns_security_box, "Security"),
                    (_nextdns_parental_box, "Parental control"),
                    (_nextdns_privacy_box, "Privacy")):
    _html = _fn("R1", "csrf", {})
    check(f"{_label}: the form applies on change, the way every other "
          f"device tab already did", 'data-mm-instant-form="1"' in _html)
    check(f"{_label}: its switches are the ones that trigger it",
          'data-mm-instant="1"' in _html)
    check(f"{_label}: the Save button stays, because that is what works "
          f"with no JavaScript", "type=\"submit\"" in _html)
    check(f"{_label}: and the page says which controls are instant",
          "apply as you click" in _html)

# Deliberately NOT instant: twenty-odd category and service checkboxes, one
# API call per click, is how the rate limiting started.
_par = _nextdns_parental_box("R1", "csrf", {})
check("the category and service checkboxes are NOT instant -- ticking twenty "
      "of them one call at a time is exactly what NextDNS rate limits",
      _par.count('data-mm-instant="1"') == 3)
check("...and the page says so, instead of leaving it to be discovered",
      "save with this button" in _par)

_lst = _nextdns_list_box("R1", "csrf", "Blocked", "denylist", [])
check("the denylist is not instant either: adding a domain is typing, not "
      "flicking, and there is nothing to submit on change",
      'data-mm-instant="1"' not in _lst)

print("")
print("One id NextDNS does not know must not take the whole section:")

# NextDNS validates parentalControl.services as a whole, so a single
# unrecognised id fails the entire PATCH with HTTP 400
# {"errors":[{"code":"invalid"}]} -- discarding every other service the
# customer had just ticked. The message named the section, not the id, so
# there was nothing to act on and the section was simply unusable.
#
# Three of our ids were wrong. But NextDNS publishes no catalogue -- their
# metadata repository is empty and the API docs give two examples -- so any
# hardcoded list here rots the next time they rename something. Being wrong
# has to be survivable, not merely avoided.

_BAD = {"messenger", "prime-video"}
_patches = []


def _fake_update(api_key, profile_id, section, patch):
    _patches.append(patch)
    for kind in ("services", "categories"):
        for e in patch.get(kind, []) or []:
            if str(e.get("id")) in _BAD:
                raise nextdns.NextDnsError(
                    f"NextDNS API PATCH /profiles/{profile_id}/{section} "
                    f'failed: HTTP 400 — {{"errors":[{{"code":"invalid"}}]}}')
    return {}


_real_update = nextdns.update_section
nextdns.update_section = _fake_update
try:
    _patches.clear()
    good = [{"id": "tiktok", "active": True},
            {"id": "youtube", "active": True}]
    saved, bad = nextdns.set_parental_entries("K", "p1", "services", good,
                                              suspect_ids={"tiktok"})
    check("a list NextDNS accepts is written in ONE call, with nothing "
          "clever happening", saved == good and not bad and len(_patches) == 1)

    _patches.clear()
    mixed = [{"id": "tiktok", "active": True},
             {"id": "youtube", "active": True},
             {"id": "messenger", "active": True}]
    saved, bad = nextdns.set_parental_entries("K", "p1", "services", mixed,
                                              suspect_ids={"messenger"})
    check("with one bad id, the GOOD ones still save -- which is the whole "
          "point: ticking four services and getting none of them is what "
          "made this section unusable",
          {e["id"] for e in saved} == {"tiktok", "youtube"})
    check("...and the bad one is NAMED, so there is something to act on "
          "instead of 'services: FAILED'", bad == ["messenger"])

    _patches.clear()
    two_bad = [{"id": "tiktok", "active": True},
               {"id": "messenger", "active": True},
               {"id": "prime-video", "active": True}]
    saved, bad = nextdns.set_parental_entries(
        "K", "p1", "services", two_bad,
        suspect_ids={"messenger", "prime-video"})
    check("two bad ids are both found, not just the first",
          sorted(bad) == ["messenger", "prime-video"]
          and [e["id"] for e in saved] == ["tiktok"])

    # The id already sitting on the profile is the awkward case: it is not a
    # suspect, so removing the suspects does not help and everything has to
    # be suspected.
    _patches.clear()
    stale = [{"id": "messenger", "active": True},
             {"id": "tiktok", "active": True}]
    saved, bad = nextdns.set_parental_entries("K", "p1", "services", stale,
                                              suspect_ids={"tiktok"})
    check("an id that was already saved on the profile and has since been "
          "renamed by NextDNS is found too, rather than blocking every "
          "future save forever",
          bad == ["messenger"] and [e["id"] for e in saved] == ["tiktok"])

    # Anything that is NOT a content rejection must propagate: sitting there
    # taking a list apart one id at a time because the API key is wrong
    # would be a slow way to learn nothing.
    def _auth_fail(api_key, profile_id, section, patch):
        _patches.append(patch)
        raise nextdns.NextDnsError("HTTP 403 — forbidden")

    nextdns.update_section = _auth_fail
    _patches.clear()
    try:
        nextdns.set_parental_entries("K", "p1", "services", good,
                                     suspect_ids={"tiktok"})
        check("a non-content error raises", False)
    except nextdns.NextDnsError as exc:
        check("an auth or network failure is raised immediately, not "
              "mistaken for a bad id and picked apart one call at a time",
              "403" in str(exc) and len(_patches) == 1)
finally:
    nextdns.update_section = _real_update

print("")
print("The ids we ship are the ones NextDNS actually uses:")

from mikromon.web import _NEXTDNS_SERVICES, _NEXTDNS_CATEGORIES

_svc = {i for i, _ in _NEXTDNS_SERVICES}
_cat = {i for i, _ in _NEXTDNS_CATEGORIES}
check("Prime Video is 'primevideo', not 'prime-video'",
      "primevideo" in _svc and "prime-video" not in _svc)
# Read from NextDNS's own metadata repository at the last commit before it
# was emptied -- not inferred from product names. Two rounds of
# reasonable-looking spellings were both rejected, because an id is a fact
# about NextDNS rather than something derivable from what a thing is called.
check("Disney+ is 'disneyplus' -- not 'disney-plus', and not 'disney+' "
      "either, which was the second wrong guess",
      "disneyplus" in _svc
      and not ({"disney+", "disney-plus"} & _svc))
check("'messenger' IS a real service and is offered again -- it was removed "
      "on a guess that turned out to be wrong too", "messenger" in _svc)
check("the whole catalogue is there, not a hand-picked handful: forty "
      "services, so nobody has to type an id into the escape-hatch box for "
      "something NextDNS has always supported", len(_svc) == 40)
check("every id is lowercase with no spaces or plus signs, which is the "
      "shape NextDNS actually uses",
      all(i == i.lower() and " " not in i and "+" not in i for i in _svc))
check("the pornography category is 'porn', which is NextDNS's own documented "
      "id -- the same one-bad-id failure was waiting here",
      "porn" in _cat and "pornography" not in _cat)
check("no id has a stray space or capital, which NextDNS rejects",
      all(i == i.strip().lower() and " " not in i for i in _svc | _cat))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL NEXTDNS CLIENT TESTS PASSED")
