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

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL NEXTDNS CLIENT TESTS PASSED")
