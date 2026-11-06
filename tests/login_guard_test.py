"""Password guessing is slow, and a stranger cannot lock the owner out.

auth.AuthStore.verify counts wrong passwords three ways (one login from one
address; one login from anywhere; one address across logins), and
note_login remembers where each login signs in from, so that an address the
owner has used is never locked by somebody else's guessing, and a sign-in
from a new address can be emailed.

Run: python tests/login_guard_test.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mikromon.auth import AuthStore  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()
auth = AuthStore(os.path.join(tmp, "auth.db"))
auth.signup("owner@acme.test", "secret123", "Acme")
auth.signup("other@beta.test", "secret123", "Beta")
OWNER, HOME, ATTACKER = "owner@acme.test", "196.1.1.1", "45.9.9.9"
owner = auth.verify(OWNER, "secret123", ip=HOME)
uid = owner["id"]

print("Remembering where people sign in from")
check("the very first sign-in is not called 'new' (nothing to compare it with)",
      auth.note_login(uid, HOME, "Firefox") is False)
check("the same address again is not new", auth.note_login(uid, HOME, "Firefox") is False)
check("a different address is new", auth.note_login(uid, "102.5.5.5", "Phone") is True)
check("...once", auth.note_login(uid, "102.5.5.5", "Phone") is False)
hist = auth.login_history(uid)
check("the history lists the addresses, newest first, with counts",
      [h["ip"] for h in hist] == ["102.5.5.5", HOME] and hist[1]["count"] == 2)
check("no address, nothing recorded", auth.note_login(uid, "", "x") is False)

print("One login, one address")
for _ in range(8):
    auth.verify(OWNER, "wrong", ip=ATTACKER)
check("8 wrong passwords lock that login from that address",
      auth.verify(OWNER, "secret123", ip=ATTACKER) is None)
check("...but not the owner, signing in from their own address",
      auth.verify(OWNER, "secret123", ip=HOME) is not None)
check("...nor the owner from a brand new address",
      auth.verify(OWNER, "secret123", ip="41.0.0.1") is not None)

print("One address, many logins")
auth2 = AuthStore(os.path.join(tmp, "auth2.db"))
for i in range(30):
    auth2.verify(f"nobody{i}@x.test", "guess", ip="66.6.6.6")
auth2.signup("real@x.test", "secret123", "X")
check("an address that tried 30 logins is refused even with a right password",
      auth2.verify("real@x.test", "secret123", ip="66.6.6.6") is None)
check("...while everyone else signs in normally",
      auth2.verify("real@x.test", "secret123", ip="1.2.3.4") is not None)

print("One login, many addresses (a botnet)")
auth3 = AuthStore(os.path.join(tmp, "auth3.db"))
auth3.signup("boss@y.test", "secret123", "Y")
me = auth3.verify("boss@y.test", "secret123", ip="10.0.0.5")
auth3.note_login(me["id"], "10.0.0.5", "Edge")
for i in range(40):
    auth3.verify("boss@y.test", "guess", ip=f"77.0.{i // 200}.{i % 200}")
check("40 wrong passwords from all over lock the login for new addresses",
      auth3.verify("boss@y.test", "secret123", ip="88.8.8.8") is None)
check("...but the owner still gets in from an address they have used",
      auth3.verify("boss@y.test", "secret123", ip="10.0.0.5") is not None)

print("Callers that pass no address keep working")
check("verify without an address still checks the password",
      auth.verify("other@beta.test", "secret123") is not None
      and auth.verify("other@beta.test", "nope") is None)

print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL LOGIN GUARD TESTS PASSED")
sys.exit(1 if FAILS else 0)
