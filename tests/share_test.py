"""Sharing one router across the company boundary, without opening it.

The org check in can_see is the one thing standing between every company's
routers and every other company's logins. Sharing punches a hole in it, so
the hole has to be exactly as small as it can be made:

  * one ROUTER, never a company
  * one PERSON, never a company
  * granted only by the owner of the company that owns the router
  * revocable by that owner and by nobody else
  * view-only unless the owner ticks otherwise

These tests are mostly about what a share does NOT give away.

Run:  ./.venv/Scripts/python.exe tests/share_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.auth import AuthStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


_fd, _p = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.unlink(_p)
a = AuthStore(_p)

ACME = a.signup("owner@acme.test", "password123", "Acme")
OTHER = a.signup("zoe@other.test", "password123", "Other Co")
a.add_member(OTHER, "bob@other.test", "password123", devices=["Other R1"])
a.add_member(ACME, "amy@acme.test", "password123", devices=["Acme R1"])

try:
    a.share_device("Acme R1", "zoe@other.test", ACME, False, "owner@acme.test")
    a.share_device("Acme R2", "bob@other.test", ACME, True, "owner@acme.test")

    zoe = a.get_user("zoe@other.test")      # other-co OWNER, view-only share
    bob = a.get_user("bob@other.test")      # other-co MEMBER, manage share
    amy = a.get_user("amy@acme.test")       # acme member, no share
    own = a.get_user("owner@acme.test")

    print("\nWhat a share gives")

    check("the guest can see the one router shared with them, even though it "
          "belongs to another company",
          AuthStore.can_see(zoe, "Acme R1", ACME))
    check("it appears in their device list alongside their own",
          "Acme R1" in AuthStore.allowed_devices(zoe, ["Other R1"]))
    check("a share WITH management lets them change it",
          AuthStore.can_manage_device(bob, "Acme R2", ACME))

    print("\nWhat it does not")

    check("view-only means exactly that -- seeing a router is not changing "
          "one, and that is the default",
          not AuthStore.can_manage_device(zoe, "Acme R1", ACME))
    check("the guest sees NO other router of the company that shared one",
          not AuthStore.can_see(zoe, "Acme R2", ACME)
          and not AuthStore.can_see(zoe, "Acme R3", ACME))
    check("...not even though they are an owner in their OWN company -- "
          "being an owner somewhere is not being an owner everywhere",
          AuthStore.is_owner(zoe)
          and not AuthStore.can_see(zoe, "Acme R3", ACME))
    check("a guest granted management of one router cannot manage another "
          "of that company's",
          not AuthStore.can_manage_device(bob, "Acme R1", ACME))
    check("the company's own member is unaffected by any of it",
          AuthStore.can_see(amy, "Acme R1", ACME)
          and not AuthStore.can_see(amy, "Acme R2", ACME))

    print("\nOnly the granting company can withdraw it")

    check("another company cannot revoke a share it did not make",
          not a.unshare_device("Acme R1", "zoe@other.test", OTHER))
    check("...and the share still stands after that attempt",
          "Acme R1" in a.shares_for_user("zoe@other.test"))
    check("the company that granted it can",
          a.unshare_device("Acme R1", "zoe@other.test", ACME))
    check("...and access ends with it",
          not AuthStore.can_see(a.get_user("zoe@other.test"), "Acme R1", ACME))

    print("\nThe owner can see what they have given away")

    shares = a.shares_of_org(ACME)
    check("every share this company granted is listed -- access nobody can "
          "enumerate is access nobody revokes",
          [s["email"] for s in shares] == ["bob@other.test"])
    check("...with whether it allows changes",
          shares[0]["can_manage"] is True)
    check("...and who granted it, so it can be asked about later",
          shares[0]["created_by"] == "owner@acme.test")

    print("\nChanging and re-granting")

    a.share_device("Acme R2", "bob@other.test", ACME, False, "owner@acme.test")
    check("re-sharing the same router to the same person UPDATES the rights "
          "rather than adding a second row",
          len(a.shares_of_org(ACME)) == 1
          and a.shares_of_org(ACME)[0]["can_manage"] is False)
    check("...and the downgrade takes effect",
          not AuthStore.can_manage_device(
              a.get_user("bob@other.test"), "Acme R2", ACME))

    print("\nDeleting the router forgets its guests")

    a.share_device("Acme R9", "zoe@other.test", ACME, True, "owner@acme.test")
    a.drop_shares_for_device("Acme R9")
    check("a name later reused by another company cannot inherit the guests "
          "of the router that used to hold it",
          "Acme R9" not in a.shares_for_user("zoe@other.test"))

    print("\nA person with no shares is unchanged")

    check("no share means no extra visibility and no extra entries",
          a.shares_for_user("amy@acme.test") == {}
          and AuthStore.allowed_devices(amy, ["Acme R1"]) == ["Acme R1"])
    check("an empty or unknown email yields nothing rather than raising",
          a.shares_for_user("") == {} and a.shares_for_user("nobody@x") == {})

    print("\nBad input is refused before anything is written")

    for bad in (("", "a@b.c"), ("R", "")):
        try:
            a.share_device(bad[0], bad[1], ACME, False, "owner@acme.test")
            check(f"a share with a missing half ({bad!r}) is refused", False)
        except ValueError:
            check(f"a share with a missing half ({bad!r}) is refused", True)
finally:
    a.close()
    try:
        os.unlink(_p)
    except OSError:
        pass

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SHARE TESTS PASSED")
