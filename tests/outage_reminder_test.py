"""A router went down, the alert fired once, and nobody saw it.

The device stayed down. Nothing said so again until somebody happened to
open the dashboard, by which time it had been off for days.

That is the failure mode of every alert that fires on a TRANSITION: the
message is sent at the moment the state changes, which is exactly the moment
nobody is looking. One missed email and the outage is invisible -- not
degraded, not delayed, invisible.

So this is not another alert and not a summary of a period. It is a standing
reminder of what is down RIGHT NOW, repeated every twelve hours until it
stops being true, built from live state rather than from whether an earlier
email happened to be delivered.

Most of this file is about the two ways a reminder like this goes wrong:
saying something when there is nothing to say, until people filter it; and
marking itself sent when it was not.

Run:  python tests/outage_reminder_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.auth import OUTAGE_REMINDER_SECONDS, AuthStore
from mikromon.config import SmtpConfig
from mikromon.notify import org_email
from mikromon.notify.org_email import (OrgEmailNotifier, _build_outage_reminder,
                                       _for_how_long, offline_devices)

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


HOUR = 3600.0
NOW = time.time()


def state_with(**devices):
    return {"devices": devices}


def down(since_hours, identity="R1", model="RB2011iL", host="10.10.0.2"):
    return {"conditions": {"reachability": {"status": "problem",
                                            "since": NOW - since_hours * HOUR}},
            "facts": {"identity": identity, "model": model, "host": host}}


def up(identity="R1"):
    return {"conditions": {"reachability": {"status": "ok"}},
            "facts": {"identity": identity}}


print("What is down, read from what is true now")

_st = state_with(alpha=down(74), bravo=up("Bravo"), charlie=down(3, "Charlie"))
_off = offline_devices(["alpha", "bravo", "charlie"], _st, NOW)
check("only the devices that are actually down are listed",
      [d["name"] for d in _off] == ["alpha", "charlie"])
check("...longest outage first, because the one down for three days is the "
      "one somebody has been getting away with not looking at",
      _off[0]["name"] == "alpha")
check("...carrying how long, which is the figure that decides whether this "
      "is a blip or a site nobody has visited",
      round(_off[0]["seconds"] / HOUR) == 74)
check("...and the identity somebody recognises, not the internal name",
      _off[1]["identity"] == "Charlie")

check("a device with no reachability condition at all is not reported down "
      "-- unknown is not the same as offline",
      offline_devices(["ghost"], state_with(ghost={}), NOW) == [])
check("a device that is up is not reported, however long it has been up",
      offline_devices(["bravo"], _st, NOW) == [])
check("an org with no devices has nothing to report",
      offline_devices([], _st, NOW) == [])

print("\nHow long, in words a person acts on")

check("minutes while it is still minutes", _for_how_long(90) == "1 minute")
check("hours once it is hours", _for_how_long(5 * HOUR) == "5 hours")
check("...still hours at a day, because '1 day 2 hours' is harder to "
      "compare than '26 hours'", _for_how_long(26 * HOUR) == "26 hours")
check("days once counting hours stops helping",
      _for_how_long(74 * HOUR) == "3 days 2 hours")
check("...with no trailing '0 hours' on a whole number of days",
      _for_how_long(7 * 24 * HOUR) == "7 days")
check("a fault with no start time says so rather than claiming zero",
      _for_how_long(None) == "an unknown time")

print("\nThe message itself")

_subj, _txt, _htm = _build_outage_reminder("Alpha Freight", _off, "[mm]", 12)
check("the count is in the subject, because that is the part read on a "
      "phone at 6am and it decides whether the rest gets opened",
      "2 devices still offline" in _subj and "Alpha Freight" in _subj)
check("one device is not called '1 devices'",
      "1 device still offline" in _build_outage_reminder(
          "Alpha", _off[:1], "[mm]", 12)[0])
check("every offline device is named in the body",
      "Charlie" in _txt and "R1" in _txt)
check("...with how long each has been down",
      "3 days 2 hours" in _txt and "3 hours" in _txt)
check("...and where to find it, since somebody may have to drive there",
      "10.10.0.2" in _txt and "RB2011iL" in _txt)
check("it says plainly that it is a reminder rather than a new fault, so "
      "nobody treats the fourteenth one as a fourteenth outage",
      "reminder, not a new fault" in _txt)
check("...and that it stops by itself, so nobody goes looking for a way to "
      "switch it off", "stops by itself" in _txt)
check("the html carries the same devices, for a reader whose client shows "
      "it", "Charlie" in _htm and "3 days 2 hours" in _htm)

print("\nWhen it fires, and when it stays quiet")

d = tempfile.mkdtemp()
adb = os.path.join(d, "auth.db")
auth = AuthStore(adb)
org = auth.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
auth.set_alert_emails(org, ["ops@alpha.test"])
auth.close()

auth = AuthStore(adb)
check("an org that has never been reminded is due immediately -- the first "
      "fault on a new install must not wait half a day for a clock that "
      "never started",
      [o["org_id"] for o in auth.orgs_due_an_outage_reminder(NOW)] == [org])

auth.set_outage_reminded(org, NOW)
check("...and is not due again straight afterwards",
      auth.orgs_due_an_outage_reminder(NOW) == [])
check("...nor at eleven hours",
      auth.orgs_due_an_outage_reminder(NOW + 11 * HOUR) == [])
check("...but is at twelve",
      len(auth.orgs_due_an_outage_reminder(
          NOW + OUTAGE_REMINDER_SECONDS + 1)) == 1)
auth.close()


class Devices:
    def __init__(self, names):
        self.names = names

    def names_for_org(self, org_id):
        return list(self.names)


class State:
    def __init__(self, data):
        self.data = data


def notifier_for(adb_path):
    smtp = SmtpConfig(host="localhost", port=25, from_addr="a@b.test",
                      subject_prefix="[mm]")
    return OrgEmailNotifier(smtp, adb_path, os.path.join(d, "devices.db"))


sent = []
_real_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
try:
    # Nothing down: the clock must NOT be reset, or the next fault waits
    # twelve hours to be mentioned.
    auth = AuthStore(adb)
    auth.set_outage_reminded(org, None)
    auth.close()

    n = notifier_for(adb)
    n.check_outage_reminders(State(state_with(alpha=up())), Devices(["alpha"]))
    check("nothing offline sends nothing -- an 'all clear' every twelve "
          "hours is the fastest way to teach somebody to filter the address",
          sent == [])

    auth = AuthStore(adb)
    still_due = [o["org_id"] for o in auth.orgs_due_an_outage_reminder(NOW)]
    auth.close()
    check("...and the clock is NOT reset by a quiet pass, so a fault "
          "starting a minute later is reported at once rather than in "
          "twelve hours", still_due == [org])

    # The case this whole feature exists for: something IS down.
    n.check_outage_reminders(State(state_with(alpha=down(74, "ECA Richards"))),
                             Devices(["alpha"]))
    check("a device that is down DOES produce an email", len(sent) == 1)
    check("...to the org's alert recipients",
          sent[0]["To"] == "ops@alpha.test")
    _body = sent[0].get_body(preferencelist=("plain",)).get_content()
    check("...naming the device and how long it has been down",
          "ECA Richards" in _body and "3 days" in _body)

    # Straight away again: this must not turn into an email per poll.
    n.check_outage_reminders(State(state_with(alpha=down(74, "ECA Richards"))),
                             Devices(["alpha"]))
    check("...and the next poll two minutes later sends NOTHING, because a "
          "reminder per poll is an alert storm, not a reminder",
          len(sent) == 1)

    # Twelve hours on, still down: the point of the feature.
    auth = AuthStore(adb)
    auth.set_outage_reminded(org, time.time() - OUTAGE_REMINDER_SECONDS - 1)
    auth.close()
    n.check_outage_reminders(State(state_with(alpha=down(86, "ECA Richards"))),
                             Devices(["alpha"]))
    check("twelve hours later, with the device STILL down, it is reported "
          "again -- which is the whole feature: one missed email can no "
          "longer hide an outage", len(sent) == 2)

    # And it stops on its own.
    auth = AuthStore(adb)
    auth.set_outage_reminded(org, time.time() - OUTAGE_REMINDER_SECONDS - 1)
    auth.close()
    n.check_outage_reminders(State(state_with(alpha=up())), Devices(["alpha"]))
    check("...and stops the moment the device comes back, with no 'resolved' "
          "email to train anybody to ignore the next one", len(sent) == 2)

    # A send that fails must be retried, not silently marked done.
    auth = AuthStore(adb)
    auth.set_outage_reminded(org, None)
    auth.close()
    org_email._smtp_send = lambda cfg, msg: (_ for _ in ()).throw(
        OSError("mail server refused the connection"))
    n.check_outage_reminders(State(state_with(alpha=down(5))),
                             Devices(["alpha"]))
    auth = AuthStore(adb)
    _due = [o["org_id"] for o in auth.orgs_due_an_outage_reminder(time.time())]
    auth.close()
    check("a reminder that could not be DELIVERED is still due, rather than "
          "marked sent -- the one thing worse than a missed outage is a "
          "system that believes it reported one", _due == [org])
finally:
    org_email._smtp_send = _real_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL OUTAGE REMINDER TESTS PASSED")
