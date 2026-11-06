"""A line whose gateway answers but whose ISP is dead must not read as online.

RouterOS keeps a default route "active" while the modem answers, whatever
is behind it. So the WAN check also asks the router to ping the internet --
and only believes "no answer" on a router whose pings have been answered
before, because some firewalls and ISPs drop pings on working lines.

Run: python tests/wan_probe_test.py
"""
import os
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mikromon.checks import wan as W  # noqa: E402
from mikromon.checks.wan import WanCheck  # noqa: E402
from mikromon.context import CheckContext  # noqa: E402
from mikromon.state import StateStore  # noqa: E402

FAILS = []
T0 = 1_800_000_000.0


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Handle:
    def __init__(self, loss):
        self.loss, self.asked = loss, []

    def ping(self, address, count=3, interval=""):
        self.asked.append(address)
        return self.loss.get(address) if isinstance(self.loss, dict) else self.loss


ACTIVE = [{"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": "true",
           "gateway-status": "10.0.0.1 reachable via ether1", "distance": "1"}]
INACTIVE = [dict(ACTIVE[0], active="false",
                 **{"gateway-status": "10.0.0.1 unreachable"})]


def run(loss, routes=ACTIVE, targets=None, memory=None, now=T0, handle=True):
    """One poll with a fake router. Returns (healthy, details) for
    internet_down, the fake ping handle, and the probe's memory."""
    seen = {}
    memory = {} if memory is None else memory
    h = Handle(loss) if handle else None
    snap = NS(errors={}, handle=h, rows=lambda n: routes if n == "route" else [])
    dev = NS(check_enabled=lambda k: k == "internet_down",
             wan=NS(links=[], ping_targets=targets or []))
    ctx = NS(store=NS(data={}), device="r1", now=now,
             memory=lambda ns: memory,
             transition=lambda key, healthy, **kw: seen.update({key: (healthy, kw)}))
    WanCheck().run(snap, dev, ctx)
    return seen.get("internet_down"), h, memory


print("A router whose pings have been answered before")
answered = {"answered": T0 - 60}
r, _, mem = run(100, memory=dict(answered))
check("route active but nothing answers: internet is DOWN",
      r[0] is False and "nothing gets through" in r[1]["title"]
      and "1.1.1.1, 8.8.8.8" in r[1]["cause"] and "ISP" in r[1]["cause"])
r, _, mem = run(0)
check("route active and pings answer: fine, and remembered as answered",
      r[0] is True and mem.get("answered") == T0)
r, _, _ = run(50, memory=dict(answered))
check("some loss is a poor line, not a dead one", r[0] is True)
r, h, _ = run({"1.1.1.1": 100, "8.8.8.8": 0}, memory=dict(answered))
check("one blocked target does not condemn a working line",
      r[0] is True and h.asked == ["1.1.1.1", "8.8.8.8"])
r, h, _ = run({"1.1.1.1": None, "8.8.8.8": 100}, memory=dict(answered))
check("only the target that really did not answer is named",
      r[0] is False and "8.8.8.8" in r[1]["cause"] and "1.1.1.1" not in r[1]["cause"])
r, h, _ = run(100, targets=["9.9.9.9"], memory=dict(answered))
check("the router's own ping targets are used when set",
      r[0] is False and h.asked == ["9.9.9.9"])

print("A router where pings cannot be trusted")
r, _, mem = run(100)
check("never answered (a firewall or ISP that drops pings): NOT called down",
      r[0] is True and "not used" in r[1]["facts"]["internet_probe"])
r, _, _ = run(100, memory={"answered": T0 - 31 * 86400})
check("...nor when the last answer was over a month ago", r[0] is True)
r, _, mem = run(None, memory=dict(answered))
check("a ping that cannot be run at all is not 'down'",
      r[0] is True and r[1]["facts"]["internet_probe"] == "unavailable"
      and mem.get("unavailable_logged") is True)
r, _, mem = run(0, memory=mem)
check("...and is noted again only once it has worked in between",
      "unavailable_logged" not in mem)
r, h, _ = run(100, handle=False, memory=dict(answered))
check("no API handle: nothing is pinged and nothing is decided", r[0] is True)

print("When the route itself says it")
r, h, _ = run(0, routes=INACTIVE)
check("no active route: down, and the active probe is not what decided it",
      r[0] is False and "unreachable" in r[1]["cause"]
      and r[1]["title"].endswith("all WAN uplinks unreachable"))
r, h, _ = run(0, routes=[])
check("no default route at all: down, without pinging",
      r[0] is False and "no default route" in r[1]["title"] and h.asked == [])

print("Debounced like every other alert")
store = StateStore(os.devnull)
mem = {"answered": T0 - 60}


def poll(loss, now):
    ctx = CheckContext("r1", store, now=now, default_confirm=2)
    snap = NS(errors={}, handle=Handle(loss),
              rows=lambda n: ACTIVE if n == "route" else [])
    dev = NS(check_enabled=lambda k: k == "internet_down",
             wan=NS(links=[], ping_targets=[]))
    store.memory("r1", "internet_probe").update(mem)
    WanCheck().run(snap, dev, ctx)
    return [a for a in ctx.alerts if a.key == "internet_down"]


check("one poll with no answer raises nothing", poll(100, T0) == [])
check("the second in a row raises the alert", len(poll(100, T0 + 60)) == 1)
check("one answered poll does not clear it yet", poll(0, T0 + 120) == [])
alerts = poll(0, T0 + 180)
check("the second answered poll says the internet is back",
      len(alerts) == 1 and alerts[0].recovery)

print()
print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL WAN PROBE TESTS PASSED")
sys.exit(1 if FAILS else 0)
