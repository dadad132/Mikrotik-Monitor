"""The AI monitor: a site loses its main line -- when, why, and a reminder
until it is back.

Covers, without a router, a mail server or an AI key:
  * the router's own evidence turning into a plain likely cause, in the
    alert that goes out (dead port = the box or its power; live port = ISP)
  * the fleet: several sites on one ISP dropping together is an outage
  * a change sent minutes before being named as the first suspect
  * the online check: the request it makes, the answer it reads back, the
    sources it keeps, one search shared by sites that dropped together, the
    daily limit, and failures that retry instead of vanishing
  * the follow-up email, and the "still on the backup line" reminders
  * data used on the backup line, and incidents closing themselves

Run:  ./.venv/Scripts/python.exe tests/aimonitor_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import aimonitor as am  # noqa: E402
from mikromon.alert import Alert, Severity  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, build_device  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.incidents import IncidentStore, norm_key  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


T0 = 1_800_000_000.0
tmp = tempfile.mkdtemp()


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def dev_raw(name, isp="Vumatel", location="Umhlanga, Durban"):
    return {"name": name, "host": "10.10.0.9", "location": location,
            "wan": {"links": [{"name": isp, "interface": "ether1"},
                              {"name": "LTE", "interface": "lte1"}]}}


def failover(device, ts, evidence=None, recovery=False):
    return Alert(device, "wan_failover", Severity.WARNING,
                 "Primary WAN down" if not recovery else "WAN restored",
                 cause="Primary uplink is not carrying traffic.",
                 recovery=recovery, ts=ts,
                 facts={"primary_link": "Vumatel", "current_link": "LTE",
                        "evidence": evidence or {}})


def state_for(**conds):
    """{"devices": {name: {"conditions": {"wan_failover": {...}}, ...}}}"""
    return {"devices": conds}


DEAD_PORT = {"primary_iface": "ether1", "primary_running": False,
             "primary_status": "unreachable", "backup_iface": "lte1",
             "backup_rx": 1_000_000, "backup_tx": 500_000,
             "log": ["09:41:02 ether1 link down"]}
LIVE_PORT_PPPOE = {"primary_iface": "pppoe-out1", "primary_running": False,
                   "primary_type": "pppoe-out", "pppoe": "down"}

print("what the router's own evidence means")
d = am.rule_diagnosis("wan_failover", DEAD_PORT, {}, None, link="Vumatel",
                      isp="Vumatel")
check("a port with no link is the ISP's box, its power or the cable -- and "
      "says load-shedding looks exactly like this",
      d["verdict"] == "local_power" and "load-shedding" in d["summary"]
      and "lights" in d["action"])
d = am.rule_diagnosis("wan_failover", {"primary_iface": "ether1",
                                       "primary_running": True,
                                       "pppoe": "down"}, {}, None,
                      isp="Vumatel")
check("a live port with the PPPoE session down is the ISP's side",
      d["verdict"] == "isp_side" and "PPPoE" in d["summary"])
d = am.rule_diagnosis("wan_failover", {"primary_running": True,
                                       "dhcp_status": "searching..."}, {}, None)
check("a live port the ISP's box stopped giving an address on says so",
      d["verdict"] == "isp_side" and "DHCP" in d["summary"])
d = am.rule_diagnosis("wan_failover", DEAD_PORT, {"same_isp": 3}, None,
                      isp="Vumatel")
check("three other sites on the same ISP dropping together outranks the "
      "local evidence: it is an outage at the ISP",
      d["verdict"] == "isp_outage" and d["confidence"] == "high"
      and "3 other sites on Vumatel" in d["summary"])
d = am.rule_diagnosis("wan_failover", DEAD_PORT, {"same_isp": 3}, 4,
                      isp="Vumatel")
check("a change sent four minutes before is named first: it is the one "
      "thing somebody here can undo",
      d["verdict"] == "change" and "4 min" in d["summary"])
check("a generic link name is not taken for the ISP's name",
      am.isp_of("Fibre") == "" and am.isp_of("ether1") == ""
      and am.isp_of("WAN1") == "" and am.isp_of("Vumatel") == "Vumatel")
check("the ISP and area compare the way people type them",
      norm_key("Vumatel (Pty) Ltd") == norm_key("vumatel")
      and norm_key("Umhlanga,  Durban") == norm_key("umhlanga durban"))

# ---- a monitor with real stores ------------------------------------------
adb, ddb = os.path.join(tmp, "a.db"), os.path.join(tmp, "d.db")
auth = AuthStore(adb)
org = auth.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
auth.set_alert_emails(org, ["ops@alpha.test"])
org2 = auth.signup("owner@beta.test", "a-password-for-the-test", "Beta")
auth.set_alert_emails(org2, ["ops@beta.test"])
auth.close()
ds = DevicesStore(ddb)
for n, o in (("R1", org), ("R2", org2), ("R3", org2), ("R4", org2)):
    ds.upsert(dev_raw(n), DEFAULT_THRESHOLDS, org_id=o)
ds.close()
devices = [build_device(dev_raw(n), DEFAULT_THRESHOLDS)
           for n in ("R1", "R2", "R3", "R4")]

sent = []
clk = Clock()


def new_monitor(path, analyzer=None, **kw):
    return am.AIMonitor(IncidentStore(path), auth_db=adb, devices_db=ddb,
                        poll_interval=60, confirmations=2, clock=clk,
                        analyzer=analyzer,
                        sender=lambda to, s, t, h: sent.append((to, s, t, h)),
                        **kw)


print("\nwhat the router shows at the moment of failover")
from mikromon.checks.wan import _link_evidence  # noqa: E402
from mikromon.config import WanEndpoint  # noqa: E402
from mikromon.device import Snapshot  # noqa: E402

snap = Snapshot()
snap.data = {
    "interface": [{"name": "ether1", "type": "ether", "running": "false",
                   "disabled": "false"},
                  {"name": "lte1", "type": "lte", "running": "true",
                   "rx-byte": "123456", "tx-byte": "7890"}],
    "dhcp_client": [{"interface": "ether1", "status": "searching..."}],
    "log": [{"time": "09:40:58", "message": "user admin logged in"},
            {"time": "09:41:02", "message": "ether1 link down"}],
}
links = [WanEndpoint(interface="ether1", name="Vumatel"),
         WanEndpoint(interface="lte1", name="LTE")]
ev = _link_evidence(snap, links, 1, {"gateway-status": "10.0.0.1 unreachable"})
check("the main line's port, DHCP and gateway state are captured",
      ev["primary_running"] is False and ev["dhcp_status"] == "searching..."
      and ev["primary_status"] == "10.0.0.1 unreachable")
check("...the router's own log lines about it, and nothing else",
      ev["log"] == ["09:41:02 ether1 link down"])
check("...and the backup line's counters, to measure what it carries",
      ev["backup_iface"] == "lte1" and ev["backup_rx"] == 123456
      and ev["backup_tx"] == 7890)

print("\na failover becomes an incident")
mon = new_monitor(os.path.join(tmp, "i1.db"))
a = failover("R1", T0, DEAD_PORT)
st = state_for(R1={"conditions": {"wan_failover": {"status": "problem",
                                                    "since": T0}}})
mon.observe([a], st, devices)
inc = mon.store.open_for("R1")
check("one incident, started one poll before the alert confirmed it",
      inc is not None and inc["started"] == T0 - 60 and inc["kind"]
      == "wan_failover")
check("it knows the ISP and the site's area (from the device's Location)",
      inc["isp"] == "Vumatel" and inc["area"] == "Umhlanga, Durban")
check("the alert going out already carries the likely cause",
      "Likely cause: The port the Vumatel line plugs into (ether1)" in a.cause)
check("with the AI switched off, the router's reading stands on its own",
      inc["ai_state"] == "off" and inc["verdict"] == "local_power")
mon.observe([a], st, devices)
check("the same outage re-announced (a restart) is still one incident",
      len(mon.store.recent("R1", 0)) == 1)

print("\ndata used on the backup line")
st["devices"]["R1"]["memory"] = {"wan_traffic": {"last": {
    "LTE1": {"rx": 801_000_000, "tx": 100_500_000, "ts": T0 + 600}}}}
used = am.backup_bytes_used(mon.store.open_for("R1"), st)
check("counted from the backup line's counters at the failover",
      used == 800_000_000 + 100_000_000)
check("...and shown the way people read it", am.human_bytes(used) == "900.0 MB")

print("\nthe line comes back")
clk.t = T0 + 3600
st["devices"]["R1"]["conditions"]["wan_failover"] = {"status": "ok"}
mon.observe([failover("R1", T0 + 3600, recovery=True)], st, devices)
done = mon.store.latest("R1")
check("the incident is closed, with the data the backup line carried",
      done["ended"] == T0 + 3600 and done["backup_bytes"] == 900_000_000)

print("\nan incident left open by a missed recovery closes itself")
mon.store.open_incident("R4", "wan_failover", started=T0, detected=T0)
mon.observe([], state_for(R4={"conditions": {"wan_failover": {
    "status": "ok", "since": T0 + 50}}}), devices)
check("the next poll that sees the line fine closes it",
      mon.store.open_for("R4") is None)

print("\nthe fleet: everyone on one ISP at once")
mon = new_monitor(os.path.join(tmp, "i2.db"))
clk.t = T0
for i, n in enumerate(("R2", "R3", "R4")):
    mon.store.open_incident(n, "wan_failover", started=T0 - 300 + i * 60,
                            detected=T0, isp="Vumatel", area="Elsewhere")
a = failover("R1", T0, DEAD_PORT)
mon.observe([a], state_for(R1={"conditions": {"wan_failover": {
    "status": "problem"}}}), devices)
inc = mon.store.open_for("R1")
check("three other sites on Vumatel within 20 minutes makes it an ISP "
      "outage, whatever this router's port says",
      inc["verdict"] == "isp_outage" and inc["evidence"]["fleet"]["same_isp"] == 3)

print("\nthe online check")


class Block(types.SimpleNamespace):
    pass


def answer_blocks(text, cites=()):
    return [Block(type="server_tool_use", name="web_search"),
            Block(type="web_search_tool_result", content=[]),
            Block(type="text", text=text, citations=[
                Block(type="web_search_result_location", url=u, title=t,
                      cited_text="...") for u, t in cites])]


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        client = self

        class Msgs:
            def create(self, **kw):
                client.calls.append(kw)
                return client.responses.pop(0)

        self.beta = types.SimpleNamespace(messages=Msgs())


def resp(stop, content, searches=1):
    return types.SimpleNamespace(
        stop_reason=stop, content=content,
        usage=types.SimpleNamespace(server_tool_use=types.SimpleNamespace(
            web_search_requests=searches)))


GOOD = ("VERDICT: isp_outage\nCONFIDENCE: high\n"
        "SUMMARY: Vumatel reports a fibre outage in Umhlanga since 09:30, "
        "estimated fix 13:00.\nACTION: Wait for Vumatel; no site visit needed.")
inc_for_ai = mon.store.open_for("R1")
fc = FakeClient([
    resp("pause_turn", answer_blocks("searching")),
    resp("end_turn", answer_blocks(GOOD, [
        ("https://status.vumatel.co.za/x", "Vumatel status"),
        ("https://status.vumatel.co.za/x", "Vumatel status"),
        ("https://news.example/y", "Outage news")]), searches=2)])
settings = {"enabled": True, "api_key": "k", "web_search": True,
            "max_searches": 3, "daily_limit": 40, "country": "za",
            "timezone": "Africa/Johannesburg"}
res = am.claude_analyze(inc_for_ai, settings, now=T0 + 120, client=fc)
first = fc.calls[0]
tool = first["tools"][0]
check("it asks Claude Opus 5.5 with the current web search tool",
      first["model"] == "claude-opus-5-5"
      and tool["type"] == "web_search_20260318" and tool["max_uses"] == 3)
check("...localised to the site's city, country and time zone",
      tool["user_location"] == {"type": "approximate", "country": "ZA",
                                "timezone": "Africa/Johannesburg",
                                "city": "Durban"})
check("...with the server-side refusal fallback switched on",
      first["fallbacks"] == "default"
      and first["betas"] == ["server-side-fallback-2026-07-01"]
      and first["output_config"] == {"effort": "medium"})
prompt = first["messages"][0]["content"]
check("the question carries the ISP, the area, the time and the evidence "
      "-- and not the company's or the router's name",
      "Vumatel" in prompt and "Umhlanga, Durban" in prompt
      and "Port ether1: no link" in prompt and "R1" not in prompt
      and "Alpha" not in prompt)
check("a paused search turn is sent back unchanged so the server carries on",
      len(fc.calls) == 2 and fc.calls[1]["messages"][1]["role"] == "assistant")
check("the answer is read back field by field",
      res["verdict"] == "isp_outage" and res["confidence"] == "high"
      and "estimated fix 13:00" in res["summary"]
      and res["action"].startswith("Wait for Vumatel"))
check("only the pages it actually cited are kept, once each",
      [s["url"] for s in res["sources"]]
      == ["https://status.vumatel.co.za/x", "https://news.example/y"])
check("searches are counted across the paused and resumed calls",
      res["searches"] == 3)
fc = FakeClient([resp("refusal", [])])
try:
    am.claude_analyze(inc_for_ai, settings, client=fc)
    refused = False
except am.AIError:
    refused = True
check("a declined request is an error to show, not an empty answer", refused)
check("an answer in the wrong shape keeps what was said",
      am.parse_answer("The ISP says it is down in the area.")["summary"]
      == "The ISP says it is down in the area.")

print("\nthe worker: one search per outage, shared, within a limit")
auth = AuthStore(adb)
auth.set_ai(dict(settings))
auth.close()
calls = []


def fake_analyzer(inc, s, now):
    calls.append(inc["device"])
    return {"verdict": "isp_outage", "confidence": "high",
            "summary": "Vumatel reports an outage in Umhlanga.",
            "action": "Wait for Vumatel.", "searches": 2,
            "sources": [{"url": "https://status.vumatel.co.za/x",
                         "title": "Vumatel status"}]}


sent.clear()
clk.t = T0
mon = new_monitor(os.path.join(tmp, "i3.db"), analyzer=fake_analyzer)
st = state_for(R1={"conditions": {"wan_failover": {"status": "problem"}}},
               R2={"conditions": {"wan_failover": {"status": "problem"}}})
mon.observe([failover("R1", T0, DEAD_PORT), failover("R2", T0, DEAD_PORT)],
            st, devices)
check("with the AI switched on, a new outage waits for its online check",
      mon.store.open_for("R1")["ai_state"] == "pending")
mon.work_once()
r1, r2 = mon.store.open_for("R1"), mon.store.open_for("R2")
check("two sites on the same ISP in the same area cost ONE search",
      calls == ["R1"] and r1["ai_state"] == r2["ai_state"] == "done"
      and r2["summary"] == r1["summary"])
check("the online answer replaces the router's guess, with its sources",
      r1["verdict"] == "isp_outage" and r1["sources"][0]["title"]
      == "Vumatel status")
subjects = sorted(s for _, s, _, _ in sent)
check("each company is told the possible cause once, by its own people",
      len(sent) == 2 and all("possible cause" in s for s in subjects)
      and sorted(tuple(t) for t, _, _, _ in sent)
      == [("ops@alpha.test",), ("ops@beta.test",)])
body = sent[0][2]
check("the email says when it went, the cause, what to do, and the sources",
      "Possible cause (high confidence)" in body and "Wait for Vumatel" in body
      and "https://status.vumatel.co.za/x" in body
      and "What the router showed" in body)
check("...and that reminders follow while it stays on the backup",
      "reminded every 2 hours" in body)
mon.work_once()
check("it is not mailed twice", len(sent) == 2)

auth = AuthStore(adb)
auth.set_ai(dict(settings, daily_limit=1))
auth.close()
mon.store.open_incident("R3", "wan_failover", started=T0, detected=T0,
                        isp="Openserve", area="Paarl")
mon.store.update(mon.store.open_for("R3")["id"], ai_state="pending")
mon.work_once()
check("past the daily limit the check is skipped and says why",
      mon.store.open_for("R3")["ai_state"] == "skipped"
      and "limit" in mon.store.open_for("R3")["ai_error"])


def broken(inc, s, now):
    raise am.AIError("The AI key was rejected.")


auth = AuthStore(adb)
auth.set_ai(dict(settings))
auth.close()
mon2 = new_monitor(os.path.join(tmp, "i4.db"), analyzer=broken)
mon2.store.open_incident("R3", "wan_failover", started=T0, detected=T0,
                         isp="Openserve", area="Paarl")
mon2.store.update(mon2.store.open_for("R3")["id"], ai_state="pending")
mon2.work_once()
r3 = mon2.store.open_for("R3")
check("a failed check is recorded with its reason for the Platform panel",
      r3["ai_state"] == "failed" and "rejected" in r3["ai_error"]
      and mon2.store.ai_usage(0)["failed"] == 1)
clk.t = T0 + am.RETRY_FAILED + 1
mon2.analyzer = fake_analyzer
mon2.work_once()
check("...and tried again half an hour later", mon2.store.open_for("R3")
      ["ai_state"] == "done")

print("\nstill on the backup line")
sent.clear()
clk.t = T0 + 30 * 60
mon.check_reminders(st)
check("nothing before the first interval has passed", sent == [])
clk.t = T0 + 2 * 3600 + 5
st["devices"]["R1"]["memory"] = {"wan_traffic": {"last": {
    "lte1": {"rx": 3_000_000_000, "tx": 100_500_000}}}}
mon.check_reminders(st)
alpha = [m for m in sent if m[0] == ["ops@alpha.test"]]
check("after two hours the company is reminded the site is STILL on backup",
      len(alpha) == 1 and "R1 is still on its backup line" in alpha[0][1])
check("...how long, how much data the backup has carried, and the latest "
      "possible cause with its source",
      "2 hours" in alpha[0][1] and "3.1 GB used on it" in alpha[0][2]
      and "Vumatel reports an outage" in alpha[0][2]
      and "https://status.vumatel.co.za/x" in alpha[0][2])
n = len(sent)
clk.t += 600
mon.check_reminders(st)
check("not again until the next interval", len(sent) == n)
auth = AuthStore(adb)
auth.set_backup_reminder_hours(org, 0)
auth.close()
clk.t += 3 * 3600
sent.clear()
mon.check_reminders(st)
check("a company that switched reminders off gets none -- the other still "
      "does", all(m[0] != ["ops@alpha.test"] for m in sent)
      and any(m[0] == ["ops@beta.test"] for m in sent))
auth = AuthStore(adb)
auth.set_backup_reminder_hours(org, 2)
auth.close()
quiet = new_monitor(os.path.join(tmp, "i3.db"), quiet=lambda: True)
sent.clear()
clk.t += 3 * 3600
quiet.check_reminders(st)
check("nothing is mailed during the startup grace", sent == [])

print("\nthe reminder email reads well for several sites")
subj, text, _h = am.reminder_email("Beta", [
    {"device": "R2", "primary_link": "Vumatel", "backup_link": "LTE",
     "started": T0, "seconds": 3 * 3600, "used": "1.2 GB",
     "verdict": "isp_outage", "summary": "Vumatel reports an outage.",
     "sources": []},
    {"device": "R3", "primary_link": "Openserve", "backup_link": "LTE",
     "started": T0, "seconds": 26 * 3600, "used": "", "verdict": "",
     "summary": "", "sources": []}], "[EM]", 2)
check("the count is in the subject", subj == "[EM] 2 sites still on their "
      "backup line — Beta")
check("each site with its duration", "3 hours" in text
      and "1 day 2 hours" in text)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL AI MONITOR TESTS PASSED")
