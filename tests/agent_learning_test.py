"""The antivirus agent learning from EasyMikroTik's shared threat list, and
from Windows Defender -- agent/antivirus.py, without a network or Defender.

What one PC finds is meant to protect the rest: the agent downloads the
list (only what changed), quarantines what is on it, never flags what the
support team called safe, and puts such a file back where it was found.
Defender's finds are reported with the file's fingerprint when one can be
had, which is what puts them on the list for every other PC.

Run:  ./.venv/Scripts/python.exe tests/agent_learning_test.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = tempfile.mkdtemp()
os.environ["HOME"] = os.environ["USERPROFILE"] = HOME

# ---- stand-ins for the PC-side libraries ----------------------------------
psutil = types.ModuleType("psutil")
psutil.Error = type("Error", (Exception,), {})
psutil.AF_LINK = -1
psutil.net_if_addrs = lambda: {}
psutil.process_iter = lambda attrs=None: []
requests = types.ModuleType("requests")
requests.RequestException = type("RequestException", (Exception,), {})


class Resp:
    def __init__(self, status, data=None):
        self.status_code, self._data, self.text = status, data, ""

    def json(self):
        if self._data is None:
            raise ValueError("not JSON")
        return self._data


GETS: list = []
PAGES: list = []        # what the fake EasyMikroTik answers, in order


def fake_get(url, params=None, timeout=None, headers=None):
    GETS.append({"url": url, "since": (params or {}).get("since"),
                 "auth": (headers or {}).get("Authorization")})
    r = PAGES.pop(0) if PAGES else Resp(200, {"rev": params["since"],
                                              "more": False, "items": []})
    if isinstance(r, Exception):
        raise r
    return r


requests.get = fake_get
requests.post = lambda *a, **k: Resp(200, {"ok": True})
watchdog = types.ModuleType("watchdog")
wd_events = types.ModuleType("watchdog.events")
wd_observers = types.ModuleType("watchdog.observers")
wd_events.FileSystemEventHandler = type("FileSystemEventHandler", (), {})
wd_observers.Observer = object
sys.modules.update({"psutil": psutil, "requests": requests,
                    "watchdog": watchdog, "watchdog.events": wd_events,
                    "watchdog.observers": wd_observers, "yara": None})

spec = importlib.util.spec_from_file_location(
    "antivirus", os.path.join(ROOT, "agent", "antivirus.py"))
av = importlib.util.module_from_spec(spec)
spec.loader.exec_module(av)
for d in (av.STATE_DIR, av.CONFIG["QUARANTINE_DIR"]):
    os.makedirs(d, exist_ok=True)


class Reporter:
    url = "https://em.test/api/v1/edr/alerts"
    key = "emk_alpha"

    def __init__(self):
        self.reports = []

    def report(self, event_type, severity, target="", reason="", action="",
               sha256="", details=None):
        self.reports.append({"type": event_type, "severity": severity,
                             "target": target, "reason": reason,
                             "action": action, "sha256": sha256,
                             "details": details or {}})


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def page(items, rev, more=False):
    return Resp(200, {"rev": rev, "more": more, "items": items})


DOWNLOADS = os.path.join(HOME, "Downloads")
os.makedirs(DOWNLOADS)
BAD = b"pretend this is malware found on another company's PC"
OK = b"an ordinary installer someone flagged by mistake"
engine = av.DetectionEngine(av.CONFIG["DB_PATH"])
rep = Reporter()
sync = av.ThreatSync(rep, engine)

print("Downloading the shared list")
check("asks EasyMikroTik's threat list beside where it reports",
      sync.url == "https://em.test/api/v1/edr/threats")
PAGES[:] = [page([[sha(BAD), "malicious", "Found at another company",
                   "HIGH"]], 7)]
check("a change on the list is applied", sync.once() == 1)
check("...asking from the start, with the company's key",
      GETS[-1]["since"] == 0 and GETS[-1]["auth"] == "Bearer emk_alpha")
check("...and the next look asks only for what changed since",
      engine.threat_rev() == 7 and (sync.once() == 0)
      and GETS[-1]["since"] == 7)
bad_file = os.path.join(DOWNLOADS, "invoice.exe")
with open(bad_file, "wb") as fh:
    fh.write(BAD)
found = engine.scan_file(bad_file)
check("a file another PC found is now caught here by its fingerprint",
      found and found["stage"] == "hash"
      and "another company" in found["reason"])

PAGES[:] = [page([["a" * 64, "malicious", "one", "HIGH"],
                  ["b" * 64, "malicious", "two", "LOW"]], 9, more=True),
            page([["c" * 64, "malicious", "three", "BOGUS"]], 10)]
check("a long list comes in pages until there is no more",
      sync.once() == 3 and engine.threat_rev() == 10
      and engine.known_hash("c" * 64) == ("three", "HIGH"))
PAGES[:] = [page([["d" * 64, "malicious", "x", "HIGH"]], 10, more=True)]
check("a server that keeps saying 'more' without moving on is not "
      "followed round in circles", sync.once() == 1 and len(PAGES) == 0)
PAGES[:] = [page([["not-a-hash", "malicious", "x", "HIGH"],
                  [1, 2], "junk"], 11)]
sync.once()
check("entries that are not fingerprints are ignored",
      engine.threat_rev() == 11 and engine.known_hash("not-a-hash") is None)
PAGES[:] = [page([[av._EICAR_SHA256, "removed", "", ""],
                  ["a" * 64, "removed", "", ""]], 12)]
sync.once()
check("taken off the list is forgotten -- except the built-in EICAR test, "
      "which stays so a test file always works",
      engine.known_hash("a" * 64) is None
      and engine.known_hash(av._EICAR_SHA256) is not None)
PAGES[:] = [page([[av._EICAR_SHA256, "safe", "", ""]], 12)]
sync.once()
check("...nor can it be marked safe, which would stop the test file working",
      engine.known_hash(av._EICAR_SHA256) is not None
      and not engine.is_allowed(av._EICAR_SHA256))

print("\nWhen EasyMikroTik cannot be asked")
PAGES[:] = [Resp(401)]
check("a key it does not know: nothing applied, and said why",
      sync.once() is None and "401" in sync.last_error
      and engine.threat_rev() == 12)
PAGES[:] = [requests.RequestException("no route to host")]
check("no network: nothing applied, tried again next time",
      sync.once() is None and "not reachable" in sync.last_error)
PAGES[:] = [Resp(200, None)]
check("an answer it cannot read changes nothing",
      sync.once() is None and engine.threat_rev() == 12)
lonely = av.ThreatSync(type("R", (), {"url": "", "key": ""})(), engine)
check("no address or key: it does not try", lonely.once() is None)

print("\nThe support team's 'safe'")
ok_file = os.path.join(DOWNLOADS, "setup.exe")
with open(ok_file, "wb") as fh:
    fh.write(OK)
PAGES[:] = [page([[sha(OK), "malicious", "Wrongly reported", "HIGH"]], 13)]
sync.once()
result = engine.scan_file(ok_file)
check("(a file wrongly on the list is caught)", result is not None)
av.quarantine_file(ok_file, result, rep)
check("(and quarantined)", not os.path.exists(ok_file))
with open(ok_file, "wb") as fh:
    fh.write(b"a new file has since been saved under the same name")
rep.reports.clear()
PAGES[:] = [page([[sha(OK), "safe", "Wrongly reported", "HIGH"]], 14)]
sync.once()
restored = os.path.join(DOWNLOADS, "setup (restored).exe")
check("marked safe, it comes out of quarantine -- beside the new file of "
      "the same name, which is left alone",
      os.path.isfile(restored) and open(restored, "rb").read() == OK
      and open(ok_file, "rb").read() != OK)
check("...and the quarantine holds nothing of it any more",
      not [n for n in os.listdir(av.CONFIG["QUARANTINE_DIR"])
           if "setup.exe" in n])
check("...which is reported, quietly",
      [(r["type"], r["severity"]) for r in rep.reports]
      == [("FILE_RESTORED", "LOW")] and rep.reports[0]["target"] == restored)
check("a file marked safe is never flagged again, even by its fingerprint",
      engine.scan_file(restored) is None and engine.is_allowed(sha(OK)))
PAGES[:] = [page([[sha(OK), "malicious", "Changed our minds", "HIGH"]], 15)]
sync.once()
check("...until the support team blocks it after all",
      not engine.is_allowed(sha(OK)) and engine.scan_file(restored))

print("\nWindows Defender")
DETECTIONS: list = []
THREATS = [{"ThreatID": "2147731250", "ThreatName": "Trojan:Win32/Test.A",
            "SeverityID": 5},
           {"ThreatID": "42", "ThreatName": "PUA:Win32/Annoying",
            "SeverityID": 1}]
STATUS = [{"AMRunningMode": "Normal", "AntivirusEnabled": True,
           "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 0}]


def rows(cls):
    return {"MSFT_MpThreatDetection": DETECTIONS, "MSFT_MpThreat": THREATS,
            "MSFT_MpComputerStatus": STATUS}[cls]


def detection(det_id, threat_id, resource, success=True):
    return {"DetectionID": det_id, "ThreatID": threat_id,
            "Resources": (resource,), "ActionSuccess": success}


rep = Reporter()
watch = av.DefenderWatch(rep, engine, rows=rows)
DETECTIONS[:] = [detection("{old}", "2147731250", "file:_C:\\old\\thing.exe")]
check("the first look reports nothing: what Defender found before the "
      "agent was installed is old news", watch.detections() == []
      and rep.reports == [])
gone = os.path.join(DOWNLOADS, "cracked-game.exe")
with open(gone, "wb") as fh:
    fh.write(b"scanned by the agent, then removed by Defender")
engine.scan_file(gone)
os.remove(gone)
DETECTIONS.append(detection("{new}", "2147731250", "file:_" + gone))
check("a new find is reported, named as Defender names it",
      watch.detections() == ["Trojan:Win32/Test.A"])
r = rep.reports[-1]
check("...as a threat, with Defender's severity and the file's path",
      r["type"] == "DEFENDER_DETECTION" and r["severity"] == "HIGH"
      and r["target"] == gone
      and r["reason"] == "Windows Defender found Trojan:Win32/Test.A"
      and r["details"]["threat"] == "Trojan:Win32/Test.A")
check("...with its fingerprint, though Defender had removed it: the agent "
      "had scanned it, and that is what shares it with every PC",
      r["sha256"] == sha(b"scanned by the agent, then removed by Defender"))
check("...and once only", watch.detections() == [])
still = os.path.join(DOWNLOADS, "stuck.exe")
with open(still, "wb") as fh:
    fh.write(b"Defender could not remove this one")
DETECTIONS.append(detection("{stuck}", "42", "containerfile:_" + still
                            + "->(Zip)", success=False))
watch.detections()
r = rep.reports[-1]
check("a file Defender could not remove is fingerprinted where it lies, "
      "and the email says it is still there",
      r["sha256"] == sha(b"Defender could not remove this one")
      and "could NOT" in r["action"])
check("...raised to MEDIUM though Defender called it low: the server only "
      "emails MEDIUM and up, and this one is still on the PC",
      r["severity"] == "MEDIUM")
replaced = os.path.join(DOWNLOADS, "swapped.exe")
with open(replaced, "wb") as fh:
    fh.write(b"the harmless file the agent scanned first")
engine.scan_file(replaced)
with open(replaced, "wb") as fh:
    fh.write(b"what Defender flags at that path later")
DETECTIONS.append(detection("{swap}", "2147731250", "file:_" + replaced,
                            success=False))
watch.detections()
check("a file replaced since the agent scanned it is fingerprinted as it is "
      "now, not as the harmless file that was there before",
      rep.reports[-1]["sha256"] == sha(b"what Defender flags at that path later"))
DETECTIONS.append(detection("{proc}", "999", "process:_pid:4242"))
watch.detections()
r = rep.reports[-1]
check("a find that is not a file still reports, without a fingerprint",
      r["sha256"] == "" and r["reason"] == "Windows Defender found "
                                          "threat 999")
check("the paths Defender gives are read whichever kind they are",
      av._defender_path("webfile:_C:\\d\\x.exe|https://e.test/x|pid:1")
      == "C:\\d\\x.exe" and av._defender_path("process:_pid:9") == "")

rep.reports.clear()
check("Defender on and up to date: nothing said", watch.health() is True
      and rep.reports == [])
STATUS[0]["RealTimeProtectionEnabled"] = False
check("real-time protection switched off is reported",
      watch.health() is False and [r["type"] for r in rep.reports]
      == ["DEFENDER_OFF"] and "real-time" in rep.reports[0]["reason"])
watch.health()
check("...once, not every five minutes", len(rep.reports) == 1)
STATUS[0]["RealTimeProtectionEnabled"] = True
watch.health()
check("back on is reported, quietly",
      rep.reports[-1]["type"] == "DEFENDER_OK"
      and rep.reports[-1]["severity"] == "LOW")
STATUS[0]["AntivirusSignatureAge"] = 12
check("definitions 12 days old count as off too",
      watch.health() is False and rep.reports[-1]["type"] == "DEFENDER_OFF"
      and "12 days old" in rep.reports[-1]["reason"])
STATUS[0]["AntivirusSignatureAge"] = 0
watch.health()
STATUS[0].update({"AMRunningMode": "Passive Mode",
                  "RealTimeProtectionEnabled": False})
n = len(rep.reports)
check("passive while another antivirus is in charge is not 'off'",
      watch.health() is True and len(rep.reports) == n)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL AGENT LEARNING TESTS PASSED")
