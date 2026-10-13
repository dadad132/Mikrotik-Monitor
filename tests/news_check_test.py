"""The AI monitor's online check with no AI and no key: the news.

Google News publishes any search as an RSS feed. The check reads the last
two days of headlines about the provider's network and about power cuts in
the site's area, keeps only those that name the provider (or a power cut)
AND say something is wrong, and weighs them against what the router itself
showed -- a port that lost its link is power at the box, which a headline
about the ISP's network does not explain.

Run:  ./.venv/Scripts/python.exe tests/news_check_test.py
"""
from __future__ import annotations

import os
import sys
import time
from email.utils import formatdate
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import aimonitor as A
from mikromon.web_ai import ai_settings_box

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


NOW = time.time()


def feed(*items):
    """A Google News RSS feed: items are (title, source, age in hours)."""
    body = "".join(
        f"<item><title>{t} - {s}</title>"
        f"<link>https://news.google.com/rss/articles/{i}</link>"
        f"<pubDate>{formatdate(NOW - h * 3600)}</pubDate>"
        f'<source url="https://x.test">{s}</source></item>'
        for i, (t, s, h) in enumerate(items))
    return (f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0">'
            f"<channel><title>t</title>{body}</channel></rss>").encode()


def fetcher(net=(), power=()):
    asked = []

    def fetch(url):
        q = unquote_plus(url.split("q=", 1)[1].split("&", 1)[0])
        asked.append(q)
        return feed(*(power if "load shedding" in q else net))
    fetch.asked = asked
    return fetch


def inc(port_up=True, isp="Vumatel", area="Umhlanga, Durban", fleet=None):
    return {"kind": "wan_failover", "isp": isp, "area": area,
            "primary_link": isp or "ether1", "started": NOW - 900,
            "evidence": {"primary_running": port_up, "primary_iface": "ether1",
                         "fleet": fleet or {}}}


S = {"country": "ZA", "max_searches": 3}

print("Reading the headlines")
f = fetcher(net=[("Vumatel outage hits Durban homes", "IOL", 3),
                 ("Vumatel makes big money for Johann Rupert", "BusinessTech", 5),
                 ("Vumatel keeps fibre downgrade fees secret", "MyBroadband", 6)])
r = A.news_analyze(inc(), S, NOW, fetch=f)
check("a headline naming the provider, the town and an outage is an ISP "
      "outage", r["verdict"] == "isp_outage" and r["confidence"] == "medium")
check("...quoted, with its source, and linked",
      '"Vumatel outage hits Durban homes" (IOL' in r["summary"]
      and len(r["sources"]) == 1
      and r["sources"][0]["url"].startswith("https://news.google.com/"))
check("...while headlines that only name the provider are left out "
      "('downgrade' is not 'down')",
      "Rupert" not in r["summary"] and "downgrade" not in str(r["sources"]))
check("it searches the provider and the town's power, nothing that names "
      "a customer", len(f.asked) == 2 and '"Vumatel"' in f.asked[0]
      and '"Durban"' in f.asked[1] and "Umhlanga" not in "".join(f.asked))
check("...and says it is the news, so the page and email can say so",
      r["provider"] == "news" and r["searches"] == 2
      and r["search_queries"] == f.asked)

r = A.news_analyze(inc(), S, NOW, fetch=fetcher(
    net=[("Vumatel outage in Johannesburg", "IOL", 3)]))
check("an outage that does not name the site's town is low confidence, "
      "and says it may be elsewhere", r["confidence"] == "low"
      and "may be elsewhere" in r["summary"])
r = A.news_analyze(inc(fleet={"same_isp": 1}), S, NOW, fetch=fetcher(
    net=[("Vumatel outage in Johannesburg", "IOL", 3)]))
check("...but medium when another site on the same provider dropped too",
      r["confidence"] == "medium")

r = A.news_analyze(inc(), S, NOW, fetch=fetcher(
    power=[("Load shedding: Durban areas face power cuts tonight",
            "The Witness", 2)]))
check("load-shedding in the town is a power cut in the area",
      r["verdict"] == "area_power" and r["confidence"] == "medium"
      and "come back with the power" in r["summary"])

print("\nWeighed against what the router showed")
r = A.news_analyze(inc(port_up=False), S, NOW, fetch=fetcher(
    net=[("Vumatel outage hits Durban homes", "IOL", 3)]))
check("a dead port is power or cabling at the box: news of the ISP's "
      "network does not override that, it is mentioned alongside",
      r["verdict"] == "local_power" and "The news also mentions" in r["summary"]
      and r["sources"])
r = A.news_analyze(inc(port_up=False), S, NOW, fetch=fetcher(
    net=[("Vumatel outage hits Durban homes", "IOL", 3)],
    power=[("Durban power outage after substation fire", "IOL", 4)]))
check("...and with a power cut in the news as well, the power cut is the "
      "answer", r["verdict"] == "area_power")
i = inc()
i["evidence"]["change_min"] = 3
r = A.news_analyze(i, S, NOW, fetch=fetcher(
    net=[("Vumatel outage hits Durban homes", "IOL", 3)]))
check("a change sent minutes before stays the first suspect",
      r["verdict"] == "change" and "The news also mentions" in r["summary"])

print("\nNothing relevant")
r = A.news_analyze(inc(), S, NOW, fetch=fetcher(
    net=[("Vumatel outage hits Durban homes", "IOL", 24 * 5)],
    power=[("AKA murder trial delayed by Durban High Court lift", "EWN", 2)]))
check("old news and unrelated headlines find nothing -- the router's own "
      "reading stands", r["verdict"] == "unknown" and not r["sources"])
try:
    A.news_analyze(inc(isp="", area=""), S, NOW, fetch=fetcher())
    check("with no provider and no area there is nothing to look up", False)
except A.AIError as exc:
    check("with no provider and no area there is nothing to look up, and "
          "it says how to fix that", "Name the line" in str(exc))
r = A.news_analyze(inc(isp=""), S, NOW, fetch=fetcher(
    power=[("Durban power outage after substation fire", "IOL", 4)]))
check("a line not named after its provider still gets the area's power "
      "news", r["verdict"] == "area_power")

print("\nThe feed itself")
try:
    A.parse_news(b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]>'
                 b"<rss><channel><item><title>&a;</title></item></channel>"
                 b"</rss>")
    check("a feed carrying entity definitions is refused", False)
except A.AIError:
    check("a feed carrying entity definitions is refused", True)
check("a link that is not https is dropped",
      A.parse_news(b"<rss><channel><item><title>x</title><link>"
                   b"javascript:alert(1)</link></item></channel></rss>")
      == [])
check("the test reads the feed", A.news_test(S, fetch=fetcher()) == "")
check("...and says when it cannot",
      "Google News" in A.news_test(S, fetch=lambda u: b"<html>nope"))

print("\nSettings and email")
check("a fresh server uses the news", A._provider({}) == "news")
orig = A._news_get
A._news_get = fetcher(net=[("Vumatel outage hits Durban homes", "IOL", 3)])
try:
    r = A.analyze(inc(), {"provider": "news", **S}, NOW)
finally:
    A._news_get = orig
check("analyze() sends the news provider to the news check",
      r["provider"] == "news" and r["verdict"] == "isp_outage")
html = ai_settings_box({"provider": "news", "enabled": True}, {}, "tok")
check("the Platform page offers it first, as free and keyless",
      '<option value="news" selected>News headlines (free, no key)' in html)
mail = A.cause_email({"device": "R1", "kind": "wan_failover",
                      "started": NOW - 900, "primary_link": "Vumatel",
                      "verdict": "isp_outage", "summary": "x",
                      "ai_provider": "news",
                      "search_queries": ['"Vumatel" outage when:2d']},
                     "[EM]", 2)[1]
check("the cause email says it searched Google News, with links there",
      "Searched Google News for" in mail
      and "news.google.com/search?q=" in mail)
check("an AI provider's email still says Google",
      "Searched Google for" in A.cause_email(
          {"device": "R1", "kind": "wan_failover", "started": NOW,
           "ai_provider": "gemini", "search_queries": ["q"]}, "[EM]", 2)[1])

print("")
if FAILS:
    print(f"FAILED: {len(FAILS)}: " + ", ".join(FAILS))
    sys.exit(1)
print("ALL NEWS-CHECK TESTS PASSED")
