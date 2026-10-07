"""Landing page for easymikrotik.

Accessible at /landing for preview. Wire it to / for unauthenticated visitors
by adding this before the auth gate in web.py do_GET:

    if path in ("/", "/home") and not self._session():
        from .web_landing import render_landing
        return self._send(200, render_landing(), "text/html; charset=utf-8")

Everything this page claims is something the product does today, in the
numbers it actually uses: polled every 60 seconds, Safe mode checking back
after a minute, remote-access links that close after 15, prices read from
the billing table. A landing page that oversells is one a customer catches
out in the first week.
"""
from __future__ import annotations

from .web_shared import (
    _BRAND, esc, _THEME_VARS, _THEME_INIT_JS, _THEME_TOGGLE_JS,
    _theme_toggle_btn, _SAFE_CHECK_SECONDS,
)
# Prices come from billing, never from a second copy kept here. They used to
# be hard-coded in both places and drifted apart -- the landing page went on
# advertising a figure the checkout no longer charged, which is the kind of
# bug a customer finds before you do.
from .billing import (PLANS, MAX_TIER_DEVICES, TIER_STEP, QUOTE_ABOVE_DEVICES,
                      TRIAL_DEVICES, GRACE_DAYS, BILLING_DAY)

_TITLE = f"{_BRAND} — MikroTik Monitoring & Remote Management"


def _tier(devices: int) -> dict:
    """The tier for a device count, for building landing-page copy."""
    return next(p for p in PLANS if p["devices"] == devices)


def _rate(devices: int) -> str:
    t = _tier(devices)
    return f'${t["price_usd"] / devices:.2f} / device / month'


def _usd(amount: float) -> str:
    return f"${amount:,.0f}" if float(amount).is_integer() else f"${amount:,.2f}"


# ---------------------------------------------------------------------------
# Icons -- stroke outlines that take the text colour, so they sit right in
# both themes. Path data from Feather (MIT licence, feathericons.com).
# ---------------------------------------------------------------------------
_ICON_PATHS = {
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "shuffle": '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" '
               'x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line '
               'x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" '
               'y2="9"/>',
    "rotate": '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 '
              '2.13-9.36L1 10"/>',
    "archive": '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" '
               'width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>',
    "monitor": '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line '
               'x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" '
               'y2="21"/>',
    "filter": '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path '
            'd="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "users": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle '
             'cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path '
             'd="M16 3.13a4 4 0 0 1 0 7.75"/>',
    "card": '<rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line '
            'x1="1" y1="10" x2="23" y2="10"/>',
    "search": '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" '
              'y2="16.65"/>',
    "trending": '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline '
                'points="17 6 23 6 23 12"/>',
    "share": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/>'
             '<circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" '
             'x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" '
             'y2="10.49"/>',
    "key": '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 '
           '0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    "alert": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 '
             '1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" '
             'x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
                '<polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" '
                'x2="12" y2="3"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" '
            'y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" '
            'y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/>'
            '<line x1="3" y1="18" x2="3.01" y2="18"/>',
    "mail": '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-'
            '2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
}


def _icon(name: str, size: int = 20) -> str:
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" '
            f'fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{_ICON_PATHS[name]}</svg>')


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

_FEATURES = [
    ("activity", "Real-time NOC dashboard",
     "Every router on one screen: CPU, memory, temperature, throughput and WAN "
     "health, polled every 60 seconds and colour-coded so the problem is the "
     "first thing you see."),
    ("shuffle", "Gateway failover you can see",
     "Primary and backup lines in priority order. When the main line drops, "
     "the router moves to the backup by itself, and you get an email saying "
     "which line failed and when."),
    ("rotate", "Safe config push & auto-revert",
     "Every change is previewed first and backed up before it is sent. If a "
     "change cuts the router off, it restores that backup by itself, usually "
     "within two minutes."),
    ("archive", "Automated router backups",
     "One-click backups saved on the router's own flash, plus an automatic "
     "one before every change. The last 10 are kept; backups you made "
     "yourself are never touched."),
    ("monitor", "Remote WebFig & Winbox",
     "Open WebFig or Winbox through the encrypted tunnel with one click, even "
     "behind CGNAT. Every link closes itself after 15 minutes."),
    ("filter", "DNS filtering & NextDNS",
     "Block malware, ads and adult content with built-in presets, or give "
     "each router its own NextDNS profile with encrypted DNS and its own "
     "blocklists."),
    ("lock", "WireGuard dial-home tunnel",
     "Routers connect out to us, so they need no public IP and no port "
     "forwarding. Ideal for LTE, home offices and sites you cannot reach."),
    ("users", "One account for the whole team",
     "Add as many team members as you like, at no extra cost. The owner "
     "decides which routers each person can see and manage."),
    ("card", "Simple per-device pricing",
     f"30 days free with {TRIAL_DEVICES} device, no card needed. Then packets "
     f"step in {TIER_STEP}s from {_usd(PLANS[0]['price_usd'])}/month for "
     f"{PLANS[0]['devices']} devices to "
     f"{_usd(_tier(MAX_TIER_DEVICES)['price_usd'])}/month for "
     f"{MAX_TIER_DEVICES}, and the price per device falls all the way."),
]

# The things people tell us they did not know it could do. Every one of them
# is a feature that exists, described in the terms it actually works in.
_DID_YOU_KNOW = [
    ("search", "It tells you why a line dropped",
     "A dead port at the ISP's box, the ISP's own network, or a change you "
     "pushed minutes before? It says which, from what the router saw and "
     "from your other sites on the same ISP.__AI_SEARCH__"),
    ("alert", "It keeps reminding you",
     "While a site runs on its backup line you are reminded every two hours, "
     "with how long it has been and how much data the backup has used, "
     "until the main line is back."),
    ("trending", "It learns what normal looks like",
     "Traffic and connected devices are compared with the same hour over the "
     "last several days, so an unusual spike, or an unusual drop like an "
     "access point that went off, stands out without a single threshold."),
    ("activity", "It notices internet that only looks up",
     "A line that is up but carrying almost nothing in the middle of a "
     "working day gets flagged: users with no working internet while every "
     "light on the router is green."),
    ("lock", "Laptops straight onto a site",
     "Add a laptop or phone from a router's VPN tab. Paste its WireGuard key "
     "and you get the settings to connect, with its own address and its own "
     "off switch."),
    ("share", "Share one router with a contractor",
     "Give one person at another company access to a single router, read-only "
     "or with rights to change it, and take it back whenever you like."),
    ("key", "Router logins that delete themselves",
     "Give a technician a temporary router login that removes itself after 30 "
     "minutes. No cleanup, nothing left behind."),
    ("alert", "It notices break-in attempts",
     "Failed logins, a new admin session, or a config change made outside the "
     "dashboard: each one raises an alert."),
    ("shield", "Lock management to your own IPs",
     "Restrict Winbox, SSH and the API to the addresses you trust and switch "
     "off telnet and FTP, from one tab."),
    ("download", "Update RouterOS from the browser",
     "Check for and install RouterOS and RouterBOOT updates without opening "
     "Winbox."),
    ("list", "Every change is on the record",
     "Each preview and change is logged with who made it and what the router "
     "answered."),
    ("mail", "Reports that write themselves",
     "A weekly, fortnightly or monthly status report for every site, emailed "
     "to whoever needs it."),
]

_STEPS = [
    ("1", "Create your account",
     f"Sign up with your company email and type in the code we send to it. "
     f"You get a 30-day free trial with {TRIAL_DEVICES} device straight away "
     f"— no credit card needed."),
    ("2", "Add your first router",
     "Leave the address blank and the Provision tab hands you one script to "
     "paste into the router. It dials home over WireGuard — no public IP, no "
     "manual key exchange."),
    ("3", "Monitor and manage",
     "Routers are polled every 60 seconds. Set up WAN failover, take backups, "
     "push changes safely, and open WebFig or Winbox from anywhere."),
]

_FAQ = [
    ("Do my routers need a public IP?",
     "No. Each router dials out to us over WireGuard, so it works behind NAT, "
     "CGNAT and LTE, and you never open a port on the router."),
    ("Which RouterOS versions work?",
     "RouterOS 7.1 or later. Every router connects to us over WireGuard, "
     "which RouterOS added in version 7.1, so a router still on RouterOS 6 "
     "needs upgrading to 7 first."),
    ("What happens if a change breaks a router?",
     "Every change is previewed first and backed up before it is sent. With "
     f"Safe mode on, about {_SAFE_CHECK_SECONDS} seconds later the router "
     "checks it can still reach us and we check we can still log in to it. "
     "If either fails, the router restores the backup by itself, and you get "
     "an email saying so."),
    ("Can my whole team use it?",
     "Yes. One company account, as many team members as you like. The owner "
     "decides which routers each member can see and manage."),
    ("How does billing work?",
     f"30 days free with {TRIAL_DEVICES} device. After that you pick a packet "
     f"by device count, priced in US dollars and billed monthly. Every account "
     f"renews on the {BILLING_DAY}th, so your first payment covers only the "
     f"days until then, and a missed payment gets {GRACE_DAYS} days' grace."),
    ("Can I cancel?",
     f"Yes, any time, with the Cancel button on your Billing tab. You keep "
     f"access until the {BILLING_DAY}th, the end of the month you have paid "
     f"for. After that you lose access to all of your units, and get it back "
     f"when you pay the next invoice. Payments are not refundable."),
]


# Cards are a sample of the ladder, not the whole of it: twenty cards is a
# wall nobody reads. The full ladder sits in the table underneath, and these
# mark the shape of it -- entry, the common size, the biggest packet, and the
# door out for anyone larger.
_PLANS = [
    {
        "name":    "Free Trial",
        "devices": f"{TRIAL_DEVICES} device",
        "amount":  "$0",
        "period":  "30 days, no card needed",
        "items":   [
            "All monitoring features",
            "WAN failover management",
            "Config push & auto-revert",
            "Automated backups",
            "Remote WebFig / Winbox access",
            "WireGuard dial-home tunnel",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": False,
    },
    {
        "name":    "Starter",
        "devices": f'{_tier(5)["devices"]} devices',
        "amount":  f'${_tier(5)["price_usd"]:,.2f}',
        "period":  "per month",
        "items":   [
            "Everything in Free Trial",
            "Unlimited team members",
            "Email alerts",
            f"{GRACE_DAYS}-day grace on missed payment",
            _rate(5),
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": False,
    },
    {
        "name":    "Growing",
        "devices": f'{_tier(50)["devices"]} devices',
        "amount":  f'${_tier(50)["price_usd"]:,.2f}',
        "period":  "per month",
        "items":   [
            "Everything in Starter",
            _rate(50),
            "Priority support",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": True,
    },
    {
        "name":    "Full house",
        "devices": f'{MAX_TIER_DEVICES} devices',
        "amount":  f'${_tier(MAX_TIER_DEVICES)["price_usd"]:,.2f}',
        "period":  "per month",
        "items":   [
            "Everything in Growing",
            _rate(MAX_TIER_DEVICES),
            "The largest off-the-shelf packet",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": False,
    },
    {
        "name":    "Custom",
        "devices": f'Over {QUOTE_ABOVE_DEVICES} devices',
        "amount":  "Let's talk",
        "period":  "quoted to fit",
        "items":   [
            f"Everything in the {MAX_TIER_DEVICES}-device packet",
            "Pricing built around your fleet",
            "Onboarding and support terms to match",
            "Billing cycle that suits you",
        ],
        "cta_href":  "/signup",
        "cta_label": "Request a quote",
        "highlight": False,
    },
]

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:Segoe UI,system-ui,Arial,sans-serif;color:var(--text);
  background:var(--surface);line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
[id]{scroll-margin-top:72px}

/* ── nav ─────────────────────────────────────────── */
.lnav{position:sticky;top:0;z-index:100;
  background:rgba(15,23,42,.97);backdrop-filter:blur(8px);
  padding:0 24px;height:60px;display:flex;align-items:center;gap:12px;
  border-bottom:1px solid rgba(255,255,255,.07)}
.lnav-logo{font-size:17px;font-weight:800;color:#fff;
  display:flex;align-items:center;gap:7px;flex-shrink:0;text-decoration:none}
.lnav-logo .dot{color:#38bdf8}
.lnav-links{display:flex;gap:2px;margin-left:20px}
.lnav-links a{color:#94a3b8;font-size:14px;padding:6px 11px;border-radius:7px;
  transition:.12s}
.lnav-links a:hover{background:#1e293b;color:#fff}
.lnav-right{margin-left:auto;display:flex;gap:8px;align-items:center}
/* the nav bar is always dark navy regardless of page theme, so the shared
   .theme-toggle button (which uses the light/dark surface tokens) needs its
   own light-on-dark styling here to stay legible in both themes. */
.lnav .theme-toggle{background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.18);color:#e2e8f0}
.lnav .theme-toggle:hover{background:rgba(255,255,255,.12);color:#fff;
  border-color:rgba(255,255,255,.3)}
.btn-nav-ghost{color:#e2e8f0;padding:8px 14px;border-radius:7px;font-size:14px;
  font-weight:500;border:1px solid rgba(255,255,255,.18);transition:.12s}
.btn-nav-ghost:hover{background:rgba(255,255,255,.08);color:#fff}
.btn-nav-primary{background:#2563eb;color:#fff;padding:8px 16px;border-radius:7px;
  font-size:14px;font-weight:600;transition:.12s}
.btn-nav-primary:hover{background:#1d4ed8;color:#fff}
.hamburger{display:none;background:0;border:0;cursor:pointer;
  padding:6px;flex-direction:column;gap:5px;margin-left:auto}
.hamburger span{display:block;width:22px;height:2px;background:#e2e8f0;
  border-radius:2px;transition:.2s}
.lnav-links.open{display:flex}

/* ── hero ────────────────────────────────────────── */
.hero{background:linear-gradient(148deg,#0f172a 0%,#1e3a5f 55%,#1e293b 100%);
  padding:88px 24px 92px;text-align:center;position:relative;overflow:hidden}
.hero::before{content:"";position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% 0%,
    rgba(37,99,235,.2),transparent);pointer-events:none}
/* A faint network of links behind the headline: what the product is about,
   without a stock photo. */
.hero::after{content:"";position:absolute;inset:0;pointer-events:none;
  opacity:.5;
  background-image:radial-gradient(rgba(148,163,184,.18) 1px,transparent 1px);
  background-size:26px 26px;
  -webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 30%,transparent 75%);
          mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 30%,transparent 75%)}
.hero-inner{position:relative;z-index:1}
.hero-badge{display:inline-flex;align-items:center;gap:6px;
  background:rgba(37,99,235,.18);color:#93c5fd;font-size:11px;font-weight:700;
  padding:5px 13px;border-radius:999px;border:1px solid rgba(37,99,235,.3);
  margin-bottom:28px;letter-spacing:.07em;text-transform:uppercase}
.hero h1{font-size:clamp(30px,6vw,58px);font-weight:800;color:#fff;
  line-height:1.1;max-width:780px;margin:0 auto 22px;letter-spacing:-.025em}
.hero h1 em{color:#38bdf8;font-style:normal}
.hero-sub{font-size:clamp(15px,2.2vw,18px);color:#94a3b8;max-width:560px;
  margin:0 auto 38px;line-height:1.65}
.hero-ctas{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-hero-primary{background:#2563eb;color:#fff;padding:13px 30px;
  border-radius:9px;font-size:15px;font-weight:700;transition:.15s;
  box-shadow:0 4px 16px rgba(37,99,235,.4);display:inline-block}
.btn-hero-primary:hover{background:#1d4ed8;color:#fff;
  box-shadow:0 4px 24px rgba(37,99,235,.55);transform:translateY(-1px)}
.btn-hero-outline{color:#e2e8f0;padding:13px 26px;border:1px solid rgba(255,255,255,.22);
  border-radius:9px;font-size:15px;font-weight:500;transition:.12s;
  display:inline-flex;align-items:center;gap:8px}
.btn-hero-outline:hover{background:rgba(255,255,255,.07);color:#fff}
.btn-hero-outline .play{width:18px;height:18px;border-radius:50%;
  background:#38bdf8;display:inline-flex;align-items:center;justify-content:center}
.btn-hero-outline .play::after{content:"";margin-left:2px;border-left:6px solid #0f172a;
  border-top:4px solid transparent;border-bottom:4px solid transparent}
.hero-facts{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;
  margin-top:34px}
.hero-fact{font-size:12px;color:#cbd5e1;background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.1);padding:5px 12px;border-radius:999px}
.hero-fact b{color:#fff}

/* ── proof bar ───────────────────────────────────── */
.proof{background:var(--surface-2);border-bottom:1px solid var(--border);
  padding:14px 24px;display:flex;justify-content:center;
  align-items:center;gap:28px;flex-wrap:wrap}
.proof-item{font-size:13px;color:var(--text-muted);display:flex;
  align-items:center;gap:6px}
.proof-item b{color:var(--success)}

/* ── shared section styles ───────────────────────── */
section{padding:76px 24px}
.s-inner{max-width:1064px;margin:0 auto}
.s-label{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.09em;color:var(--accent);margin-bottom:10px}
.s-title{font-size:clamp(22px,4vw,38px);font-weight:800;color:var(--text);
  margin-bottom:14px;line-height:1.15;letter-spacing:-.02em}
.s-sub{font-size:15px;color:var(--text-muted);max-width:560px;line-height:1.65;
  margin-bottom:48px}

/* ── feature cards ───────────────────────────────── */
.feat-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(292px,1fr));gap:18px}
.feat-card{background:var(--surface-2);border:1px solid var(--border);
  border-radius:12px;padding:24px 22px;transition:box-shadow .15s,transform .15s,
  border-color .15s}
.feat-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px);
  border-color:var(--accent)}
.feat-icon{width:40px;height:40px;border-radius:10px;margin-bottom:14px;
  display:flex;align-items:center;justify-content:center;
  background:var(--accent-soft);color:var(--accent)}
.feat-card h3{font-size:15px;font-weight:700;margin-bottom:7px;color:var(--text)}
.feat-card p{font-size:13px;color:var(--text-muted);line-height:1.65}

/* ── did you know ────────────────────────────────── */
.dyk-bg{background:var(--bg)}
.dyk-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(292px,1fr));
  gap:14px}
.dyk{display:flex;gap:14px;align-items:flex-start;background:var(--surface);
  border:1px solid var(--border);border-radius:12px;padding:18px;
  transition:border-color .15s,box-shadow .15s}
.dyk:hover{border-color:var(--accent);box-shadow:var(--shadow-md)}
.dyk-ic{flex:0 0 36px;height:36px;border-radius:50%;display:flex;
  align-items:center;justify-content:center;
  background:linear-gradient(135deg,#2563eb,#38bdf8);color:#fff}
.dyk h3{font-size:14px;font-weight:700;color:var(--text);margin-bottom:4px}
.dyk p{font-size:13px;color:var(--text-muted);line-height:1.6}

/* ── steps ───────────────────────────────────────── */
.steps-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:36px}
.step{display:flex;flex-direction:column;gap:12px}
.step-num{width:40px;height:40px;border-radius:50%;background:var(--accent);
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:17px;font-weight:800;flex-shrink:0;
  box-shadow:0 0 0 6px var(--accent-soft)}
.step h3{font-size:15px;font-weight:700;color:var(--text);margin-top:4px}
.step p{font-size:13px;color:var(--text-muted);line-height:1.65}

/* ── pricing cards ───────────────────────────────── */
.pricing-bg{background:var(--bg)}
.price-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(188px,1fr));
  gap:16px;align-items:stretch;margin-bottom:36px}
.price-card{border:1px solid var(--border);border-radius:14px;
  padding:26px 20px;display:flex;flex-direction:column;background:var(--surface);
  position:relative;transition:box-shadow .15s,transform .15s}
.price-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px)}
.price-card.highlight{background:#0f172a;border-color:#0f172a}
.price-card.highlight::before{content:"Most popular";position:absolute;top:-11px;
  left:20px;background:#38bdf8;color:#0f172a;font-size:10px;font-weight:800;
  text-transform:uppercase;letter-spacing:.06em;padding:3px 10px;border-radius:999px}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) .price-card.highlight{
    background:var(--surface-2);border-color:var(--accent)}
}
:root[data-theme="dark"] .price-card.highlight{
  background:var(--surface-2);border-color:var(--accent)}
.price-plan{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--accent);margin-bottom:4px}
.price-card.highlight .price-plan{color:#38bdf8}
.price-devices{font-size:13px;color:var(--text-faint);margin-bottom:6px}
.price-card.highlight .price-devices{color:#94a3b8}
.price-amount{font-size:32px;font-weight:800;line-height:1;
  color:var(--text);margin-bottom:3px;letter-spacing:-.02em}
.price-card.highlight .price-amount{color:#fff}
.price-period{font-size:12px;color:var(--text-faint);margin-bottom:22px}
.price-card.highlight .price-period{color:#94a3b8}
.price-items{list-style:none;flex:1;margin-bottom:24px}
.price-items li{font-size:13px;padding:6px 0;
  border-bottom:1px solid var(--border);
  display:flex;align-items:flex-start;gap:8px;color:var(--text-muted);
  line-height:1.4}
.price-card.highlight .price-items li{
  color:#e2e8f0;border-bottom-color:rgba(255,255,255,.07)}
.price-items li::before{content:"✓";color:var(--success);font-weight:700;
  flex-shrink:0}
.price-card.highlight .price-items li::before{color:#4ade80}
.price-cta{display:block;text-align:center;padding:11px;border-radius:8px;
  font-size:14px;font-weight:600;transition:.12s}
.price-cta.solid{background:var(--accent);color:#fff;border:2px solid var(--accent)}
.price-cta.solid:hover{background:var(--accent-hover);border-color:var(--accent-hover);
  color:#fff}
.price-cta.ghost{background:var(--surface);color:var(--text);
  border:2px solid var(--border)}
.price-cta.ghost:hover{border-color:var(--text-faint);background:var(--surface-2)}

/* ── all-tiers table ─────────────────────────────── */
.tier-table{width:100%;border-collapse:collapse;font-size:13px;
  background:var(--surface);border-radius:12px;overflow:hidden;
  border:1px solid var(--border);box-shadow:var(--shadow)}
.tier-table th{background:var(--surface-2);font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--text-faint);padding:10px 16px;
  border-bottom:1px solid var(--border);text-align:left}
.tier-table td{padding:10px 16px;border-bottom:1px solid var(--border);
  color:var(--text-muted)}
.tier-table tbody tr:hover td{background:var(--surface-2)}
.tier-table tr:last-child td{border-bottom:0}
.tier-table .usd{font-weight:700;color:var(--text)}
.tier-table .per{color:var(--text-faint)}

/* ── FAQ ─────────────────────────────────────────── */
.faq{max-width:760px}
.faq details{border-bottom:1px solid var(--border)}
.faq details:first-of-type{border-top:1px solid var(--border)}
.faq summary{cursor:pointer;list-style:none;padding:18px 34px 18px 0;
  font-size:15px;font-weight:600;color:var(--text);position:relative}
.faq summary::-webkit-details-marker{display:none}
.faq summary::after{content:"+";position:absolute;right:4px;top:14px;
  font-size:22px;font-weight:400;color:var(--accent);transition:transform .2s}
.faq details[open] summary::after{transform:rotate(45deg)}
.faq details p{font-size:14px;color:var(--text-muted);line-height:1.7;
  padding:0 34px 18px 0}

/* ── CTA banner ──────────────────────────────────── */
.cta-wrap{background:linear-gradient(135deg,#1e3a5f,#2563eb);
  padding:76px 24px;text-align:center}
.cta-wrap h2{font-size:clamp(22px,4vw,36px);font-weight:800;color:#fff;
  margin-bottom:12px;letter-spacing:-.02em}
.cta-wrap p{font-size:15px;color:#bfdbfe;margin-bottom:32px;
  max-width:460px;margin-left:auto;margin-right:auto;line-height:1.6}

/* ── footer ──────────────────────────────────────── */
footer{background:#0f172a;padding:44px 24px 28px}
.foot-inner{max-width:1064px;margin:0 auto}
.foot-top{display:flex;justify-content:space-between;align-items:flex-start;
  gap:32px;flex-wrap:wrap;margin-bottom:32px}
.foot-logo{font-size:17px;font-weight:800;color:#fff;display:flex;
  align-items:center;gap:7px;margin-bottom:8px;text-decoration:none}
.foot-logo .dot{color:#38bdf8}
.foot-tag{font-size:13px;color:#64748b;max-width:220px;line-height:1.5}
.foot-col h4{font-size:11px;font-weight:700;color:#e2e8f0;
  text-transform:uppercase;letter-spacing:.07em;margin-bottom:12px}
.foot-col a{display:block;color:#64748b;font-size:13px;
  padding:3px 0;transition:.1s}
.foot-col a:hover{color:#e2e8f0}
.foot-bottom{border-top:1px solid rgba(255,255,255,.07);
  padding-top:20px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:8px;
  font-size:12px;color:#64748b}

/* ── responsive ──────────────────────────────────── */
@media(max-width:860px){
  .lnav-links,.lnav-right .btn-nav-ghost{display:none}
  .hamburger{display:flex}
  .lnav-links.open{
    display:flex;flex-direction:column;
    position:absolute;top:60px;left:0;right:0;margin-left:0;
    background:#0f172a;padding:12px 16px 16px;
    border-bottom:1px solid rgba(255,255,255,.08);gap:2px}
  .lnav-links.open a{padding:11px 12px;border-radius:7px;
    color:#e2e8f0;font-size:15px}
  .lnav-right{gap:6px}
  .btn-nav-primary{font-size:13px;padding:7px 12px}
}
@media(max-width:768px){
  section{padding:52px 20px}
  .hero{padding:60px 20px 72px}
  .foot-top{flex-direction:column;gap:20px}
  .foot-bottom{flex-direction:column;gap:4px;text-align:center}
  .tier-table th:nth-child(2),.tier-table td:nth-child(2){display:none}
}
@media(max-width:480px){
  .lnav{padding:0 14px;gap:8px}
  .lnav-logo{font-size:15px}
  .btn-nav-primary{white-space:nowrap;font-size:12.5px;padding:7px 10px}
  .proof{flex-direction:column;gap:10px;text-align:center}
  .hero-ctas{flex-direction:column;align-items:center}
  .hero-ctas a{width:100%;max-width:300px;justify-content:center;text-align:center}
  .steps-grid,.price-grid{grid-template-columns:1fr}
  .tier-table th,.tier-table td{padding:9px 10px}
}
"""

# ---------------------------------------------------------------------------
# The demo: the product's own screens, playing out what usually means a site
# visit.
#
# Every screen in it is one the product really has -- the dashboard's device
# table and status badges, a tab's dry-run preview, the Safe-mode page that
# follows a change, the Remote access box, the provisioning script -- in the
# same layout and wording. Alerts appear in an inbox BESIDE the window, because
# that is where they really arrive: by email. Nothing here may show something
# the product does not do; that would be advertising a different product.
# ---------------------------------------------------------------------------

_DEMO_CSS = """
.demo-bg{background:linear-gradient(180deg,var(--surface) 0%,var(--bg) 100%)}
.demo-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.dt{font:inherit;font-size:13px;font-weight:600;cursor:pointer;
  color:var(--text-muted);background:var(--surface);border:1px solid var(--border);
  padding:8px 14px;border-radius:999px;display:inline-flex;align-items:center;
  gap:8px;transition:.15s}
.dt:hover{color:var(--text);border-color:var(--accent)}
.dt .n{width:20px;height:20px;border-radius:50%;font-size:11px;display:inline-flex;
  align-items:center;justify-content:center;background:var(--surface-2);
  color:var(--text-faint);border:1px solid var(--border)}
.dt.on{background:var(--accent);border-color:var(--accent);color:#fff;
  box-shadow:0 4px 14px rgba(37,99,235,.3)}
.dt.on .n{background:rgba(255,255,255,.2);color:#fff;border-color:transparent}
.dmo{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(0,1fr);gap:18px;
  align-items:start}
/* the browser window around the app */
.dw{background:var(--bg);border:1px solid var(--border);border-radius:14px;
  box-shadow:var(--shadow-md),0 30px 60px -30px rgba(15,23,42,.35);overflow:hidden}
.dw-bar{display:flex;align-items:center;gap:12px;padding:9px 14px;
  background:var(--surface-2);border-bottom:1px solid var(--border)}
.dw-dots{display:flex;gap:6px}
.dw-dots i{width:10px;height:10px;border-radius:50%;display:block}
.dw-dots i:nth-child(1){background:#ff5f57}.dw-dots i:nth-child(2){background:#febc2e}
.dw-dots i:nth-child(3){background:#28c840}
.dw-url{flex:1;font-size:12px;color:var(--text-faint);background:var(--surface);
  border:1px solid var(--border);border-radius:7px;padding:4px 10px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dw-pause{font:inherit;font-size:11px;font-weight:600;cursor:pointer;
  color:var(--text-muted);background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:3px 9px}
.dw-pause:hover{color:var(--text);border-color:var(--accent)}
/* the app itself: the same nav, cards, table and badges as the dashboard */
.ap-nav{display:flex;align-items:center;gap:4px;padding:0 12px;height:42px;
  background:var(--surface);border-bottom:1px solid var(--border);overflow:hidden}
.ap-logo{display:flex;align-items:center;gap:6px;font-weight:700;font-size:13px;
  color:var(--text);margin-right:8px;white-space:nowrap}
.ap-logo img,.ap-logo svg{width:18px;height:18px}
.ap-nav span.it{font-size:12px;color:var(--text-muted);padding:5px 9px;
  border-radius:7px;white-space:nowrap}
.ap-nav span.it.on{background:var(--accent-soft);color:var(--accent)}
.ap-main{padding:16px 18px 18px;min-height:372px}
.v{display:none}.v.on{display:block;animation:din .35s ease}
.ap-top{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:12px}
.ap-top h3,.ap-devhead h3{font-size:17px;margin:0;color:var(--text)}
.ap-search{font-size:11px;color:var(--text-faint);border:1px solid var(--border);
  border-radius:8px;padding:5px 10px;background:var(--surface);width:150px}
.ap-chips{display:flex;gap:10px;margin-bottom:12px}
.ap-chip{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:9px 14px;min-width:92px;box-shadow:var(--shadow)}
.ap-chip b{display:block;font-size:20px;line-height:1.1;color:var(--text)}
.ap-chip b.red{color:var(--danger)}
.ap-chip span{font-size:10px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;color:var(--text-faint)}
.ap-card{background:var(--surface);border:1px solid var(--border);
  border-radius:12px;box-shadow:var(--shadow);overflow:hidden}
.ap-bk{display:none;background:var(--surface);border:1px solid var(--border);
  border-left:4px solid var(--warning);border-radius:12px;padding:9px 12px;
  margin-bottom:12px;font-size:12px;line-height:1.45;color:var(--text-muted);
  box-shadow:var(--shadow);animation:din .4s ease}
.ap-bk.on{display:block}
.ap-bk i{font-style:normal;font-size:9.5px;font-weight:700;letter-spacing:.05em;
  text-transform:uppercase;background:var(--warning-bg);color:var(--warning);
  border-radius:999px;padding:1px 7px;margin-right:6px}
.ap-bk b{color:var(--text)}
.ap-card-head{display:flex;align-items:center;justify-content:space-between;
  padding:11px 14px}
.ap-card-head b{font-size:13px;color:var(--text)}
.ap-pills{display:flex;gap:5px}
.ap-pills i{font-style:normal;font-size:10.5px;font-weight:600;padding:4px 9px;
  border-radius:999px;background:var(--surface-2);border:1px solid var(--border);
  color:var(--text-muted)}
.ap-pills i.on{background:var(--accent);border-color:var(--accent);color:#fff}
.ap-table{width:100%;border-collapse:collapse;font-size:12px}
.ap-table th{font-size:10px;text-transform:uppercase;letter-spacing:.04em;
  color:var(--text-faint);text-align:left;padding:7px 14px;
  border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.ap-table td{padding:9px 14px;border-bottom:1px solid var(--border)}
.ap-table tr:last-child td{border-bottom:0}
.ap-table tr.hl td{background:var(--accent-soft)}
.ap-table tr.new td{animation:din .5s ease}
.ap-table .nm{font-weight:600;color:var(--text);white-space:nowrap}
.ap-table .nm i{font-style:normal;color:var(--text-faint);font-size:11px;
  margin-right:7px}
.ap-table .vw{text-align:right;color:var(--text-faint);font-size:11px;
  font-weight:600;white-space:nowrap}
.bdg{display:inline-block;padding:2px 9px;border-radius:999px;font-size:10.5px;
  font-weight:700}
.bdg.ok{background:var(--success-bg);color:var(--success)}
.bdg.warn{background:var(--warning-bg);color:var(--warning)}
.bdg.crit{background:var(--danger-bg);color:var(--danger)}
.abdg{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:999px}
.abdg.warn{background:rgba(217,119,6,.14);color:#b45309}
.abdg.crit{background:var(--danger-bg);color:var(--danger)}
.ap-devhead{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.ap-tabs{display:flex;gap:2px;border-bottom:2px solid var(--border);
  margin-bottom:12px;overflow:hidden}
.ap-tabs span{font-size:11.5px;color:var(--text-muted);padding:6px 9px;
  border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap}
.ap-tabs span.on{color:var(--accent);border-bottom-color:var(--accent);
  font-weight:600}
.ap-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:13px 15px;box-shadow:var(--shadow);margin-bottom:10px}
.ap-box.ok{border-left:4px solid var(--success)}
.ap-box h4{font-size:13px;margin:0 0 8px;color:var(--text)}
.ap-box p{font-size:11.5px;color:var(--text-muted);margin:0 0 6px;line-height:1.5}
.ap-pre{font-family:Consolas,Menlo,monospace;font-size:10.5px;line-height:1.55;
  background:var(--surface-2);color:var(--text);border:1px solid var(--border);
  border-radius:7px;padding:8px 10px;white-space:pre-wrap;word-break:break-all;
  margin:0 0 8px}
.ap-chk{font-size:11px;color:var(--text-muted);display:block;margin:0 0 9px}
.ap-chk b{color:var(--text)}
.ap-btn{display:inline-block;background:var(--accent);color:#fff;font-size:11.5px;
  font-weight:600;padding:6px 12px;border-radius:7px;transition:transform .15s,
  box-shadow .15s}
.ap-btn.ghost{background:var(--surface-2);color:var(--text);
  border:1px solid var(--border)}
.ap-btn.press{transform:scale(.94);box-shadow:0 0 0 4px var(--accent-soft)}
.ap-count{font-size:19px;font-weight:700;color:var(--text);margin:4px 0 0}
.ap-row{display:flex;align-items:center;gap:10px;padding:7px 0;
  border-bottom:1px solid var(--border);font-size:11.5px;color:var(--text);
  flex-wrap:wrap}
.ap-row:last-child{border-bottom:0}
.ap-row b{min-width:58px}
.ap-row a{color:var(--accent)}
.ap-row .muted{color:var(--text-faint)}
/* beside the window: the narration, and the inbox alerts actually land in */
.dside{display:flex;flex-direction:column;gap:14px;min-width:0}
.dc{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px;box-shadow:var(--shadow)}
.dc-step{font-size:10px;font-weight:700;letter-spacing:.08em;
  text-transform:uppercase;color:var(--accent)}
.dc-text{font-size:15.5px;font-weight:600;color:var(--text);line-height:1.45;
  min-height:4.4em;margin-top:4px}
.dc-text.in{animation:din .45s ease}
.dmail{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  box-shadow:var(--shadow);overflow:hidden}
.dmail-head{display:flex;align-items:center;gap:8px;padding:9px 14px;
  border-bottom:1px solid var(--border);font-size:11px;font-weight:700;
  letter-spacing:.06em;text-transform:uppercase;color:var(--text-faint)}
.dmail-head svg{flex:none}
.dmail-list{display:flex;flex-direction:column}
.dm{--c:var(--accent);padding:10px 14px;border-bottom:1px solid var(--border);
  border-left:3px solid var(--c);animation:din .4s ease}
.dm:last-child{border-bottom:0}
.dm.warn{--c:var(--warning)}.dm.crit{--c:var(--danger)}.dm.ok{--c:var(--success)}
.dm-from{font-size:10px;color:var(--text-faint)}
.dm-sub{display:block;font-size:12px;color:var(--text);margin:2px 0 4px;
  line-height:1.35}
.dm p{font-size:11px;color:var(--text-muted);margin:0;line-height:1.5;
  font-family:Consolas,Menlo,monospace}
.dm-empty{font-size:12px;color:var(--text-faint);padding:16px 14px;text-align:center}
.dp{height:3px;background:var(--border)}
.dp-bar{display:block;height:100%;width:0;background:var(--accent);
  transition:width .6s ease}
.demo-note{font-size:12px;color:var(--text-faint);margin-top:12px}
@keyframes din{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@media(max-width:900px){.dmo{grid-template-columns:1fr}}
@media(max-width:560px){
  .ap-search,.ap-nav span.it:nth-child(n+4),.ap-tabs span:nth-child(n+5){display:none}
  .ap-main{padding:12px;min-height:0}
  .ap-table th,.ap-table td{padding:7px 9px}
  .ap-table .vw{display:none}
  .dt{font-size:12px;padding:7px 11px}
}
@media (prefers-reduced-motion:reduce){
  .demo-bg *,.demo-bg *::before{animation:none!important;transition:none!important}
}
"""


def _demo_html() -> str:
    from .brand import logo_img
    tabs = "".join(
        f'<button class="dt{" on" if i == 0 else ""}" type="button" '
        f'role="tab" aria-selected="{"true" if i == 0 else "false"}" '
        f'data-s="{i}"><span class="n">{i + 1}</span>{esc(t)}</button>'
        for i, t in enumerate(("Internet line fails", "A change goes wrong",
                               "Fix it from anywhere",
                               "Add a router in a minute")))
    nav = "".join(f'<span class="it{" on" if n == "Dashboard" else ""}">'
                  f'{n}</span>' for n in ("Dashboard", "Devices", "Activity",
                                         "Guide", "Account"))
    dev_tabs = "".join(f'<span data-tab="{t}">{t}</span>' for t in (
        "Overview", "Provision", "Routes", "WAN", "Security", "DNS", "Queues",
        "Maintenance"))
    mail_ic = ('<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
               'stroke="currentColor" stroke-width="2" aria-hidden="true">'
               '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-'
               '2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>')
    return (
        f'<div class="demo" id="demo-app">'
        f'<div class="demo-tabs" role="tablist" '
        f'aria-label="Demo scenarios">{tabs}</div>'
        f'<div class="dmo">'
        f'<div class="dw">'
        f'<div class="dw-bar"><span class="dw-dots"><i></i><i></i><i></i></span>'
        f'<span class="dw-url">{esc(_BRAND.lower())}.com/dashboard</span>'
        f'<button class="dw-pause" type="button">Pause</button></div>'
        f'<div class="ap-nav"><span class="ap-logo">{logo_img(18)}'
        f'{esc(_BRAND)}</span>{nav}</div>'
        f'<div class="ap-main">'
        f'<div class="v v-dash on">'
        f'<div class="ap-top"><h3>Dashboard</h3>'
        f'<span class="ap-search">Search devices…</span></div>'
        f'<div class="ap-chips"><div class="ap-chip"><b class="c-dev">4</b>'
        f'<span>Devices</span></div><div class="ap-chip"><b class="c-off">0</b>'
        f'<span>Offline</span></div></div>'
        f'<div class="ap-bk" id="dm-bk"><i>On backup</i><b>1 site running on '
        f'the backup line</b><br><b>Branch · Durban</b> Vumatel down since '
        f'09:41 · on LTE</div>'
        f'<div class="ap-card"><div class="ap-card-head"><b>Devices</b>'
        f'<span class="ap-pills"><i class="on">All</i><i>Problems</i>'
        f'<i>Offline</i></span></div>'
        f'<table class="ap-table"><thead><tr><th>Name</th><th>Status</th>'
        f'<th>Alerts</th><th class="vw"></th></tr></thead><tbody></tbody></table></div>'
        f'</div>'
        f'<div class="v v-dev">'
        f'<div class="ap-devhead"><h3 class="ap-dname">—</h3>'
        f'<span class="bdg ok ap-dbadge">Healthy</span></div>'
        f'<div class="ap-tabs">{dev_tabs}</div>'
        f'<div class="ap-body"></div>'
        f'</div>'
        f'</div>'
        f'<div class="dp"><span class="dp-bar"></span></div>'
        f'</div>'
        f'<aside class="dside">'
        f'<div class="dc"><div class="dc-step">Scenario 1 · Internet line fails'
        f'</div><p class="dc-text" aria-live="polite">Pick a scenario above, or '
        f'let it play.</p></div>'
        f'<div class="dmail" role="log" aria-label="Alert emails">'
        f'<div class="dmail-head">{mail_ic}Your inbox</div>'
        f'<div class="dmail-list"><div class="dm-empty">Alert emails arrive '
        f'here.</div></div></div>'
        f'</aside>'
        f'</div>'
        f'<p class="demo-note">The real screens, with made-up sites. Timings '
        f'are sped up.</p>'
        f'</div>')


# Written as plain ES5 so it runs on whatever a prospect opens it in. It only
# ever touches the demo's own elements, and does nothing until the demo is
# scrolled into view.
# Only shown when the online check is on (see render_landing).
_AI_DEMO_STEP = r"""{d:3600, cap:'A minute later: what is reported online for that area, with the sources.',
       f:function(){ mail('', '09:42', '[EasyMikrotik] Branch · Durban: possible cause — Outage at the ISP',
         ['Vumatel reports a fibre outage in Umhlanga since 09:30; repairs are under way.',
          'Source: Vumatel status — Umhlanga fibre outage']); }},"""

_DEMO_JS = r"""
<script>
(function(){
  var app = document.getElementById('demo-app');
  if (!app) return;
  var reduce = !!(window.matchMedia &&
                  matchMedia('(prefers-reduced-motion: reduce)').matches);
  var host = (location.hostname && location.hostname.indexOf('.') > 0)
             ? location.hostname : 'easymikrotik.com';
  function $(s){ return app.querySelector(s); }
  var tabs = [].slice.call(app.querySelectorAll('.dt'));
  var capEl = $('.dc-text'), stepEl = $('.dc-step'), list = $('.dmail-list');
  var bar = $('.dp-bar'), pauseBtn = $('.dw-pause'), url = $('.dw-url');
  var vDash = $('.v-dash'), vDev = $('.v-dev'), body = $('.ap-body');
  var tbody = $('.ap-table tbody'), cDev = $('.c-dev'), cOff = $('.c-off');
  var LABEL = {ok:'Healthy', warn:'Partial', crit:'Offline'};
  var rows = [];

  function esc(t){ var d = document.createElement('div');
    d.textContent = t; return d.innerHTML; }
  function drawTable(){
    var html = '', off = 0;
    rows.forEach(function(r){
      if (r.st === 'crit') off++;
      html += '<tr class="' + (r.hl ? 'hl ' : '') + (r.fresh ? 'new' : '') +
        '"><td class="nm"><i>&#9638;</i>' + esc(r.name) + '</td>' +
        '<td><span class="bdg ' + r.st + '">' + LABEL[r.st] + '</span></td>' +
        '<td>' + (r.al ? '<span class="abdg ' + (r.st === 'crit' ? 'crit' : 'warn') +
        '">&#9650; ' + r.al + '</span>' : '<span style="color:var(--text-faint)">&mdash;</span>') +
        '</td><td class="vw">View &rarr;</td></tr>';
      r.fresh = false;
    });
    tbody.innerHTML = html;
    cDev.textContent = rows.length;
    cOff.textContent = off; cOff.className = 'c-off' + (off ? ' red' : '');
  }
  function row(name){ for (var i = 0; i < rows.length; i++)
    if (rows[i].name === name) return rows[i]; }
  function setRow(name, o){ var r = row(name); if (!r) return;
    for (var k in o) r[k] = o[k]; drawTable(); }
  function showDash(){ vDev.classList.remove('on'); vDash.classList.add('on');
    url.textContent = host + '/dashboard'; }
  function showDev(name, tab, st){
    vDash.classList.remove('on'); vDev.classList.add('on');
    $('.ap-dname').textContent = name;
    var b = $('.ap-dbadge'); b.className = 'bdg ap-dbadge ' + (st || 'ok');
    b.textContent = LABEL[st || 'ok'];
    [].slice.call(app.querySelectorAll('.ap-tabs span')).forEach(function(s){
      s.classList.toggle('on', s.getAttribute('data-tab') === tab); });
    url.textContent = host + '/device?name=' + name.split(' ')[0] +
      (tab === 'Overview' ? '' : '&tab=' + tab.toLowerCase());
  }
  function press(sel){ var b = body.querySelector(sel); if (!b) return;
    b.classList.add('press'); later(260, function(){ b.classList.remove('press'); }); }
  function mail(kind, when, subject, lines){
    var empty = list.querySelector('.dm-empty');
    if (empty) list.removeChild(empty);
    var d = document.createElement('div');
    d.className = 'dm ' + kind;
    d.innerHTML = '<div class="dm-from"></div><b class="dm-sub"></b>';
    d.querySelector('.dm-from').textContent = 'EasyMikrotik alerts · ' + when;
    d.querySelector('.dm-sub').textContent = subject;
    lines.forEach(function(t){ var p = document.createElement('p');
      p.textContent = t; d.appendChild(p); });
    list.insertBefore(d, list.firstChild);
    while (list.children.length > 2) list.removeChild(list.lastChild);
  }

  var timers = [], cur = 0, step = 0, paused = false, scen = null;
  function later(ms, f){ timers.push(setTimeout(f, ms)); }
  function stopAll(){ timers.forEach(clearTimeout); timers = []; }
  function mmss(v){ v = Math.max(0, Math.round(v));
    return Math.floor(v / 60) + ':' + ('0' + (v % 60)).slice(-2); }
  function count(el, label, from, to, ms){
    var n = 14, k = 0;
    (function t(){
      if (el) el.textContent = label + mmss(from - (from - to) * (k / n));
      if (k++ < n) later(ms / n, t);
    })();
  }
  function count2(el, from, to, ms){
    var n = 12, k = 0;
    (function t(){
      if (el) el.textContent = 'In about ' + Math.round(from - (from - to) * (k / n)) +
        ' s the router checks it can still reach the hub.';
      if (k++ < n) later(ms / n, t);
    })();
  }
  function type(el, text, ms){
    var k = 0, per = Math.max(6, ms / text.length);
    (function t(){ el.textContent = text.slice(0, k);
      if (k++ < text.length) later(per, t); })();
  }
  function reset(){
    rows = [{name:'Head Office', st:'ok', al:0},
            {name:'Branch · Durban', st:'ok', al:0},
            {name:'Clinic · Paarl', st:'ok', al:0},
            {name:'Warehouse · Midrand', st:'ok', al:0}];
    drawTable(); showDash(); body.innerHTML = '';
    var bk = document.getElementById('dm-bk'); if (bk) bk.classList.remove('on');
    list.innerHTML = '<div class="dm-empty">Alert emails arrive here.</div>';
  }
  var PLAN = 'Clinic · Paarl: 2 change(s) [security]\n' +
             '  + add SSH brute-force blacklist (5 rules)\n' +
             '  ~ update /ip/service ssh: disabled=yes';
  var SCRIPT = '/interface wireguard add name=mikromon listen-port=13231\n' +
               '/interface wireguard peers add interface=mikromon \\\n' +
               '    endpoint-address=' + host + ' endpoint-port=51820 \\\n' +
               '    persistent-keepalive=25s\n' +
               '/ip address add address=10.10.0.42/16 interface=mikromon';

  var SC = [
    {title:'Internet line fails', init:reset, steps:[
      {d:2600, cap:'The dashboard: every router, one row each.'},
      {d:2800, cap:'09:41 — Branch · Durban’s fibre stops answering. The router moves to its LTE backup: its row turns Partial, and an On backup card stays at the top until the line is back.',
       f:function(){ setRow('Branch · Durban', {st:'warn', al:1, hl:true});
         var bk = document.getElementById('dm-bk'); if (bk) bk.classList.add('on'); }},
      {d:3800, cap:'You get an email saying what happened, and the likely cause: two other sites on the same ISP dropped too.',
       f:function(){ mail('warn', '09:41', '[EasyMikrotik] WARNING: Branch · Durban (1 event)',
         ['[WARNING] Primary WAN "Vumatel" is DOWN — running on backup "LTE"',
          'Why: Primary uplink Vumatel is not carrying traffic. Likely cause: 2 other sites on Vumatel lost their line within 20 minutes of this one, so this is an outage at Vumatel, not a fault on site.']); }},
      /*AI_STEP*/
      {d:3400, cap:'Two hours later it is still on LTE, so you are reminded, with how much data the backup has carried.',
       f:function(){ mail('warn', '11:41', '[EasyMikrotik] Branch · Durban is still on its backup line (2 hours)',
         ['Branch · Durban: Vumatel line down since 09:41 (2 hours), running on LTE, 1.8 GB used on it.']); }},
      {d:3400, cap:'When the fibre answers again, the row goes back to Healthy and a last email says so.',
       f:function(){ setRow('Branch · Durban', {st:'ok', al:0});
         var bk = document.getElementById('dm-bk'); if (bk) bk.classList.remove('on');
         mail('ok', '11:58', '[EasyMikrotik] RESOLVED: Branch · Durban (1 event)',
              ['[RESOLVED] WAN restored — back on primary uplink Vumatel']); }},
      {d:2600, cap:'You heard about it from an email, not from a phone call.'}
    ]},
    {title:'A change goes wrong', init:reset, steps:[
      {d:3200, cap:'You change a router’s firewall. A dry run shows exactly what will be sent; nothing is written yet.',
       f:function(){ showDev('Clinic · Paarl', 'Security', 'ok');
         body.innerHTML = '<div class="ap-box"><h4>Dry run — nothing has been written yet</h4>' +
           '<pre class="ap-pre">' + esc(PLAN) + '</pre>' +
           '<span class="ap-chk"><b>☑ Safe mode</b> — a backup is taken and a safety timer is set on the router <i>before</i> the change is sent. About 60 seconds later the router checks it can still reach the hub and the server checks it can still log in. If either fails, the router puts its previous settings back by itself and restarts.</span>' +
           '<span class="ap-btn" id="dm-apply">Confirm &amp; apply to the router</span></div>'; }},
      {d:3400, cap:'A backup is taken and a safety timer is set on the router first. Only then does the change go out.',
       f:function(){ press('#dm-apply');
         later(400, function(){
           body.innerHTML = '<div class="ap-box ok"><h4>Change sent to Clinic · Paarl</h4>' +
             '<p>Safe mode is watching it. About 60 seconds after the change the router pings this server, and then this server logs in to it. If either fails, the router restores the settings it had just before the change and restarts. No site visit.</p>' +
             '<p class="ap-count"><b>Watching the change</b><br><span id="dm-count">In about 60 s the router checks it can still reach the hub.</span></p></div>';
           count2(document.getElementById('dm-count'), 60, 8, 2400); }); }},
      {d:3000, cap:'The change locked the router out. On the dashboard it shows Offline.',
       f:function(){ showDash(); setRow('Clinic · Paarl', {st:'crit', al:1, hl:true}); }},
      {d:3600, cap:'A minute after the change the router cannot reach us, so it loads the backup by itself, restarts and comes back online.',
       f:function(){ later(1400, function(){ setRow('Clinic · Paarl', {st:'ok', al:0});
         mail('warn', '10:14', '[EasyMikrotik] Safe mode put Clinic · Paarl back to its previous settings',
              ['A change to Clinic · Paarl (Security) cut the router off from the dashboard.',
               'Safe mode restored the settings it had just before that change. The change is NOT on the router any more.']); }); }},
      {d:2600, cap:'Nobody locked out. Nobody drove anywhere.'}
    ]},
    {title:'Fix it from anywhere', init:reset, steps:[
      {d:3000, cap:'Warehouse · Midrand is on LTE behind CGNAT: no public IP, no port forwarding. Its page has a Remote access box.',
       f:function(){ showDev('Warehouse · Midrand', 'Overview', 'ok');
         body.innerHTML = '<div class="ap-box"><h4>Remote access</h4>' +
           '<div class="ap-row"><b>WebFig</b><span class="ap-btn" id="dm-open">Open WebFig</span></div>' +
           '<div class="ap-row"><b>Winbox</b><span class="ap-btn">Open Winbox</span></div></div>'; }},
      {d:3400, cap:'One click opens a private link to that router, through the encrypted tunnel.',
       f:function(){ press('#dm-open');
         later(400, function(){
           body.querySelector('.ap-row').innerHTML = '<b>WebFig</b>' +
             '<a>https://' + host + ':20417</a><span class="muted" id="dm-exp">expires in 15:00</span>' +
             '<span class="ap-btn ghost">Close</span>';
           count(document.getElementById('dm-exp'), 'expires in ', 900, 840, 2600); }); }},
      {d:3200, cap:'It closes by itself after 15 minutes, so nothing is left open.',
       f:function(){ count(document.getElementById('dm-exp'), 'expires in ', 840, 0, 2600); }},
      {d:2800, cap:'Closed. The port is gone until someone opens it again.',
       f:function(){ body.querySelector('.ap-row').innerHTML =
         '<b>WebFig</b><span class="ap-btn">Open WebFig</span>'; }}
    ]},
    {title:'Add a router in a minute', init:reset, steps:[
      {d:3800, cap:'Add a router with no address, and its Provision tab hands you one script to paste into its terminal.',
       f:function(){ showDev('Shop · Cape Town', 'Provision', 'ok');
         $('.ap-dbadge').style.visibility = 'hidden';
         body.innerHTML = '<div class="ap-box ok"><h4>Provisioning script — paste into the new router</h4>' +
           '<p>Open the router in WinBox/WebFig → New Terminal, paste this, press Enter.</p>' +
           '<pre class="ap-pre" id="dm-script"></pre></div>';
         type(document.getElementById('dm-script'), SCRIPT, 2600); }},
      {d:3400, cap:'The router dials home over WireGuard, and appears on the dashboard — no public IP needed.',
       f:function(){ $('.ap-dbadge').style.visibility = '';
         showDash(); rows.push({name:'Shop · Cape Town', st:'ok', al:0, hl:true, fresh:true});
         drawTable(); }},
      {d:2600, cap:'From here it is polled every 60 seconds, like every other router.'}
    ]}
  ];

  function play(n){
    stopAll();
    cur = (n + SC.length) % SC.length; scen = SC[cur]; step = 0;
    tabs.forEach(function(t, i){
      t.classList.toggle('on', i === cur);
      t.setAttribute('aria-selected', i === cur ? 'true' : 'false');
    });
    scen.init();
    next();
  }
  function next(){
    if (paused) return;
    if (step >= scen.steps.length) { later(2200, function(){ play(cur + 1); }); return; }
    var st = scen.steps[step++];
    stepEl.textContent = 'Scenario ' + (cur + 1) + ' · ' + scen.title +
                         ' · step ' + step + ' of ' + scen.steps.length;
    if (st.cap) {
      capEl.textContent = st.cap;
      capEl.classList.remove('in'); void capEl.offsetWidth; capEl.classList.add('in');
    }
    if (st.f) st.f();
    bar.style.width = (step / scen.steps.length * 100) + '%';
    later(reduce ? st.d * 1.5 : st.d, next);
  }
  tabs.forEach(function(t, i){
    t.addEventListener('click', function(){
      paused = false; pauseBtn.textContent = 'Pause'; play(i);
    });
  });
  pauseBtn.addEventListener('click', function(){
    paused = !paused;
    pauseBtn.textContent = paused ? 'Play' : 'Pause';
    if (paused) stopAll(); else next();
  });

  var started = false;
  function start(){ if (!started) { started = true; play(0); } }
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function(es){
      es.forEach(function(e){ if (e.isIntersecting) start(); });
    }, {threshold: 0.2}).observe(app);
  } else { start(); }
  reset();
})();
</script>
"""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _feat_card(icon: str, title: str, body: str) -> str:
    return (f'<div class="feat-card">'
            f'<span class="feat-icon">{_icon(icon)}</span>'
            f'<h3>{esc(title)}</h3>'
            f'<p>{esc(body)}</p>'
            f'</div>')


def _dyk_card(icon: str, title: str, body: str) -> str:
    return (f'<div class="dyk"><span class="dyk-ic">{_icon(icon, 18)}</span>'
            f'<div><h3>{esc(title)}</h3><p>{esc(body)}</p></div></div>')


def _step_card(num: str, title: str, body: str) -> str:
    return (f'<div class="step">'
            f'<div class="step-num">{num}</div>'
            f'<div>'
            f'<h3>{esc(title)}</h3>'
            f'<p>{esc(body)}</p>'
            f'</div></div>')


def _faq_item(q: str, a: str) -> str:
    return f'<details><summary>{esc(q)}</summary><p>{esc(a)}</p></details>'


def _price_card(plan: dict) -> str:
    hl = plan["highlight"]
    items = "".join(f'<li>{esc(i)}</li>' for i in plan["items"])
    cta_cls = "ghost" if hl else "solid"
    return (f'<div class="price-card{" highlight" if hl else ""}">'
            f'<div class="price-plan">{esc(plan["name"])}</div>'
            f'<div class="price-devices">{esc(plan["devices"])}</div>'
            f'<div class="price-amount">{esc(plan["amount"])}</div>'
            f'<div class="price-period">{esc(plan["period"])}</div>'
            f'<ul class="price-items">{items}</ul>'
            f'<a href="{esc(plan["cta_href"])}" class="price-cta {cta_cls}">'
            f'{esc(plan["cta_label"])}</a>'
            f'</div>')


def _tier_rows() -> str:
    """Every packet, in fives, then the row that leads out of the table.

    The whole ladder is shown rather than a summary: a visitor's first
    question is "what does MY size cost", and making them interpolate between
    two sample tiers is how you lose them to a competitor who just says.
    """
    rows = ""
    for p in PLANS:
        per = p["price_usd"] / p["devices"]
        rows += (f'<tr>'
                 f'<td><b>{p["devices"]} devices</b></td>'
                 f'<td>{p["devices"]}</td>'
                 f'<td class="usd">${p["price_usd"]:,.2f}</td>'
                 f'<td class="per">${per:.2f} / device</td>'
                 f'<td><a class="btn-nav-primary" href="/signup" '
                 f'style="display:inline-block;padding:5px 14px;font-size:13px">'
                 f'Start trial</a></td>'
                 f'</tr>')
    rows += (f'<tr style="background:var(--surface-2)">'
             f'<td><b>Over {QUOTE_ABOVE_DEVICES} devices</b></td>'
             f'<td>Custom</td>'
             f'<td class="usd">Let&rsquo;s talk</td>'
             f'<td class="per">Quoted to fit your fleet</td>'
             f'<td><a class="btn-nav-primary" href="/signup" '
             f'style="display:inline-block;padding:5px 14px;font-size:13px">'
             f'Request a quote</a></td>'
             f'</tr>')
    return rows


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render_landing(ai_on: bool = False) -> str:
    """The public page. `ai_on` is whether this server has the AI monitor's
    online check switched on: the page only claims the search when it is
    true -- a claim the product does not back is one a customer catches."""
    feat_cards = "\n".join(_feat_card(i, t, b) for i, t, b in _FEATURES)
    search = (" With the online check on, it also looks for outages and "
              "load-shedding reported in that area, and sends the sources."
              if ai_on else "")
    dyk_cards = "\n".join(_dyk_card(i, t, b.replace("__AI_SEARCH__", search))
                          for i, t, b in _DID_YOU_KNOW)
    step_cards = "\n".join(_step_card(n, t, b) for n, t, b in _STEPS)
    faq_items = "\n".join(_faq_item(q, a) for q, a in _FAQ)
    price_cards = "\n".join(_price_card(p) for p in _PLANS)
    tier_rows = _tier_rows()
    brand = esc(_BRAND)
    from .brand import logo_img, favicon_tags
    mark = logo_img(26)
    favicon = favicon_tags()

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Monitor and manage every MikroTik router from one dashboard. Real-time alerts, WAN failover, safe config push with auto-revert, automated backups, and remote WebFig access — even behind NAT.">
  {favicon}
  <title>{esc(_TITLE)}</title>
  {_THEME_INIT_JS}
  <style>{_THEME_VARS}{_CSS}{_DEMO_CSS}</style>
</head>
<body>

<!-- ── NAV ─────────────────────────────────────── -->
<nav class="lnav" id="lnav">
  <a class="lnav-logo" href="/">
    {mark}{brand}
  </a>
  <div class="lnav-links" id="lnav-links">
    <a href="#demo">See it work</a>
    <a href="#features">Features</a>
    <a href="#how-it-works">How it works</a>
    <a href="#pricing">Pricing</a>
    <a href="#faq">FAQ</a>
  </div>
  <div class="lnav-right">
    {_theme_toggle_btn()}
    <a class="btn-nav-ghost" href="/login">Sign in</a>
    <a class="btn-nav-primary" href="/signup">Start free trial</a>
  </div>
  <button class="hamburger" aria-label="Open menu"
    onclick="document.getElementById('lnav-links').classList.toggle('open')">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- ── HERO ────────────────────────────────────── -->
<section class="hero">
  <div class="hero-inner">
    <div class="hero-badge">&#10022; Built for MikroTik admins &amp; MSPs</div>
    <h1>All your MikroTik routers.<br><em>One dashboard. Zero surprises.</em></h1>
    <p class="hero-sub">
      Real-time health, WAN failover management, safe remote config push,
      automated backups, and on-demand WebFig access — even behind NAT and CGNAT.
    </p>
    <div class="hero-ctas">
      <a class="btn-hero-primary" href="/signup">Start 30-day free trial</a>
      <a class="btn-hero-outline" href="#demo"><span class="play"></span>See it in action</a>
    </div>
    <div class="hero-facts">
      <span class="hero-fact">Polled every <b>60 s</b></span>
      <span class="hero-fact">Bad changes undo themselves in <b>about 2 min</b></span>
      <span class="hero-fact">Remote links close after <b>15 min</b></span>
      <span class="hero-fact"><b>No public IP</b> needed</span>
    </div>
  </div>
</section>

<!-- ── PROOF BAR ────────────────────────────────── -->
<div class="proof">
  <div class="proof-item"><b>&#10003;</b>&nbsp;30-day free trial — no card needed</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;No public IP required on routers</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;Works behind NAT &amp; CGNAT</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;Unlimited team members per account</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;RouterOS 7.1+ compatible</div>
</div>

<!-- ── DEMO ─────────────────────────────────────── -->
<section id="demo" class="demo-bg">
  <div class="s-inner">
    <p class="s-label">See it work</p>
    <h2 class="s-title">The things that used to mean a site visit, handled from your desk</h2>
    <p class="s-sub">
      Four everyday moments, played out on the product's own screens. Pick
      one, or let it run.
    </p>
    {_demo_html()}
  </div>
</section>

<!-- ── FEATURES ─────────────────────────────────── -->
<section id="features">
  <div class="s-inner">
    <p class="s-label">Features</p>
    <h2 class="s-title">Everything you need to run a professional MikroTik operation</h2>
    <p class="s-sub">
      From a single router to a whole MSP fleet — {brand} gives you the
      visibility and control to fix problems before users notice.
    </p>
    <div class="feat-grid">
      {feat_cards}
    </div>
  </div>
</section>

<!-- ── DID YOU KNOW ─────────────────────────────── -->
<section id="did-you-know" class="dyk-bg">
  <div class="s-inner">
    <p class="s-label">Did you know?</p>
    <h2 class="s-title">It does more than you would think to ask for</h2>
    <p class="s-sub">
      The small things that save an afternoon, all built in and switched on
      from the same dashboard.
    </p>
    <div class="dyk-grid">
      {dyk_cards}
    </div>
  </div>
</section>

<!-- ── HOW IT WORKS ──────────────────────────────── -->
<section id="how-it-works">
  <div class="s-inner">
    <p class="s-label">How it works</p>
    <h2 class="s-title">Up and monitoring in minutes</h2>
    <p class="s-sub">
      No Docker, no Kubernetes, no certificates to manage. Create an account,
      add a router, and you're live.
    </p>
    <div class="steps-grid">
      {step_cards}
    </div>
  </div>
</section>

<!-- ── PRICING ───────────────────────────────────── -->
<section id="pricing" class="pricing-bg">
  <div class="s-inner">
    <p class="s-label">Pricing</p>
    <h2 class="s-title">Pay only for what you monitor</h2>
    <p class="s-sub">
      Start with a 30-day free trial — no credit card. Upgrade to a paid plan
      when you're ready. {GRACE_DAYS}-day grace period on missed payments; cancel anytime.
    </p>
    <div class="price-grid">
      {price_cards}
    </div>

    <!-- Full tier table -->
    <h3 style="font-size:16px;font-weight:700;margin-bottom:14px;color:var(--text)">
      Every packet includes every feature &mdash; you only pay for more devices.
    </h3>
    <table class="tier-table">
      <thead><tr>
        <th>Plan</th><th>Devices</th><th>Monthly</th><th>Per device</th><th></th>
      </tr></thead>
      <tbody>{tier_rows}</tbody>
    </table>
    <p style="font-size:12px;color:var(--text-faint);margin-top:12px">
      Packets step in {TIER_STEP}s up to {MAX_TIER_DEVICES} devices. Need more than that?
      <a href="/signup">Sign up</a> and request a quote from your Billing tab &mdash;
      the team will come back to you with pricing built around your fleet.
    </p>
  </div>
</section>

<!-- ── FAQ ───────────────────────────────────────── -->
<section id="faq">
  <div class="s-inner">
    <p class="s-label">FAQ</p>
    <h2 class="s-title">Questions people ask first</h2>
    <div class="faq">
      {faq_items}
    </div>
  </div>
</section>

<!-- ── CTA BANNER ───────────────────────────────── -->
<div class="cta-wrap">
  <h2>Ready to take control of your network?</h2>
  <p>
    Start your 30-day free trial today. Add your first router in minutes —
    no credit card, no commitment.
  </p>
  <a class="btn-hero-primary" href="/signup">Start free trial</a>
</div>

<!-- ── FOOTER ───────────────────────────────────── -->
<footer>
  <div class="foot-inner">
    <div class="foot-top">
      <div>
        <a class="foot-logo" href="/">
          {mark}{brand}
        </a>
        <p class="foot-tag">MikroTik monitoring &amp; remote management for IT teams and MSPs.</p>
      </div>
      <div class="foot-col">
        <h4>Product</h4>
        <a href="#demo">See it work</a>
        <a href="#features">Features</a>
        <a href="#did-you-know">Did you know?</a>
        <a href="#pricing">Pricing</a>
      </div>
      <div class="foot-col">
        <h4>Help</h4>
        <a href="#how-it-works">How it works</a>
        <a href="#faq">FAQ</a>
        <a href="/terms">Terms &amp; Conditions</a>
      </div>
      <div class="foot-col">
        <h4>Account</h4>
        <a href="/login">Sign in</a>
        <a href="/signup">Start free trial</a>
      </div>
    </div>
    <div class="foot-bottom">
      <span>&copy; 2026 {brand}. All rights reserved.</span>
      <span>Built for MikroTik admins everywhere.</span>
    </div>
  </div>
</footer>

{_THEME_TOGGLE_JS}
{_DEMO_JS.replace("/*AI_STEP*/", _AI_DEMO_STEP if ai_on else "")}
</body>
</html>"""
