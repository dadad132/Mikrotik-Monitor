"""Landing page for easymikrotik.

Accessible at /landing for preview. Wire it to / for unauthenticated visitors
by adding this before the auth gate in web.py do_GET:

    if path in ("/", "/home") and not self._session():
        from .web_landing import render_landing
        return self._send(200, render_landing(), "text/html; charset=utf-8")
"""
from __future__ import annotations

from .web_shared import _BRAND, esc

_TITLE = f"{_BRAND} — MikroTik Monitoring & Remote Management"

# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

_FEATURES = [
    ("&#9670;", "Real-time NOC Dashboard",
     "Device grid with live CPU, RAM, temperature, throughput charts, and WAN "
     "health indicators. Problems colour-coded — see what's wrong before users "
     "start calling."),
    ("&#8644;", "Gateway Failover Management",
     "Configure primary/secondary WAN uplinks with automatic gateway detection. "
     "Netwatch distance-based switching means failover without reboots — and an "
     "alert the moment traffic moves to the backup link."),
    ("&#8635;", "Safe Config Push & Auto-Revert",
     "Push RouterOS changes through the API. If the change breaks connectivity "
     "the router auto-reverts to the previous backup within 5 minutes — you "
     "cannot lock yourself out of a remote router again."),
    ("&#128190;", "Automated Router Backups",
     "One-click encrypted backup saved directly to the router's flash. The "
     "system keeps the last 10 server-created backups and prunes older ones "
     "automatically — manual backups you create on the router are never touched."),
    ("&#9671;", "Secure Remote Access",
     "Open WebFig or Winbox through the encrypted hub tunnel — time-limited and "
     "audited. No port forwarding, no exposed API port on the internet, works "
     "even behind double NAT."),
    ("&#9737;", "WireGuard Dial-Home Tunnel",
     "Routers connect outbound to your server. No public IP required on the "
     "router side — ideal for CGNAT, home offices, LTE uplinks, and any site "
     "you can't port-forward."),
    ("&#10022;", "Multi-tenant Company Accounts",
     "One company account for your whole team. The owner controls which devices "
     "each member can see and manage. Add unlimited staff — your team grows "
     "without extra per-seat charges."),
    ("&#128179;", "Transparent Per-Device Billing",
     "30-day free trial with 1 device. Then pay only for what you use — from "
     "$25/mo for 5 devices up to $3 000/mo for 1 000 devices. Cancel anytime; "
     "7-day grace period on missed payments."),
]

_STEPS = [
    ("1", "Create your account",
     "Sign up with your company email. You get a 30-day free trial with 1 device "
     "immediately — no credit card needed."),
    ("2", "Add your first router",
     "Enter the router IP or provision it over the WireGuard tunnel. The Provision "
     "tab generates a ready-to-paste RouterOS script — no manual key exchange."),
    ("3", "Monitor and manage",
     "The dashboard refreshes every 60 seconds. Set up WAN failover, schedule "
     "backups, push config changes, and open WebFig/Winbox from anywhere."),
]

# Real billing tiers shown on the landing page.
_PLANS = [
    {
        "name":    "Free Trial",
        "devices": "1 device",
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
        "soon":      False,
    },
    {
        "name":    "Starter",
        "devices": "5 devices",
        "amount":  "$25",
        "period":  "per month",
        "items":   [
            "Everything in Free Trial",
            "Unlimited team members",
            "Email alerts",
            "7-day grace on missed payment",
            "$5.00 / device / month",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": False,
        "soon":      False,
    },
    {
        "name":    "Business",
        "devices": "50 devices",
        "amount":  "$210",
        "period":  "per month",
        "items":   [
            "Everything in Starter",
            "$4.20 / device / month",
            "Priority support",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": True,
        "soon":      False,
    },
    {
        "name":    "Professional",
        "devices": "100 devices",
        "amount":  "$400",
        "period":  "per month",
        "items":   [
            "Everything in Business",
            "$4.00 / device / month",
            "Ideal for MSPs",
        ],
        "cta_href":  "/signup",
        "cta_label": "Start free trial",
        "highlight": False,
        "soon":      False,
    },
]

_ALL_TIERS = [
    ("Starter",        5,    25),
    ("Small",         15,    69),
    ("Medium",        30,   135),
    ("Business",      50,   210),
    ("Professional", 100,   400),
    ("Ent 250",      250,   925),
    ("Ent 500",      500,  1750),
    ("Ent 1000",    1000,  3000),
]

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:Segoe UI,system-ui,Arial,sans-serif;color:#0f172a;
  background:#fff;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:#2563eb;text-decoration:none}

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
  padding:88px 24px 100px;text-align:center;position:relative;overflow:hidden}
.hero::before{content:"";position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% 0%,
    rgba(37,99,235,.2),transparent);pointer-events:none}
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
  box-shadow:0 4px 16px rgba(37,99,235,.4)}
.btn-hero-primary:hover{background:#1d4ed8;color:#fff;
  box-shadow:0 4px 24px rgba(37,99,235,.55);transform:translateY(-1px)}
.btn-hero-outline{color:#e2e8f0;padding:13px 26px;border:1px solid rgba(255,255,255,.22);
  border-radius:9px;font-size:15px;font-weight:500;transition:.12s}
.btn-hero-outline:hover{background:rgba(255,255,255,.07);color:#fff}

/* ── proof bar ───────────────────────────────────── */
.proof{background:#f8fafc;border-bottom:1px solid #e2e8f0;
  padding:14px 24px;display:flex;justify-content:center;
  align-items:center;gap:28px;flex-wrap:wrap}
.proof-item{font-size:13px;color:#475569;display:flex;align-items:center;gap:6px}
.proof-item b{color:#0f172a}

/* ── shared section styles ───────────────────────── */
section{padding:76px 24px}
.s-inner{max-width:1064px;margin:0 auto}
.s-label{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.09em;color:#2563eb;margin-bottom:10px}
.s-title{font-size:clamp(22px,4vw,38px);font-weight:800;color:#0f172a;
  margin-bottom:14px;line-height:1.15;letter-spacing:-.02em}
.s-sub{font-size:15px;color:#475569;max-width:540px;line-height:1.65;
  margin-bottom:48px}

/* ── feature cards ───────────────────────────────── */
.feat-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(292px,1fr));gap:18px}
.feat-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;
  padding:24px 22px;transition:box-shadow .15s,transform .15s}
.feat-card:hover{box-shadow:0 8px 28px rgba(15,23,42,.09);
  transform:translateY(-2px)}
.feat-icon{font-size:24px;margin-bottom:14px;display:block;color:#2563eb}
.feat-card h3{font-size:15px;font-weight:700;margin-bottom:7px;color:#0f172a}
.feat-card p{font-size:13px;color:#475569;line-height:1.65}

/* ── steps ───────────────────────────────────────── */
.steps-bg{background:#f1f5f9}
.steps-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:36px}
.step{display:flex;flex-direction:column;gap:12px}
.step-num{width:40px;height:40px;border-radius:50%;background:#2563eb;
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:17px;font-weight:800;flex-shrink:0}
.step h3{font-size:15px;font-weight:700;color:#0f172a;margin-top:4px}
.step p{font-size:13px;color:#475569;line-height:1.65}

/* ── pricing cards ───────────────────────────────── */
.price-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(228px,1fr));
  gap:20px;align-items:start;margin-bottom:36px}
.price-card{border:1px solid #e2e8f0;border-radius:14px;
  padding:28px 24px;display:flex;flex-direction:column;background:#fff}
.price-card.highlight{background:#0f172a;border-color:#0f172a}
.price-plan{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:#2563eb;margin-bottom:4px}
.price-card.highlight .price-plan{color:#38bdf8}
.price-devices{font-size:13px;color:#64748b;margin-bottom:6px}
.price-card.highlight .price-devices{color:#94a3b8}
.price-amount{font-size:36px;font-weight:800;line-height:1;
  color:#0f172a;margin-bottom:3px}
.price-card.highlight .price-amount{color:#fff}
.price-period{font-size:12px;color:#64748b;margin-bottom:22px}
.price-card.highlight .price-period{color:#94a3b8}
.price-items{list-style:none;flex:1;margin-bottom:24px}
.price-items li{font-size:13px;padding:6px 0;
  border-bottom:1px solid #f1f5f9;
  display:flex;align-items:flex-start;gap:8px;color:#334155;line-height:1.4}
.price-card.highlight .price-items li{
  color:#e2e8f0;border-bottom-color:rgba(255,255,255,.07)}
.price-items li::before{content:"✓";color:#16a34a;font-weight:700;flex-shrink:0}
.price-card.highlight .price-items li::before{color:#4ade80}
.price-cta{display:block;text-align:center;padding:11px;border-radius:8px;
  font-size:14px;font-weight:600;transition:.12s}
.price-cta.solid{background:#2563eb;color:#fff;border:2px solid #2563eb}
.price-cta.solid:hover{background:#1d4ed8;border-color:#1d4ed8;color:#fff}
.price-cta.ghost{background:#fff;color:#0f172a;border:2px solid #e2e8f0}
.price-cta.ghost:hover{border-color:#94a3b8;background:#f8fafc}

/* ── all-tiers table ─────────────────────────────── */
.tier-table{width:100%;border-collapse:collapse;font-size:13px;
  background:#fff;border-radius:12px;overflow:hidden;
  border:1px solid #e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.tier-table th{background:#f8fafc;font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;color:#64748b;padding:10px 16px;
  border-bottom:1px solid #e2e8f0;text-align:left}
.tier-table td{padding:10px 16px;border-bottom:1px solid #f1f5f9;color:#334155}
.tier-table tr:last-child td{border-bottom:0}
.tier-table .usd{font-weight:700;color:#0f172a}
.tier-table .per{color:#64748b}

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
.foot-tag{font-size:13px;color:#475569;max-width:190px;line-height:1.5}
.foot-col h4{font-size:11px;font-weight:700;color:#e2e8f0;
  text-transform:uppercase;letter-spacing:.07em;margin-bottom:12px}
.foot-col a{display:block;color:#64748b;font-size:13px;
  padding:3px 0;transition:.1s}
.foot-col a:hover{color:#e2e8f0}
.foot-bottom{border-top:1px solid rgba(255,255,255,.07);
  padding-top:20px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:8px;
  font-size:12px;color:#475569}

/* ── responsive ──────────────────────────────────── */
@media(max-width:768px){
  .lnav-links,.lnav-right .btn-nav-ghost{display:none}
  .hamburger{display:flex}
  .lnav-links.open{
    display:flex;flex-direction:column;
    position:absolute;top:60px;left:0;right:0;
    background:#0f172a;padding:12px 16px 16px;
    border-bottom:1px solid rgba(255,255,255,.08);gap:2px}
  .lnav-links.open a{padding:11px 12px;border-radius:7px;
    color:#e2e8f0;font-size:15px}
  .lnav-right{gap:6px}
  .btn-nav-primary{font-size:13px;padding:7px 12px}
  section{padding:52px 20px}
  .hero{padding:60px 20px 72px}
  .foot-top{flex-direction:column;gap:20px}
  .foot-bottom{flex-direction:column;gap:4px;text-align:center}
}
@media(max-width:480px){
  .proof{flex-direction:column;gap:10px;text-align:center}
  .hero-ctas{flex-direction:column;align-items:center}
  .hero-ctas a{width:100%;max-width:300px;text-align:center}
  .steps-grid,.price-grid{grid-template-columns:1fr}
}
"""

# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _feat_card(icon: str, title: str, body: str) -> str:
    return (f'<div class="feat-card">'
            f'<span class="feat-icon">{icon}</span>'
            f'<h3>{esc(title)}</h3>'
            f'<p>{esc(body)}</p>'
            f'</div>')


def _step_card(num: str, title: str, body: str) -> str:
    return (f'<div class="step">'
            f'<div class="step-num">{num}</div>'
            f'<div>'
            f'<h3>{esc(title)}</h3>'
            f'<p>{esc(body)}</p>'
            f'</div></div>')


def _price_card(plan: dict) -> str:
    hl = plan["highlight"]
    items = "".join(f'<li>{esc(i)}</li>' for i in plan["items"])
    cta_cls = "ghost" if hl else "solid"
    return (f'<div class="price-card{"  highlight" if hl else ""}">'
            f'<div class="price-plan">{esc(plan["name"])}</div>'
            f'<div class="price-devices">{esc(plan["devices"])}</div>'
            f'<div class="price-amount">{plan["amount"]}</div>'
            f'<div class="price-period">{plan["period"]}</div>'
            f'<ul class="price-items">{items}</ul>'
            f'<a href="{esc(plan["cta_href"])}" class="price-cta {cta_cls}">'
            f'{esc(plan["cta_label"])}</a>'
            f'</div>')


def _tier_rows() -> str:
    rows = ""
    for name, devices, price in _ALL_TIERS:
        per = round(price / devices, 2)
        rows += (f'<tr>'
                 f'<td><b>{esc(name)}</b></td>'
                 f'<td>{devices}</td>'
                 f'<td class="usd">${price:,}</td>'
                 f'<td class="per">${per:.2f} / device</td>'
                 f'<td><a class="btn-nav-primary" href="/signup" '
                 f'style="display:inline-block;padding:5px 14px;font-size:13px">'
                 f'Start trial</a></td>'
                 f'</tr>')
    return rows


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render_landing() -> str:
    feat_cards = "\n".join(_feat_card(i, t, b) for i, t, b in _FEATURES)
    step_cards = "\n".join(_step_card(n, t, b) for n, t, b in _STEPS)
    price_cards = "\n".join(_price_card(p) for p in _PLANS)
    tier_rows = _tier_rows()
    brand = esc(_BRAND)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Monitor and manage every MikroTik router from one dashboard. Real-time alerts, WAN failover, safe config push, automated backups, and remote WebFig access — even behind NAT.">
  <title>{esc(_TITLE)}</title>
  <style>{_CSS}</style>
</head>
<body>

<!-- ── NAV ─────────────────────────────────────── -->
<nav class="lnav" id="lnav">
  <a class="lnav-logo" href="/">
    <span class="dot">&#9670;</span>{brand}
  </a>
  <div class="lnav-links" id="lnav-links">
    <a href="#features">Features</a>
    <a href="#how-it-works">How it works</a>
    <a href="#pricing">Pricing</a>
  </div>
  <div class="lnav-right">
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
      <a class="btn-hero-outline" href="#how-it-works">See how it works</a>
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

<!-- ── FEATURES ─────────────────────────────────── -->
<section id="features">
  <div class="s-inner">
    <p class="s-label">Features</p>
    <h2 class="s-title">Everything you need to run a professional MikroTik operation</h2>
    <p class="s-sub">
      From a 1-router home lab to a 1 000-device MSP deployment — {brand} gives
      you the visibility and control to fix problems before users notice.
    </p>
    <div class="feat-grid">
      {feat_cards}
    </div>
  </div>
</section>

<!-- ── HOW IT WORKS ──────────────────────────────── -->
<section id="how-it-works" class="steps-bg">
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
<section id="pricing">
  <div class="s-inner">
    <p class="s-label">Pricing</p>
    <h2 class="s-title">Pay only for what you monitor</h2>
    <p class="s-sub">
      Start with a 30-day free trial — no credit card. Upgrade to a paid plan
      when you're ready. 7-day grace period on missed payments; cancel anytime.
    </p>
    <div class="price-grid">
      {price_cards}
    </div>

    <!-- Full tier table -->
    <h3 style="font-size:16px;font-weight:700;margin-bottom:14px;color:#0f172a">
      All plans include every feature — you only pay for more devices.
    </h3>
    <table class="tier-table">
      <thead><tr>
        <th>Plan</th><th>Devices</th><th>Monthly</th><th>Per device</th><th></th>
      </tr></thead>
      <tbody>{tier_rows}</tbody>
    </table>
    <p style="font-size:12px;color:#94a3b8;margin-top:12px">
      Need more than 1 000 devices? <a href="/signup">Contact us</a> for a custom quote.
    </p>
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
          <span class="dot">&#9670;</span>{brand}
        </a>
        <p class="foot-tag">MikroTik monitoring &amp; remote management for IT teams and MSPs.</p>
      </div>
      <div class="foot-col">
        <h4>Product</h4>
        <a href="#features">Features</a>
        <a href="#how-it-works">How it works</a>
        <a href="#pricing">Pricing</a>
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

</body>
</html>"""
