"""Landing page for easymikrotik.

DORMANT — complete but not wired to any route. Nothing in the running app
serves this until you explicitly hook it in (same pattern as billing.py).

To enable for unauthenticated visitors, add these two blocks inside the
request handler in web.py, BEFORE the auth-gate section
(around the `if not auth:` check, roughly line 2400):

    # ---- landing page for unauthenticated visitors ----
    if path in ("/", "/home") and not self._session():
        from .web_landing import render_landing
        return self._send(200, render_landing(), "text/html; charset=utf-8")

    # ---- dev/staging preview (remove before production) ----
    if path == "/landing":
        from .web_landing import render_landing
        return self._send(200, render_landing(), "text/html; charset=utf-8")
    # ---------------------------------------------------
"""
from __future__ import annotations

from .web_shared import _BRAND, esc

_TITLE = f"{_BRAND} — MikroTik Monitoring Made Easy"

# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

_FEATURES = [
    ("&#9670;", "Real-time Dashboard",
     "CPU, RAM, temperature, interface state, and WAN health across every router "
     "at a glance. Problems are colour-coded so you see what needs attention first."),
    ("&#8635;", "Safe Config Push",
     "Push RouterOS configuration changes through the API. A 5-minute auto-revert "
     "safety net rolls the change back if it breaks the tunnel — you can't lock "
     "yourself out of a router again."),
    ("&#8644;", "WAN Failover Alerts",
     "Name your ISP uplinks (Vodacom, MTN, LTE) and get alerted the moment a "
     "router switches to a backup link, so you act before users even notice."),
    ("&#9671;", "Secure Remote Access",
     "Open WebFig or Winbox for any router through a time-limited, encrypted proxy "
     "— even behind double NAT. No port forwarding, no exposed API ports on the router."),
    ("&#10022;", "Works Behind Any NAT",
     "Routers dial home over WireGuard. No public IP needed on the router side — "
     "ideal for CGNAT connections, home offices, and remote branch sites."),
    ("&#10022;", "Multi-tenant Teams",
     "Create a company account, invite your team, and control exactly which routers "
     "each member can see and manage. Perfect for MSPs and multi-site businesses."),
]

_STEPS = [
    ("1", "Install on your server",
     "One command on any Ubuntu 22+ VPS. The installer sets up the monitoring "
     "service, the WireGuard hub, nginx, and the web dashboard automatically."),
    ("2", "Add your routers",
     "Enter the router's IP or leave it blank to provision over the tunnel. The "
     "Provision tab generates a ready-to-paste RouterOS script — no manual key "
     "exchange, no copying public keys."),
    ("3", "Monitor and manage",
     "The dashboard refreshes every 60 seconds. You get email alerts when something "
     "breaks, and one-click WebFig / Winbox access when you need to fix it."),
]

_PLANS = [
    {
        "name":    "Self-hosted",
        "amount":  "Free",
        "period":  "forever, open source",
        "items":   [
            "Unlimited routers",
            "All monitoring features",
            "WireGuard dial-home tunnel",
            "Safe config push + auto-revert",
            "On-demand WebFig / Winbox",
            "Email alerts",
            "Multi-tenant team accounts",
        ],
        "cta_href":  "/signup",
        "cta_label": "Get started free",
        "highlight": False,
        "soon":      False,
    },
    {
        "name":    "Cloud",
        "amount":  "Coming soon",
        "period":  "hosted &amp; managed",
        "items":   [
            "Hosted on our infrastructure",
            "Automatic updates",
            "Managed backups",
            "Priority email support",
            "Grafana / Prometheus export",
            "SSO / SAML login",
            "Custom domain",
        ],
        "cta_href":  "#",
        "cta_label": "Notify me",
        "highlight": True,
        "soon":      True,
    },
    {
        "name":    "Enterprise",
        "amount":  "Contact us",
        "period":  "dedicated &amp; on-premise",
        "items":   [
            "Dedicated instance",
            "Custom SLA",
            "On-premise option",
            "White-label branding",
            "Professional services",
            "Team training",
        ],
        "cta_href":  "#",
        "cta_label": "Get in touch",
        "highlight": False,
        "soon":      True,
    },
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
/* hamburger */
.hamburger{display:none;background:0;border:0;cursor:pointer;
  padding:6px;flex-direction:column;gap:5px;margin-left:auto}
.hamburger span{display:block;width:22px;height:2px;background:#e2e8f0;
  border-radius:2px;transition:.2s}
/* mobile nav open state */
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

/* ── pricing ─────────────────────────────────────── */
.price-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(268px,1fr));
  gap:20px;align-items:start}
.price-card{border:1px solid #e2e8f0;border-radius:14px;
  padding:28px 24px;display:flex;flex-direction:column;background:#fff}
.price-card.highlight{background:#0f172a;border-color:#0f172a}
.price-plan{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:#2563eb;margin-bottom:8px}
.price-card.highlight .price-plan{color:#38bdf8}
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
.price-cta.outline{border:2px solid #e2e8f0;color:#64748b;background:#fff}
.price-cta.outline:hover{border-color:#94a3b8;background:#f8fafc;color:#334155}
.badge-soon{background:#fef3c7;color:#92400e;font-size:10px;font-weight:700;
  padding:2px 7px;border-radius:999px;text-transform:uppercase;
  letter-spacing:.04em;vertical-align:middle;margin-left:6px}
.price-card.highlight .badge-soon{background:rgba(254,243,199,.15);color:#fcd34d}

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
    soon_badge = '<span class="badge-soon">soon</span>' if plan["soon"] else ""
    items = "".join(f'<li>{esc(i)}</li>' for i in plan["items"])
    cta_cls = "solid" if not plan["soon"] else "outline"
    return (f'<div class="price-card{"  highlight" if hl else ""}">'
            f'<div class="price-plan">{esc(plan["name"])}</div>'
            f'<div class="price-amount">{plan["amount"]}{soon_badge}</div>'
            f'<div class="price-period">{plan["period"]}</div>'
            f'<ul class="price-items">{items}</ul>'
            f'<a href="{esc(plan["cta_href"])}" class="price-cta {cta_cls}">'
            f'{esc(plan["cta_label"])}</a>'
            f'</div>')


# ---------------------------------------------------------------------------
# Public render function
# ---------------------------------------------------------------------------

def render_landing() -> str:
    feat_cards = "\n".join(_feat_card(i, t, b) for i, t, b in _FEATURES)
    step_cards = "\n".join(_step_card(n, t, b) for n, t, b in _STEPS)
    price_cards = "\n".join(_price_card(p) for p in _PLANS)
    brand = esc(_BRAND)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Monitor and manage every MikroTik router from one dashboard. Real-time alerts, safe config push, and remote access — even behind NAT.">
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
    <a class="btn-nav-primary" href="/signup">Get started</a>
  </div>
  <button class="hamburger" aria-label="Open menu"
    onclick="document.getElementById('lnav-links').classList.toggle('open')">
    <span></span><span></span><span></span>
  </button>
</nav>

<!-- ── HERO ────────────────────────────────────── -->
<section class="hero">
  <div class="hero-inner">
    <div class="hero-badge">&#10022; Built for MikroTik admins</div>
    <h1>Monitor every router.<br><em>Fix problems before users notice.</em></h1>
    <p class="hero-sub">
      A single dashboard for all your MikroTik routers — real-time health,
      instant alerts, safe remote config, and on-demand WebFig access.
      Works behind NAT and CGNAT.
    </p>
    <div class="hero-ctas">
      <a class="btn-hero-primary" href="/signup">Create free account</a>
      <a class="btn-hero-outline" href="#how-it-works">See how it works</a>
    </div>
  </div>
</section>

<!-- ── PROOF BAR ────────────────────────────────── -->
<div class="proof">
  <div class="proof-item"><b>&#10003;</b>&nbsp;Self-hosted — your data, your server</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;No public IP needed on routers</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;Works behind NAT &amp; CGNAT</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;RouterOS 7.1+ compatible</div>
  <div class="proof-item"><b>&#10003;</b>&nbsp;Open source</div>
</div>

<!-- ── FEATURES ─────────────────────────────────── -->
<section id="features">
  <div class="s-inner">
    <p class="s-label">Features</p>
    <h2 class="s-title">Everything you need to stay on top of your network</h2>
    <p class="s-sub">
      From a 1-router home lab to a 50-site MSP deployment — {brand} scales
      with you without adding complexity.
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
    <h2 class="s-title">Up and running in under 10 minutes</h2>
    <p class="s-sub">
      No Docker, no Kubernetes, no certificates to manage. One command
      on a standard Ubuntu VPS is all you need to start.
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
    <h2 class="s-title">Simple, honest pricing</h2>
    <p class="s-sub">
      Start free and self-hosted. Managed cloud and enterprise tiers are
      coming — join the waitlist to be first in line.
    </p>
    <div class="price-grid">
      {price_cards}
    </div>
  </div>
</section>

<!-- ── CTA BANNER ───────────────────────────────── -->
<div class="cta-wrap">
  <h2>Ready to take control of your network?</h2>
  <p>
    Create your free account and have your first router connected in
    under 10 minutes. No credit card required.
  </p>
  <a class="btn-hero-primary" href="/signup">Create free account</a>
</div>

<!-- ── FOOTER ───────────────────────────────────── -->
<footer>
  <div class="foot-inner">
    <div class="foot-top">
      <div>
        <a class="foot-logo" href="/">
          <span class="dot">&#9670;</span>{brand}
        </a>
        <p class="foot-tag">MikroTik monitoring made easy for IT teams and MSPs.</p>
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
        <a href="/signup">Create account</a>
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
