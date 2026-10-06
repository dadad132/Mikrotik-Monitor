"""Terms & Conditions: the page, and the tick-box that accepts it.

Accepted twice -- when an account is created and again with every payment --
and the version accepted is recorded each time, on the user and on the order.
TERMS_VERSION is the date of the text below; change it whenever the text
changes, so a record says which terms somebody actually agreed to.

The provider is named from the platform's billing contact (Platform admin ->
Billing contact): the bank account holder if one is saved, else the contact
name, else the brand. Terms that do not say who they are with are not much
of an agreement.
"""
from __future__ import annotations

from .web_shared import (_BRAND, _THEME_INIT_JS, _THEME_TOGGLE_JS, _THEME_VARS,
                         _REVERT_MINUTES, _theme_toggle_btn, esc)

TERMS_VERSION = "2026-10-05"


def terms_checkbox(note: str = "") -> str:
    """The required tick-box for a form that signs up or pays.

    `required` stops the form in the browser; the handler checks again,
    because a browser is not where a rule like this can live.
    """
    extra = f" {esc(note)}" if note else ""
    return (f'<label style="display:flex;gap:8px;align-items:flex-start;'
            f'font-size:12.5px;line-height:1.45;margin:10px 0;text-align:left;'
            f'cursor:pointer">'
            f'<input type="checkbox" name="agree" value="1" required '
            f'style="margin-top:2px;flex:none">'
            f'<span>I agree to the <a href="/terms" target="_blank" '
            f'rel="noopener">Terms &amp; Conditions</a>.{extra}</span></label>')


def _sections(provider: str, email: str) -> list:
    from .billing import BILLING_DAY, GRACE_DAYS, TRIAL_DEVICES
    from .billing_runner import _DEFAULT_DUE_DAYS
    contact = (f"by email at {email}" if email else
               "through the contact details in your dashboard")
    return [
        ("1. Who these terms are with",
         [f"These terms are an agreement between you and {provider} "
          f"(\"we\", \"us\"), the provider of {_BRAND} (\"the service\"). "
          f"\"You\" means the company that holds the account and every person "
          f"it gives access to.",
          "By creating an account, or by paying for the service, you agree "
          "to these terms. If you do not agree, do not use the service."]),
        ("2. The service",
         [f"{_BRAND} monitors and helps manage MikroTik routers: it polls them "
          f"for health and alerts, keeps backups, pushes configuration changes "
          f"you choose, and opens remote access on request.",
          "Routers must run RouterOS 7.1 or later. Each router connects to us "
          "over WireGuard, which RouterOS added in version 7.1.",
          "You are responsible for the routers you add and for the changes "
          f"you push to them. Previews, automatic backups and Safe mode (which "
          f"restores a backup if a router cannot reach us {_REVERT_MINUTES} "
          f"minutes after a change) reduce the risk of a change going wrong; "
          f"they do not remove it."]),
        ("3. Your account",
         ["Keep your login details private. You are responsible for "
          "everything done under your account, including by team members "
          "you invite.",
          "Only add routers you own or are authorised to manage."]),
        ("4. Free trial",
         [f"A new account gets a 30-day free trial for {TRIAL_DEVICES} device. "
          f"To keep using the service after the trial, or to add more "
          f"devices, choose a packet."]),
        ("5. Packets and prices",
         ["Packets are priced per month by the number of devices they allow, "
          "in US dollars. You cannot add more devices than your packet "
          "allows.",
          "Card payments are processed by Yoco and charged in South African "
          "rand, converted at the day's published exchange rate, which is "
          "recorded with the payment. You can also pay by EFT using the "
          "reference on your invoice.",
          "We may change prices. Any change applies from your next renewal "
          "after we have given you at least 30 days' notice."]),
        ("6. Billing",
         [f"Every account renews on the {BILLING_DAY}th of each month.",
          f"Your first payment covers only the days from the day you pay to "
          f"the next {BILLING_DAY}th, and is charged pro rata for those days. "
          f"After that each payment covers one month, from one "
          f"{BILLING_DAY}th to the next.",
          f"We send each renewal invoice before the {BILLING_DAY}th, payable "
          f"within {_DEFAULT_DUE_DAYS} days.",
          "Moving to a bigger packet in the middle of a month is charged for "
          "the difference over the days left in that month. Moving to a "
          f"smaller packet takes effect on the next {BILLING_DAY}th."]),
        ("7. Late payment and suspension",
         [f"If a renewal is not paid by the {BILLING_DAY}th, you have "
          f"{GRACE_DAYS} days' grace. After that the account is suspended: "
          f"you lose access to the service and to all of your units until "
          f"the outstanding invoice is paid. Paying switches the account "
          f"back on.",
          "Your settings and data are kept while the account is suspended. "
          "An account that stays suspended for a long time may be closed and "
          "its data deleted after we have warned you."]),
        ("8. Cancelling",
         ["You can cancel at any time from the Billing tab.",
          f"Cancelling does not end the service immediately: you keep access "
          f"until the end of the month you have paid for, the next "
          f"{BILLING_DAY}th. On that date you lose access to all of your "
          f"units, with no grace period.",
          "To come back, pay the next invoice and your access returns. Until "
          "the end of the month you can also withdraw your cancellation from "
          "the Billing tab."]),
        ("9. Refunds",
         ["Payments are not refundable. This includes part-months, unused "
          "days, unused devices, and the rest of a month after you cancel.",
          "Nothing in these terms takes away a right to a refund that the "
          "law gives you and that cannot be excluded."]),
        ("10. Acceptable use",
         ["Do not use the service to access or interfere with networks or "
          "devices you are not authorised to manage, to attack anyone, or to "
          "break the law. We may suspend an account that does."]),
        ("11. Your data",
         ["We store what the service needs to work: your account details, "
          "your routers' connection details, the readings taken from them "
          "and a record of the changes made through the service.",
          "We use this data only to provide the service, do not sell it, and "
          "handle personal information in line with the Protection of "
          "Personal Information Act (POPIA)."]),
        ("12. Availability",
         ["We work to keep the service running, but do not promise that it "
          "will be uninterrupted or error-free. We may carry out maintenance "
          "and change or improve features over time."]),
        ("13. Liability",
         ["To the extent the law allows, we are not liable for indirect or "
          "consequential loss, including lost profit, lost data, or downtime "
          "of your network or routers.",
          "To the extent the law allows, our total liability to you is "
          "limited to the amount you paid us in the three months before the "
          "claim arose."]),
        ("14. Changes to these terms",
         ["We may update these terms. We will tell you about material "
          "changes before they take effect. Continuing to use the service, "
          "or paying for it, after a change means you accept the new terms."]),
        ("15. Law",
         ["These terms are governed by the laws of the Republic of South "
          "Africa."]),
        ("16. Contact",
         [f"Questions about these terms, or about your account, can be sent "
          f"to us {contact}."]),
    ]


_CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,system-ui,Arial,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.65}
a{color:var(--accent)}
.tnav{background:#0f172a;height:58px;display:flex;align-items:center;
  gap:12px;padding:0 24px}
.tnav a.logo{display:flex;align-items:center;gap:8px;color:#fff;
  font-weight:800;font-size:16px;text-decoration:none}
.tnav .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.tnav .right a{color:#e2e8f0;font-size:14px;text-decoration:none;
  padding:7px 12px;border-radius:7px;border:1px solid rgba(255,255,255,.18)}
.tnav .theme-toggle{background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.18);color:#e2e8f0}
.tdoc{max-width:780px;margin:32px auto 60px;padding:34px 38px;
  background:var(--surface);border:1px solid var(--border);border-radius:14px;
  box-shadow:var(--shadow)}
.tdoc h1{font-size:28px;margin:0 0 4px;letter-spacing:-.01em}
.tdoc .ver{font-size:13px;color:var(--text-faint);margin:0 0 22px}
.tdoc h2{font-size:16px;margin:26px 0 6px}
.tdoc p{font-size:14.5px;color:var(--text-muted);margin:0 0 10px}
.tdoc .lead{font-size:15px;color:var(--text)}
@media(max-width:640px){.tdoc{margin:0;border-radius:0;padding:24px 18px}}
"""


def render_terms(contact: dict | None = None) -> str:
    c = contact or {}
    provider = (c.get("bank_holder") or c.get("name") or _BRAND).strip()
    email = (c.get("email") or "").strip()
    body = "".join(
        f'<h2>{esc(title)}</h2>' + "".join(f'<p>{esc(p)}</p>' for p in paras)
        for title, paras in _sections(provider, email))
    from .brand import favicon_tags, logo_img
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{favicon_tags()}
<title>Terms &amp; Conditions · {esc(_BRAND)}</title>
{_THEME_INIT_JS}
<style>{_THEME_VARS}{_CSS}</style></head>
<body>
<nav class="tnav"><a class="logo" href="/">{logo_img(24)}{esc(_BRAND)}</a>
<span class="right">{_theme_toggle_btn()}<a href="/login">Sign in</a></span></nav>
<main class="tdoc">
<h1>Terms &amp; Conditions</h1>
<p class="ver">Version {esc(TERMS_VERSION)}</p>
<p class="lead">Please read these terms before you create an account or pay.
Payments are not refundable, and cancelling ends access to all of your units
at the end of the month you have paid for.</p>
{body}
</main>
{_THEME_TOGGLE_JS}
</body></html>"""
