"""Your own invoice design, filled in by this system.

The built-in invoice is fine and looks like everyone else's. A business that
already has an invoice design — one an accountant recognises, one that
matches the quotes going out beside it — should be able to use it here
rather than keep two.

So: upload an HTML file with `{{placeholders}}` where the numbers go. This
fills them in and puts the EasyMikroTik mark wherever `{{logo}}` appears, so
the drawing on the document is the real one at the size the page asks for,
not a screenshot pasted into a Word file two years ago.

Two rules, both about not making things worse than the built-in invoice:

  Every value is escaped on the way in. A company name with an ampersand in
  it must not be able to break the page it is printed on, and a company name
  is the one field on an invoice that somebody else chose.

  The template itself is not escaped — it is markup on purpose. Which means
  whoever uploads it can put anything in it, including a script tag, and it
  will run for the customers who open their invoices. That is the superadmin
  editing their own site, not a hole anyone else can reach: nothing here
  accepts a template from a customer. It is still worth knowing, so the
  upload says it.

And one rule about the specific business this runs: it is not VAT
registered. An invoice that says "Tax Invoice", or shows a VAT line, is a
real problem rather than a cosmetic one — so an upload containing either is
accepted with a warning rather than silently filed away.
"""
from __future__ import annotations

import logging
import os
import re

log = logging.getLogger(__name__)

FILENAME = "invoice_template.html"

# A body big enough for a real design with an embedded logo, small enough
# that a wrong file (a PDF, a photo) is refused rather than stored.
MAX_BYTES = 512 * 1024

# What a template may ask for. Anything else is left alone rather than
# blanked: a stray {{brace}} in somebody's CSS should not silently vanish.
FIELDS = (
    ("logo", "The EasyMikroTik mark and name, drawn at document size"),
    ("invoice_no", "Invoice number, e.g. EMT-2026-0142"),
    ("number", "The bare order id, e.g. 00042"),
    ("issue_date", "The date on the invoice"),
    ("date", "The same date, for older templates"),
    ("due_date", "When payment is due"),
    ("due_days", "How many days there are to pay"),
    ("status_pill", "The DUE / PAID badge, already styled"),
    ("company", "The company being billed"),
    ("client_lines", "The billed-to address block, as markup"),
    ("seller_name", "Your trading name"),
    ("seller_tagline", "The line under it"),
    ("seller_lines", "Your web, billing and support addresses, as markup"),
    ("seller", "Your name and email on one line, for older templates"),
    ("support_email", "Where questions go"),
    ("reference", "The payment reference to quote on a transfer"),
    ("description", "What is being charged for"),
    ("devices", "How many routers the packet covers"),
    ("unit", "The price per month"),
    ("months", "How many months this invoice covers"),
    ("items", "The priced table rows, as markup"),
    ("total", "The amount, with its currency symbol"),
    ("total_label", '"Total Due" or "Total Paid"'),
    ("currency", "The currency code, e.g. USD"),
    ("paid_on", "The date it was paid, blank if it has not been"),
    ("payment_block", "Bank details and reference, as markup; blank if "
                      "no bank details have been saved"),
    ("pay_button", "The Pay by card button, as markup; blank once paid"),
    ("pay_link", "The URL that pays this invoice, blank if none"),
)

# Filled with markup rather than text, so a template can place them but
# nothing escapes them on the way in. Everything not in here is escaped.
MARKUP_FIELDS = frozenset((
    "logo", "status_pill", "items", "payment_block", "pay_button",
    "seller_lines", "client_lines",
))
FIELD_NAMES = tuple(name for name, _desc in FIELDS)

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")

# Wording that would make this business's invoices wrong rather than ugly.
_VAT_WORDS = ("tax invoice", "btw", "vat no", "vat number", "vat reg",
              "vat:", "v.a.t")


class TemplateError(Exception):
    """An upload that cannot be used, with the reason a person needs."""


def path(app_dir: str = "") -> str:
    root = app_dir or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, FILENAME)


def uploaded(app_dir: str = "") -> str:
    """The uploaded template, or "" when there is none.

    Read on every render rather than cached: replacing a template is a thing
    somebody does once and then expects to see, and restarting a service to
    find out whether a file landed is the small unnecessary loop this
    codebase keeps tripping over.
    """
    try:
        with open(path(app_dir), encoding="utf-8") as f:
            return f.read()
    except (OSError, ValueError):
        return ""


def load(app_dir: str = "") -> str:
    """The template every invoice is rendered from.

    An uploaded design wins; otherwise the built-in one. There is only ever
    one code path to an invoice, so the thing being previewed and the thing
    being sent cannot drift apart.
    """
    from .invoice_design import DEFAULT

    return uploaded(app_dir) or DEFAULT


def placeholders(template: str) -> set:
    """Every {{name}} the template asks for."""
    return set(_PLACEHOLDER.findall(template or ""))


def check(template: str) -> list:
    """Warnings about a template that is otherwise usable.

    Warnings, not refusals. A design is the uploader's business; the things
    listed here are the ones that would surprise them later, which is a
    different thing from being wrong.
    """
    notes = []
    low = (template or "").lower()
    for word in _VAT_WORDS:
        if word in low:
            notes.append(
                "This template mentions VAT or calls itself a Tax Invoice. "
                "This business is not VAT registered, so issuing one is a "
                "real problem rather than a cosmetic one — worth removing "
                "before anything goes out.")
            break
    if "<script" in low:
        notes.append(
            "There is a <script> in this template. It will run in the "
            "browser of every customer who opens an invoice. Nothing else "
            "can put one there, but it is worth being sure you meant it.")
    unknown = placeholders(template) - set(FIELD_NAMES)
    if unknown:
        notes.append(
            "Left as written, because nothing fills them: "
            + ", ".join(sorted("{{" + u + "}}" for u in unknown)) + ".")
    missing = [f for f in ("total", "company") if f not in placeholders(template)]
    if missing:
        notes.append(
            "No " + " or ".join("{{" + m + "}}" for m in missing)
            + " anywhere in the template, so the invoice will not say "
              "who it is for or what is owed.")
    return notes


def save(raw: bytes, app_dir: str = "") -> list:
    """Store an uploaded template. Returns warnings; raises on refusal.

    Refuses only what cannot be used at all — the wrong kind of file, or
    nothing. Everything else is a warning, because how an invoice should
    look is not this function's decision.
    """
    if not raw:
        raise TemplateError("No file was chosen.")
    if len(raw) > MAX_BYTES:
        raise TemplateError(
            f"That file is {len(raw) // 1024} KB; the limit is "
            f"{MAX_BYTES // 1024} KB. An invoice template is HTML — if this "
            f"is a PDF or a Word file, save it as HTML first.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise TemplateError(
            "That file is not text. An invoice template is an HTML file; a "
            "PDF, a .docx or an image cannot be filled in.") from None
    if "<" not in text:
        raise TemplateError(
            "That does not look like HTML. Save your invoice as an HTML "
            "file and upload that.")
    notes = check(text)
    tmp = path(app_dir) + ".new"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path(app_dir))
    log.info("invoice template replaced (%d bytes, %d warning(s))",
             len(raw), len(notes))
    return notes


def remove(app_dir: str = "") -> bool:
    """Go back to the built-in invoice. True if a template was removed."""
    try:
        os.remove(path(app_dir))
        log.info("invoice template removed; the built-in invoice is back")
        return True
    except OSError:
        return False


def render(template: str, fields: dict) -> str:
    """Fill a template in. Values are escaped; the template is not.

    An unknown placeholder is left exactly as it was found rather than
    blanked, so a mistyped name shows up on the page as itself instead of
    disappearing into a gap nobody can account for.
    """
    from .web_shared import esc

    def sub(m):
        key = m.group(1)
        if key not in fields:
            return m.group(0)
        val = fields[key]
        # A few fields ARE markup -- a drawing, a table of rows, a badge.
        # Everything else is a value somebody else chose, and a company name
        # with an ampersand in it must not break the page it is printed on.
        if key in MARKUP_FIELDS:
            return str(val if val is not None else "")
        return esc(str(val if val is not None else ""))

    return _PLACEHOLDER.sub(sub, template or "")


def example() -> str:
    """The design this system ships, to change and upload back.

    The real one rather than a simplified stand-in: somebody adjusting their
    invoice wants the document they have been looking at, not a sketch of
    it.
    """
    from .invoice_design import DEFAULT

    return DEFAULT


def _old_example() -> str:
    """A template somebody can download, change and upload back.

    Deliberately plain: it is a starting point for somebody's own design,
    not a second invoice design competing with the built-in one.
    """
    rows = "\n".join(
        f"      <!-- {{{{{name}}}}} — {desc} -->" for name, desc in FIELDS)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Invoice {{{{number}}}}</title>
    <style>
      body {{ font: 14px/1.5 system-ui, sans-serif; color: #111;
             max-width: 760px; margin: 40px auto; padding: 0 20px; }}
      .head {{ display: flex; justify-content: space-between;
               align-items: flex-start; gap: 20px; }}
      h1 {{ margin: 0 0 4px; font-size: 26px; }}
      .muted {{ color: #666; font-size: 12px; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 24px; }}
      th, td {{ text-align: left; padding: 8px 0;
                border-bottom: 1px solid #ddd; }}
      td.r, th.r {{ text-align: right; }}
      .total {{ font-size: 18px; font-weight: 700; }}
    </style>
  </head>
  <body>
    <!-- Every placeholder this system fills in:
{rows}
    -->
    <div class="head">
      <div>
        <h1>Invoice</h1>
        <div class="muted">#{{{{number}}}} &middot; {{{{date}}}}</div>
      </div>
      <div style="text-align:right">
        {{{{logo}}}}
        <div class="muted">{{{{seller}}}}</div>
      </div>
    </div>

    <p><b>Billed to</b><br>{{{{company}}}}<br>
       <span class="muted">Reference {{{{reference}}}}</span></p>

    <table>
      <thead>
        <tr><th>Description</th><th class="r">Amount</th></tr>
      </thead>
      <tbody>
        <tr>
          <td>{{{{description}}}}<br>
              <span class="muted">{{{{unit}}}} per month</span></td>
          <td class="r">{{{{total}}}}</td>
        </tr>
      </tbody>
      <tfoot>
        <tr><td class="total">Total</td>
            <td class="r total">{{{{total}}}} {{{{currency}}}}</td></tr>
      </tfoot>
    </table>

    <p class="muted">No VAT has been charged.</p>
  </body>
</html>
"""
