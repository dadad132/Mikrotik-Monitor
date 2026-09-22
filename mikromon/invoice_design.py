"""The invoice, as a document.

Built from a design that was handed over as a PDF, with four things changed
because the design described a business other than this one.

  NO VAT LINE. The original carried "Tax / VAT (15%): $34.35". This business
  is not VAT registered, so charging a VAT line — or calling the document a
  Tax Invoice — is a real problem rather than a cosmetic one. Removed, and
  the footer says plainly that no VAT has been charged.

  NO DISCOUNT LINE. There is no discount anywhere in this system, and a row
  that always reads -$0.00 is a row somebody eventually asks about.

  REAL BANK DETAILS OR NONE. The original had an account number in it. It
  came from a sample and it is not this business's account, so nothing here
  hardcodes one: the block is filled from what the superadmin actually
  saved, and left out entirely when nothing has been. A wrong account number
  on an invoice is the most expensive kind of placeholder there is.

  ONE LINE ITEM. The original listed three invented services. This system
  sells one thing on a renewal — the monthly packet — so the table has the
  line it actually charges for.

Also: the original said credentials "activate immediately upon proof of
payment". They do not. A card payment activates the account by itself
through Yoco's webhook, with nobody here in the loop, and wording that asks
for proof invites exactly the manual step the card rail exists to remove.
"""
from __future__ import annotations

# Colours lifted from the design: near-black header band, the blue rule
# under the title block, and a pale ground the white cards sit on.
INK = "#0f172a"
BLUE = "#2563eb"
SKY = "#38bdf8"
GROUND = "#f4f7fb"
LINE = "#e2e8f0"
MUTED = "#64748b"

DEFAULT = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Invoice {{invoice_no}}</title>
    <style>
      :root {
        --ink: %(INK)s; --blue: %(BLUE)s; --sky: %(SKY)s;
        --ground: %(GROUND)s; --line: %(LINE)s; --muted: %(MUTED)s;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0; background: var(--ground); color: var(--ink);
        font: 14px/1.55 -apple-system, "Segoe UI", Inter, system-ui, sans-serif;
        -webkit-print-color-adjust: exact; print-color-adjust: exact;
      }
      .sheet {
        max-width: 860px; margin: 28px auto; background: #fff;
        padding: 44px 48px 30px;
      }
      .top { display: flex; justify-content: space-between;
             align-items: flex-start; gap: 24px; flex-wrap: wrap; }
      .logo { background: #fdf6e3; border-radius: 10px; padding: 12px 14px;
              display: inline-block; }
      .titles { text-align: right; margin-left: auto; }
      .pill {
        display: inline-block; background: #e0f2fe; color: #0369a1;
        font-size: 11px; font-weight: 700; letter-spacing: .09em;
        text-transform: uppercase; padding: 5px 12px; border-radius: 4px;
        margin-bottom: 14px;
      }
      .pill.paid { background: #dcfce7; color: #15803d; }
      h1 { margin: 0 0 12px; font-size: 40px; letter-spacing: -.02em;
           line-height: 1; }
      .meta { font-size: 13px; color: var(--muted); }
      .meta b { color: var(--ink); }
      .rule { height: 4px; border-radius: 3px; margin: 26px 0 24px;
              background: linear-gradient(90deg, var(--blue), var(--sky)); }
      .parties { display: flex; gap: 18px; flex-wrap: wrap; }
      .card {
        flex: 1 1 280px; border: 1px solid var(--line); border-radius: 8px;
        padding: 18px 20px; background: #fff;
      }
      .eyebrow {
        font-size: 11px; font-weight: 700; letter-spacing: .1em;
        text-transform: uppercase; color: var(--blue); margin-bottom: 10px;
      }
      .who { font-size: 17px; font-weight: 700; margin: 0 0 8px; }
      .card p { margin: 3px 0; color: var(--muted); font-size: 13px; }
      .card p b { color: var(--ink); font-weight: 600; }
      table.items { width: 100%%; border-collapse: collapse; margin-top: 26px; }
      table.items thead th {
        background: var(--ink); color: #fff; text-align: left;
        font-size: 11px; letter-spacing: .09em; text-transform: uppercase;
        padding: 13px 14px; font-weight: 700;
      }
      table.items thead th.n { text-align: right; }
      table.items td { padding: 16px 14px; border-bottom: 1px solid var(--line);
                       vertical-align: top; }
      table.items td.n { text-align: right; white-space: nowrap;
                         font-variant-numeric: tabular-nums; }
      .item { font-weight: 700; }
      .item small { display: block; font-weight: 400; color: var(--muted);
                    margin-top: 4px; font-size: 12.5px; }
      .foot { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 26px;
              align-items: flex-start; }
      .pay { flex: 1 1 320px; }
      .pay table { width: 100%%; border-collapse: collapse; }
      .pay td { padding: 5px 0; font-size: 13px; color: var(--muted);
                vertical-align: top; }
      .pay td.v { color: var(--ink); text-align: right; font-weight: 600; }
      .totals { flex: 0 1 320px; background: var(--ground); border-radius: 8px;
                padding: 18px 20px; }
      .totals .row { display: flex; justify-content: space-between;
                     padding: 6px 0; font-size: 13.5px; color: var(--muted); }
      .totals .row b { color: var(--ink); }
      .totals .grand { border-top: 2px solid var(--blue); margin-top: 10px;
                       padding-top: 14px; display: flex;
                       justify-content: space-between; align-items: baseline; }
      .totals .grand span { font-size: 17px; font-weight: 700; }
      .totals .grand b { font-size: 26px; color: var(--blue);
                         letter-spacing: -.02em; }
      .cta { display: inline-block; margin-top: 14px; background: var(--blue);
             color: #fff; text-decoration: none; padding: 12px 22px;
             border-radius: 6px; font-weight: 700; }
      .terms { margin-top: 26px; border-left: 3px solid var(--blue);
               background: var(--ground); padding: 14px 18px; font-size: 12.5px;
               color: var(--muted); border-radius: 0 6px 6px 0; }
      .terms b { color: var(--ink); }
      .pagefoot { text-align: center; color: #94a3b8; font-size: 11.5px;
                  margin: 22px 0 34px; }
      @media print {
        body { background: #fff; }
        .sheet { margin: 0; padding: 0; max-width: none; }
      }
      @media (max-width: 560px) {
        .sheet { padding: 24px 18px; margin: 0; }
        h1 { font-size: 30px; }
        .titles { text-align: left; margin-left: 0; }
      }
    </style>
  </head>
  <body>
    <div class="sheet">
      <div class="top">
        <div class="logo">{{logo}}</div>
        <div class="titles">
          {{status_pill}}
          <h1>INVOICE</h1>
          <div class="meta">
            <div><b>Invoice #:</b> {{invoice_no}}</div>
            <div><b>Issue Date:</b> {{issue_date}}</div>
            <div><b>Due Date:</b> {{due_date}}</div>
          </div>
        </div>
      </div>

      <div class="rule"></div>

      <div class="parties">
        <div class="card">
          <div class="eyebrow">Issued by</div>
          <p class="who">{{seller_name}}</p>
          <p>{{seller_tagline}}</p>
          {{seller_lines}}
        </div>
        <div class="card">
          <div class="eyebrow">Billed to</div>
          <p class="who">{{company}}</p>
          <p>Attn: Accounts Payable</p>
          {{client_lines}}
        </div>
      </div>

      <table class="items">
        <thead>
          <tr>
            <th style="width:34px">#</th>
            <th>Description / Service item</th>
            <th class="n" style="width:70px">Qty</th>
            <th class="n" style="width:110px">Rate ({{currency}})</th>
            <th class="n" style="width:120px">Amount ({{currency}})</th>
          </tr>
        </thead>
        <tbody>{{items}}</tbody>
      </table>

      <div class="foot">
        <div class="pay">{{payment_block}}</div>
        <div class="totals">
          <div class="row"><span>Subtotal</span><b>{{total}}</b></div>
          <div class="grand">
            <span>{{total_label}}</span>
            <b>{{total}}</b>
          </div>
          <div class="row" style="justify-content:flex-end;padding-top:2px">
            {{currency}}
          </div>
          {{pay_button}}
        </div>
      </div>

      <div class="terms">
        <b>Terms &amp; Notes:</b> Payment is due within {{due_days}} days of
        the invoice date. Paying by card takes a moment and your service
        simply carries on &mdash; the packet is extended automatically the
        moment the payment clears, and nobody here has to do anything. No VAT
        has been charged. Questions: {{support_email}}.
      </div>
    </div>

    <div class="pagefoot">
      EasyMikroTik &bull; Automated RouterOS &amp; Network Infrastructure
      Solutions &bull; https://easymikrotik.com
    </div>
  </body>
</html>
""" % {"INK": INK, "BLUE": BLUE, "SKY": SKY, "GROUND": GROUND,
       "LINE": LINE, "MUTED": MUTED}
