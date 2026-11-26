"""The payslip as a PDF: what a settled invoice actually paid for.

The receipt said "paid" and how much, but not which packet it bought or how
long the account now runs. This is drawn from the very same values as the
receipt (web_auth._invoice_data), alongside it in the payment email, in the
same EasyMikroTik design: the vector mark, the fonts, the palette and the
blue-to-sky rule all come from invoice_pdf so the two documents match.

A payslip is a confirmation, not a bill: it carries no pay link and no bank
details, because either would read as "this is still owed" and invite somebody
to pay twice. No VAT has been charged, and the slip says so. reportlab is pure
Python, so this needs nothing installed on the server beyond requirements.txt.
"""
from __future__ import annotations

import io
import time
from xml.sax.saxutils import escape

from . import brand
from .invoice_pdf import (BLUE, CREAM, GROUND, INK, LINE, MUTED, SKY,
                          _font_names, _mark)


def render(d: dict, *, payment_id: str = "",
           paid_until: float | None = None, sample: bool = False) -> bytes:
    """A single-page A4 payment slip for one settled invoice's data."""
    from reportlab.lib.colors import HexColor, white
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (Flowable, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    reg, bold = _font_names()
    ink, blue, muted = HexColor(INK), HexColor(BLUE), HexColor(MUTED)
    W = A4[0] - 36 * mm

    def st(name, size=9.5, color=ink, font=reg, lead=None, **kw):
        return ParagraphStyle(name, fontName=font, fontSize=size,
                              leading=lead or size * 1.38, textColor=color,
                              **kw)

    def t(text):
        return escape(str(text if text is not None else ""))

    def money(v):
        return f"{d['sym']}{v:,.2f}"

    pid = str(payment_id or "")
    if pid.startswith("eft:"):
        method = "Bank Transfer (EFT)"
    elif pid:
        method = "Card (Yoco)"
    else:
        method = "Recorded Payment"

    when = ""
    if paid_until:
        try:
            when = time.strftime("%d %B %Y",
                                 time.localtime(float(paid_until))).lstrip("0")
        except (TypeError, ValueError, OSError, OverflowError):
            when = ""
    payslip_no = str(d["invoice_no"]).replace("EMT-", "PS-", 1)

    def clip(value, limit=96):
        """Party names are data, not a blank cheque for a second page."""
        s = str(value if value is not None else "")
        return s if len(s) <= limit else s[:limit - 3].rstrip() + "..."

    body = st("body")
    small = st("small", 8.5, muted)
    eyebrow = st("eyebrow", 7.5, blue, bold)
    who = st("who", 12.5, ink, bold)
    right = st("right", 9, muted, alignment=TA_RIGHT)

    class Header(Flowable):
        """Logo card left; PAID pill, PAYSLIP and its references right."""

        def wrap(self, aw, ah):
            self.height = 34 * mm
            return W, self.height

        def draw(self):
            c = self.canv
            c.setFillColor(HexColor(CREAM))
            c.roundRect(0, self.height - 15 * mm, 50 * mm, 15 * mm, 3 * mm,
                        stroke=0, fill=1)
            _mark(c, 3 * mm, self.height - 13.5 * mm, 12 * mm)
            c.setFillColor(HexColor(brand.INK))
            c.setFont(reg, 12)
            c.drawString(16.5 * mm, self.height - 9.3 * mm, "Easy")
            c.setFont(bold, 12)
            c.drawString(16.5 * mm + c.stringWidth("Easy", reg, 12),
                         self.height - 9.3 * mm, "MikroTik")
            label = "SAMPLE \u00b7 PAID" if sample else "PAID"
            c.setFont(bold, 7.5)
            pw = c.stringWidth(label, bold, 7.5) + 6 * mm
            c.setFillColor(HexColor("#dcfce7"))
            c.roundRect(W - pw, self.height - 6 * mm, pw, 6 * mm, 1.2 * mm,
                        stroke=0, fill=1)
            c.setFillColor(HexColor("#15803d"))
            c.drawRightString(W - 3 * mm, self.height - 4.1 * mm, label)
            c.setFillColor(ink)
            c.setFont(bold, 26)
            c.drawRightString(W, self.height - 16.5 * mm, "PAYSLIP")
            c.setFont(reg, 9)
            c.setFillColor(muted)
            c.drawRightString(W, self.height - 20.5 * mm,
                              "Payment Confirmation")
            y = self.height - 23.5 * mm
            for k, v in (("Payslip #:", payslip_no),
                         ("Invoice #:", d["invoice_no"]),
                         ("Payment Date:", d["paid_on"])):
                c.setFont(reg, 8.5)
                c.setFillColor(muted)
                c.drawRightString(W, y, str(v))
                c.setFont(bold, 8.5)
                c.setFillColor(ink)
                c.drawRightString(W - c.stringWidth(str(v), reg, 8.5)
                                  - 1.5 * mm, y, k)
                y -= 3.8 * mm

    class Rule(Flowable):
        """The blue-to-sky rule under the title block."""

        def wrap(self, aw, ah):
            return W, 4 * mm

        def draw(self):
            c = self.canv
            c.saveState()
            p = c.beginPath()
            p.roundRect(0, 1.5 * mm, W, 1.4 * mm, 0.7 * mm)
            c.clipPath(p, stroke=0, fill=0)
            c.linearGradient(0, 0, W, 0, (blue, HexColor(SKY)), extend=False)
            c.restoreState()

    def card(title, name, lines):
        rows = [[Paragraph(t(title).upper(), eyebrow)],
                [Paragraph(t(name), who)]]
        rows += [[Paragraph(line, small)] for line in lines]
        tbl = Table(rows, colWidths=[(W - 6 * mm) / 2 - 1])
        tbl.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.8, HexColor(LINE)),
            ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
            ("TOPPADDING", (0, 0), (-1, 0), 4.5 * mm),
            ("TOPPADDING", (0, 1), (-1, -1), 0.6 * mm),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 4.5 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -2), 0.6 * mm),
        ]))
        return tbl

    def bits(pairs):
        return [f"<font name='{bold}' color='{INK}'>{t(k)}:</font> {t(clip(v))}"
                for k, v in pairs]

    parties = Table([[
        card("Paid to", clip(d["seller_name"]),
             [t(clip(d["seller_tagline"]))] + bits(d["seller_bits"])),
        card("Paid by", clip(d["company"]), bits(d["client_bits"]))]],
        colWidths=[W / 2, W / 2])
    parties.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 3 * mm),
        ("LEFTPADDING", (1, 0), (1, 0), 3 * mm),
        ("RIGHTPADDING", (1, 0), (1, 0), 0)]))

    label_style = st("label", 9.5, muted)

    def field(key, value):
        return [Paragraph(f"<font name='{bold}' color='{INK}'>{t(key)}:"
                          f"</font>", body),
                Paragraph(t(value), body)]

    detail_rows = [
        [Paragraph("PAYMENT DETAILS", eyebrow), ""],
        field("Invoice Reference", d["invoice_no"]),
        [Paragraph("<font name='" + bold + "' color='" + INK +
                   "'>Service / Packet:</font>", body),
         [Paragraph(t(d["item"]), st("service", 9.5, ink, bold)),
          Spacer(1, 1 * mm), Paragraph(t(d["item_detail"]), small)]],
        field("Payment Method", method),
    ]
    if pid:
        detail_rows.append(field("Transaction / Payment ID", pid))
    detail_rows.append(field("Account Reference", d["reference"]))
    if when:
        detail_rows.append(field("Paid Up Until", when))
    tot_w = 62 * mm
    details = Table(detail_rows, colWidths=[W - tot_w - 6 * mm, tot_w + 6 * mm])
    details.setStyle(TableStyle([
        ("SPAN", (0, 0), (-1, 0)),
        ("BACKGROUND", (0, 0), (-1, 0), HexColor(GROUND)),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, blue),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 2.6 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.6 * mm)]))

    grand = st("grand", 17, blue, bold, alignment=TA_RIGHT, lead=21)
    totals_rows = [
        [Paragraph("Amount Paid", label_style),
         Paragraph(t(money(d["total"])), grand)],
        [Paragraph("Currency", small), Paragraph(t(d["currency"]), right)],
        [Paragraph("Balance Due", label_style),
         Paragraph(t(money(0)), right)],
        [Paragraph("Status", label_style),
         Paragraph("PAID IN FULL",
                   st("paid", 10, HexColor("#15803d"), bold,
                      alignment=TA_RIGHT))],
    ]
    totals = Table(totals_rows, colWidths=[tot_w * 0.48, tot_w * 0.52])
    totals.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor(GROUND)),
        ("LINEABOVE", (0, 1), (-1, 1), 1.6, blue),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("TOPPADDING", (0, 0), (-1, 0), 4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 3.5 * mm),
        ("TOPPADDING", (0, 1), (-1, -1), 2.4 * mm),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 4 * mm)]))

    summary = Table([[details, totals]], colWidths=[W - tot_w, tot_w])
    summary.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 6 * mm),
        ("RIGHTPADDING", (1, 0), (1, 0), 0)]))

    notes_rows = [[Paragraph("CONFIRMATION", eyebrow)],
                  [Paragraph("This payslip confirms payment in full for the "
                             "invoice above.", body)],
                  [Paragraph("No VAT has been charged.", body)]]
    if d["support_email"]:
        notes_rows.append([Paragraph(
            f"Questions: {t(d['support_email'])}.", small)])
    notes = Table(notes_rows, colWidths=[W])
    notes.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor(GROUND)),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
        ("TOPPADDING", (0, 0), (0, 0), 3.6 * mm),
        ("BOTTOMPADDING", (0, 0), (0, -2), 0.6 * mm),
        ("TOPPADDING", (0, 1), (-1, -1), 0.6 * mm),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 3.6 * mm)]))

    out = io.BytesIO()
    doc = SimpleDocTemplate(
        out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Payslip {d['invoice_no']}", author=d["seller_name"],
        subject=f"Payment confirmation for {d['company']}")

    def page_foot(c, _doc):
        c.saveState()
        c.setFont(reg, 8)
        c.setFillColor(HexColor("#94a3b8"))
        c.drawCentredString(A4[0] / 2, 10 * mm,
                            "EasyMikroTik \u2022 Automated RouterOS & Network "
                            "Infrastructure Solutions \u2022 "
                            "https://easymikrotik.com")
        c.restoreState()

    flow = [Header(), Rule(), Spacer(1, 3 * mm), parties,
            Spacer(1, 5 * mm), summary, Spacer(1, 3 * mm)]
    if d["fx_note"]:
        flow += [Paragraph(t(d["fx_note"]), st("fx", 8.5, muted)),
                 Spacer(1, 3 * mm)]
    flow.append(notes)
    doc.build(flow, onFirstPage=page_foot, onLaterPages=page_foot)
    return out.getvalue()


def filename(d: dict) -> str:
    """What the payslip attachment is called."""
    return f"EasyMikroTik-payslip-{d['invoice_no']}.pdf"
