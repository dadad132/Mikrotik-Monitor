"""The invoice as a PDF: the document that is attached to the email.

The invoice existed only as a web page, so the email that went out with it
carried a link and nothing else -- nothing for the person who pays the bills
to file, forward or print, and nothing to show at all once the link was
gone. Now every email about an invoice carries this PDF beside the link.

It is drawn from the same values as the page (web_auth._invoice_data), so
the two cannot say different things, and laid out like the built-in design:
the mark, INVOICE and its dates, who issued it and who it is for, the line
charged for, how to pay it, and the totals. The pay link in it is a real
link. An invoice design uploaded as HTML changes the page, not this: drawing
arbitrary HTML as a PDF would need a browser engine on the server.

reportlab is pure Python, so this needs nothing installed on the server
beyond requirements.txt.
"""
from __future__ import annotations

import io
import os
from xml.sax.saxutils import escape

from . import brand

# The design's colours (invoice_design.py), so the PDF and the page match.
INK = "#0f172a"
BLUE = "#2563eb"
SKY = "#38bdf8"
GROUND = "#f4f7fb"
LINE = "#e2e8f0"
MUTED = "#64748b"
CREAM = "#fdf6e3"

# A font that has the characters company names are written in. The standard
# PDF fonts stop at Western European; these are tried in order, and the
# standard Helvetica is the fallback when none is installed.
_FONT_CANDIDATES = (
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/dejavu/DejaVuSans.ttf",
     "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
    ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
)
_fonts = None


def _font_names() -> tuple:
    """(regular, bold) font names, registering a TrueType pair once."""
    global _fonts
    if _fonts:
        return _fonts
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for regular, bold in _FONT_CANDIDATES:
        if os.path.isfile(regular) and os.path.isfile(bold):
            try:
                pdfmetrics.registerFont(TTFont("Inv", regular))
                pdfmetrics.registerFont(TTFont("Inv-Bold", bold))
                from reportlab.lib.fonts import addMapping
                addMapping("Inv", 0, 0, "Inv")
                addMapping("Inv", 1, 0, "Inv-Bold")
                _fonts = ("Inv", "Inv-Bold")
                return _fonts
            except Exception:  # noqa: BLE001 - fall back to Helvetica
                continue
    _fonts = ("Helvetica", "Helvetica-Bold")
    return _fonts


def _mark(c, x, y, size):
    """The EasyMikroTik mark (brand._MARK) drawn as vectors, its 128-unit
    box placed with its bottom-left corner at (x, y)."""
    from reportlab.lib.colors import HexColor
    s = size / 128.0

    def P(px, py):
        return x + px * s, y + (128 - py) * s

    def poly(points, fill, stroke, width, fill_alpha=1.0):
        p = c.beginPath()
        p.moveTo(*P(*points[0]))
        for pt in points[1:]:
            p.lineTo(*P(*pt))
        p.close()
        c.saveState()
        c.setLineJoin(1)
        c.setLineWidth(width * s)
        c.setStrokeColor(HexColor(stroke))
        if fill:
            c.setFillColor(HexColor(fill))
            c.setFillAlpha(fill_alpha)
        c.drawPath(p, stroke=1, fill=1 if fill else 0)
        c.restoreState()

    poly([(64, 78), (104, 98), (64, 118), (24, 98)], brand.SLAB, brand.INK, 7)
    poly([(64, 54), (104, 74), (64, 94), (24, 74)], brand.MID_FACE,
         brand.MID_LINE, 7, fill_alpha=0.72)
    poly([(64, 30), (96, 46), (64, 62), (32, 46)], None, brand.TEAL, 6)
    c.saveState()
    c.setStrokeColor(HexColor(brand.TEAL))
    c.setLineWidth(6 * s)
    c.setLineCap(1)
    for (a, b) in (((42.7, 40.7), (74.7, 56.7)), ((53.3, 35.3), (85.3, 51.3)),
                   ((74.7, 35.3), (42.7, 51.3)), ((85.3, 40.7), (53.3, 56.7))):
        c.line(*P(*a), *P(*b))
    c.setStrokeColor(HexColor(brand.CABLE))
    c.setLineWidth(7 * s)
    p = c.beginPath()
    p.moveTo(*P(26, 50))
    p.curveTo(*P(28, 24), *P(52, 15), *P(71, 20))
    p.curveTo(*P(87, 25), *P(92, 34), *P(105, 36))
    p.lineTo(*P(122, 36))
    c.drawPath(p, stroke=1, fill=0)
    c.restoreState()


def render(d: dict) -> bytes:
    """The PDF for one invoice, from web_auth._invoice_data."""
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

    body = st("body")
    small = st("small", 8.5, muted)
    eyebrow = st("eyebrow", 7.5, blue, bold)
    who = st("who", 12.5, ink, bold)
    right = st("right", 9, muted, alignment=TA_RIGHT)

    def t(text):
        return escape(str(text if text is not None else ""))

    def money(v):
        return f"{d['sym']}{v:,.2f}"

    class Header(Flowable):
        """Logo card on the left; status, INVOICE and the dates right."""

        def wrap(self, aw, ah):
            # Set here, not as a class attribute: Flowable.__init__ zeroes
            # height, and a header that says it is 0 tall is drawn over
            # by everything after it.
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
            # The status, as a pill.
            label = ("PAID" if d["settled"]
                     else f"DUE {d['due_date']}".upper())
            c.setFont(bold, 7.5)
            pw = c.stringWidth(label, bold, 7.5) + 6 * mm
            c.setFillColor(HexColor("#dcfce7" if d["settled"] else "#e0f2fe"))
            c.roundRect(W - pw, self.height - 6 * mm, pw, 6 * mm, 1.2 * mm,
                        stroke=0, fill=1)
            c.setFillColor(HexColor("#15803d" if d["settled"] else "#0369a1"))
            c.drawRightString(W - 3 * mm, self.height - 4.1 * mm, label)
            c.setFillColor(ink)
            c.setFont(bold, 28)
            c.drawRightString(W, self.height - 17 * mm, "INVOICE")
            y = self.height - 23 * mm
            for k, v in (("Invoice #:", d["invoice_no"]),
                         ("Issue Date:", d["issue_date"]),
                         ("Due Date:", d["due_date"])):
                c.setFont(reg, 9)
                c.setFillColor(muted)
                c.drawRightString(W, y, v)
                c.setFont(bold, 9)
                c.setFillColor(ink)
                c.drawRightString(W - c.stringWidth(v, reg, 9) - 1.5 * mm, y,
                                  k)
                y -= 4.4 * mm

    class Rule(Flowable):
        """The blue-to-sky rule under the title block."""

        def wrap(self, aw, ah):
            return W, 5 * mm

        def draw(self):
            c = self.canv
            c.saveState()
            p = c.beginPath()
            p.roundRect(0, 2 * mm, W, 1.4 * mm, 0.7 * mm)
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
        return [f"<font name='{bold}' color='{INK}'>{t(k)}:</font> {t(v)}"
                for k, v in pairs]

    parties = Table([[
        card("Issued by", d["seller_name"],
             [t(d["seller_tagline"])] + bits(d["seller_bits"])),
        card("Billed to", d["company"],
             ["Attn: Accounts Payable"] + bits(d["client_bits"]))]],
        colWidths=[W / 2, W / 2])
    parties.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 3 * mm),
        ("LEFTPADDING", (1, 0), (1, 0), 3 * mm),
        ("RIGHTPADDING", (1, 0), (1, 0), 0)]))

    head = st("th", 7.5, white, bold)
    head_r = st("thr", 7.5, white, bold, alignment=TA_RIGHT)
    num = st("num", 9.5, ink, reg, alignment=TA_RIGHT)
    items = Table([
        [Paragraph("#", head), Paragraph("DESCRIPTION / SERVICE ITEM", head),
         Paragraph("QTY", head_r),
         Paragraph(f"RATE ({t(d['currency'])})", head_r),
         Paragraph(f"AMOUNT ({t(d['currency'])})", head_r)],
        [Paragraph("1", body),
         [Paragraph(t(d["item"]), st("item", 10, ink, bold)),
          Spacer(1, 1.2 * mm), Paragraph(t(d["item_detail"]), small)],
         Paragraph(str(d["months"]), num),
         Paragraph(f"{d['unit']:,.2f}", num),
         Paragraph(f"{d['total']:,.2f}", num)]],
        colWidths=[9 * mm, W - 9 * mm - 16 * mm - 28 * mm - 30 * mm,
                   16 * mm, 28 * mm, 30 * mm])
    items.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ink),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.4 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, HexColor(LINE))]))

    # How to pay -- the same three cases as the page.
    pay = [Paragraph("PAYMENT INFORMATION", eyebrow), Spacer(1, 1.5 * mm)]
    if d["pay"] == "paid":
        pay.append(Paragraph(f"Paid on {t(d['paid_on'])}. Thank you.", body))
    elif d["pay"] == "card":
        link = t(d["pay_link"])
        pay += [Paragraph("Pay online:", small),
                Paragraph(f"<a href='{link}' color='{BLUE}'>{link}</a>",
                          st("link", 8.5, blue)),
                Spacer(1, 1.5 * mm),
                Paragraph("Pay by card with the link above. Your service "
                          "carries on the moment the payment clears.", small)]
    else:
        rows = list(d["bank_rows"]) + [("Payment Ref", d["reference"])]
        pay += [Paragraph(f"<font color='{MUTED}'>{t(k)}:</font> "
                          f"<font name='{bold}'>{t(v)}</font>", body)
                for k, v in rows]
        pay.append(Paragraph(
            "Quote the reference above on the bank transfer."
            if d["bank_rows"] else "To pay, sign in and open the Billing tab.",
            small))
    if d["fx_note"]:
        pay += [Spacer(1, 1.5 * mm), Paragraph(t(d["fx_note"]), small)]

    tot_w = 72 * mm
    grand = st("grand", 20, blue, bold, alignment=TA_RIGHT, lead=24)
    totals_rows = [
        [Paragraph("Subtotal", st("sub", 9.5, muted)),
         Paragraph(f"<font name='{bold}' color='{INK}'>"
                   f"{t(money(d['total']))}</font>", right)],
        [Paragraph(t(d["total_label"]), st("tl", 12, ink, bold, lead=24)),
         Paragraph(t(money(d["total"])), grand)],
        ["", Paragraph(t(d["currency"]), right)]]
    if d["pay"] == "card":
        totals_rows.append([Paragraph(
            f"<a href='{t(d['pay_link'])}' color='white'>"
            f"<font name='{bold}' color='white'>Pay by card</font></a>",
            st("btn", 10, white, bold, alignment=TA_CENTER)), ""])
    totals = Table(totals_rows, colWidths=[tot_w * 0.45, tot_w * 0.55])
    tstyle = [
        ("BACKGROUND", (0, 0), (-1, 2), HexColor(GROUND)),
        ("LINEABOVE", (0, 1), (-1, 1), 1.6, blue),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5 * mm),
        ("TOPPADDING", (0, 0), (-1, 0), 4 * mm),
        ("TOPPADDING", (0, 1), (-1, 1), 3.5 * mm),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 3.5 * mm)]
    if d["pay"] == "card":
        tstyle += [("SPAN", (0, 3), (-1, 3)),
                   ("BACKGROUND", (0, 3), (-1, 3), blue),
                   ("TOPPADDING", (0, 3), (-1, 3), 2.8 * mm),
                   ("BOTTOMPADDING", (0, 3), (-1, 3), 2.8 * mm)]
    totals.setStyle(TableStyle(tstyle))
    foot = Table([[pay, totals]], colWidths=[W - tot_w, tot_w])
    foot.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 8 * mm),
        ("RIGHTPADDING", (1, 0), (1, 0), 0)]))

    questions = (f" Questions: {t(d['support_email'])}."
                 if d["support_email"] else "")
    terms = Table([[Paragraph(
        f"<font name='{bold}' color='{INK}'>Terms &amp; Notes:</font> "
        f"Payment is due within {t(d['due_days'])} days of the invoice date. "
        f"Paying by card takes a moment and your service simply carries on "
        f"\u2014 the packet is extended automatically the moment the payment "
        f"clears, and nobody here has to do anything. No VAT has been "
        f"charged.{questions}", small)]], colWidths=[W])
    terms.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor(GROUND)),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 3.6 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6 * mm)]))

    out = io.BytesIO()
    doc = SimpleDocTemplate(
        out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Invoice {d['invoice_no']}", author=d["seller_name"],
        subject=f"{d['item']} for {d['company']}")

    def page_foot(c, _doc):
        c.saveState()
        c.setFont(reg, 8)
        c.setFillColor(HexColor("#94a3b8"))
        c.drawCentredString(A4[0] / 2, 10 * mm,
                            "EasyMikroTik \u2022 Automated RouterOS & Network "
                            "Infrastructure Solutions \u2022 "
                            "https://easymikrotik.com")
        c.restoreState()

    doc.build([Header(), Rule(), Spacer(1, 3 * mm), parties,
               Spacer(1, 6 * mm), items, Spacer(1, 7 * mm), foot,
               Spacer(1, 7 * mm), terms],
              onFirstPage=page_foot, onLaterPages=page_foot)
    return out.getvalue()


def filename(d: dict) -> str:
    """What the attachment is called."""
    kind = "receipt" if d["settled"] else "invoice"
    return f"EasyMikroTik-{kind}-{d['invoice_no']}.pdf"
