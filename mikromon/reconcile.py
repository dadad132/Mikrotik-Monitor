"""Match bank deposits to invoices, so you can see who paid.

A bank transfer arrives where the invoicing system cannot see it, so nothing
marks it paid on its own. The only thing that knows is the bank statement --
and the reference on each deposit already says which company it came from,
because payment_reference() puts it there and org_id_from_reference() reads
it back out of whatever mangled form the bank prints.

So this is deliberately small: turn a pasted statement into rows, match each
credit to an open invoice, and show what it found. It decides nothing. The
whole point is the person looking at it decides, having been shown the
matches, the near-misses and the deposits that match nothing.

Paste rather than upload, because a textarea works from any bank's export,
from a phone, and from a block of rows copied straight out of online
banking -- and because a file picker would have needed multipart parsing
this server does not otherwise do.

Expanding later means feeding `match_rows` from somewhere else: a bank API,
a scheduled export, anything that can produce (date, description, amount).
Nothing below knows or cares where the rows came from.
"""
from __future__ import annotations

import csv
import hashlib
import io
import logging
import re
import time

log = logging.getLogger(__name__)

# Headers the SA banks use, lowercased. Capitec, FNB, Standard Bank, Absa and
# Nedbank all export something different, and none of them is wrong -- so the
# columns are found by name rather than by position wherever there is a
# header row at all.
_DATE_KEYS = ("date", "posting date", "transaction date", "value date",
              "effective date", "txn date")
_DESC_KEYS = ("description", "narrative", "details", "reference",
              "transaction description", "memo", "payee", "particulars")
_AMOUNT_KEYS = ("amount", "credit amount", "transaction amount", "value")
_IN_KEYS = ("money in", "credit", "credits", "deposit", "cr", "amount in")
_OUT_KEYS = ("money out", "debit", "debits", "withdrawal", "dr", "amount out")


def _sniff_delimiter(text: str) -> str:
    """Comma, semicolon or tab -- whichever the first real line has most of.

    Guessed rather than configured: nobody should have to tell a page what
    separator their bank chose, and getting it wrong is obvious immediately
    rather than subtly.
    """
    for line in text.splitlines():
        if not line.strip():
            continue
        counts = {d: line.count(d) for d in (",", ";", "\t", "|")}
        best = max(counts, key=counts.get)
        return best if counts[best] else ","
    return ","


def _clean_amount(raw) -> float | None:
    """Turn what a bank prints into a number, or None.

    Handles "1 234,56", "R1,234.56", "(50.00)" for a debit, and a trailing
    minus. Deliberately refuses anything with letters in it beyond a
    currency marker: it used to strip the digits out of any text at all, so
    "EFT BRAVOLOG-0007 ref" came back as -7.00 and a narrative was read as
    an amount.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Currency markers are allowed; other letters mean this is not a number.
    s = re.sub(r"(?i)\b(zar|usd|eur|gbp)\b", "", s)
    s = s.replace("R", "", 1) if s[:1] == "R" else s
    s = s.replace("$", "").replace("\u20ac", "").replace("\u00a3", "")
    if re.search(r"[A-Za-z]", s):
        return None
    neg = s.startswith("(") and s.endswith(")")
    s = s.strip("()").strip()
    s = re.sub(r"[\s\u00a0']", "", s)          # 1 234,56 and 1'234.56
    if s.endswith("-"):                         # 50.00- is a debit
        neg, s = True, s[:-1]
    if not re.fullmatch(r"[-+]?[\d.,]*\d", s or ""):
        return None
    # Which of . and , is the decimal point: whichever comes last.
    if "," in s and "." in s:
        s = (s.replace(",", "") if s.rindex(".") > s.rindex(",")
             else s.replace(".", "").replace(",", "."))
    elif "," in s:
        # A lone comma is a decimal comma with 1-2 digits after it, and a
        # thousands separator otherwise: "1,50" vs "1,500".
        s = (s.replace(",", ".") if len(s.split(",")[-1]) in (1, 2)
             else s.replace(",", ""))
    try:
        val = float(s)
    except ValueError:
        return None
    return -abs(val) if neg else val


def _pick(header, keys):
    """The index of the first column whose name matches, or None.

    Exact match first, then whole-word. NOT substring: "cr" lives inside
    "Description", so a substring match found the credit column to be the
    narrative on every export that used that header.
    """
    names = [(name or "").strip().lower() for name in header]
    for i, n in enumerate(names):
        if n in keys:
            return i
    for i, n in enumerate(names):
        words = set(re.findall(r"[a-z]+", n))
        for k in keys:
            kw = set(re.findall(r"[a-z]+", k))
            if kw and kw <= words:
                return i
    return None


def parse_statement(text: str) -> list:
    """Pasted statement -> [{date, description, amount, raw}] for CREDITS.

    Only money coming in. A statement is mostly the customer's own spending,
    and offering to match a debit against an invoice would be noise at best.
    """
    text = (text or "").strip()
    if not text:
        return []
    delim = _sniff_delimiter(text)
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    except csv.Error:
        return []
    rows = [r for r in rows if any((c or "").strip() for c in r)]
    if not rows:
        return []

    header = rows[0]
    header_is_text = not any(_clean_amount(c) is not None for c in header)
    if header_is_text:
        i_date = _pick(header, _DATE_KEYS)
        i_desc = _pick(header, _DESC_KEYS)
        i_amt = _pick(header, _AMOUNT_KEYS)
        i_in = _pick(header, _IN_KEYS)
        i_out = _pick(header, _OUT_KEYS)
        body = rows[1:]
    else:
        # No header. Assume the widest text column is the description and
        # the last numeric one is the amount -- which is every bank export
        # that omits headers.
        i_date = 0 if rows and _clean_amount(rows[0][0]) is None else None
        i_desc = i_amt = i_in = i_out = None
        body = rows

    out = []
    for r in body:
        # Each column decided on its own. This used to abandon a perfectly
        # good description column and start guessing positions whenever the
        # amount column happened to be missing -- which it is on every
        # export that splits money in from money out.
        d_i, a_i = i_desc, i_amt
        if d_i is None:
            texts = [(len(str(c)), i) for i, c in enumerate(r)
                     if _clean_amount(c) is None and str(c).strip()]
            d_i = max(texts)[1] if texts else None
        if a_i is None and i_in is None:
            nums = [i for i, c in enumerate(r) if _clean_amount(c) is not None]
            a_i = nums[0] if nums else None

        desc = str(r[d_i]).strip() if d_i is not None and d_i < len(r) else ""
        amount = None
        if i_in is not None and i_in < len(r):
            amount = _clean_amount(r[i_in])
        if amount is None and a_i is not None and a_i < len(r):
            amount = _clean_amount(r[a_i])
        if amount is None:
            continue
        if i_out is not None and i_out < len(r):
            out_val = _clean_amount(r[i_out])
            if out_val:
                continue                        # explicitly a debit
        if amount <= 0:
            continue                            # money out, or a zero row
        date = (str(r[i_date]).strip()
                if i_date is not None and i_date < len(r) else "")
        out.append({"date": date, "description": desc, "amount": amount,
                    "raw": delim.join(str(c) for c in r)})
    return out


def line_key(row) -> str:
    """A stable id for one statement line.

    So the same statement pasted twice does not pay the same invoice twice.
    Built from what the bank prints rather than from anything we add, which
    is what makes it the same key on the second paste.
    """
    basis = f'{row.get("date", "")}|{row.get("amount", "")}|' \
            f'{(row.get("description") or "").strip().lower()}'
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:20]


def match_rows(rows, open_invoices, tolerance: float = 0.01) -> dict:
    """Match credits to invoices. Decides nothing; reports everything.

    Returns {"matched", "wrong_amount", "unmatched", "already"} -- four
    lists, because those are four different things a person does something
    different about, and collapsing them into "matched / not matched" would
    hide the one that needs a phone call.
    """
    from .billing import org_id_from_reference

    by_org = {}
    for inv in open_invoices:
        by_org.setdefault(int(inv.get("org_id") or 0), []).append(inv)

    out = {"matched": [], "wrong_amount": [], "unmatched": [], "already": []}
    claimed = set()
    for row in rows:
        org_id = org_id_from_reference(row.get("description", ""))
        entry = dict(row, key=line_key(row), org_id=org_id)
        if not org_id:
            out["unmatched"].append(entry)
            continue
        candidates = [i for i in by_org.get(org_id, [])
                      if i.get("order_id") not in claimed]
        if not candidates:
            # The reference is one of ours, but nothing is outstanding for
            # them. Usually a duplicate payment or one already recorded --
            # worth seeing, never worth applying.
            entry["note"] = ("no invoice is outstanding for this company"
                             if org_id in by_org or True else "")
            out["already"].append(entry)
            continue
        exact = [i for i in candidates
                 if abs(float(i.get("amount") or 0) - row["amount"]) <= tolerance]
        pick = exact[0] if exact else min(
            candidates,
            key=lambda i: abs(float(i.get("amount") or 0) - row["amount"]))
        entry["invoice"] = pick
        claimed.add(pick.get("order_id"))
        (out["matched"] if exact else out["wrong_amount"]).append(entry)
    return out


def summarise(result) -> str:
    """One line a person can read before deciding anything."""
    n = {k: len(v) for k, v in result.items()}
    total = sum(r["amount"] for r in result["matched"])
    bits = [f"{n['matched']} matched"]
    if total:
        bits[0] += f" ({total:,.2f})"
    for key, label in (("wrong_amount", "amount differs"),
                       ("already", "nothing outstanding"),
                       ("unmatched", "no reference")):
        if n[key]:
            bits.append(f"{n[key]} {label}")
    return ", ".join(bits)
