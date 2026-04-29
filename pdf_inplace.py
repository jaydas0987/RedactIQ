"""
pdf_inplace.py — Two-layer in-place PDF redaction.

Layer 1 — Visual: black filled rectangles at exact word coordinates.
           Original layout, fonts, tables, images fully preserved.

Layer 2 — Stream: PII strings blanked directly in the PDF content stream.
           Copy-paste and text extraction return nothing.

Key design decisions:
  - Stream is scanned as a whole (joined BT blocks) so split Aadhaar
    like "(included PAN X and Aadhaar 4821 7391) ... (6625.)" is caught
  - Case IDs (CS-320) preserved in stream, only blanked visually if needed
  - re.search used on whole BT block text, not just individual literals
  - Each Aadhaar digit group word gets its own rectangle (cross-line safe)
"""

import re
import hashlib
import pdfplumber
import pikepdf
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# UNIFORM REPLACEMENT STRATEGY
# ─────────────────────────────────────────────────────────────

PUBLIC_FIXED = {
    "aadhaar": "████████████",
    "pan":     "██████████",
    "ssn":     "███████████",
    "email":   "████████████████",
    "phone":   "████████████",
    "ip":      "███████████",
    "card":    "████████████████",
    "name":    "████████████",
    "generic": "████████████",
}

AUDIT_LABELS = {
    "aadhaar": "[AADHAAR]",
    "pan":     "[PAN]",
    "ssn":     "[SSN]",
    "email":   "[EMAIL]",
    "phone":   "[PHONE]",
    "ip":      "[IP]",
    "card":    "[CARD]",
    "name":    "[NAME]",
    "generic": "[REDACTED]",
}


def pdf_replace(pii_type: str, value: str, mode: str) -> str:
    if mode == "public":
        return PUBLIC_FIXED.get(pii_type, PUBLIC_FIXED["generic"])
    elif mode == "research":
        key = hashlib.sha256(f"{pii_type}:{value.lower().strip()}".encode()).hexdigest()[:6]
        return f"[{pii_type.upper()}-R{key.upper()}]"
    elif mode == "audit":
        return AUDIT_LABELS.get(pii_type, AUDIT_LABELS["generic"])
    return value


# ─────────────────────────────────────────────────────────────
# PII PATTERNS FOR COORDINATE MATCHING (pdfplumber word tokens)
# ─────────────────────────────────────────────────────────────

COORD_PATTERNS = [
    # (pii_type, regex, redact_public, redact_research, redact_audit)
    ("pan",   re.compile(r"^[A-Z]{5}\d{4}[A-Z]$"),               True,  True,  False),
    ("ssn",   re.compile(r"^\d{3}-\d{2}-\d{4}$"),                True,  True,  False),
    ("card",  re.compile(r"^(?:\d{4}[- ]){3}\d{4}$"),            True,  True,  False),
    ("ip",    re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),          True,  True,  False),
    ("email", re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"),
                                                                   True,  True,  False),
    # Phone: "+91" + "9876511234" are two tokens — match as 2-word span
    ("phone", re.compile(r"^(?:\+91[-.\s]?)?\d{5}\s?\d{6}$|^\+91[-.\s]?\d{10}$"),
                                                                   True,  True,  False),
]

NON_NAME_WORDS = {
    "activity","trends","success","teams","support","operations","summary","during",
    "archival","references","interaction","session","profile","feedback","engagement",
    "following","gathered","latest","product","update","service","request","portal",
    "engine","billing","internal","analytics","dashboard","tracking","feature",
    "adoption","customer","user","client","data","review","process","system",
    "compliance","infrastructure","quarterly","marketing","engineering","finance",
    "security","verified","identity","agent","case","account","description",
    "assistance","raised","regarding","recent","included","and","phone","email",
}


# ─────────────────────────────────────────────────────────────
# LAYER 1 — FIND WORD COORDINATES
# ─────────────────────────────────────────────────────────────

def find_pii_boxes(page, mode, known_names):
    """
    Returns list of (x0, top, x1, bottom, replacement) for all PII on page.
    """
    words = page.extract_words(x_tolerance=3, y_tolerance=3, keep_blank_chars=False)
    if not words:
        return []

    hits = []
    seen = set()

    def add(x0, top, x1, bot, replacement):
        key = (round(x0), round(top))
        if key not in seen:
            seen.add(key)
            hits.append((x0, top, x1, bot, replacement))

    def flag(pii_type):
        for (pt, _, rp, rr, ra) in COORD_PATTERNS:
            if pt == pii_type:
                return {"public": rp, "research": rr, "audit": ra}[mode]
        return True

    # Group into lines
    lines, cur = [], [words[0]]
    for w in words[1:]:
        if abs(w["top"] - cur[-1]["top"]) <= 3:
            cur.append(w)
        else:
            lines.append(cur)
            cur = [w]
    lines.append(cur)

    for line in lines:
        # Sliding windows: 1, 2, 3 word spans
        for size in range(1, 4):
            for i in range(len(line) - size + 1):
                group = line[i:i+size]
                texts = [g["text"].rstrip(".,;)(") for g in group]
                span  = " ".join(texts).strip()
                x0    = group[0]["x0"]
                x1    = group[-1]["x1"]
                top   = min(g["top"]    for g in group)
                bot   = max(g["bottom"] for g in group)

                for (pii_type, pattern, rp, rr, ra) in COORD_PATTERNS:
                    if not {"public": rp, "research": rr, "audit": ra}[mode]:
                        continue
                    if pattern.match(span):
                        add(x0, top, x1, bot, pdf_replace(pii_type, span, mode))
                        break

        # Named person: 2 capitalised words matching a known name
        for i in range(len(line) - 1):
            t1 = line[i]["text"].rstrip(".,;)(")
            t2 = line[i+1]["text"].rstrip(".,;)(")
            if not (t1 and t2 and t1[0].isupper() and t2[0].isupper()):
                continue
            if t1.lower() in NON_NAME_WORDS or t2.lower() in NON_NAME_WORDS:
                continue
            span = f"{t1} {t2}"
            for name in known_names:
                if span.lower() == name.lower():
                    add(line[i]["x0"],
                        min(line[i]["top"],    line[i+1]["top"]),
                        line[i+1]["x1"],
                        max(line[i]["bottom"], line[i+1]["bottom"]),
                        pdf_replace("name", span, mode))
                    break

    # Aadhaar: 3 digit groups — may span across lines, handle word by word
    if flag("aadhaar"):
        clean = [w["text"].rstrip(".,;)(") for w in words]
        for i in range(len(words) - 2):
            three = f"{clean[i]} {clean[i+1]} {clean[i+2]}"
            if re.fullmatch(r"\d{4} \d{4} \d{4}", three):
                repl = pdf_replace("aadhaar", three, mode)
                for j in range(3):
                    w = words[i+j]
                    add(w["x0"], w["top"], w["x1"], w["bottom"], repl)

    return hits


# ─────────────────────────────────────────────────────────────
# LAYER 2 — BLANK PII IN CONTENT STREAM
# Strategy: scan joined stream text, find PII in string literals,
# replace matched chars with spaces of same byte length.
# Handles split values (e.g. Aadhaar last 4 on next line) by
# scanning the full raw stream as one string, not line by line.
# ─────────────────────────────────────────────────────────────

# Patterns to blank inside stream string literals
STREAM_PATTERNS = [
    re.compile(r"[A-Z]{5}\d{4}[A-Z]"),                                   # PAN
    re.compile(r"\d{3}-\d{2}-\d{4}"),                                     # SSN
    re.compile(r"(?:\d{4}[- ]){3}\d{4}"),                                 # card
    re.compile(r"(?:\d{1,3}\.){3}\d{1,3}"),                               # IP
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),     # email
    re.compile(r"(?:\+91[-. ]?)?\d{5}[ ]?\d{6}|\+91[-. ]?\d{10}"),       # phone
    re.compile(r"\d{4} \d{4} \d{4}"),                                     # aadhaar full (same line)
    re.compile(r"(?<=Aadhaar )\d{4} \d{4}"),                              # aadhaar first 8 digits
    re.compile(r"(?<=aadhaar )\d{4} \d{4}", re.IGNORECASE),               # aadhaar first 8 (case insensitive)
]


def blank_pii_in_stream(raw_bytes: bytes, known_names: set) -> bytes:
    """
    Blank PII values inside PDF string literals in the content stream.
    
    The PDF content stream encodes text as:
        (string content) Tj
        T* (next line content) Tj
    
    We decode the full stream, apply regex replacements inside each
    string literal, then re-encode. Replacement chars are spaces so
    byte length is preserved (PDF coordinates stay intact).
    
    For split values like Aadhaar last 4 on a new literal, we also
    scan the raw stream for the first 8 digits and blank any orphaned
    4-digit group that follows.
    """
    try:
        text = raw_bytes.decode("latin-1")
    except Exception:
        return raw_bytes

    # Build name patterns
    name_patterns = [re.compile(re.escape(n), re.IGNORECASE) for n in known_names]

    def blank_literal(m):
        inner = m.group(1)
        result = inner
        # Structured PII
        for pat in STREAM_PATTERNS:
            result = pat.sub(lambda mm: " " * len(mm.group()), result)
        # Known names
        for pat in name_patterns:
            result = pat.sub(lambda mm: " " * len(mm.group()), result)
        return f"({result})"

    # First pass: blank all string literals
    modified = re.sub(r"\(([^)]*)\)", blank_literal, text)

    # Second pass: orphaned Aadhaar last-4 or last-8
    # After first pass, "4821 7391" is gone but "(6625.)" may remain
    # Detect by checking if we blanked digits in the previous literal
    # Simpler: blank any 4-digit standalone group that appears after
    # a known Aadhaar context keyword in the raw stream
    def blank_orphan_aadhaar(m):
        inner = m.group(1)
        # If the literal is just 4 digits (possibly with punctuation), blank it
        if re.fullmatch(r"\s*\d{4}[.,]?\s*", inner):
            return f"({'  ' * len(inner)})"
        return m.group(0)

    # Only apply orphan blanking to literals that look like isolated digit groups
    # near aadhaar context — safer to just blank all 4-digit-only literals
    modified = re.sub(r"\((\s*\d{4}[.,]?\s*)\)", blank_orphan_aadhaar, modified)

    return modified.encode("latin-1")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def redact_pdf_inplace(input_path, output_path, mode, known_names):
    """
    Two-layer PDF redaction:
      Layer 1 — Black rectangles at exact word coordinates (visual)
      Layer 2 — Content stream text blanked (copy-paste proof)
    Layout, fonts, tables, images fully preserved. Metadata stripped.
    """
    stats = {}

    with pdfplumber.open(str(input_path)) as plumber_pdf:
        pdf = pikepdf.Pdf.open(str(input_path))

        for page_idx, (plumber_page, pikepdf_page) in enumerate(
            zip(plumber_pdf.pages, pdf.pages)
        ):
            page_h = float(plumber_page.height)
            hits   = find_pii_boxes(plumber_page, mode, known_names)

            # ── Layer 2: blank stream text ──────────────────────────────
            contents = pikepdf_page.get("/Contents")
            if contents is not None:
                streams = list(contents) if isinstance(contents, pikepdf.Array) else [contents]
                for stream_obj in streams:
                    try:
                        raw      = bytes(stream_obj.read_bytes())
                        blanked  = blank_pii_in_stream(raw, known_names)
                        if blanked != raw:
                            stream_obj.write(blanked)
                    except Exception:
                        pass

            if not hits:
                continue

            # ── Layer 1: draw black rectangles ─────────────────────────
            rect_ops = []
            for (x0, top, x1, bot, replacement) in hits:
                pdf_y0 = page_h - bot
                pdf_y1 = page_h - top
                pad    = 1.5
                rect_ops.append(
                    f"q 0 0 0 rg "
                    f"{x0-pad:.2f} {pdf_y0-pad:.2f} "
                    f"{(x1-x0)+2*pad:.2f} {(pdf_y1-pdf_y0)+2*pad:.2f} "
                    f"re f Q"
                )
                # Stats
                pii_type = "name"
                for (pt, pattern, *_) in COORD_PATTERNS:
                    if pattern.search(replacement.replace("█", "A").replace(" ", "")):
                        pii_type = pt
                        break
                stats[pii_type] = stats.get(pii_type, 0) + 1

            new_content = pikepdf.Stream(pdf, "\n".join(rect_ops).encode())
            existing    = pikepdf_page.get("/Contents")

            if existing is None:
                pikepdf_page["/Contents"] = new_content
            elif isinstance(existing, pikepdf.Array):
                existing.append(new_content)
                pikepdf_page["/Contents"] = existing
            else:
                pikepdf_page["/Contents"] = pikepdf.Array([existing, new_content])

        # Strip metadata
        with pdf.open_metadata() as meta:
            for key in list(meta.keys()):
                try: del meta[key]
                except Exception: pass

        if "/Info" in pdf.trailer:
            info = pdf.trailer["/Info"]
            for key in ["/Author","/Creator","/Producer","/Title","/Subject","/Keywords"]:
                if key in info:
                    try: del info[key]
                    except Exception: pass

        pdf.save(str(output_path),
                 compress_streams=True,
                 object_stream_mode=pikepdf.ObjectStreamMode.generate)

    return stats
