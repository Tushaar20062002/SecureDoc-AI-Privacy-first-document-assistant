"""Local PII detection. Runs entirely on the server, BEFORE any external call.

Techniques: label-aware extraction ("Name: ...", "PAN No: ..."), format regexes,
checksum validation (Verhoeff for Aadhaar, Luhn for cards), lightweight local
heuristic NER for names/addresses (honorifics, declarations, pincode lines) and
propagation of detected values to every other occurrence in the document.

Detection is NOT perfect. Low-confidence detections are flagged needs_review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..security.permissions import RESTRICTED_CATEGORIES

# ------------------------------------------------------------------ validators
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def digits_only(s: str) -> str:
    return re.sub(r"\D", "", s)


# ------------------------------------------------------------------ entity model
METHOD_RANK = {"label": 4.0, "validated": 3.0, "propagated": 2.5, "pattern": 2.0, "heuristic": 1.0}


@dataclass
class Entity:
    category: str
    text: str
    start: int
    end: int
    confidence: float
    method: str
    page: int = 0
    canonical: str | None = None  # value used for consistent placeholder assignment
    placeholder: str | None = None

    @property
    def restricted(self) -> bool:
        return self.category in RESTRICTED_CATEGORIES

    @property
    def needs_review(self) -> bool:
        return self.confidence < 0.7


# ------------------------------------------------------------------ label specs
_NO = r"(?:\s*(?:no|number|num|#)\.?)"
_LIKE = r"(?:[\s-]+(?:like|shaped|style|type))?"  # "Aadhaar-like number", "PAN-shaped value"
LABELS: list[tuple[str, str]] = [
    ("PERSON", r"(?:full\s+name|applicant'?s?\s+name|candidate'?s?\s+name|name\s+of\s+(?:the\s+)?(?:applicant|candidate|account\s+holder|employee|student)"
               r"|father'?s?\s+name|mother'?s?\s+name|spouse'?s?\s+name|guardian'?s?\s+name|husband'?s?\s+name|nominee'?s?\s+name"
               r"|(?:emergency\s+)?contact\s+(?:person|name)|account\s+holder(?:'?s?\s+name)?|first\s+name|last\s+name|middle\s+name"
               r"|surname|signed\s+by|signature|declarant|name)"),
    ("EMAIL", r"(?:e-?mail(?:\s+(?:id|address))?)"),
    ("ADDRESS", r"(?:residential\s+address|permanent\s+address|current\s+address|correspondence\s+address|postal\s+address"
                r"|mailing\s+address|home\s+address|present\s+address|address(?:\s+line\s*\d)?)"),
    ("ADDRESS", r"(?:pin\s*code|pincode|postal\s+code|zip(?:\s+code)?)"),
    ("PHONE", rf"(?:phone|mobile|telephone|contact|tel|cell|whatsapp){_NO}?"),
    ("DOB", r"(?:date\s+of\s+birth|d\.?\s?o\.?\s?b\.?|birth\s+date)"),
    ("AADHAAR", rf"(?:aadhaa?r{_LIKE}(?:\s+card)?{_NO}?|uid(?:ai)?{_NO}|vid)"),
    ("PAN", rf"(?:pan{_LIKE}(?:\s+card)?{_NO}?|permanent\s+account\s+number)"),
    ("PASSPORT", rf"(?:passport{_LIKE}(?:\s+(?:card|book))?(?:{_NO}|\s+ref(?:erence)?)?)"),
    ("BANK_ACCOUNT", rf"(?:(?:bank\s+)?(?:a/?c|account){_NO}|savings\s+account|current\s+account|bank\s+account)"),
    ("IFSC", r"(?:ifsc(?:\s+code)?|swift(?:\s+code)?|micr(?:\s+code)?)"),
    ("CREDIT_CARD", rf"(?:(?:credit|debit|atm)\s+card{_NO}?|card{_NO}|card\s+expiry(?:\s+date)?|expiry\s+date|valid\s+(?:thru|through|till))"),
    ("CVV", r"(?:cvv2?|cvc|card\s+verification\s+value)"),
    ("PASSWORD", r"(?:password|passcode|passwd|pwd|secret\s+answer)"),
    ("PIN", r"(?:(?:atm|card|mpin|m-pin|upi)\s*pin|mpin|pin)(?!\s*code)"),
    ("OTP", r"(?:otp|one[\s-]time\s+password|verification\s+code)"),
    ("OTHER_ID", rf"(?:voter\s+id{_NO}?|epic{_NO}|driving\s+licen[cs]e{_NO}?|dl{_NO}|uan{_NO}?|ration\s+card{_NO}?"
                 rf"|customer\s+id|cif{_NO}?|national\s+id{_NO}?|ssn|social\s+security{_NO}?|gstin|tax\s+id{_NO}?"
                 # government / tax identity numbers in generic wording
                 rf"|(?:national\s*/\s*)?identity\s+(?:number|no\.?|reference|ref)|id(?:entity)?\s+card\s+(?:number|no\.?)"
                 rf"|tax\s+(?:reference|ref|number|no\.?|identification\s+number)(?:\s+pattern)?|tin{_NO}"
                 rf"|national\s+insurance{_NO}?"
                 # generic "<something> ID" / "ID No." on ID cards (longer labels such as "Email ID",
                 # "Application ID", "Employee ID" win because the longest label match is used)
                 rf"|id(?:\s+(?:no\.?|number|ref(?:erence)?))?|(?:card|document)\s+(?:no\.?|number))"),
    ("APP_REF", rf"(?:application\s+(?:id|ref(?:erence)?{_NO}?){_NO}?|application{_NO}|reference{_NO}|ref(?:erence)?\s*id"
                rf"|ref\.?{_NO}|registration{_NO}|roll{_NO}|enrol(?:l)?ment{_NO}"
                rf"|(?:employee|staff)\s+(?:id|code|ref(?:erence)?){_NO}?)"),
]

_ALL_LABELS = "|".join(f"(?:{p})" for _, p in LABELS)
# A label must begin a "cell": line start, after a tab / pipe / semicolon / 2+ spaces / ", ".
_CELL_START = r"(?:^|(?<=\s\s)|(?<=[\t|;])|(?<=,\s))[ \t]*"
# Separator: ':' or '=' or a dash followed by whitespace ("DOB - 01/01/1990"). A dash glued to a
# word ("PAN-SHAPED") is NOT a separator.
_SEP = r"[ \t]*(?:[:=]|[\-–](?=[ \t]))[ \t]*(?:\n[ \t]*)?"
_NEXT_LABEL_RE = re.compile(rf"(?i)(?:^|\s)(?:{_ALL_LABELS})[ \t]*[:\-–=]")
_LABEL_RES = [
    (cat, re.compile(rf"(?im){_CELL_START}(?P<label>{pat}){_SEP}(?P<value>[^\n]*?)(?=[ \t]{{2,}}|\t|[ \t]*\||[ \t]*$)"))
    for cat, pat in LABELS
]
_EMPTY_VALUES = {"", "-", "--", "n/a", "na", "nil", "none", "null", "not applicable", "_", "__"}
_NEEDS_DIGIT = {"PHONE", "AADHAAR", "BANK_ACCOUNT", "CREDIT_CARD", "CVV", "OTP", "PIN", "PASSPORT", "PAN", "IFSC", "OTHER_ID"}

# ------------------------------------------------------------------ pattern specs
_PATTERNS: list[tuple[str, re.Pattern, float, str]] = [
    ("EMAIL", re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), 0.99, "validated"),
    ("IP_ADDRESS", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"), 0.9, "validated"),
    ("PAN", re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z](?![A-Za-z0-9])"), 0.95, "validated"),
    ("PAN", re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"), 0.75, "pattern"),
    ("IFSC", re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])"), 0.9, "validated"),
    ("PASSPORT", re.compile(r"(?<![A-Za-z0-9])[A-PR-WY][1-9]\d{6}(?![A-Za-z0-9])"), 0.6, "pattern"),
    ("PHONE", re.compile(r"(?<![\d+])(?:\+91[ -]?|0091[ -]?|91[ -]|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)"), 0.9, "validated"),
    ("PHONE", re.compile(r"(?<![\d+])\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}(?!\d)"), 0.8, "pattern"),
    ("PHONE", re.compile(r"(?<!\d)0\d{2,4}[ -]\d{6,8}(?!\d)"), 0.7, "pattern"),
    ("DOB", re.compile(r"(?i)(?<=born on )\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}"), 0.8, "pattern"),
]
_AADHAAR_RE = re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])")
_SPACED_12_RE = re.compile(r"(?<![\d-])\d{4}[ -]\d{4}[ -]\d{4}(?![\d-]|[ -]\d)")
_AADHAAR_CONTEXT_RE = re.compile(r"(?i)\b(?:aadhaa?r|aadhar|uidai)\b|आधार")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_LONG_DIGITS_RE = re.compile(r"(?<![\d.])\d{9,18}(?![\d.])")

# ------------------------------------------------------------------ heuristic NER
_HONORIFIC_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Shri|Smt|Sri|Kumari|Kum)\.?\s+"
    r"(?P<name>[A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-zA-Z'-]+){0,3})"
)
_DECLARATION_RE = re.compile(
    r"\b(?:I|undersigned),?\s+(?P<name>[A-Z][a-z'-]+(?:\s+[A-Z][a-z'-]+){1,3}),?\s+(?:hereby|do\s+hereby|son|daughter|wife|s/o|d/o|w/o)"
)
_RELATION_RE = re.compile(r"\b(?:S/O|D/O|W/O|C/O|son of|daughter of|wife of|care of)\s+(?P<name>[A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,3})")
_ADDRESS_LINE_RE = re.compile(
    r"(?im)^[^\n]*\b(?:road|rd\.|street|st\.|lane|nagar|colony|sector|flat|house|h\.?no|apartment|apt|block|marg|"
    r"village|district|dist\.|taluka|tehsil|post|p\.o\.|near|opp\.?|society|chawl|layout|cross|main)\b[^\n]*\b\d{6}\b[^\n]*$"
)
_PINCODE_IN_ADDR_RE = re.compile(r"(?i)\b[A-Za-z .]+[, -]+\d{6}\b")

_NAME_STOPWORDS = {
    "the", "and", "for", "name", "date", "mr", "mrs", "ms", "dr", "shri", "smt", "kumar", "singh", "devi",
    "application", "form", "bank", "india", "indian", "of", "to", "in", "on", "at", "by", "with", "page",
}


def _value_ok(category: str, value: str) -> bool:
    v = value.strip()
    if v.lower().strip(" .") in _EMPTY_VALUES or len(v) < 2:
        return False
    if category in _NEEDS_DIGIT and not re.search(r"\d", v):
        return False
    if category == "PERSON":
        if not re.search(r"[A-Za-z]", v) or len(v) > 80 or len(v.split()) > 6:
            return False
        if re.search(r"\d", v):  # names rarely contain digits; avoid masking codes as names
            return False
    if category == "ADDRESS" and len(v) < 4:
        return False
    if category == "EMAIL" and "@" not in v:
        return False
    return True


def _trim_value(value: str) -> tuple[str, int]:
    """Cut a captured value at the next label, return (value, trailing_cut)."""
    m = _NEXT_LABEL_RE.search(value)
    if m and m.start() > 0:
        value = value[: m.start()]
    elif m and m.start() == 0:
        return "", 0
    stripped = value.rstrip(" \t,;.|")
    return stripped, 0


def _label_entities(text: str) -> list[Entity]:
    out: list[Entity] = []
    for cat, rx in _LABEL_RES:
        for m in rx.finditer(text):
            raw = m.group("value")
            value, _ = _trim_value(raw)
            lead = len(raw) - len(raw.lstrip())
            value = value.strip()
            if not _value_ok(cat, value):
                continue
            start = m.start("value") + lead
            out.append(Entity(cat, value, start, start + len(value), 0.9, "label"))
    return out


# "Stacked" form layout: the label is alone on a line and the value is on the next line(s)
#   FULL NAME
#   Riya Testperson
_STACKED_RES = [(cat, re.compile(rf"(?i)(?<![A-Za-z])(?:{pat})(?![A-Za-z])")) for cat, pat in LABELS]
_TRAILING_NOTE_RE = re.compile(r"\s*\([^()]*\)\s*$")  # "123 (dummy value)" -> "123"
_MULTILINE_CATEGORIES = {"ADDRESS"}
_GENERIC_LABELS = {"name", "address", "contact", "signature"}


def _label_line_matches(line: str) -> list[tuple[str, int]]:
    """If `line` looks like a standalone label, return [(category, matched_length)] longest first."""
    s = line.strip().rstrip(":").strip()
    if not s or len(s) > 50 or ":" in s:
        return []
    found = []
    for cat, rx in _STACKED_RES:
        m = rx.search(s)
        if m:
            # Generic labels ("name", "address") must start the line: "BANK NAME", "COMPANY NAME",
            # "INSTITUTION NAME" are not personal names.
            if m.group(0).lower() in _GENERIC_LABELS and s[: m.start()].strip():
                continue
            rest = (s[: m.start()] + " " + s[m.end():]).split()
            rest = [w for w in rest if re.search(r"[A-Za-z0-9]", w) and not re.fullmatch(r"\d+\.?", w)]
            if len(rest) <= 3:  # short label line, not a sentence
                found.append((cat, m.end() - m.start(), m.group(0).lower()))
    return sorted(found, key=lambda x: -x[1])


def _looks_like_heading(line: str) -> bool:
    s = line.strip()
    return bool(s) and s.isupper() and len(s.split()) <= 4 and not re.search(r"\d", s)


def _row_label_entities(lines: list[str], offsets: list[int]) -> list[Entity]:
    """Table rows rebuilt as 'Label<TAB>Value': the left cell is matched like a stacked label."""
    out: list[Entity] = []
    for line, off in zip(lines, offsets):
        if "\t" not in line:
            continue
        cells = line.split("\t")
        pos = 0
        for k in range(len(cells) - 1):
            label, value_cell = cells[k], cells[k + 1]
            value_start = off + pos + len(label) + 1
            pos += len(label) + 1
            cands = _label_line_matches(label)
            if not cands:
                continue
            lead = len(value_cell) - len(value_cell.lstrip())
            value = _TRAILING_NOTE_RE.sub("", value_cell.strip()).rstrip(" ,;")
            for cat, _, _ in cands:
                if _value_ok(cat, value) and len(value) <= 200:
                    out.append(Entity(cat, value, value_start + lead, value_start + lead + len(value), 0.85, "label"))
                    break
    return out


def _stacked_label_entities(text: str) -> list[Entity]:
    out: list[Entity] = []
    lines = text.split("\n")
    offsets, pos = [], 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    out.extend(_row_label_entities(lines, offsets))
    for i, line in enumerate(lines):
        if "\t" in line:
            continue  # handled as a table row
        cands = _label_line_matches(line)
        if not cands:
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines) or _label_line_matches(lines[j]):
            continue
        for cat, _, label in cands:
            end_line = j
            if cat in _MULTILINE_CATEGORIES and "address" in label:  # addresses may wrap onto following lines
                while (end_line + 1 < len(lines) and end_line - j < 2 and lines[end_line + 1].strip()
                       and not _label_line_matches(lines[end_line + 1])
                       and not _looks_like_heading(lines[end_line + 1])
                       and len(lines[end_line + 1].strip()) <= 60):
                    end_line += 1
            start = offsets[j] + (len(lines[j]) - len(lines[j].lstrip()))
            raw = "\n".join(lines[j: end_line + 1]).strip()
            value = _TRAILING_NOTE_RE.sub("", raw).rstrip(" ,;")
            if _value_ok(cat, value) and len(value) <= 200:
                out.append(Entity(cat, value, start, start + len(value), 0.85, "label"))
                break
    return out


def _pattern_entities(text: str) -> list[Entity]:
    out: list[Entity] = []
    for cat, rx, conf, method in _PATTERNS:
        for m in rx.finditer(text):
            out.append(Entity(cat, m.group(0), m.start(), m.end(), conf, method))
    for m in _AADHAAR_RE.finditer(text):
        d = digits_only(m.group(0))
        valid = verhoeff_valid(d)
        out.append(Entity("AADHAAR", m.group(0), m.start(), m.end(), 0.97 if valid else 0.72, "validated" if valid else "pattern"))
    # A 12-digit number printed as 4-4-4 on a document that mentions Aadhaar/UIDAI is an Aadhaar
    # number even without a label or a valid checksum (cards print the number alone, specimens use
    # dummy numbers). Without that context it is still masked as an unlabelled identifier.
    aadhaar_context = bool(_AADHAAR_CONTEXT_RE.search(text))
    for m in _SPACED_12_RE.finditer(text):
        if aadhaar_context:
            out.append(Entity("AADHAAR", m.group(0), m.start(), m.end(), 0.85, "pattern"))
        else:
            out.append(Entity("OTHER_ID", m.group(0), m.start(), m.end(), 0.6, "heuristic"))
    for m in _CARD_RE.finditer(text):
        d = digits_only(m.group(0))
        if 13 <= len(d) <= 19 and luhn_valid(d) and not (len(d) == 12):
            out.append(Entity("CREDIT_CARD", m.group(0).strip(), m.start(), m.start() + len(m.group(0).strip()), 0.93, "validated"))
    out.extend(_mrz_entities(text))
    for m in _LONG_DIGITS_RE.finditer(text):
        # Unlabelled long numbers may be account numbers or other identifiers: mask conservatively.
        out.append(Entity("OTHER_ID", m.group(0), m.start(), m.end(), 0.6, "heuristic"))
    return out


# ---------------------------------------------------------------- passport / ID machine-readable zone
# ICAO 9303 MRZ lines (TD1 3x30, TD2 2x36, TD3 2x44): characters A-Z, 0-9 and the filler '<'.
# Vision transcriptions often insert spaces inside an MRZ line ('4220167749 USA8810171F...'), so
# spaces are allowed between characters and the length/check digits are tested on the compacted line.
_MRZ_LINE_RE = re.compile(r"(?m)^[ \t]*([A-Z0-9<](?:[A-Z0-9<]| (?=[A-Z0-9<])){27,70})[ \t]*$")


def icao_check_digit(value: str) -> int:
    total = 0
    for i, ch in enumerate(value):
        v = int(ch) if ch.isdigit() else (ord(ch) - 55 if "A" <= ch <= "Z" else 0)
        total += v * (7, 3, 1)[i % 3]
    return total % 10


def mrz_document_number(line: str) -> str | None:
    """Document number from a TD3/TD2 second line (validated by its ICAO check digit)."""
    line = line.strip()
    if len(line) >= 36 and line[:9].replace("<", "").isalnum() and line[9].isdigit():
        if icao_check_digit(line[:9]) == int(line[9]):
            num = line[:9].replace("<", "")
            return num if len(num) >= 6 else None
    return None


def _mrz_entities(text: str) -> list[Entity]:
    out = []
    for m in _MRZ_LINE_RE.finditer(text):
        line = m.group(1)
        compact = line.replace(" ", "")
        if not 28 <= len(compact) <= 46:
            continue
        valid = mrz_document_number(compact) is not None
        if not valid and (compact.count("<") < 2 or not re.search(r"[A-Z]", compact)):
            continue
        out.append(Entity("PASSPORT", line, m.start(1), m.end(1), 0.97 if valid else 0.85,
                          "validated" if valid else "pattern"))
    return out


def _heuristic_entities(text: str) -> list[Entity]:
    out: list[Entity] = []
    for rx, conf in ((_HONORIFIC_RE, 0.75), (_DECLARATION_RE, 0.7), (_RELATION_RE, 0.75)):
        for m in rx.finditer(text):
            name = m.group("name").strip()
            if _value_ok("PERSON", name) and name.lower() not in _NAME_STOPWORDS:
                out.append(Entity("PERSON", name, m.start("name"), m.start("name") + len(name), conf, "heuristic"))
    for m in _ADDRESS_LINE_RE.finditer(text):
        line = m.group(0)
        lead = len(line) - len(line.lstrip())
        val = line.strip()
        out.append(Entity("ADDRESS", val, m.start() + lead, m.start() + lead + len(val), 0.65, "heuristic"))
    return out


def _resolve_overlaps(entities: list[Entity]) -> list[Entity]:
    def key(e: Entity):
        return (-METHOD_RANK.get(e.method, 0) - (0.5 if e.restricted else 0), -(e.end - e.start), -e.confidence)

    # A propagated copy never replaces a direct detection (same category) that already covers it,
    # e.g. the digits-only re-match '00 0000 000 003' must not cut the '+' off '+00 0000 000 003'.
    direct = [(e.start, e.end, e.category) for e in entities if e.method != "propagated"]
    entities = [e for e in entities if e.method != "propagated"
                or not any(s <= e.start and e.end <= t and c == e.category for s, t, c in direct)]
    chosen: list[Entity] = []
    occupied: list[tuple[int, int]] = []
    for e in sorted(entities, key=key):
        if e.end <= e.start:
            continue
        if any(not (e.end <= s or e.start >= t) for s, t in occupied):
            continue
        chosen.append(e)
        occupied.append((e.start, e.end))
    return sorted(chosen, key=lambda e: e.start)


def _flex_regex(value: str, category: str) -> re.Pattern | None:
    """Regex matching other occurrences of a detected value (spacing-insensitive)."""
    d = digits_only(value)
    if category not in {"PERSON", "ADDRESS", "EMAIL", "PASSWORD"} and len(d) >= 4 and len(d) >= len(re.sub(r"\W", "", value)) - 2:
        return re.compile(r"(?<!\d)" + r"[ -]?".join(re.escape(c) for c in d) + r"(?!\d)")
    words = value.split()
    if not words:
        return None
    return re.compile(r"(?i)(?<![\w])" + r"\s+".join(re.escape(w) for w in words) + r"(?![\w])")


_NO_PROPAGATE = {"CVV", "PIN", "OTP", "PASSWORD"}


def _propagatable(e: Entity) -> bool:
    """Short values (CVV '000', expiry '00/00', PIN) are only sensitive where they are labelled:
    searching the whole document for them masks unrelated numbers ('ZZ 000000', '+00 0000 000 003')."""
    if e.category in _NO_PROPAGATE:
        return False
    compact = re.sub(r"[\s\-./()+]", "", e.text)
    digits = sum(c.isdigit() for c in compact)
    if compact and digits >= len(compact) - 1 and digits < 6:
        return False
    return len(compact) >= 4


_DIGIT_RUN_RE = re.compile(r"(?<!\d)\d{6,}(?!\d)")
# A piece of an MRZ line (letters, digits, '<'; no spaces) left over when a transcription split the line.
_MRZ_FRAGMENT_RE = re.compile(r"(?m)^[ \t]*([A-Z0-9<]{12,})[ \t]*$")


def _mrz_fragment_entities(text: str) -> list[Entity]:
    """Only used on a page that already has an MRZ: masks leftover MRZ pieces as passport data."""
    out = []
    for m in _MRZ_FRAGMENT_RE.finditer(text):
        frag = m.group(1)
        if sum(c.isdigit() for c in frag) >= 5:
            out.append(Entity("PASSPORT", frag, m.start(1), m.end(1), 0.9, "validated"))
    return out


def _propagate(text: str, entities: list[Entity]) -> list[Entity]:
    """Mask every other occurrence of each detected value (and name tokens)."""
    extra: list[Entity] = []
    seen: set[tuple[str, str]] = set()
    for e in entities:
        if e.method == "propagated":  # only propagate from original detections (no chain reactions)
            continue
        canonical = e.canonical or e.text
        k = (e.category, e.text.lower())
        if k in seen:
            continue
        seen.add(k)
        rx = _flex_regex(e.text, e.category) if _propagatable(e) else None
        if rx:
            for m in rx.finditer(text):
                extra.append(Entity(e.category, m.group(0), m.start(), m.end(), e.confidence, "propagated", canonical=canonical))
        if e.category == "PASSPORT" and (num := mrz_document_number(e.text)):
            # the MRZ encodes the passport number: mask it wherever else it is printed
            nrx = _flex_regex(num, "PASSPORT") if any(c.isdigit() for c in num) else None
            for m in (nrx.finditer(text) if nrx else ()):
                extra.append(Entity("PASSPORT", m.group(0), m.start(), m.end(), e.confidence, "propagated", canonical=num))
        if e.restricted and len(d := digits_only(e.text)) >= 8:
            # A partial copy of an identifier (e.g. '22016774' of passport '422016774', from a line
            # the transcription cut short) is masked too.
            # Only near-complete copies (at most 3 digits cut off, not a run like '000000'), so a
            # postal code or other short number is never masked because it happens to appear inside.
            for m in _DIGIT_RUN_RE.finditer(text):
                frag = m.group(0)
                if frag != d and frag in d and len(frag) >= len(d) - 3 and len(set(frag)) >= 3:
                    extra.append(Entity(e.category, m.group(0), m.start(), m.end(), e.confidence, "propagated",
                                        canonical=canonical))
        if e.category == "PERSON":
            for tok in re.findall(r"[A-Z][a-zA-Z'-]{2,}", e.text):
                if tok.lower() in _NAME_STOPWORDS:
                    continue
                for m in re.finditer(rf"(?<![\w]){re.escape(tok)}(?![\w])", text):
                    extra.append(Entity("PERSON", tok, m.start(), m.end(), min(e.confidence, 0.8), "propagated", canonical=canonical))
    return extra


def detect(text: str, categories: frozenset[str] | set[str] | None = None) -> list[Entity]:
    """Detect PII spans in text. Returns non-overlapping entities sorted by start.

    `categories` limits which categories are returned (masking scope). Filtering happens BEFORE
    overlap resolution, so e.g. a phone number inside an (unmasked) address line is still found."""
    if not text:
        return []
    cands = _label_entities(text) + _stacked_label_entities(text) + _pattern_entities(text) + _heuristic_entities(text)
    if categories is not None:
        cands = [e for e in cands if e.category in categories]
    base = _resolve_overlaps(cands)
    return _resolve_overlaps(base + _propagate(text, base))


def detect_document(pages: list[str], categories: frozenset[str] | set[str] | None = None) -> list[Entity]:
    """Detect on each page, then propagate values found anywhere to all pages."""
    per_page: list[list[Entity]] = []
    for i, t in enumerate(pages, start=1):
        ents = detect(t, categories)
        for e in ents:
            e.page = i
        per_page.append(ents)
    all_found = [e for ents in per_page for e in ents]
    has_mrz = any(e.category == "PASSPORT" and "<" in e.text and e.method != "propagated" for e in all_found)
    result: list[Entity] = []
    for i, t in enumerate(pages, start=1):
        extra = _propagate(t, all_found) + (_mrz_fragment_entities(t) if has_mrz else [])
        for e in extra:
            e.page = i
        merged = _resolve_overlaps(per_page[i - 1] + extra)
        for e in merged:
            e.page = i
        result.extend(merged)
    return result


# ---------------------------------------------------------------- strong guard
_STRONG_CATEGORIES = {"EMAIL", "PAN", "IFSC", "AADHAAR", "CREDIT_CARD", "PHONE", "IP_ADDRESS"}


def strong_identifier_hits(text: str) -> list[str]:
    """Categories of high-confidence identifiers present in text (used as an egress guard).
    Only categories inside the current masking scope count."""
    from ..security.permissions import masked_categories

    scope = masked_categories()
    hits = []
    for e in _pattern_entities(text):
        if e.category in _STRONG_CATEGORIES and e.category in scope and e.confidence >= 0.9:
            hits.append(e.category)
    return hits


def mask_restricted_inline(text: str) -> str:
    """Replace any restricted-looking identifier in free text with a generic token."""
    ents = [e for e in _resolve_overlaps(_pattern_entities(text) + _label_entities(text)) if e.restricted]
    for e in sorted(ents, key=lambda x: x.start, reverse=True):
        text = text[: e.start] + f"[{e.category}_REDACTED]" + text[e.end:]
    return text
