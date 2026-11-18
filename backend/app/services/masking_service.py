"""Masking engine: consistent placeholders, masked text, permanently redacted PDFs
and post-generation validation (re-open, re-extract, search for originals)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pymupdf

from .pii_service import Entity, digits_only

NUMERIC_CATEGORIES = {
    "PHONE", "AADHAAR", "BANK_ACCOUNT", "CREDIT_CARD", "CVV", "PIN", "OTP", "OTHER_ID", "IP_ADDRESS",
}


def _norm_value(category: str, value: str) -> str:
    if category in NUMERIC_CATEGORIES and len(digits_only(value)) >= 3:
        return digits_only(value)
    return re.sub(r"\s+", " ", value).strip().lower()


class Masker:
    """Assigns stable placeholders such as [PERSON_001] per (category, value)."""

    def __init__(self) -> None:
        self._map: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        self.originals: dict[str, dict] = {}  # placeholder -> {"category", "value"} (memory only)

    def placeholder_for(self, e: Entity) -> str:
        canonical = e.canonical or e.text
        key = (e.category, _norm_value(e.category, canonical))
        ph = self._map.get(key)
        if ph is None:
            n = self._counters.get(e.category, 0) + 1
            self._counters[e.category] = n
            ph = f"[{e.category}_{n:03d}]"
            self._map[key] = ph
            self.originals[ph] = {"category": e.category, "value": canonical.strip()}
        e.placeholder = ph
        return ph

    def mask_text(self, text: str, entities: list[Entity]) -> str:
        for e in sorted(entities, key=lambda x: x.start, reverse=True):
            text = text[: e.start] + self.placeholder_for(e) + text[e.end:]
        return text


PLACEHOLDER_RE = re.compile(r"\[([A-Z_]+)_(\d{3})\]")


# ------------------------------------------------------------------ PDF output
@dataclass
class PdfBuildResult:
    data: bytes
    warnings: list[str] = field(default_factory=list)


def _whole_word_hit(hit: pymupdf.Rect, words: list[tuple], segment: str | None = None) -> bool:
    """page.search_for() matches substrings: '000' is also found inside '000000' or
    'TEST-TAX-000-XYZ'. Keep a hit only if every word it touches is (almost) fully covered and,
    when `segment` is given, the covered words spell exactly that value (search_for merges
    adjacent repeats, so two '000' hits inside '000000' come back as one full-word box)."""
    covered = []
    for w in words:
        wr = pymupdf.Rect(w[:4])
        if wr.width <= 0:
            continue
        ov_x = min(hit.x1, wr.x1) - max(hit.x0, wr.x0)
        ov_y = min(hit.y1, wr.y1) - max(hit.y0, wr.y0)
        if ov_x <= 0.15 * wr.width or ov_y <= 0.3 * min(hit.height, wr.height):
            continue  # not really touching this word
        if ov_x < 0.8 * wr.width:
            return False  # covers only part of a longer word
        covered.append((wr.x0, w[4]))
    if segment is not None and covered:
        def norm(s: str) -> str:
            return re.sub(r"\s+", "", s).strip(".,;:()|").lower()
        spelled = norm("".join(t.strip(".,;:()|") for _, t in sorted(covered)))
        if spelled != norm(segment):
            return False
    return True


def _search_rects(page: pymupdf.Page, text: str, words: list[tuple]) -> list[pymupdf.Rect]:
    rects: list[pymupdf.Rect] = []
    for segment in [s.strip() for s in text.splitlines() if s.strip()]:
        found = page.search_for(segment)
        if found and words:
            found = [r for r in found if _whole_word_hit(r, words, segment)]
        if not found:
            # fallback: redact individual words that belong to the value
            tokens = {t.strip(".,;:()").lower() for t in segment.split() if len(t.strip(".,;:()")) >= 2}
            found = [pymupdf.Rect(w[:4]) for w in words if w[4].strip(".,;:()").lower() in tokens]
        rects.extend(found)
    return rects


_MASK_CHAR = "X"


def x_mask(text: str) -> str:
    """Format-preserving mask like a masked Aadhaar card: every letter/digit becomes X,
    spaces and punctuation are kept (e.g. '2345 6789 0124' -> 'XXXX XXXX XXXX').
    No original character is ever revealed."""
    masked = re.sub(r"[A-Za-z0-9]", _MASK_CHAR, " ".join(text.split()))
    return masked or _MASK_CHAR * 4


def _merge_rects(rects: list[pymupdf.Rect]) -> list[pymupdf.Rect]:
    """Union overlapping / touching boxes on the same line so each area gets ONE mask."""
    merged: list[pymupdf.Rect] = []
    for r in sorted((pymupdf.Rect(x) for x in rects if not pymupdf.Rect(x).is_empty), key=lambda x: (round(x.y0), x.x0)):
        for m in merged:
            same_line = min(m.y1, r.y1) - max(m.y0, r.y0) > 0.5 * min(m.height, r.height)
            if same_line and r.x0 <= m.x1 + 1 and r.x1 >= m.x0 - 1:
                m |= r
                break
        else:
            merged.append(r)
    return merged


def _free_right_edge(page: pymupdf.Page, rect: pymupdf.Rect, words: list[tuple]) -> float:
    """Right-most x the mask may extend to without touching any other word on the same line."""
    limit = page.rect.x1 - 20
    for w in words:
        x0, y0, x1, y1 = w[:4]
        if y1 > rect.y0 + 1 and y0 < rect.y1 - 1 and x0 >= rect.x1 - 0.5:
            limit = min(limit, x0 - 6)  # keep a visible word gap before the next word
    return max(rect.x1, limit)


def _invisible_rects(page: pymupdf.Page) -> list[pymupdf.Rect]:
    """Rects of text drawn in render mode 3 (invisible, e.g. OCR layers)."""
    try:
        return [pymupdf.Rect(t["bbox"]) for t in page.get_texttrace() if t.get("type") == 3]
    except Exception:  # noqa: BLE001
        return []


def _span_size(page: pymupdf.Page, rect: pymupdf.Rect) -> float | None:
    """Font size of the original text under `rect` (so the X-mask keeps the same size)."""
    best = None
    for b in page.get_text("dict", clip=rect).get("blocks", []):
        for line in b.get("lines", []):
            for span in line.get("spans", []):
                if span.get("text", "").strip():
                    best = max(best or 0, span.get("size", 0))
    return best


def _add_x_redaction(page: pymupdf.Page, rect: pymupdf.Rect, words: list[tuple],
                     invisible: list[pymupdf.Rect] | None = None) -> tuple | None:
    """Redaction annotation (no replacement text) that removes the original glyphs.
    Returns (point, X-mask, fontsize) to draw AFTER apply_redactions(): letting PyMuPDF insert the
    text inside the tight search box shrinks it to ~5pt, so the mask is drawn at the original size."""
    if invisible and any(abs(rect & r) >= 0.5 * abs(rect) for r in invisible):
        page.add_redact_annot(rect, fill=False)  # hidden text: delete it, draw nothing
        return None
    original = page.get_textbox(rect) or ""
    label = x_mask(original)
    fontsize = max(5.0, min(12.0, _span_size(page, rect) or rect.height * 1.05))

    def width(s: str, fs: float) -> float:
        return pymupdf.get_text_length(s, fontname="helv", fontsize=fs)

    # Extend only into EMPTY space on the right (never over other words) so the mask keeps
    # a readable size; then shrink the font / shorten the X-run if it still does not fit.
    needed = width(label, fontsize) + 2
    if needed > rect.width:
        rect = pymupdf.Rect(rect.x0, rect.y0, min(rect.x0 + needed, _free_right_edge(page, rect, words)), rect.y1)
    while fontsize > 5.0 and width(label, fontsize) > rect.width - 1:
        fontsize -= 0.25
    while len(label) > 1 and width(label, fontsize) > rect.width - 1:
        label = label[:-1]
    page.add_redact_annot(rect, fill=False)  # no fill: the glyphs are deleted by apply_redactions()
    # baseline: the search box spans ascender..descender; Helvetica's descender is ~21% of the size
    baseline = rect.y1 - 0.21 * (rect.height if rect.height < fontsize * 1.4 else fontsize)
    return pymupdf.Point(rect.x0, baseline), label, fontsize


def _notice_page(out: pymupdf.Document, width: float, height: float, message: str) -> None:
    page = out.new_page(width=width, height=height)
    page.insert_textbox(pymupdf.Rect(40, 40, width - 40, height - 40), message, fontsize=11, fontname="helv")


def _masked_text_pages(out: pymupdf.Document, width: float, height: float, header: str, text: str) -> None:
    """Rebuild a page from MASKED text only (no original pixels), paginating if needed."""
    fontsize, leading, margin = 10, 14, 40
    max_chars = max(20, int((width - 2 * margin) / (fontsize * 0.5)))
    lines: list[str] = []
    for raw in [header, ""] + text.splitlines():
        while len(raw) > max_chars:
            lines.append(raw[:max_chars])
            raw = raw[max_chars:]
        lines.append(raw)
    per_page = max(1, int((height - 2 * margin) / leading))
    for i in range(0, len(lines), per_page):
        page = out.new_page(width=width, height=height)
        y = margin + fontsize
        for line in lines[i: i + per_page]:
            page.insert_text((margin, y), line, fontsize=fontsize, fontname="helv")
            y += leading


def _significant_rects(page: pymupdf.Page) -> list[pymupdf.Rect]:
    """Same selection as extraction_service.significant_images (images large enough to hold text)."""
    from .extraction_service import significant_images

    return [pymupdf.Rect(b) for b in significant_images(page)]


def build_masked_pdf(
    src_path: str,
    page_kinds: dict[int, str],
    text_entities: dict[int, list[Entity]],
    page_words: dict[int, list[tuple]],
    scanned_masked_text: dict[int, str],
    *,
    image_outputs: dict[int, list[tuple]] | None = None,
    images_consent: bool = False,
) -> PdfBuildResult:
    """Create a sanitized PDF.

    * text pages: redaction annotations + apply_redactions (removes underlying text);
      every embedded image is removed; a pixel-redacted, verified copy is put back when one
      exists (image consent), otherwise a labelled placeholder;
    * scanned pages with a verified pixel-redacted image: page = that image only;
    * scanned pages transcribed with consent: the original image is DROPPED and the page is
      rebuilt from the locally masked transcription only;
    * scanned pages without consent: replaced by a notice page.
    Metadata, XML metadata, annotations, form fields, links, JavaScript, attachments
    and thumbnails are removed.
    """
    warnings: list[str] = []
    with open(src_path, "rb") as fh:
        src = pymupdf.open(stream=fh.read(), filetype="pdf")
    out = pymupdf.open()
    try:
        for pno in range(src.page_count):
            n = pno + 1
            page = src[pno]
            kind = page_kinds.get(n, "blank")
            # Remove annotations and form widgets (may hold personal data).
            for w in list(page.widgets() or []):
                page.delete_widget(w)
            for a in list(page.annots() or []):
                page.delete_annot(a)

            if kind == "text":
                rects = []
                for e in text_entities.get(n, []):
                    found = _search_rects(page, e.text, page_words.get(n, []))
                    if e.category == "PERSON" and e.method == "propagated" and " " not in e.text.strip():
                        # PDF search is case-insensitive: keep only exact-case hits for single name words
                        # (surname 'Sample' must not redact the common word 'SAMPLE'/'sample').
                        found = [r for r in found if e.text.strip() in (page.get_textbox(r) or "")]
                    rects.extend(found)
                hidden = _invisible_rects(page)
                x_marks = [m for r in _merge_rects(rects)
                           if (m := _add_x_redaction(page, r, page_words.get(n, []), hidden))]
                images = page.get_image_info()
                big = _significant_rects(page)
                for im in images:
                    page.add_redact_annot(pymupdf.Rect(im["bbox"]), fill=False)
                page.apply_redactions(
                    images=pymupdf.PDF_REDACT_IMAGE_REMOVE,
                    graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                    text=pymupdf.PDF_REDACT_TEXT_REMOVE,
                )
                for point, label, size in x_marks:  # X-masks at the original text size
                    page.insert_text(point, label, fontname="helv", fontsize=size, color=(0.1, 0.1, 0.1))
                done = {tuple(round(v) for v in clip): png for clip, png in (image_outputs or {}).get(n, []) if clip}
                removed = 0
                for r in big:
                    key = tuple(round(v) for v in r)
                    if key in done and done[key]:
                        page.insert_image(r, stream=done[key])  # verified pixel-redacted copy
                        continue
                    removed += 1
                    msg = ("Image removed: it could not be masked reliably." if key in done else
                           "Image removed: not inspected. Turn on image processing in Privacy settings "
                           "to include a masked copy." if not images_consent else
                           "Image removed: it could not be read by the vision provider.")
                    from .image_service import placeholder_png
                    page.insert_image(r, stream=placeholder_png(int(r.width * 2), int(r.height * 2), msg))
                if removed or (images and not big):
                    warnings.append(f"Page {n}: embedded images were removed because they could not be inspected "
                                    "or masked safely.")
                out.insert_pdf(src, from_page=pno, to_page=pno, links=False, annots=False, widgets=False)
            elif kind == "scanned" and any(png for clip, png in (image_outputs or {}).get(n, []) if clip is None):
                png = next(png for clip, png in image_outputs[n] if clip is None and png)
                newp = out.new_page(width=page.rect.width, height=page.rect.height)
                newp.insert_image(newp.rect, stream=png)  # only the verified, pixel-redacted image
            elif kind == "scanned" and n in scanned_masked_text:
                _masked_text_pages(
                    out, page.rect.width, page.rect.height,
                    f"[Page {n}: scanned image removed - masked AI transcription below; may contain transcription errors]",
                    scanned_masked_text[n],
                )
                warnings.append(f"Page {n}: scanned image replaced by its masked transcription (original layout not preserved).")
            elif kind == "scanned":
                _notice_page(
                    out, page.rect.width, page.rect.height,
                    f"Page {n} was a scanned image and has been omitted.\n\n"
                    "Scanned pages are not processed without your explicit consent to send original page images "
                    "to the external vision provider, and no local vision model is available. "
                    "The original content has not been included in this masked document.",
                )
            else:
                out.insert_pdf(src, from_page=pno, to_page=pno, links=False, annots=False, widgets=False)

        out.scrub(
            attached_files=True, clean_pages=True, embedded_files=True, hidden_text=True, javascript=True,
            metadata=True, redactions=True, remove_links=True, reset_fields=True, reset_responses=True,
            thumbnails=True, xml_metadata=True,
        )
        out.set_metadata({})
        out.del_xml_metadata()
        data = out.tobytes(garbage=4, deflate=True, clean=True, no_new_id=True)
    finally:
        out.close()
        src.close()
    return PdfBuildResult(data=data, warnings=warnings)


# ------------------------------------------------------------------ validation
def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def find_residual_values(pdf_bytes: bytes, originals: list[tuple]) -> list[str]:
    """Re-open the generated PDF, extract all text + metadata and search for every
    original sensitive value. Returns the categories of values still recoverable.

    Items are (category, value) or (category, value, case_sensitive). Case-sensitive checks are
    used only for single name words (e.g. surname 'Sample' vs the common word 'sample'),
    mirroring how those tokens are masked. Full values and identifiers are case-insensitive."""
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        parts = [page.get_text("text") for page in doc]
        for page in doc:
            for w in page.widgets() or []:
                parts.append(str(w.field_value or ""))
            for a in page.annots() or []:
                parts.append(str(a.info.get("content", "")))
        parts.extend(str(v) for v in (doc.metadata or {}).values() if v)
        parts.append(doc.get_xml_metadata() or "")
    finally:
        doc.close()
    raw_text = "\n".join(parts)
    text = _norm_text(raw_text)
    words_text = f" {re.sub(r'[^a-z0-9@.]+', ' ', text)} "
    leaks: list[str] = []
    for item in originals:
        category, value = item[0], item[1]
        if len(item) > 2 and item[2]:
            if re.search(rf"(?<![A-Za-z0-9]){re.escape(value.strip())}(?![A-Za-z0-9])", raw_text):
                leaks.append(category)
            continue
        v = _norm_text(value)
        if len(v) < 3:
            continue
        d = digits_only(v)
        if len(d) < 6 and re.fullmatch(r"[\d\s\-+/().]+", v):
            # Short numbers (CVV '000', expiry '00/00') are redacted where they are labelled; a
            # document-wide search would flag unrelated numbers such as 'Flat 123' as leaks.
            continue
        if len(d) >= 6 and re.fullmatch(r"[\d\s\-+/().]+", v):
            # numeric value: match its digits as ONE token (any spacing/dashes/line breaks between
            # digits), never across unrelated neighbouring numbers
            rx = r"(?<!\d)" + r"[\s\-./]*".join(d) + r"(?!\d)"
            if re.search(rx, raw_text):
                leaks.append(category)
            continue
        token = re.sub(r"[^a-z0-9@.]+", " ", v).strip()
        if token and f" {token} " in words_text:
            leaks.append(category)
    return leaks
