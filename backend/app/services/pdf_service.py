"""PDF validation and page-level extraction with PyMuPDF (no OCR engines)."""
from __future__ import annotations

from dataclasses import dataclass, field

import pymupdf

from ..config import get_settings


class PDFValidationError(Exception):
    """Safe, user-facing validation error (no internal details)."""


@dataclass
class PageData:
    number: int  # 1-based
    kind: str  # text | scanned | blank
    text: str
    width: float
    height: float
    has_images: bool
    words: list[tuple] = field(default_factory=list)


def validate_signature(data: bytes) -> None:
    if not data:
        raise PDFValidationError("The uploaded file is empty.")
    if len(data) > get_settings().max_upload_bytes:
        raise PDFValidationError(f"File exceeds the {get_settings().max_upload_mb} MB limit.")
    head = data[:1024].lstrip()
    if not head.startswith(b"%PDF-"):
        raise PDFValidationError("Only PDF files are accepted (invalid file signature).")


def open_validated(path: str) -> pymupdf.Document:
    """Open and structurally validate a PDF. Raises PDFValidationError."""
    try:
        # Open from memory so no OS file handle lingers (allows reliable temp-file deletion).
        with open(path, "rb") as fh:
            data = fh.read()
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:  # noqa: BLE001 - library raises various types
        raise PDFValidationError("The PDF is malformed or could not be read.") from exc
    try:
        if not doc.is_pdf:
            raise PDFValidationError("Only PDF files are accepted.")
        if doc.needs_pass or doc.is_encrypted:
            raise PDFValidationError("Encrypted or password-protected PDFs are not supported.")
        if doc.page_count == 0:
            raise PDFValidationError("The PDF has no pages.")
        if doc.page_count > get_settings().max_pages:
            raise PDFValidationError(f"The PDF exceeds the {get_settings().max_pages}-page limit.")
        for page in doc:  # forces parsing of every page tree entry
            _ = page.rect
    except PDFValidationError:
        doc.close()
        raise
    except Exception as exc:  # noqa: BLE001
        doc.close()
        raise PDFValidationError("The PDF structure is invalid.") from exc
    return doc


def _widget_text(page: pymupdf.Page) -> str:
    lines = []
    for w in page.widgets() or []:
        val = w.field_value
        if val in (None, "", "Off", False):
            continue
        label = (w.field_label or w.field_name or "Field").strip()
        lines.append(f"{label}: {val}")
    return "\n".join(lines)


def layout_text(page: pymupdf.Page) -> str:
    """Page text with table rows rebuilt: text lines that sit on the same row are joined left to
    right, cells separated by a TAB. Forms with a label column and a value column then read as
    'Mobile phone<TAB>+00 0000 000 000' instead of two unrelated lines."""
    items = []
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            text = "".join(span.get("text", "") for span in line.get("spans", [])).strip()
            if text:
                x0, y0, x1, y1 = line["bbox"]
                items.append((x0, y0, x1, y1, text))
    rows: list[dict] = []
    for x0, y0, x1, y1, text in sorted(items, key=lambda it: ((it[1] + it[3]) / 2, it[0])):
        yc, h = (y0 + y1) / 2, max(1.0, y1 - y0)
        for row in rows:
            if abs(row["yc"] - yc) <= max(2.0, 0.45 * min(h, row["h"])):
                row["items"].append((x0, x1, text))
                break
        else:
            rows.append({"yc": yc, "h": h, "items": [(x0, x1, text)]})
    out = []
    for row in sorted(rows, key=lambda r: r["yc"]):
        cells = sorted(row["items"])
        line = cells[0][2]
        for prev, cur in zip(cells, cells[1:]):
            line += ("\t" if cur[0] - prev[1] > 12 else " ") + cur[2]
        out.append(line)
    return "\n".join(out)


def extract_pages(doc: pymupdf.Document) -> list[PageData]:
    pages: list[PageData] = []
    for i, page in enumerate(doc, start=1):
        text = layout_text(page) or ""
        widgets = _widget_text(page)
        if widgets:
            text = f"{text}\n{widgets}" if text.strip() else widgets
        images = page.get_image_info()
        page_area = abs(page.rect) or 1
        img_area = sum(abs(pymupdf.Rect(im["bbox"]) & page.rect) for im in images)
        stripped = text.strip()
        if len(stripped) >= 20:
            kind = "text"
        elif images and img_area / page_area > 0.05:
            kind = "scanned"
        elif stripped:
            kind = "text"
        else:
            kind = "blank"
        pages.append(
            PageData(
                number=i, kind=kind, text=text if kind == "text" else "",
                width=page.rect.width, height=page.rect.height,
                has_images=bool(images), words=page.get_text("words") if kind == "text" else [],
            )
        )
    return pages
