"""Image uploads and pixel-level image redaction.

* Uploads: PNG / JPEG / WebP are identified by their CONTENT (magic bytes), never by the file
  extension. Images are decoded with a pixel limit (decompression-bomb guard), auto-rotated,
  re-encoded WITHOUT metadata (EXIF/GPS is dropped) and wrapped into a one-page PDF in memory,
  which then goes through the normal pipeline as a scanned page.
* Redaction: sensitive regions are BURNED INTO THE PIXELS (filled and overwritten with X marks),
  never drawn as an overlay on top of the original, so nothing recoverable remains underneath.
  No OCR is used: region positions come from the consented vision transcription.
"""
from __future__ import annotations

import io

import pymupdf
from PIL import Image, ImageDraw, ImageFont, ImageOps

MAX_PIXELS = 40_000_000  # decode limit (Groq accepts up to 33 MP; larger inputs are downscaled)
MAX_SIDE = 2400  # longest side after normalisation (keeps vision payloads well under the 20 MB limit)
A4_LONG_SIDE_PT = 842.0

Image.MAX_IMAGE_PIXELS = MAX_PIXELS


class ImageValidationError(Exception):
    """Safe, user-facing validation error."""


def sniff(data: bytes) -> str | None:
    """Return 'png' | 'jpeg' | 'webp' from the file signature, or None."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def load_image(data: bytes) -> Image.Image:
    """Decode safely: verify, enforce pixel limits, apply EXIF orientation, convert to RGB."""
    if not sniff(data):
        raise ImageValidationError("Unsupported file. Upload a PDF, PNG, JPEG or WebP file.")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        im = Image.open(io.BytesIO(data))
        if im.width * im.height > MAX_PIXELS:
            raise ImageValidationError("The image resolution is too large.")
        im.load()
        im = ImageOps.exif_transpose(im)
    except ImageValidationError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ImageValidationError("The image resolution is too large.") from None
    except Exception:  # noqa: BLE001 - Pillow raises many types for corrupt input
        raise ImageValidationError("The image is corrupt or could not be read.") from None
    if im.mode in ("RGBA", "LA", "P"):
        bg = Image.new("RGB", im.size, "white")
        rgba = im.convert("RGBA")
        bg.paste(rgba, mask=rgba.split()[-1])
        im = bg
    else:
        im = im.convert("RGB")
    if min(im.size) < 32:
        raise ImageValidationError("The image is too small to contain a readable document.")
    if max(im.size) > MAX_SIDE:
        im.thumbnail((MAX_SIDE, MAX_SIDE), Image.Resampling.LANCZOS)
    return im


def to_png(im: Image.Image) -> bytes:
    out = io.BytesIO()
    im.save(out, "PNG", optimize=True)  # no EXIF / text chunks are written
    return out.getvalue()


def image_to_pdf_bytes(data: bytes) -> bytes:
    """One-page PDF containing the normalised image (metadata-free), sized to fit A4."""
    im = load_image(data)
    scale = A4_LONG_SIDE_PT / max(im.size)
    w, h = im.width * scale, im.height * scale
    doc = pymupdf.open()
    try:
        page = doc.new_page(width=w, height=h)
        page.insert_image(page.rect, stream=to_png(im))
        return doc.tobytes(garbage=4, deflate=True, no_new_id=True)
    finally:
        doc.close()


# ------------------------------------------------------------------ redaction
Box = tuple[float, float, float, float]


def snap_to_ink(gray: Image.Image | None, box: Box, lh: float) -> tuple[Box, bool]:
    """Grow a model box vertically to the band of dark text pixels it points at.

    Simple local image processing (row darkness profile), not OCR: within the box's columns we
    look slightly above and well below the model box (its boxes sit too high and are too short
    for large print) and take every ink band that touches the expected area."""
    if gray is None:
        return box, True  # cannot check: keep the model box
    x1, y1, x2, y2 = box
    W, H = gray.size
    top, bottom = max(0, int(y1 - lh)), min(H, int(y2 + 2.5 * lh) + 1)
    left, right = max(0, int(x1)), min(W, int(x2) + 1)
    if right - left < 3 or bottom - top < 3:
        return box, True  # cannot check: keep the model box
    crop = gray.crop((left, top, right, bottom))
    cw, ch = crop.size
    px = crop.load()
    # a row is "ink" when enough pixels are clearly darker than the local background
    lum = sorted(px[x, y] for y in range(0, ch, max(1, ch // 40)) for x in range(0, cw, max(1, cw // 60)))
    background = lum[int(len(lum) * 0.7)] if lum else 255
    thresh = min(140, background - 60)
    ink_rows = []
    for y in range(ch):
        dark = sum(1 for x in range(0, cw, 2) if px[x, y] < thresh)
        ink_rows.append(dark / max(1, cw // 2) > 0.03)
    # bands of ink rows (allowing 2px gaps) that overlap the expected area [y1, y2 + lh]
    exp_a, exp_b = y1 - top, y2 + lh - top
    ny1, ny2 = y1, y2
    found = False
    y = 0
    while y < ch:
        if not ink_rows[y]:
            y += 1
            continue
        a = y
        gap = 0
        while y < ch and gap <= 2:
            gap = 0 if ink_rows[y] else gap + 1
            y += 1
        b = y - gap
        if b > exp_a and a < exp_b and (b - a) <= 4 * max(lh, 8):
            ny1, ny2 = min(ny1, a + top), max(ny2, b + top)
            found = True
    return (x1, ny1, x2, ny2), found


def plan_boxes(
    lines: list[str], boxes: list[Box | None], spans: dict[int, list[tuple[int, int]]],
    size: tuple[int, int], pad: float = 1.0, gray: Image.Image | None = None,
) -> list[Box] | None:
    """Pixel regions covering each sensitive span. Returns None if a sensitive line has no box
    (then the image cannot be redacted reliably)."""
    W, H = size
    out: list[Box] = []
    for i, sp in spans.items():
        if not sp:
            continue
        b = boxes[i] if i < len(boxes) else None
        if b is None:
            return None
        x1, y1, x2, y2 = b
        n = max(len(lines[i]), 1)
        cw = (x2 - x1) / n  # approximate character width
        lh = y2 - y1
        (_, sy1, _, sy2), has_ink = snap_to_ink(gray, b, lh)
        if not has_ink:
            return None  # box over empty background: the model mislocated this line
        snapped = sy2 > y2 + 1 or sy1 < y1 - 1
        for a, z in sp:
            if (z - a) / n >= 0.6:  # most of the line is sensitive -> whole line
                rx1, rx2 = x1, x2
            else:
                rx1, rx2 = x1 + cw * a, x1 + cw * z
            px = cw * 1.5 * pad + 4
            # Measured on real ID images: model boxes sit too HIGH (about half a line near the top,
            # growing ~8% of y towards the bottom). Half-covered digits are still readable by a
            # person even when an AI re-check cannot read them, so pad mostly DOWNWARDS.
            if snapped:  # box grown to the real ink band: a small margin is enough
                th = sy2 - sy1
                ry1, ry2 = sy1 - (th * 0.15 * pad + 2), sy2 + (th * 0.2 * pad + 3)
            else:
                ry1 = y1 - (lh * 0.4 * pad + 2)
                ry2 = y2 + lh * 1.1 * pad + 0.08 * y2 * pad + 2
            out.append((max(0, rx1 - px), max(0, ry1), min(W, rx2 + px), min(H, ry2)))
    return out


def merge_regions(regions: list[Box]) -> list[Box]:
    """Union overlapping regions so adjacent masked lines become one clean box."""
    out = [tuple(r) for r in regions]
    changed = True
    while changed:
        changed = False
        for i in range(len(out)):
            for j in range(i + 1, len(out)):
                a, b = out[i], out[j]
                if a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]:
                    out[i] = (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))
                    del out[j]
                    changed = True
                    break
            if changed:
                break
    return out


def burn_in(png: bytes, regions: list[Box]) -> bytes:
    """Fill each region and overwrite it with X marks (pixels are replaced, not covered)."""
    with Image.open(io.BytesIO(png)) as src:
        im = src.convert("RGB")
    draw = ImageDraw.Draw(im)
    for x1, y1, x2, y2 in merge_regions(regions):
        draw.rectangle((x1, y1, x2, y2), fill=(236, 238, 242), outline=(170, 176, 190))
        h = y2 - y1
        size = max(8, int(min(h * 0.55, 48)))
        try:
            font = ImageFont.load_default(size=size)
        except TypeError:  # very old Pillow without scalable default font
            font = ImageFont.load_default()
        char_w = max(1.0, draw.textlength("X", font=font))
        count = max(1, int((x2 - x1 - 8) / (char_w * 1.15)))
        text = "X" * count
        tw = draw.textlength(text, font=font)
        draw.text((x1 + (x2 - x1 - tw) / 2, y1 + (h - size) / 2), text, fill=(55, 65, 81), font=font)
    return to_png(im)


def placeholder_png(width: int, height: int, message: str) -> bytes:
    """Neutral panel used where an image had to be removed."""
    width, height = max(width, 120), max(height, 60)
    im = Image.new("RGB", (width, height), (241, 245, 249))
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, width - 1, height - 1), outline=(148, 163, 184), width=2)
    size = max(10, min(22, width // 40))
    try:
        font = ImageFont.load_default(size=size)
    except TypeError:
        font = ImageFont.load_default()
    words, lines, cur = message.split(), [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if d.textlength(trial, font=font) > width - 24 and cur:
            lines.append(cur)
            cur = w
        else:
            cur = trial
    if cur:
        lines.append(cur)
    y = (height - len(lines) * (size + 6)) / 2
    for ln in lines:
        d.text(((width - d.textlength(ln, font=font)) / 2, y), ln, fill=(71, 85, 105), font=font)
        y += size + 6
    return to_png(im)
