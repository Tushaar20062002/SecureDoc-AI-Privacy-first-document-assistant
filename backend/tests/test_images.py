"""Images: content-sniffed uploads, pixel-level redaction with re-check, embedded images in PDFs,
MRZ detection, Groq output limits, batch ZIP download and 'is X present?' chat answers.
All data is synthetic; the vision model is mocked (boxes are given on the 0-1000 grid)."""
import io
import zipfile

import httpx
import pymupdf
import pytest
from PIL import Image

from app.config import get_settings
from app.security.permissions import RESTRICTED_REFUSAL
from app.services import extraction_service, groq_service, image_service, pii_service

from .conftest import FORM_LINES, SYNTH, make_image_pdf, make_text_pdf, onboard, upload

FILL = (236, 238, 242)
X_INK = (55, 65, 81)


def _pdf(client, doc_id) -> bytes:
    r = client.get(f"/api/documents/{doc_id}/download/pdf")
    assert r.status_code == 200, r.text
    return r.content


def _post_file(client, data: bytes, name: str, ctype: str):
    return client.post("/api/documents/upload", files={"file": (name, data, ctype)},
                       data={"output_mode": "pdf_and_json"})


def _png(w=400, h=200, lines=("IDENTITY CARD",)) -> bytes:
    tmp = pymupdf.open()
    p = tmp.new_page(width=w, height=h)
    for i, ln in enumerate(lines):
        p.insert_text((20, 40 + 30 * i), ln, fontsize=14)
    png = p.get_pixmap(dpi=100).tobytes("png")
    tmp.close()
    return png


# ------------------------------------------------------------------ MRZ (ICAO 9303)
MRZ1 = "P<NELSON<<CALLIE<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
MRZ2 = "4220167749USA8810171F2712239572615374<585990"


def test_mrz_lines_detected_and_passport_number_propagated():
    assert pii_service.icao_check_digit("422016774") == 9
    assert pii_service.mrz_document_number(MRZ2) == "422016774"
    text = f"Passport No. / No du Passeport\n422016774\n{MRZ1}\n{MRZ2}"
    found = {(e.category, e.text) for e in pii_service.detect(text)}
    assert ("PASSPORT", MRZ1) in found and ("PASSPORT", MRZ2) in found
    assert ("PASSPORT", "422016774") in found
    # the MRZ is not mis-read as a card number (Luhn-valid digits inside it)
    assert not any(c == "CREDIT_CARD" for c, _ in found)


@pytest.mark.parametrize("mrz2", [
    "4220167749 USA8810171F2712239572615374<585990",
    "4220167749 USA 8810171 F 2712239 572615374 < 585990",
])
def test_mrz_line_with_spaces_from_vision_is_one_passport_entity(mrz2):
    """Vision transcriptions may insert spaces inside an MRZ line; it must still be masked as ONE
    passport value, not split into 'OTHER_ID' / 'CREDIT_CARD' pieces leaving the rest readable."""
    text = f"Passport No.\n422016774\n{MRZ1}\n{mrz2}"
    found = {(e.category, e.text) for e in pii_service.detect(text)}
    assert ("PASSPORT", mrz2) in found
    assert not any(c in ("CREDIT_CARD", "OTHER_ID") for c, _ in found)
    assert pii_service.detect("UNITED STATES DEPARTMENT OF STATE OF AMERICA") == []


def test_mrz_and_id_fragments_from_a_split_transcription_are_masked():
    """When a transcription cuts lines (image read in parts), the MRZ pieces and a partial copy of
    the passport number must still be masked - not left readable or labelled a credit card."""
    text = "\n".join([MRZ1, "4220167749USA8810171F2712", "Passport No.", "422016774",
                      "Passport No.", "22016774", "SEE PAGE 27", "2712239572615374<585990"])
    found = {(e.category, e.text) for e in pii_service.detect_document([text])}
    assert ("PASSPORT", "4220167749USA8810171F2712") in found
    assert ("PASSPORT", "2712239572615374<585990") in found
    assert any(t == "22016774" for _, t in found)
    assert not any(c == "CREDIT_CARD" for c, _ in found)
    # without an MRZ on the page, ordinary uppercase/number lines are not treated as MRZ pieces
    assert pii_service.detect_document(["INVOICE2024REF123456"]) == []


def test_passport_heading_words_are_not_values():
    found = pii_service.detect("PASSPORT\nPASSEPORT\nPASAPORTE\nUNITED STATES OF AMERICA")
    assert not [e for e in found if e.category == "PASSPORT"]


# ------------------------------------------------------------------ scanned page: pixel redaction
def _norm_box(i, line, side_pt=842.0):
    """Box of FORM_LINES[i] as drawn by conftest._render_lines_png, on the 0-1000 square grid."""
    y = 60 + 22 * i
    x2 = 50 + pymupdf.get_text_length(line, fontsize=12)
    return [round(v / side_pt * 1000) for v in (50, y - 10, x2, y + 3)]


def _transcription():
    """Boxes as the model returns them: relative to the region actually sent, which is the page
    cropped to its content (vision_service.content_bbox)."""
    from app.services import vision_service

    d = pymupdf.open(stream=make_image_pdf(), filetype="pdf")
    png = vision_service.render_page_png(d[0])
    d.close()
    crop = vision_service.content_bbox(png)
    assert crop, "the form occupies only the top of the page, so it is cropped"
    cx, cy, cx2, cy2 = crop
    side = max(cx2 - cx, cy2 - cy)
    k = vision_service.VISION_DPI / 72.0
    rows = []
    for i, ln in enumerate(FORM_LINES):
        y = 60 + 22 * i
        x2 = 50 + pymupdf.get_text_length(ln, fontsize=12)
        px = [50 * k - cx, (y - 10) * k - cy, x2 * k - cx, (y + 3) * k - cy]
        rows.append([ln, *[round(v / side * 1000) for v in px]])
    return {"l": rows}


def _page_image(pdf: bytes) -> Image.Image:
    d = pymupdf.open(stream=pdf, filetype="pdf")
    imgs = d[0].get_images()
    assert len(imgs) == 1
    im = Image.open(io.BytesIO(d.extract_image(imgs[0][0])["image"])).convert("RGB")
    d.close()
    return im


def _row_fraction(im, line_index, char_from, char_to, colors):
    """Share of pixels along the middle of a text span that have one of `colors`."""
    line = FORM_LINES[line_index]
    sx = im.width / 595.0
    x1 = (50 + pymupdf.get_text_length(line[:char_from], fontsize=12)) * sx
    x2 = (50 + pymupdf.get_text_length(line[:char_to], fontsize=12)) * sx
    y = (60 + 22 * line_index - 4) * sx
    px = [im.getpixel((int(x), int(y))) for x in range(int(x1), int(x2))]
    return sum(1 for p in px if any(sum(abs(a - b) for a, b in zip(p, c)) < 30 for c in colors)) / len(px)


def _span_is_redacted(im, line_index, char_from, char_to) -> bool:
    """No original pixels survive: neither the white page nor black glyphs (X marks are anti-aliased,
    so in-between greys are expected), and the fill colour dominates."""
    line = FORM_LINES[line_index]
    sx = im.width / 595.0
    x1 = (50 + pymupdf.get_text_length(line[:char_from], fontsize=12)) * sx
    x2 = (50 + pymupdf.get_text_length(line[:char_to], fontsize=12)) * sx
    for dy in (-7, -4, -1):  # several rows across the glyph height
        y = (60 + 22 * line_index + dy) * sx
        px = [im.getpixel((int(x), int(y))) for x in range(int(x1), int(x2))]
        if any(min(p) > 250 or max(p) < 25 for p in px):
            return False
    return _row_fraction(im, line_index, char_from, char_to, [FILL, X_INK]) > 0.75


def test_scanned_page_is_masked_inside_the_image_and_rechecked(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=True)
    clean_recheck = {"l": [ln if i in (0, 12, 13, 14, 15, 16) else "[masked]" for i, ln in enumerate(FORM_LINES)]}
    groq_mock.vision_queue = [_transcription(), clean_recheck]
    body = upload(user_client, make_image_pdf()).json()
    md = body["masked_data"]
    assert md["validation"]["images"] == [{"page": 1, "kind": "page", "outcome": "masked"}]
    assert any("masked directly in the image" in n for n in md["notices"])
    vision_calls = [m for m in groq_mock.requests if isinstance(m["messages"][0]["content"], list)]
    assert len(vision_calls) == 2  # transcription + independent re-check of the redacted image

    im = _page_image(_pdf(user_client, body["id"]))
    aad = FORM_LINES.index(f"Aadhaar No: {SYNTH['aadhaar']}")
    pan = FORM_LINES.index(f"PAN: {SYNTH['pan']}")
    # sensitive values are replaced IN THE PIXELS by the fill / X marks
    assert _span_is_redacted(im, aad, 12, len(FORM_LINES[aad]))
    assert _span_is_redacted(im, pan, 5, len(FORM_LINES[pan]))
    # non-sensitive text is left as it was (dark ink still present)
    last = len(FORM_LINES) - 1
    assert _row_fraction(im, last, 0, len(FORM_LINES[last]), [FILL]) < 0.2


def test_redaction_that_fails_the_recheck_is_never_used(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=True)
    leak = {"l": [f"Aadhaar No: {SYNTH['aadhaar']}"]}  # the re-check can still read the number
    groq_mock.vision_queue = [_transcription(), leak, leak]
    body = upload(user_client, make_image_pdf()).json()
    md = body["masked_data"]
    assert md["validation"]["images"][0]["outcome"] == "unreliable"
    assert body["processing_status"] == "needs_review"
    pdf = _pdf(user_client, body["id"])
    d = pymupdf.open(stream=pdf, filetype="pdf")
    assert not d[0].get_images()  # fallback: page rebuilt from MASKED text only, no pixels kept
    text = d[0].get_text()
    d.close()
    assert SYNTH["aadhaar"] not in text and "[AADHAAR_001]" in text


# ------------------------------------------------------------------ embedded image on a text page
def _text_pdf_with_card(lines_on_card):
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 80), "Qualification: Bachelor of Commerce", fontsize=12)
    page.insert_image(pymupdf.Rect(50, 300, 450, 500), stream=_png(lines=lines_on_card))
    data = doc.tobytes()
    doc.close()
    return data


CARD = ("IDENTITY CARD", f"Aadhaar No: {SYNTH['aadhaar']}", "Valid in India")


def _card_box(i, line):  # clip is 400x200 pt -> square side 400
    y = 40 + 30 * i
    x2 = 20 + pymupdf.get_text_length(line, fontsize=14)
    return [round(v / 400 * 1000) for v in (20, y - 12, x2, y + 4)]


def test_embedded_image_is_masked_and_put_back(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=True)
    groq_mock.vision_queue = [
        {"l": [[ln, *_card_box(i, ln)] for i, ln in enumerate(CARD)]},
        {"l": ["IDENTITY CARD", "Aadhaar No: [masked]", "Valid in India"]},
    ]
    body = upload(user_client, _text_pdf_with_card(CARD)).json()
    md = body["masked_data"]
    assert md["validation"]["images"] == [{"page": 1, "kind": "embedded_image", "outcome": "masked"}]
    assert "[AADHAAR_001]" in md["pages"][0]["masked_text"]  # image text joins detection & JSON
    d = pymupdf.open(stream=_pdf(user_client, body["id"]), filetype="pdf")
    assert len(d[0].get_images()) == 1 and "Bachelor of Commerce" in d[0].get_text()
    im = Image.open(io.BytesIO(d.extract_image(d[0].get_images()[0][0])["image"])).convert("RGB")
    d.close()
    s = im.width / 400.0
    line = CARD[1]
    x1 = (20 + pymupdf.get_text_length(line[:12], fontsize=14)) * s
    x2 = (20 + pymupdf.get_text_length(line, fontsize=14)) * s
    y = (40 + 30 - 5) * s
    px = [im.getpixel((int(x), int(y))) for x in range(int(x1), int(x2))]
    assert not any(min(p) > 250 or max(p) < 25 for p in px)  # no original page/ink pixels left


def test_embedded_image_without_image_consent_is_removed_and_not_sent(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=False)
    body = upload(user_client, _text_pdf_with_card(CARD)).json()
    assert not any(isinstance(m["messages"][0]["content"], list) for m in groq_mock.requests)
    assert any("embedded images were removed" in w for w in body["masked_data"]["warnings"])
    d = pymupdf.open(stream=_pdf(user_client, body["id"]), filetype="pdf")
    imgs = d[0].get_images()
    assert len(imgs) == 1  # the placeholder panel only
    im = Image.open(io.BytesIO(d.extract_image(imgs[0][0])["image"])).convert("RGB")
    d.close()
    assert im.getpixel((im.width // 2, 3)) == (241, 245, 249) or im.width == 800  # placeholder, not the card


def test_invisible_text_layer_is_removed_without_visible_marks(user_client):
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 80), "Qualification: Bachelor of Commerce", fontsize=12)
    page.insert_text((50, 120), "Passport No: K1234567", fontsize=12, render_mode=3)  # OCR-style hidden text
    data = doc.tobytes()
    doc.close()
    body = upload(user_client, data).json()
    d = pymupdf.open(stream=_pdf(user_client, body["id"]), filetype="pdf")
    text = d[0].get_text()
    d.close()
    assert "K1234567" not in text and "XXXX" not in text and "Bachelor of Commerce" in text


# ------------------------------------------------------------------ image uploads
def test_image_upload_requires_image_consent(user_client):
    r = _post_file(user_client, _png(), "id.png", "image/png")
    assert r.status_code == 400 and "external image processing" in r.json()["detail"]


def test_image_upload_is_identified_by_content_not_extension(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=True)
    webp = io.BytesIO()
    Image.open(io.BytesIO(_png(lines=CARD))).save(webp, "WEBP")  # WebP bytes with a .jpeg name
    groq_mock.vision_response = {"l": [["IDENTITY CARD", 50, 50, 400, 100]]}
    r = _post_file(user_client, webp.getvalue(), "card.jpeg", "image/jpeg")
    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["document_name"] == "card.jpeg" and doc["page_count"] == 1
    pdf = user_client.get(f"/api/documents/{doc['id']}/download/pdf")
    assert 'filename="card_masked.pdf"' in pdf.headers["content-disposition"]
    # a text file renamed to .png is rejected by its signature
    bad = _post_file(user_client, b"just some text, not an image", "fake.png", "image/png")
    assert bad.status_code == 400


def test_image_metadata_is_dropped_and_huge_images_rejected():
    im = Image.new("RGB", (300, 200), "white")
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"  # Make
    exif[0x8825] = {2: (18.0, 31.0, 0.0)}  # GPS latitude
    buf = io.BytesIO()
    im.save(buf, "JPEG", exif=exif.tobytes())
    assert b"SecretCameraMaker" in buf.getvalue()
    pdf = image_service.image_to_pdf_bytes(buf.getvalue())
    assert b"SecretCameraMaker" not in pdf and b"Exif" not in pdf
    big = io.BytesIO()
    Image.new("1", (7000, 7000)).save(big, "PNG")  # 49 MP > limit (decompression-bomb guard)
    with pytest.raises(image_service.ImageValidationError):
        image_service.image_to_pdf_bytes(big.getvalue())
    with pytest.raises(image_service.ImageValidationError):
        image_service.image_to_pdf_bytes(b"\x89PNG\r\n\x1a\n" + b"corrupt")


# ------------------------------------------------------------------ Groq output limits
def _resp(status=200, content='{"a": 1}', finish="stop", text=None):
    if text is not None:
        return httpx.Response(status, text=text)
    return httpx.Response(status, json={"choices": [{"message": {"content": content}, "finish_reason": finish}]})


def test_groq_requests_respect_the_output_cap_and_reject_truncation(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "groq_api_key", "test-key")
    sent = []
    monkeypatch.setattr(groq_service, "_post", lambda u, h, p, t: sent.append(p) or _resp(finish="length"))
    with pytest.raises(groq_service.GroqIncomplete):
        groq_service.chat_json([{"role": "user", "content": "hi"}], max_tokens=8000)
    assert sent[0]["max_tokens"] <= s.groq_max_output_tokens
    # "request too large" can never succeed: no retries
    calls = []
    too_large = '{"error":{"message":"Request too large for model on output tokens per minute (OTPM)"}}'
    monkeypatch.setattr(groq_service, "_post", lambda u, h, p, t: calls.append(1) or _resp(429, text=too_large))
    with pytest.raises(groq_service.GroqError):
        groq_service.chat_json([{"role": "user", "content": "hi"}])
    assert len(calls) == 1


def test_leak_check_flags_values_still_readable():
    assert extraction_service.leaked_values(["Aadhaar No: 2345 6789 0124"], ["2345 6789 0124"])
    assert not extraction_service.leaked_values(["Aadhaar No: [masked]"], ["2345 6789 0124"])


# ------------------------------------------------------------------ batch download
def test_zip_download_contains_only_own_masked_outputs(user_client, client):
    ids = [upload(user_client, make_text_pdf(), name=n).json()["id"] for n in ("a.pdf", "a.pdf")]
    r = user_client.get(f"/api/documents/download/zip?ids={','.join(ids)}")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert sorted(names) == ["a (2)_masked.json", "a (2)_masked.pdf", "a_masked.json", "a_masked.pdf"]
    for n in names:
        data = zipfile.ZipFile(io.BytesIO(r.content)).read(n).decode("latin-1")
        assert SYNTH["aadhaar"] not in data and SYNTH["pan"] not in data
    assert user_client.get("/api/documents/download/zip?ids=does-not-exist").status_code == 404


# ------------------------------------------------------------------ chat: presence of protected data
def test_chat_says_whether_protected_data_is_present_without_revealing_it(user_client):
    doc = upload(user_client, make_text_pdf()).json()["id"]

    def ask(q):
        r = user_client.post(f"/api/documents/{doc}/chat", json={"message": q})
        assert r.status_code == 200, r.text
        return r.json()["assistant_message"]

    a = ask("adhaar number is present in document?")
    assert a["content"].startswith("Yes") and "page 1" in a["content"] and SYNTH["aadhaar"] not in a["content"]
    assert a["kind"] == "restricted"
    assert ask("is there any passport number?")["content"] == "No passport number was detected in this document."
    assert ask("what is my aadhaar number")["content"] == RESTRICTED_REFUSAL
