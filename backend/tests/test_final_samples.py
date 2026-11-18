"""Regression tests for bugs found with the final synthetic sample set (2026-11-12):
two-column table forms, '-like' labels, short values propagating, identity/tax numbers,
international phones, scanned ID cards on a page, Groq daily quota and compact extraction."""
import httpx
import pymupdf
import pytest

from app.config import get_settings
from app.services import extraction_service, groq_service, pdf_service, pii_service
from app.security.permissions import masked_categories

from .conftest import onboard, upload

ROWS = [
    ("Full legal name", "Alex Example"),
    ("Date of birth", "18 April 1994"),
    ("Email address", "alex.example@example.test"),
    ("Mobile phone", "+00 0000 000 000"),
    ("Sample identity reference", "TEST-ID-0000-1234 (invalid placeholder)"),
    ("Tax reference pattern", "TESTX0000T (synthetic pattern; invalid value)"),
    ("Postal code", "ZZ 000000"),
    ("Card expiry", "00/00"),
    ("CVV", "000 (dummy placeholder; invalid)"),
    ("Aadhaar-like number", "0000 0000 0000 (invalid dummy value)"),
    ("PAN-like number", "TESTX0000T (invalid dummy value)"),
    ("Passport-like reference", "TST000000 (invalid dummy value)"),
    ("Tax reference", "TEST-TAX-000-XYZ"),
    ("Reference 1", "Casey Sample | casey.sample@example.test | +00 0000 000 003"),
    ("Qualification", "Bachelor of Example Studies"),
]


@pytest.fixture(autouse=True)
def default_scope(monkeypatch):
    """These samples are checked under the production default scope (IDs + phone + email)."""
    monkeypatch.setattr(get_settings(), "mask_categories", "PHONE,EMAIL")


def table_pdf(rows=ROWS) -> bytes:
    """Two-column form like the sample PDFs: label cell at x=60, value cell at x=230."""
    doc = pymupdf.open()
    page = doc.new_page()
    y = 60
    for label, value in rows:
        page.insert_text((60, y), label, fontsize=9)
        page.insert_text((230, y), value, fontsize=10)
        y += 26
    data = doc.tobytes()
    doc.close()
    return data


def _detect_table():
    d = pymupdf.open(stream=table_pdf(), filetype="pdf")
    text = pdf_service.extract_pages(d)[0].text
    d.close()
    return text, {(e.category, e.text) for e in pii_service.detect(text, masked_categories())}


def test_table_rows_are_rebuilt_as_label_tab_value():
    text, _ = _detect_table()
    assert "Mobile phone\t+00 0000 000 000" in text
    assert "Aadhaar-like number\t0000 0000 0000 (invalid dummy value)" in text


def test_like_labels_identity_and_tax_numbers_are_detected():
    _, found = _detect_table()
    for item in [("AADHAAR", "0000 0000 0000"), ("PAN", "TESTX0000T"), ("PASSPORT", "TST000000"),
                 ("OTHER_ID", "TEST-ID-0000-1234"), ("OTHER_ID", "TEST-TAX-000-XYZ"),
                 ("CVV", "000"), ("CREDIT_CARD", "00/00")]:
        assert item in found, item


def test_short_values_do_not_spread_into_other_numbers():
    text, found = _detect_table()
    # the CVV '000' / expiry '00/00' must not mask parts of the postal code or other numbers
    ents = pii_service.detect(text, masked_categories())
    postal = text.index("ZZ 000000")
    assert not any(e.start < postal + 9 and e.end > postal for e in ents), "postal code must stay intact"
    # international phone keeps its '+' (a digits-only propagated copy must not win)
    assert ("PHONE", "+00 0000 000 003") in found


def test_masked_table_pdf_is_clean_and_not_garbled(user_client):
    body = upload(user_client, table_pdf()).json()
    pdf = user_client.get(f"/api/documents/{body['id']}/download/pdf").content
    d = pymupdf.open(stream=pdf, filetype="pdf")
    text = d[0].get_text()
    d.close()
    assert "ZZ 000000" in text  # postal code untouched
    assert "TEST-ID-0000-1234" not in text and "TEST-TAX-000-XYZ" not in text and "TST000000" not in text
    assert "0000 0000 0000" not in text and "+00 0000 000 003" not in text
    assert body["masked_data"]["validation"]["residual_matches"] == 0
    details = {r["field"]: r for r in body["person_details"]}
    # local extraction reads the table rows as label/value pairs
    assert details["date_of_birth"]["value"] == "18 April 1994"
    assert details["aadhaar_like_number"]["masked"] or details.get("aadhaar_like_number", {}).get("value", "").startswith("X")


def test_generic_id_label_on_cards():
    found = {(e.category, e.text) for e in pii_service.detect(
        "FULL NAME\nALEX EXAMPLE\nSAMPLE ID\nTEST-0000-1234\nEmail ID: a.b@example.com\nApplication ID: APP-1",
        masked_categories())}
    assert ("OTHER_ID", "TEST-0000-1234") in found and ("EMAIL", "a.b@example.com") in found
    assert not any(t == "APP-1" for _, t in found)  # application references stay readable


# ------------------------------------------------------------------ scanned ID card on a page
def test_content_is_cropped_before_vision():
    from PIL import Image
    import io
    from app.services import vision_service

    im = Image.new("RGB", (1000, 1400), (247, 247, 242))
    card = Image.new("RGB", (600, 380), (40, 60, 80))
    im.paste(card, (200, 500))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    x1, y1, x2, y2 = vision_service.content_bbox(buf.getvalue())
    assert 150 <= x1 <= 200 and 450 <= y1 <= 500 and 800 <= x2 <= 850 and 880 <= y2 <= 930


def test_misplaced_box_over_empty_background_is_rejected():
    from PIL import Image
    from app.services import image_service

    gray = Image.new("L", (400, 300), 245)  # blank: no printed text anywhere
    assert image_service.plan_boxes(["ID 1234"], [(250, 220, 380, 240)], {0: [(0, 7)]}, (400, 300), gray=gray) is None


# ------------------------------------------------------------------ Groq
def test_daily_quota_fails_fast(monkeypatch):
    monkeypatch.setattr(get_settings(), "groq_api_key", "test-key")
    calls = []
    body = '{"error":{"message":"Rate limit reached ... on tokens per day (TPD): Limit 200000, Used 199022"}}'
    monkeypatch.setattr(groq_service, "_post", lambda u, h, p, t: calls.append(1) or httpx.Response(429, text=body))
    with pytest.raises(groq_service.GroqError, match="daily usage limit"):
        groq_service.chat_json([{"role": "user", "content": "hi"}])
    assert len(calls) == 1  # no minutes-long retry loop


def test_extraction_accepts_compact_answers_and_splits_long_pages(monkeypatch):
    monkeypatch.setattr(get_settings(), "groq_api_key", "test-key")
    answers = [
        httpx.Response(200, json={"choices": [{"message": {"content": "{}"}, "finish_reason": "length"}]}),
        httpx.Response(200, json={"choices": [{"message": {"content":
            '{"t": "kyc_form", "f": [["full_name", "Alex Example", "PERSON", 1]]}'}, "finish_reason": "stop"}]}),
        httpx.Response(200, json={"choices": [{"message": {"content":
            '{"t": "kyc_form", "f": [["pan_number", "[PAN_001]", "PAN", 1]]}'}, "finish_reason": "stop"}]}),
    ]
    sent = []
    monkeypatch.setattr(groq_service, "_post", lambda u, h, p, t: sent.append(p) or answers.pop(0))
    page = "\n".join(f"Line {i}\tvalue {i}" for i in range(20))
    result = extraction_service.groq_extract([page], [])
    assert [f.field for f in result.fields] == ["full_name", "pan_number"]
    assert result.document_type == "kyc_form"
    assert all(p["max_tokens"] <= 1000 for p in sent) and len(sent) == 3  # 1 truncated + 2 halves


def test_image_failure_message_is_accurate_when_consent_given(user_client, monkeypatch, groq_mock):
    from .conftest import make_image_pdf
    onboard(user_client, ai_text=True, ai_images=True)
    groq_mock.fail_with = 503
    monkeypatch.setattr(get_settings(), "groq_max_retries", 0)
    r = upload(user_client, make_image_pdf())
    assert r.status_code == 400
    assert "could not be read" in r.json()["detail"] and "enable" not in r.json()["detail"]


def test_chat_uses_its_own_model_and_extraction_keeps_the_main_model(user_client, groq_mock, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "groq_chat_model", "openai/gpt-oss-120b")
    monkeypatch.setattr(s, "groq_chat_reasoning_effort", "low")
    onboard(user_client, ai_text=True)
    from .conftest import make_text_pdf
    doc = upload(user_client, make_text_pdf()).json()["id"]
    user_client.post(f"/api/documents/{doc}/chat", json={"message": "What qualification is mentioned?"})
    extraction = [p for p in groq_mock.requests if "extract structured fields" in str(p["messages"][0]["content"])]
    chat = [p for p in groq_mock.requests if p not in extraction]
    assert extraction and all(p["model"] == s.groq_model for p in extraction)
    assert chat and chat[-1]["model"] == "openai/gpt-oss-120b" and chat[-1]["reasoning_effort"] == "low"


def test_chat_switches_to_fallback_model_instead_of_waiting(user_client, groq_mock, monkeypatch):
    import time as _t
    s = get_settings()
    monkeypatch.setattr(s, "groq_chat_model", "openai/gpt-oss-120b")
    monkeypatch.setattr(s, "groq_chat_fallback_model", "openai/gpt-oss-20b")
    onboard(user_client, ai_text=True)
    from .conftest import make_text_pdf
    doc = upload(user_client, make_text_pdf()).json()["id"]
    # the primary chat model's per-minute window is used up
    groq_service._rl_state["openai/gpt-oss-120b"] = {"remaining": 10, "reset_at": _t.monotonic() + 50}
    try:
        t0 = _t.monotonic()
        user_client.post(f"/api/documents/{doc}/chat", json={"message": "What qualification is mentioned?"})
        assert _t.monotonic() - t0 < 10  # no 50-second wait
        assert groq_mock.requests[-1]["model"] == "openai/gpt-oss-20b"
        # once the window is free again, the primary model is used
        groq_service._rl_state["openai/gpt-oss-120b"] = {"remaining": None, "reset_at": 0.0}
        user_client.post(f"/api/documents/{doc}/chat", json={"message": "Which university?"})
        assert groq_mock.requests[-1]["model"] == "openai/gpt-oss-120b"
    finally:
        groq_service._rl_state.clear()
