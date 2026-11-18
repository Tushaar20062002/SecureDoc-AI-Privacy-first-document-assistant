"""Document processing, masked PDF security, storage and isolation tests."""
from pathlib import Path

import pymupdf
from sqlalchemy import select, text

from app.config import get_settings
from app.database import SessionLocal
from app.models import ChatMessage, ChatSession, Document
from app.security import encryption
from app.services import extraction_service, masking_service

from .conftest import (
    SENSITIVE_VALUES,
    SYNTH,
    make_blank_pdf,
    make_encrypted_pdf,
    make_image_pdf,
    make_mixed_pdf,
    make_text_pdf,
    new_client,
    onboard,
    register,
    upload,
)


def _pdf_text(client, doc_id) -> tuple[str, dict, bytes]:
    r = client.get(f"/api/documents/{doc_id}/download/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    d = pymupdf.open(stream=r.content, filetype="pdf")
    text = "\n".join(p.get_text() for p in d)
    meta = d.metadata
    d.close()
    return text, meta, r.content


def _temp_files():
    return list(Path(get_settings().temp_dir).glob("*"))


# ------------------------------------------------------------------ processing
def test_text_pdf_extracts_and_masks(user_client):
    r = upload(user_client, make_text_pdf())
    assert r.status_code == 201, r.text
    body = r.json()
    md = body["masked_data"]
    cats = set(md["entity_summary"])
    for c in ("PERSON", "ADDRESS", "EMAIL", "PHONE", "DOB", "AADHAAR", "PAN", "BANK_ACCOUNT", "IFSC", "APP_REF"):
        assert c in cats, f"{c} not detected"
    dumped = str(md)
    for v in SENSITIVE_VALUES:
        assert v not in dumped, "original value leaked into masked JSON"
    assert "Bachelor of Commerce" in dumped  # non-sensitive content preserved
    assert "Infosys Limited" in dumped
    assert body["has_pdf"] and body["page_count"] == 1
    assert "[PERSON_001]" in md["pages"][0]["masked_text"]


def test_consistent_placeholders_across_pages(user_client):
    r = upload(user_client, make_text_pdf(pages=2))
    pages = r.json()["masked_data"]["pages"]
    assert pages[0]["masked_text"].count("[AADHAAR_001]") == 1
    assert "[AADHAAR_001]" in pages[1]["masked_text"]
    assert "[AADHAAR_002]" not in pages[1]["masked_text"]


def test_invalid_pdf_rejected(user_client):
    r = upload(user_client, b"This is not a PDF at all", name="fake.pdf")
    assert r.status_code == 400 and "PDF" in r.json()["detail"]
    r = upload(user_client, b"%PDF-1.7\n garbage garbage \n%%EOF", name="broken.pdf")
    assert r.status_code == 400
    assert not _temp_files()


def test_pdf_larger_than_10mb_rejected(user_client):
    big = b"%PDF-1.4\n" + b"0" * (10 * 1024 * 1024 + 10)
    r = upload(user_client, big)
    assert r.status_code == 413
    assert not _temp_files()


def test_empty_pdf_rejected(user_client):
    assert upload(user_client, b"").status_code == 400
    r = upload(user_client, make_blank_pdf())
    assert r.status_code == 400 and "no extractable" in r.json()["detail"].lower()


def test_encrypted_pdf_rejected(user_client):
    r = upload(user_client, make_encrypted_pdf())
    assert r.status_code == 400 and "encrypted" in r.json()["detail"].lower()


def test_page_limit(user_client):
    s = get_settings()
    old = s.max_pages
    s.max_pages = 2
    try:
        r = upload(user_client, make_text_pdf(pages=3))
        assert r.status_code == 400 and "page limit" in r.json()["detail"]
    finally:
        s.max_pages = old


def test_image_pdf_without_consent_is_unsupported_and_not_sent(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=False)
    r = upload(user_client, make_image_pdf())
    assert r.status_code == 400
    assert "Scanned" in r.json()["detail"] or "scanned" in r.json()["detail"]
    assert all(not isinstance(m["messages"][0]["content"], list) for m in groq_mock.requests)
    assert groq_mock.requests == []


def test_mixed_pdf_processes_text_pages_and_omits_scanned(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=False)
    r = upload(user_client, make_mixed_pdf())
    assert r.status_code == 201, r.text
    md = r.json()["masked_data"]
    kinds = [p["type"] for p in md["pages"]]
    assert kinds == ["text", "scanned"]
    assert md["pages"][1]["processed"] is False
    assert r.json()["processing_status"] == "needs_review"
    assert any("Page 2" in w for w in md["warnings"])
    # no image was sent to the external provider
    assert not any(isinstance(m["messages"][0]["content"], list) for m in groq_mock.requests)
    text, _, pdf = _pdf_text(user_client, r.json()["id"])
    assert "has been omitted" in text
    d = pymupdf.open(stream=pdf, filetype="pdf")
    assert d.page_count == 2 and not d[1].get_images()  # original scan not included
    d.close()


def test_image_pdf_with_explicit_consent_rebuilt_from_masked_text(user_client, groq_mock):
    onboard(user_client, ai_text=True, ai_images=True)
    groq_mock.vision_response = {
        "lines": [
            {"text": f"Full Name: {SYNTH['name']}"},
            {"text": f"Aadhaar No: {SYNTH['aadhaar']}"},
            {"text": f"PAN: {SYNTH['pan']}"},
            {"text": "Qualification: Bachelor of Commerce"},
            {"bogus": ["not", "a", "line"], "text": {"nested": 1}},
        ],
    }
    r = upload(user_client, make_image_pdf())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["processing_status"] == "needs_review"
    md = body["masked_data"]
    assert md["pages"][0]["method"] == "external_vision"
    assert {"AADHAAR", "PAN", "PERSON"} <= set(md["entity_summary"])
    assert any("invalid transcription items" in w for w in md["warnings"])
    assert md["validation"]["residual_matches"] == 0
    # the image went to the vision model ONLY because of explicit consent;
    # the text extraction call carried masked text only
    vision_calls = [m for m in groq_mock.requests if isinstance(m["messages"][0]["content"], list)]
    assert len(vision_calls) == 1
    text_calls = [m for m in groq_mock.requests if isinstance(m["messages"][0]["content"], str)]
    for call in text_calls:
        dumped = str(call)
        assert SYNTH["aadhaar"] not in dumped and SYNTH["name"] not in dumped and SYNTH["pan"] not in dumped
    text, _, pdf = _pdf_text(user_client, body["id"])
    d = pymupdf.open(stream=pdf, filetype="pdf")
    assert not d[0].get_images()  # original scanned pixels are NOT reused
    d.close()
    assert "[AADHAAR_001]" in text and "[PAN_001]" in text and "Bachelor of Commerce" in text
    for v in (SYNTH["name"], SYNTH["aadhaar"], SYNTH["pan"]):
        assert v not in text


def test_vision_not_used_without_vision_model(user_client, groq_mock):
    get_settings().groq_vision_model = ""
    try:
        onboard(user_client, ai_text=True, ai_images=True)
        r = upload(user_client, make_image_pdf())
        assert r.status_code == 400
        assert not any(isinstance(m["messages"][0]["content"], list) for m in groq_mock.requests)
    finally:
        get_settings().groq_vision_model = "test-vision-model"


# ------------------------------------------------------------------ PDF security
def test_masked_pdf_has_no_recoverable_originals_or_metadata(user_client):
    r = upload(user_client, make_text_pdf())
    body = r.json()
    assert body["masked_data"]["validation"]["performed"] is True
    assert body["masked_data"]["validation"]["residual_matches"] == 0
    text, meta, raw = _pdf_text(user_client, body["id"])
    for v in SENSITIVE_VALUES:
        assert v not in text
        assert v.encode() not in raw
    assert "6789" not in text and "ABCPM" not in text
    assert "Bachelor of Commerce" in text  # non-sensitive content remains
    # masked values are shown as format-preserving X-masks (like a masked Aadhaar card)
    assert "XXXX XXXX XXXX" in text and "XXXXXXXXXX" in text
    assert not any(meta.get(k) for k in ("author", "title", "subject", "keywords", "creator", "producer") if meta.get(k) and SYNTH["name"] in str(meta.get(k)))
    assert not meta.get("author") and not meta.get("subject")


def test_redaction_is_permanent_not_overlay(user_client):
    r = upload(user_client, make_text_pdf())
    _, _, raw = _pdf_text(user_client, r.json()["id"])
    d = pymupdf.open(stream=raw, filetype="pdf")
    page = d[0]
    assert not list(page.annots() or [])  # no redaction annotations left on top of text
    words = " ".join(w[4] for w in page.get_text("words"))
    assert "Mehta" not in words and "ABCPM1234Q" not in words
    d.close()


def test_validation_detects_residuals_and_marks_needs_review():
    pdf = make_text_pdf()
    leaks = masking_service.find_residual_values(pdf, [("AADHAAR", SYNTH["aadhaar"]), ("PAN", SYNTH["pan"])])
    assert set(leaks) == {"AADHAAR", "PAN"}


def test_uncertain_redaction_produces_needs_review(user_client, monkeypatch):
    # Simulate a redaction failure: the builder returns the original PDF unchanged.
    original_build = masking_service.build_masked_pdf

    def broken_build(src_path, *a, **k):
        res = original_build(src_path, *a, **k)
        res.data = Path(src_path).read_bytes()
        return res

    monkeypatch.setattr(masking_service, "build_masked_pdf", broken_build)
    r = upload(user_client, make_text_pdf())
    body = r.json()
    assert body["processing_status"] == "needs_review"
    assert body["has_pdf"] is False  # unsafe PDF is withheld
    assert any("withheld" in w for w in body["masked_data"]["warnings"])
    assert user_client.get(f"/api/documents/{body['id']}/download/pdf").status_code == 404


def test_json_only_mode_skips_pdf(user_client):
    r = upload(user_client, make_text_pdf(), mode="json_only")
    body = r.json()
    assert body["output_mode"] == "json_only" and body["has_pdf"] is False
    assert user_client.get(f"/api/documents/{body['id']}/download/pdf").status_code == 404
    j = user_client.get(f"/api/documents/{body['id']}/download/json")
    assert j.status_code == 200 and "attachment" in j.headers["content-disposition"]
    assert SYNTH["aadhaar"] not in j.text
    data = j.json()
    # person-only JSON: just the person's details, sensitive identifiers X-masked
    assert set(data) == {"document_name", "document_type", "person_details", "masked_fields"}
    assert data["person_details"]["aadhaar_no"] == "XXXX XXXX XXXX"
    assert data["person_details"]["qualification"] == "Bachelor of Commerce"
    assert "aadhaar_no" in data["masked_fields"] and "qualification" not in data["masked_fields"]
    assert "full_name" in data["person_details"] and "job_application_form" not in data["person_details"]
    assert not list(Path(get_settings().storage_dir).glob("*.pdf"))
    with SessionLocal() as db:
        d = db.get(Document, body["id"])
        assert d.masked_pdf is None and d.has_masked_pdf is False and d.masked_data


def test_invalid_output_mode_rejected(user_client):
    r = upload(user_client, make_text_pdf(), mode="everything")
    assert r.status_code == 422


# ------------------------------------------------------------------ database & storage
def test_only_permitted_owner_values_encrypted_and_restricted_not_stored(user_client):
    r = upload(user_client, make_text_pdf())
    doc_id = r.json()["id"]
    with SessionLocal() as db:
        d = db.get(Document, doc_id)
        assert d.encrypted_owner_fields.startswith("v1:")
        for v in SENSITIVE_VALUES:
            assert v not in d.encrypted_owner_fields
            assert v not in str(d.masked_data)
        owner = encryption.decrypt_json(d.encrypted_owner_fields, d.user_id, d.id)
    cats = {v["category"] for v in owner.values()}
    assert "PERSON" in cats and "ADDRESS" in cats and "APP_REF" in cats
    assert "EMAIL" not in cats and "PHONE" not in cats and "DOB" not in cats  # disabled by default
    assert not cats & {"AADHAAR", "PAN", "BANK_ACCOUNT", "IFSC", "PASSPORT", "CREDIT_CARD"}
    # raw DB file contains none of the restricted originals
    raw = Path(get_settings().database_url.replace("sqlite:///", "")).read_bytes()
    for v in (SYNTH["aadhaar"], SYNTH["pan"], SYNTH["account"], SYNTH["ifsc"], SYNTH["email"], SYNTH["name"]):
        assert v.encode() not in raw  # also covers the masked PDF blob stored in the DB


def test_ciphertext_bound_to_document():
    blob = encryption.encrypt_json({"x": 1}, "user-a", "doc-a")
    assert encryption.decrypt_json(blob, "user-a", "doc-a") == {"x": 1}
    try:
        encryption.decrypt_json(blob, "user-b", "doc-a")
        raise AssertionError("decryption should fail for another user")
    except encryption.DecryptionError:
        pass


def test_masked_json_persists(user_client):
    r = upload(user_client, make_text_pdf())
    doc_id = r.json()["id"]
    listing = user_client.get("/api/documents").json()
    assert listing[0]["id"] == doc_id and listing[0]["has_json"] and listing[0]["has_pdf"]
    detail = user_client.get(f"/api/documents/{doc_id}").json()
    assert detail["masked_data"]["entity_summary"] == r.json()["masked_data"]["entity_summary"]


def test_user_isolation(user_client):
    r = upload(user_client, make_text_pdf())
    doc_id = r.json()["id"]
    with new_client() as other:
        register(other, "mallory@example.com")
        onboard(other)
        assert other.get("/api/documents").json() == []
        assert other.get(f"/api/documents/{doc_id}").status_code == 404
        assert other.get(f"/api/documents/{doc_id}/download/pdf").status_code == 404
        assert other.get(f"/api/documents/{doc_id}/download/json").status_code == 404
        assert other.get(f"/api/documents/{doc_id}/chat/history").status_code == 404
        assert other.post(f"/api/documents/{doc_id}/chat", json={"message": "What is my name?"}).status_code == 404
        assert other.delete(f"/api/documents/{doc_id}").status_code == 404
    assert user_client.get(f"/api/documents/{doc_id}").status_code == 200


def test_document_deletion_removes_files_and_chats(user_client):
    r = upload(user_client, make_text_pdf())
    doc_id = r.json()["id"]
    user_client.post(f"/api/documents/{doc_id}/chat", json={"message": "What is my name?"})
    with SessionLocal() as db:
        d = db.get(Document, doc_id)
        assert d.has_masked_pdf and d.masked_pdf.startswith(b"%PDF")  # masked PDF stored in the DB
    assert not list(Path(get_settings().storage_dir).glob("*.pdf"))  # nothing on the filesystem
    assert user_client.delete(f"/api/documents/{doc_id}").status_code == 200
    with SessionLocal() as db:
        assert db.get(Document, doc_id) is None
        assert db.scalars(select(ChatSession)).all() == []
        assert db.scalars(select(ChatMessage)).all() == []
    assert user_client.get(f"/api/documents/{doc_id}").status_code == 404


def test_temp_files_cleaned_after_success_and_failure(user_client, monkeypatch, caplog):
    upload(user_client, make_text_pdf())
    assert not _temp_files()
    stored_before = len(list(Path(get_settings().storage_dir).glob("*.pdf")))

    def boom(*a, **k):
        raise RuntimeError("simulated failure with secret 2345 6789 0124")

    monkeypatch.setattr(extraction_service, "process_document", boom)
    r = upload(user_client, make_text_pdf())
    assert r.status_code == 500
    assert r.json()["detail"] == "Document processing failed."  # no internal details
    assert "2345" not in r.text and "Traceback" not in r.text
    assert "2345 6789 0124" not in caplog.text  # logs never contain document content
    assert not _temp_files()
    assert len(list(Path(get_settings().storage_dir).glob("*.pdf"))) == stored_before


def test_failure_after_pdf_saved_removes_stored_pdf(user_client, monkeypatch):
    from app.security import encryption as enc

    def boom(*a, **k):
        raise RuntimeError("db failure")

    monkeypatch.setattr(enc, "encrypt_json", boom)
    r = upload(user_client, make_text_pdf())
    assert r.status_code == 500
    assert not list(Path(get_settings().storage_dir).glob("*.pdf"))
    assert not _temp_files()


def test_history_disabled_documents_removed_at_logout(client):
    register(client)
    onboard(client, history=False)
    r = upload(client, make_text_pdf())
    body = r.json()
    assert body["retained"] is False and body["expires_at"]
    assert client.post("/api/auth/logout").status_code == 204
    with SessionLocal() as db:
        assert db.scalars(select(Document)).all() == []
    assert not list(Path(get_settings().storage_dir).glob("*.pdf"))


def test_form_field_values_are_masked(user_client):
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 60), "Bank form", fontsize=12)
    w = pymupdf.Widget()
    w.field_name, w.field_label = "pan_field", "PAN"
    w.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    w.rect = pymupdf.Rect(50, 100, 300, 120)
    w.field_value = SYNTH["pan"]
    page.add_widget(w)
    data = doc.tobytes()
    doc.close()
    r = upload(user_client, data)
    assert r.status_code == 201, r.text
    assert "PAN" in r.json()["masked_data"]["entity_summary"]
    _, _, raw = _pdf_text(user_client, r.json()["id"])
    d = pymupdf.open(stream=raw, filetype="pdf")
    assert not list(d[0].widgets() or [])
    assert SYNTH["pan"] not in d[0].get_text()
    d.close()


# ------------------------------------------------------------------ stacked-label layouts
STACKED = [
    "Personal Information Form", "SYNTHETIC SAMPLE",
    "FULL NAME", "Riya Testperson",
    "DATE OF BIRTH", "14 February 1995",
    "EMAIL ADDRESS", "riya.test@example.com",
    "RESIDENTIAL ADDRESS", "Flat 404, Demo Residency, Sample Road, Mumbai", "000000",
    "POSTAL CODE", "000000 (dummy value)",
    "INSTITUTION", "Example State College",
    "AADHAAR-SHAPED VALUE", "0000 0000 0000 (all-zero dummy)",
    "PAN-SHAPED VALUE", "AAAAA0000A (invalid dummy)",
    "BANK NAME", "Example Cooperative Test Bank",
    "ACCOUNT NUMBER", "0000000000000000 (dummy)",
    "CARD EXPIRY", "12/30 (test value)",
    "CVV", "123 (dummy)",
    "CONTACT NAME", "Kiran Sample",
    "Synthetic sample for testing only.",
]
STACKED_SECRETS = ["Riya Testperson", "14 February 1995", "riya.test@example.com", "Demo Residency",
                   "0000 0000 0000", "AAAAA0000A", "0000000000000000", "12/30", "Kiran Sample"]


def test_stacked_label_layout_is_fully_masked(user_client):
    r = upload(user_client, make_text_pdf(STACKED, metadata=False))
    assert r.status_code == 201, r.text
    body = r.json()
    dumped = str(body["masked_data"])
    for v in STACKED_SECRETS:
        assert v not in dumped, f"stacked value not masked: {v}"
    assert "CVV_001" in dumped
    # non-personal labels/values are NOT over-masked
    for keep in ("Example State College", "Example Cooperative Test Bank", "SYNTHETIC SAMPLE", "Synthetic sample"):
        assert keep in dumped, keep
    assert body["has_pdf"], body["masked_data"]["warnings"]
    text, _, _ = _pdf_text(user_client, body["id"])
    for v in STACKED_SECRETS:
        assert v not in text
    assert "XXXX XXXX XXXX" in text


def test_ai_flagged_personal_data_missed_locally_is_masked(user_client, groq_mock):
    onboard(user_client, ai_text=True)
    lines = ["Reference letter", "Dear Zorawar Bhatnagar, thank you for applying.", "Qualification: Bachelor of Commerce"]
    groq_mock.extra_fields = [{"field": "recipient", "value": "Zorawar Bhatnagar", "category": "PERSON", "page": 1}]
    r = upload(user_client, make_text_pdf(lines, metadata=False))
    body = r.json()
    md = body["masked_data"]
    assert "Zorawar" not in str(md)
    assert any("missed by local detection" in w for w in md["warnings"])
    assert body["processing_status"] == "needs_review"
    text, _, _ = _pdf_text(user_client, body["id"])
    assert "Zorawar" not in text and "Bhatnagar" not in text


def test_ai_hint_with_wrong_shape_is_ignored(user_client, groq_mock):
    """A bank NAME mislabelled as BANK_ACCOUNT by the AI must not be masked or trigger review."""
    onboard(user_client, ai_text=True)
    lines = ["Bank details", "Bank Name: Example Cooperative Test Bank", "Qualification: Bachelor of Commerce"]
    groq_mock.extra_fields = [{"field": "bank_name", "value": "Example Cooperative Test Bank",
                               "category": "BANK_ACCOUNT", "page": 1}]
    body = upload(user_client, make_text_pdf(lines, metadata=False)).json()
    md = body["masked_data"]
    assert not any("missed by local detection" in w for w in md["warnings"])
    assert body["processing_status"] == "completed", md["warnings"]
    text, _, _ = _pdf_text(user_client, body["id"])
    assert "Example Cooperative Test Bank" in text
    row = next(r for r in body["person_details"] if r["field"] == "bank_name")
    assert row["value"] == "Example Cooperative Test Bank" and not row["masked"]


def test_person_details_stored_as_encrypted_rows(user_client):
    from app.models import PersonDetail

    r = upload(user_client, make_text_pdf())
    doc_id = r.json()["id"]
    with SessionLocal() as db:
        rows = db.scalars(select(PersonDetail).where(PersonDetail.document_id == doc_id)).all()
        by_field = {p.field_name: p for p in rows}
        assert by_field["aadhaar_no"].value == "XXXX XXXX XXXX" and by_field["aadhaar_no"].is_masked
        assert by_field["qualification"].value == "Bachelor of Commerce" and not by_field["qualification"].is_masked
        # values are ciphertext inside the database file (field-level encryption at rest)
        raw = db.execute(text("SELECT value FROM person_details")).scalars().all()
        assert raw and all(v.startswith("enc:v1:") for v in raw)
        raw_doc = db.execute(text("SELECT masked_data FROM documents")).scalar_one()
        assert raw_doc.startswith("enc:v1:") and "Bachelor" not in raw_doc
    # rows are deleted with the document
    user_client.delete(f"/api/documents/{doc_id}")
    with SessionLocal() as db:
        assert db.scalars(select(PersonDetail)).all() == []
