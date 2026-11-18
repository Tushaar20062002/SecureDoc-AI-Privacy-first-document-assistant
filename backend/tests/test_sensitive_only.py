"""Default policy: mask ONLY sensitive identifiers (government IDs, bank/card data, secrets,
mobile, email). Names, addresses, DOB, references, education and employment stay readable."""
import pymupdf
import pytest

from app.config import get_settings
from app.security.permissions import RESTRICTED_REFUSAL

from .conftest import make_text_pdf, onboard, upload

FORM = [
    "FULL NAME", "Riya Testperson",
    "DATE OF BIRTH", "14 February 1995",
    "EMAIL ADDRESS", "riya.test@example.com",
    "MOBILE NUMBER", "+91 90000 00000 (dummy)",
    "RESIDENTIAL ADDRESS", "Flat 404, Demo Residency, Sample Road, Mumbai",
    "HIGHEST QUALIFICATION", "Bachelor of Commerce",
    "AADHAAR NUMBER", "0000 0000 0000",
    "PAN", "AAAAA0000A",
    "PASSPORT NUMBER", "X0000000",
    "ACCOUNT NUMBER", "0000000000000000",
    "IFSC CODE", "TEST0000000",
    "CARD NUMBER", "4111 1111 1111 1111",
    "CVV", "123",
    "APPLICATION REFERENCE", "APP-2026-TEST-000173",
]
MASKED = ["riya.test@example.com", "90000 00000", "0000 0000 0000", "AAAAA0000A", "X0000000",
          "0000000000000000", "TEST0000000", "4111 1111 1111 1111"]
VISIBLE = ["Riya Testperson", "14 February 1995", "Flat 404, Demo Residency", "Bachelor of Commerce",
           "APP-2026-TEST-000173"]


@pytest.fixture(autouse=True)
def _sensitive_only_scope():
    s = get_settings()
    old = s.mask_categories
    s.mask_categories = "PHONE,EMAIL"
    yield
    s.mask_categories = old


def test_only_sensitive_identifiers_are_masked(user_client):
    r = upload(user_client, make_text_pdf(FORM, metadata=False))
    assert r.status_code == 201, r.text
    body = r.json()
    md = str(body["masked_data"])
    for v in MASKED:
        assert v not in md, f"sensitive value not masked: {v}"
    for v in VISIBLE:
        assert v in md, f"non-sensitive value should stay readable: {v}"
    assert "PERSON" not in body["masked_data"]["entity_summary"]
    assert {"AADHAAR", "PAN", "CREDIT_CARD", "CVV", "PHONE", "EMAIL"} <= set(body["masked_data"]["entity_summary"])
    assert body["has_pdf"], body["masked_data"]["warnings"]
    pdf = user_client.get(f"/api/documents/{body['id']}/download/pdf").content
    text = " ".join(p.get_text() for p in pymupdf.open(stream=pdf, filetype="pdf"))
    for v in MASKED:
        assert v not in text
    for v in VISIBLE:
        assert v in text
    assert "XXXX XXXX XXXX XXXX" in text


def test_groq_receives_names_but_never_sensitive_identifiers(user_client, groq_mock):
    onboard(user_client, ai_text=True)
    upload(user_client, make_text_pdf(FORM, metadata=False))
    sent = groq_mock.all_text()
    assert "Riya Testperson" in sent  # consented: non-sensitive details are sent
    for v in MASKED:
        assert v not in sent, f"sensitive identifier reached Groq: {v}"


def test_chat_with_sensitive_only_policy(user_client):
    doc = upload(user_client, make_text_pdf(FORM, metadata=False)).json()["id"]

    def ask(q):
        return user_client.post(f"/api/documents/{doc}/chat", json={"message": q}).json()["assistant_message"]["content"]

    assert "Riya Testperson" in ask("What is my full name?")
    assert ask("What is my Aadhaar number?") == RESTRICTED_REFUSAL
    phone = ask("What is my phone number?")
    assert "90000" not in phone and "[PHONE_001]" in phone  # phone permission is off by default


def test_policy_lists_only_meaningful_toggles(client):
    p = client.get("/api/privacy/policy").json()
    keys = {f["key"] for f in p["configurable_fields"]}
    assert keys == {"email", "phone", "education", "employment"}
    assert "Name" in p["not_masked"]
    assert "AADHAAR" in p["masked_categories"] and "PERSON" not in p["masked_categories"]
