"""Intercept every Groq request and assert no original PII leaves the server."""
import pytest

from app.services import groq_service

from .conftest import SYNTH, make_text_pdf, onboard, upload

ORIGINALS = {
    "name": [SYNTH["name"], "Mehta"],
    "address": [SYNTH["address"], "Lotus Residency"],
    "email": [SYNTH["email"]],
    "phone": [SYNTH["phone"], "98765 43210", "9876543210"],
    "aadhaar": [SYNTH["aadhaar"], "234567890124"],
    "pan": [SYNTH["pan"]],
    "account": [SYNTH["account"]],
}


@pytest.fixture
def ai_client(user_client, groq_mock):
    onboard(user_client, ai_text=True, fields={"email": True, "phone": True})
    return user_client


def _ask(c, doc_id, q):
    return c.post(f"/api/documents/{doc_id}/chat", json={"message": q}).json()["assistant_message"]["content"]


@pytest.mark.parametrize("kind", list(ORIGINALS))
def test_no_original_values_in_groq_requests(ai_client, groq_mock, kind):
    r = upload(ai_client, make_text_pdf())
    assert r.status_code == 201
    doc = r.json()["id"]
    for q in ("What qualification is mentioned?", "What is my name?", "What is my address?",
              "Who is the employer?", "What is the weather today?"):
        _ask(ai_client, doc, q)
    assert groq_mock.requests, "Groq should have been called with consent"
    sent = groq_mock.all_text()
    for v in ORIGINALS[kind]:
        assert v not in sent, f"original {kind} value reached Groq"


def test_masked_placeholders_present_in_groq_request(ai_client, groq_mock):
    upload(ai_client, make_text_pdf())
    sent = groq_mock.all_text()
    for ph in ("[PERSON_001]", "[ADDRESS_001]", "[EMAIL_001]", "[PHONE_001]", "[AADHAAR_001]", "[PAN_001]"):
        assert ph in sent
    assert "Bachelor of Commerce" in sent  # useful non-sensitive content is still provided
    assert r"response_format" in str(groq_mock.requests[0])


def test_extraction_result_uses_groq_and_policy_enforced(ai_client, groq_mock):
    body = upload(ai_client, make_text_pdf()).json()
    md = body["masked_data"]
    assert md["extraction_method"] == "groq"
    by_field = {f["field"]: f for f in md["fields"]}
    assert by_field["qualification"]["sensitive"] is False
    assert by_field["aadhaar"]["sensitive"] is True and by_field["aadhaar"]["restricted"] is True


def test_owner_field_answers_never_use_groq(ai_client, groq_mock):
    doc = upload(ai_client, make_text_pdf()).json()["id"]
    before = len(groq_mock.requests)
    a = _ask(ai_client, doc, "What is my name?")
    assert SYNTH["name"] in a
    assert len(groq_mock.requests) == before  # answered locally from encrypted storage


def test_api_failure_does_not_expose_document_contents(ai_client, groq_mock):
    groq_mock.fail_with = 500
    r = upload(ai_client, make_text_pdf())
    assert r.status_code == 201  # falls back to local extraction
    body = r.json()
    assert body["masked_data"]["extraction_method"] == "local"
    assert any("AI extraction unavailable" in w for w in body["masked_data"]["warnings"])
    for v in (SYNTH["aadhaar"], SYNTH["name"], SYNTH["pan"]):
        assert v not in r.text
    a = ai_client.post(f"/api/documents/{body['id']}/chat", json={"message": "What qualification is mentioned?"})
    assert a.status_code == 200
    assert SYNTH["aadhaar"] not in a.text


def test_rate_limit_from_groq_handled(ai_client, groq_mock):
    groq_mock.fail_with = 429
    r = upload(ai_client, make_text_pdf())
    assert r.status_code == 201
    assert any("rate limit" in w for w in r.json()["masked_data"]["warnings"])


def test_malformed_groq_json_rejected(ai_client, groq_mock, monkeypatch):
    import httpx

    monkeypatch.setattr(groq_service, "_post", lambda *a, **k: httpx.Response(
        200, json={"choices": [{"message": {"content": "not json {"}}]}))
    body = upload(ai_client, make_text_pdf()).json()
    assert body["masked_data"]["extraction_method"] == "local"
    assert any("malformed" in w for w in body["masked_data"]["warnings"])


def test_egress_guard_blocks_unmasked_payload():
    with pytest.raises(groq_service.PrivacyGuardError):
        groq_service.assert_safe_egress("Applicant PAN is ABCPM1234Q")
    with pytest.raises(groq_service.PrivacyGuardError):
        groq_service.assert_safe_egress("hello Ravi Shankar Mehta", ["Ravi Shankar Mehta"])
    groq_service.assert_safe_egress("Applicant [PERSON_001] holds [PAN_001]", ["Ravi Shankar Mehta"])


def test_reasoning_blocks_stripped_from_model_output():
    raw = '<think>the user wants JSON</think>\n```json\n{"status": "answered"}\n```'
    assert groq_service._strip_reasoning(raw) == '{"status": "answered"}'


def test_no_groq_calls_without_text_consent(user_client, groq_mock):
    onboard(user_client, ai_text=False)
    doc = upload(user_client, make_text_pdf()).json()
    assert doc["masked_data"]["extraction_method"] == "local"
    _ask(user_client, doc["id"], "What qualification is mentioned?")
    assert groq_mock.requests == []


def test_user_typed_pii_is_masked_before_groq_and_storage(ai_client, groq_mock):
    doc = upload(ai_client, make_text_pdf()).json()["id"]
    ai_client.post(f"/api/documents/{doc}/chat", json={"message": "Is my mail other.person@example.org in the qualification section?"})
    assert "other.person@example.org" not in groq_mock.all_text()
    hist = ai_client.get(f"/api/documents/{doc}/chat/history").json()["messages"]
    assert all("other.person@example.org" not in m["content"] for m in hist)
