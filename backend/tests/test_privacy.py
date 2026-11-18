from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import ConsentRecord, Document
from app.security import encryption

from .conftest import SYNTH, make_text_pdf, onboard, register, upload


def _ask(c, doc_id, q):
    r = c.post(f"/api/documents/{doc_id}/chat", json={"message": q})
    assert r.status_code == 200, r.text
    return r.json()["assistant_message"]["content"]


def _setup(client, **fields):
    register(client)
    onboard(client, fields=fields)
    r = upload(client, make_text_pdf())
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_onboarding_requires_policy_acknowledgement(client):
    register(client)
    body = {"allowed_fields": {}, "external_ai_text": False, "external_ai_images": False, "save_history": True,
            "accept_policy": False, "policy_version": get_settings().policy_version}
    assert client.put("/api/privacy/preferences", json=body).status_code == 400


def test_default_preferences_and_fixed_restrictions(client):
    r = client.get("/api/privacy/policy").json()
    defaults = {f["key"]: f["default"] for f in r["configurable_fields"]}
    assert defaults["name"] and defaults["address"] and defaults["education"] and defaults["employment"]
    assert not defaults["email"] and not defaults["phone"]
    assert any("Aadhaar" in x for x in r["fixed_restrictions"])
    # restricted categories cannot be configured at all
    register(client)
    body = {"allowed_fields": {"aadhaar": True}, "external_ai_text": False, "external_ai_images": False,
            "save_history": True, "accept_policy": True, "policy_version": get_settings().policy_version}
    assert client.put("/api/privacy/preferences", json=body).status_code == 422


def test_name_permission_enabled(client):
    doc = _setup(client, name=True)
    assert SYNTH["name"] in _ask(client, doc, "What is my name?")


def test_name_permission_disabled(client):
    doc = _setup(client, name=False)
    a = _ask(client, doc, "What is my name?")
    assert SYNTH["name"] not in a and "[PERSON_" in a and "privacy settings" in a


def test_address_permission_enabled(client):
    doc = _setup(client, address=True)
    assert SYNTH["address"] in _ask(client, doc, "What is my address?")


def test_address_permission_disabled(client):
    doc = _setup(client, address=False)
    a = _ask(client, doc, "What is my address?")
    assert SYNTH["address"] not in a and "[ADDRESS_" in a


def test_phone_permission_disabled(client):
    doc = _setup(client, phone=False)
    a = _ask(client, doc, "What is my phone number?")
    assert "98765" not in a and "[PHONE_" in a


def test_aadhaar_masked_regardless_of_preferences(client):
    doc = _setup(client, name=True, address=True, email=True, phone=True, dob=True)
    a = _ask(client, doc, "What is my Aadhaar number?")
    assert "6789" not in a and "cannot access or reveal" in a
    with SessionLocal() as db:
        d = db.get(Document, doc)
        owner = encryption.decrypt_json(d.encrypted_owner_fields, d.user_id, d.id)
    assert all(v["category"] not in {"AADHAAR", "PAN", "BANK_ACCOUNT", "IFSC"} for v in owner.values())
    assert not any(SYNTH["aadhaar"] in v["value"] for v in owner.values())


def test_permission_changes_apply_to_future_requests(client):
    doc = _setup(client, name=True)
    assert SYNTH["name"] in _ask(client, doc, "What is my name?")
    onboard(client, fields={"name": False})  # revoke
    a = _ask(client, doc, "What is my name?")
    assert SYNTH["name"] not in a
    # history is re-evaluated against current permissions too
    hist = client.get(f"/api/documents/{doc}/chat/history").json()["messages"]
    assert all(SYNTH["name"] not in m["content"] for m in hist)
    # revocation destroyed the retained original value
    with SessionLocal() as db:
        d = db.get(Document, doc)
        owner = encryption.decrypt_json(d.encrypted_owner_fields, d.user_id, d.id)
    assert all(v["category"] != "PERSON" for v in owner.values())


def test_consent_version_recorded(client):
    register(client)
    onboard(client, ai_text=False)
    onboard(client, ai_text=True)  # change -> old record revoked, new one granted
    with SessionLocal() as db:
        recs = db.scalars(select(ConsentRecord).where(ConsentRecord.consent_type == "external_ai_text")).all()
        assert len(recs) == 2
        assert recs[0].revoked_at is not None and recs[0].granted is False
        assert recs[1].revoked_at is None and recs[1].granted is True
        assert all(r.policy_version == get_settings().policy_version for r in recs)
        policy = db.scalars(select(ConsentRecord).where(ConsentRecord.consent_type == "privacy_policy")).all()
        assert len(policy) == 1
    consents = client.get("/api/privacy/consents").json()
    assert any(c["consent_type"] == "display_field:name" for c in consents)


def test_education_disabled_hides_content(client):
    doc = _setup(client, education=False)
    a = _ask(client, doc, "What qualification is mentioned?")
    assert "Bachelor" not in a and "hidden" in a
    detail = client.get(f"/api/documents/{doc}").json()
    assert "Bachelor of Commerce" not in str(detail)
