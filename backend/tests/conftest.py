"""Test fixtures. All fixtures use SYNTHETIC data only (no real IDs or bank details)."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="securedoc_test_"))
os.environ.update(
    APP_ENV="test",
    DATABASE_URL=f"sqlite:///{(_TMP / 'test.db').as_posix()}",
    STORAGE_DIR=str(_TMP / "storage"),
    TEMP_DIR=str(_TMP / "temp"),
    KEY_DIR=str(_TMP / "keys"),
    GROQ_API_KEY="",
    GROQ_MODEL="test-text-model",
    GROQ_VISION_MODEL="test-vision-model",
    # Existing suites exercise the full masking scope (names, addresses, DOB, references too).
    MASK_CATEGORIES="PERSON,ADDRESS,DOB,APP_REF,PHONE,EMAIL",
    RATE_LIMIT_ENABLED="false",
    ENCRYPTION_KEY="",
    SECRET_KEY="",
)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
import pymupdf  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security.auth import rate_limiter  # noqa: E402
from app.services import groq_service  # noqa: E402

PASSWORD = "Str0ng!Passw0rd"

# ------------------------------------------------------------------ synthetic data
SYNTH = {
    "name": "Ravi Shankar Mehta",
    "father": "Mohan Lal Mehta",
    "address": "221 Lotus Residency, MG Road, Pune 411001",
    "email": "ravi.mehta.test@example.com",
    "phone": "+91 98765 43210",
    "aadhaar": "2345 6789 0124",
    "pan": "ABCPM1234Q",
    "account": "123456789012",
    "ifsc": "HDFC0001234",
    "dob": "14/08/1994",
    "app_ref": "APP-2024-00987",
}
SENSITIVE_VALUES = [SYNTH[k] for k in ("name", "address", "email", "phone", "aadhaar", "pan", "account", "ifsc")]

FORM_LINES = [
    "JOB APPLICATION FORM",
    f"Full Name: {SYNTH['name']}",
    f"Father's Name: {SYNTH['father']}",
    f"Date of Birth: {SYNTH['dob']}",
    f"Residential Address: {SYNTH['address']}",
    f"Email: {SYNTH['email']}",
    f"Phone: {SYNTH['phone']}",
    f"Aadhaar No: {SYNTH['aadhaar']}",
    f"PAN: {SYNTH['pan']}",
    f"Bank Account Number: {SYNTH['account']}",
    f"IFSC Code: {SYNTH['ifsc']}",
    f"Application Number: {SYNTH['app_ref']}",
    "Qualification: Bachelor of Commerce",
    "University: University of Mumbai",
    "Current Employer: Infosys Limited",
    "Designation: Senior Analyst",
    "Experience: 5 years",
]


def make_text_pdf(lines=FORM_LINES, pages: int = 1, metadata: bool = True) -> bytes:
    doc = pymupdf.open()
    for _ in range(pages):
        page = doc.new_page()
        y = 60
        for line in lines:
            page.insert_text((50, y), line, fontsize=10)
            y += 18
    if metadata:
        doc.set_metadata({"author": SYNTH["name"], "title": f"Application of {SYNTH['name']}", "subject": SYNTH["pan"]})
    data = doc.tobytes()
    doc.close()
    return data


def _render_lines_png(lines) -> bytes:
    tmp = pymupdf.open()
    p = tmp.new_page()
    y = 60
    for line in lines:
        p.insert_text((50, y), line, fontsize=12)
        y += 22
    png = p.get_pixmap(dpi=100).tobytes("png")
    tmp.close()
    return png


def make_image_pdf(lines=FORM_LINES) -> bytes:
    png = _render_lines_png(lines)
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_image(page.rect, stream=png)
    data = doc.tobytes()
    doc.close()
    return data


def make_mixed_pdf() -> bytes:
    doc = pymupdf.open(stream=make_text_pdf(metadata=False), filetype="pdf")
    page = doc.new_page()
    page.insert_image(page.rect, stream=_render_lines_png(FORM_LINES[:8]))
    data = doc.tobytes()
    doc.close()
    return data


def make_encrypted_pdf() -> bytes:
    doc = pymupdf.open(stream=make_text_pdf(), filetype="pdf")
    data = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="userpw", owner_pw="ownerpw")
    doc.close()
    return data


def make_blank_pdf() -> bytes:
    doc = pymupdf.open()
    doc.new_page()
    data = doc.tobytes()
    doc.close()
    return data


# ------------------------------------------------------------------ app fixtures
@pytest.fixture(autouse=True)
def _clean_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    s = get_settings()
    for d in (s.storage_dir, s.temp_dir):
        shutil.rmtree(d, ignore_errors=True)
        Path(d).mkdir(parents=True, exist_ok=True)
    rate_limiter.reset()
    s.groq_api_key = ""
    yield
    s.groq_api_key = ""


def new_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def client():
    with new_client() as c:
        yield c


def register(c: TestClient, email: str = "user@example.com", password: str = PASSWORD) -> dict:
    r = c.post("/api/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return r.json()


DEFAULT_FIELDS = {
    "name": True, "address": True, "email": False, "phone": False, "dob": False,
    "education": True, "employment": True, "application_reference": True,
}


def onboard(c: TestClient, *, fields: dict | None = None, ai_text=False, ai_images=False, history=True):
    body = {
        "allowed_fields": {**DEFAULT_FIELDS, **(fields or {})},
        "external_ai_text": ai_text, "external_ai_images": ai_images, "save_history": history,
        "accept_policy": True, "policy_version": get_settings().policy_version,
    }
    r = c.put("/api/privacy/preferences", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def upload(c: TestClient, data: bytes, mode: str = "pdf_and_json", name: str = "application.pdf"):
    return c.post("/api/documents/upload", files={"file": (name, data, "application/pdf")}, data={"output_mode": mode})


@pytest.fixture
def user_client(client):
    register(client)
    onboard(client)
    return client


# ------------------------------------------------------------------ Groq interception
class GroqMock:
    """Intercepts the HTTP layer of groq_service and records every outgoing payload."""

    def __init__(self):
        self.requests: list[dict] = []
        self.fail_with: int | None = None
        self.chat_override: dict | None = None
        self.vision_response: dict | None = None
        self.vision_queue: list[dict] = []  # successive vision replies (transcription, then re-checks)
        self.extra_fields: list[dict] = []

    def all_text(self) -> str:
        return json.dumps(self.requests, ensure_ascii=False)

    def __call__(self, url, headers, payload, timeout):
        self.requests.append(payload)
        if self.fail_with:
            return httpx.Response(self.fail_with, json={"error": {"message": "mock failure"}})
        msgs = payload["messages"]
        first = msgs[0]["content"]
        if isinstance(first, list):  # vision
            content = (self.vision_queue.pop(0) if self.vision_queue
                       else self.vision_response or {"lines": []})
        elif "extract structured fields" in first:
            text = msgs[-1]["content"]
            fields = []
            for ph in sorted(set(re.findall(r"\[[A-Z_]+_\d{3}\]", text))):
                cat = ph[1:-5]
                fields.append({"field": cat.lower(), "value": ph, "category": cat, "page": 1, "confidence": 0.9})
            if "Bachelor of Commerce" in text:
                fields.append({"field": "qualification", "value": "Bachelor of Commerce", "category": "EDUCATION", "page": 1})
            if "Infosys" in text:
                fields.append({"field": "employer", "value": "Infosys Limited", "category": "EMPLOYMENT", "page": 1})
            content = {"document_type": "job_application", "fields": fields + self.extra_fields}
        else:
            q = msgs[-1]["content"].lower()
            if self.chat_override is not None:
                content = self.chat_override
            elif "qualification" in q:
                content = {"status": "answered", "answer": "The qualification mentioned is Bachelor of Commerce.", "pages": [1]}
            elif "weather" in q:
                content = {"status": "out_of_scope", "answer": "", "pages": []}
            else:
                content = {"status": "not_found", "answer": "", "pages": []}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(content)}}]})


@pytest.fixture
def groq_mock(monkeypatch):
    mock = GroqMock()
    get_settings().groq_api_key = "test-key-not-real"
    get_settings().groq_max_retries = 0
    monkeypatch.setattr(groq_service, "_post", mock)
    return mock


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP, ignore_errors=True)
