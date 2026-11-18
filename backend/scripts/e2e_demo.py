"""End-to-end demo against the RUNNING stack (through the Vite proxy by default).

  .venv/Scripts/python scripts/e2e_demo.py [base_url]

Registers two users, onboards, uploads a synthetic PDF, chats, downloads outputs,
verifies isolation, and deletes the document. Uses only synthetic data.
"""
from __future__ import annotations

import secrets
import sys

import httpx
import pymupdf

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5173"
PW = "Str0ng!Passw0rd"
LINES = [
    "JOB APPLICATION FORM",
    "Full Name: Ravi Shankar Mehta",
    "Residential Address: 221 Lotus Residency, MG Road, Pune 411001",
    "Email: ravi.mehta.test@example.com",
    "Phone: +91 98765 43210",
    "Aadhaar No: 2345 6789 0124",
    "PAN: ABCPM1234Q",
    "Bank Account Number: 123456789012",
    "Qualification: Bachelor of Commerce",
    "Current Employer: Infosys Limited",
]
SECRETS = ["2345 6789 0124", "ABCPM1234Q", "123456789012", "ravi.mehta.test@example.com"]


def make_pdf() -> bytes:
    d = pymupdf.open()
    p = d.new_page()
    for i, line in enumerate(LINES):
        p.insert_text((50, 60 + 18 * i), line, fontsize=10)
    return d.tobytes()


def client(email: str) -> httpx.Client:
    c = httpx.Client(base_url=BASE, timeout=120, headers={"Origin": BASE})
    r = c.post("/api/auth/register", json={"email": email, "password": PW})
    r.raise_for_status()
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    policy = c.get("/api/privacy/policy").json()
    r = c.put("/api/privacy/preferences", json={
        "allowed_fields": {f["key"]: f["default"] for f in policy["configurable_fields"]},
        "external_ai_text": True, "external_ai_images": False, "save_history": True,
        "accept_policy": True, "policy_version": policy["policy_version"],
    })
    r.raise_for_status()
    return c


def step(msg: str) -> None:
    print(f"\n== {msg}")


def main() -> None:
    tag = secrets.token_hex(3)
    step(f"Register + onboard user A and user B via {BASE}")
    a, b = client(f"demo-a-{tag}@example.com"), client(f"demo-b-{tag}@example.com")
    print("me:", a.get("/api/auth/me").json()["email"])

    step("Upload synthetic job application (pdf_and_json)")
    r = a.post("/api/documents/upload", files={"file": ("application.pdf", make_pdf(), "application/pdf")},
               data={"output_mode": "pdf_and_json"})
    r.raise_for_status()
    doc = r.json()
    md = doc["masked_data"]
    print("status:", doc["processing_status"], "| type:", doc["document_type"], "| extraction:", md["extraction_method"])
    print("entities:", md["entity_summary"])
    print("sample masked text:", md["pages"][0]["masked_text"].splitlines()[1:6])
    assert not any(s in r.text for s in SECRETS), "original sensitive value in API response!"

    step("Chat")
    for q in ["What is my name?", "What is my Aadhaar number?", "What is my phone number?",
              "What qualification is mentioned?", "What is the weather today?", "What is my date of birth?"]:
        ans = a.post(f"/api/documents/{doc['id']}/chat", json={"message": q}).json()["assistant_message"]
        print(f"Q: {q}\nA: {ans['content']}  [{ans['kind']}]")

    step("Download outputs")
    pdf = a.get(f"/api/documents/{doc['id']}/download/pdf")
    js = a.get(f"/api/documents/{doc['id']}/download/json")
    print("pdf:", pdf.status_code, len(pdf.content), "bytes | json:", js.status_code, len(js.content), "bytes")
    text = "".join(p.get_text() for p in pymupdf.open(stream=pdf.content, filetype="pdf"))
    leaks = [s for s in SECRETS if s in text or s in js.text]
    print("residual originals in downloaded outputs:", leaks or "none")
    assert not leaks

    step("Isolation: user B tries to access user A's document")
    for path in ("", "/download/pdf", "/download/json", "/chat/history"):
        print(f"B GET /api/documents/<A's id>{path} ->", b.get(f"/api/documents/{doc['id']}{path}").status_code)
    print("B's document list:", b.get("/api/documents").json())
    print("unauthenticated list ->", httpx.get(f"{BASE}/api/documents").status_code)

    step("Delete document and log out")
    print("delete ->", a.delete(f"/api/documents/{doc['id']}").status_code)
    print("after delete ->", a.get(f"/api/documents/{doc['id']}").status_code)
    print("logout ->", a.post("/api/auth/logout").status_code, "| me after logout ->", a.get("/api/auth/me").status_code)
    print("\nE2E demo completed successfully.")


if __name__ == "__main__":
    main()
