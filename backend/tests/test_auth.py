from datetime import datetime, timedelta, UTC

from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import User, UserSession
from app.security.auth import rate_limiter

from .conftest import PASSWORD, new_client, register


def test_successful_registration_hashes_password_with_argon2id(client):
    data = register(client, "alice@example.com")
    assert data["email"] == "alice@example.com"
    assert data["onboarding_complete"] is False
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "alice@example.com"))
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash
    cookie = client.cookies.get(get_settings().session_cookie_name)
    assert cookie
    with SessionLocal() as db:  # only the hash of the session token is stored
        sess = db.scalar(select(UserSession))
        assert sess.token_hash != cookie and len(sess.token_hash) == 64


def test_session_cookie_flags(client):
    r = client.post("/api/auth/register", json={"email": "flags@example.com", "password": PASSWORD})
    set_cookie = ";".join(r.headers.get_list("set-cookie")).lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie


def test_duplicate_email_registration(client):
    register(client, "dup@example.com")
    with new_client() as c2:
        r = c2.post("/api/auth/register", json={"email": "DUP@example.com", "password": PASSWORD})
        assert r.status_code == 409


def test_invalid_email_and_weak_password_rejected(client):
    assert client.post("/api/auth/register", json={"email": "not-an-email", "password": PASSWORD}).status_code == 422
    r = client.post("/api/auth/register", json={"email": "weak@example.com", "password": "short"})
    assert r.status_code == 422
    assert "short" not in r.text  # submitted values are never echoed


def test_successful_login(client):
    register(client, "bob@example.com")
    with new_client() as c2:
        r = c2.post("/api/auth/login", json={"email": "bob@example.com", "password": PASSWORD})
        assert r.status_code == 200
        assert c2.get("/api/auth/me").json()["email"] == "bob@example.com"


def test_incorrect_password(client):
    register(client, "carol@example.com")
    with new_client() as c2:
        r = c2.post("/api/auth/login", json={"email": "carol@example.com", "password": "Wrong!Passw0rd"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid email or password"
        r = c2.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})
        assert r.status_code == 401 and r.json()["detail"] == "Invalid email or password"


def test_logout_invalidates_session(client):
    register(client, "dave@example.com")
    token = client.cookies.get(get_settings().session_cookie_name)
    assert client.post("/api/auth/logout").status_code == 204
    with new_client() as c2:  # replaying the old token must fail
        c2.cookies.set(get_settings().session_cookie_name, token)
        assert c2.get("/api/auth/me").status_code == 401


def test_expired_session_rejected(client):
    register(client, "erin@example.com")
    with SessionLocal() as db:
        for s in db.scalars(select(UserSession)).all():
            s.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_unauthenticated_document_access(client):
    assert client.get("/api/documents").status_code == 401
    assert client.get("/api/documents/abc").status_code == 401
    assert client.get("/api/documents/abc/download/pdf").status_code == 401
    assert client.post("/api/documents/abc/chat", json={"message": "hi"}).status_code == 401
    r = client.post("/api/documents/upload", files={"file": ("a.pdf", b"%PDF-1.4", "application/pdf")})
    assert r.status_code == 401


def test_csrf_required_for_state_changes(client):
    register(client, "frank@example.com")
    good = client.headers.pop("X-CSRF-Token")
    assert client.post("/api/auth/logout").status_code == 403
    client.headers["X-CSRF-Token"] = "forged"
    assert client.put("/api/privacy/preferences", json={}).status_code in (403, 422)
    client.headers["X-CSRF-Token"] = good
    assert client.post("/api/auth/logout").status_code == 204


def test_foreign_origin_rejected(client):
    register(client, "gina@example.com")
    r = client.post("/api/auth/logout", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_upload_requires_privacy_onboarding(client):
    register(client, "henry@example.com")
    r = client.post("/api/documents/upload", files={"file": ("a.pdf", b"%PDF-1.4 x", "application/pdf")},
                    data={"output_mode": "json_only"})
    assert r.status_code == 403
    assert "onboarding" in r.json()["detail"].lower()


def test_login_rate_limited(client):
    s = get_settings()
    s.rate_limit_enabled = True
    rate_limiter.reset()
    try:
        codes = [client.post("/api/auth/login", json={"email": "x@example.com", "password": "bad"}).status_code
                 for _ in range(s.rate_limit_auth + 2)]
        assert 429 in codes
    finally:
        s.rate_limit_enabled = False
        rate_limiter.reset()


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
