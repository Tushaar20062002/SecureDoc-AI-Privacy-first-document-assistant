"""Password hashing (Argon2id), server-side sessions, CSRF and rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, UTC

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import PrivacyPreference, User, UserSession

# Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1).
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, type=Type.ID)
# Dummy hash used to equalise timing for unknown emails.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token_for(token_hash: str) -> str:
    """CSRF token bound to the session (HMAC of the session token hash)."""
    key = get_settings().secret_key.encode()
    return hmac.new(key, f"csrf|{token_hash}".encode(), hashlib.sha256).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def create_session(db: Session, user: User, response: Response) -> UserSession:
    s = get_settings()
    token = secrets.token_urlsafe(32)
    sess = UserSession(
        user_id=user.id,
        token_hash=_hash_token(token),
        expires_at=datetime.now(UTC) + timedelta(minutes=s.session_ttl_minutes),
    )
    db.add(sess)
    db.commit()
    max_age = s.session_ttl_minutes * 60
    response.set_cookie(
        s.session_cookie_name, token, max_age=max_age, httponly=True,
        secure=s.cookie_secure, samesite=s.cookie_samesite, path="/",
    )
    response.set_cookie(
        s.csrf_cookie_name, csrf_token_for(sess.token_hash), max_age=max_age, httponly=False,
        secure=s.cookie_secure, samesite=s.cookie_samesite, path="/",
    )
    return sess


def clear_session_cookies(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(s.session_cookie_name, path="/")
    response.delete_cookie(s.csrf_cookie_name, path="/")


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def get_current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    if not token or len(token) > 200:
        raise _unauthorized()
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == _hash_token(token)))
    if sess is None:
        raise _unauthorized()
    if _aware(sess.expires_at) <= datetime.now(UTC):
        db.delete(sess)
        db.commit()
        raise _unauthorized()
    if not sess.user or not sess.user.is_active:
        raise _unauthorized()
    # CSRF: every state-changing request must echo the session-bound token.
    if request.method not in SAFE_METHODS:
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, csrf_token_for(sess.token_hash)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return sess


def get_current_user(sess: UserSession = Depends(get_current_session)) -> User:
    return sess.user


def onboarding_complete(pref: PrivacyPreference | None) -> bool:
    s = get_settings()
    return bool(pref and pref.policy_accepted and pref.policy_version == s.policy_version)


def require_onboarded_user(user: User = Depends(get_current_user)) -> User:
    if not onboarding_complete(user.preferences):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Privacy onboarding required")
    return user


# ---------------------------------------------------------------- rate limiting
class RateLimiter:
    """Simple in-memory sliding-window limiter (per process). Adequate for an MVP."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter()


def rate_limit(bucket: str):
    def dependency(request: Request) -> None:
        s = get_settings()
        if not s.rate_limit_enabled:
            return
        limit = {"auth": s.rate_limit_auth, "upload": s.rate_limit_upload, "chat": s.rate_limit_chat}[bucket]
        client = request.client.host if request.client else "unknown"
        if not rate_limiter.check(f"{bucket}:{client}", limit):
            raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")

    return dependency
