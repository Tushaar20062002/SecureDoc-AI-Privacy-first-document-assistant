"""Application configuration loaded from environment variables (.env supported).

Secrets (GROQ_API_KEY, ENCRYPTION_KEY, SECRET_KEY) are only read from the
environment / .env file and are never exposed to the frontend.
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
logger = logging.getLogger("securedoc.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    app_env: str = "development"  # development | production | test
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'securedoc.db').as_posix()}"

    # Secrets
    secret_key: str = ""  # HMAC key for CSRF tokens
    encryption_key: str = ""  # base64 encoded 32-byte AES-256 key
    key_dir: str = str(BACKEND_DIR / ".keys")  # dev-only fallback key location (outside the DB)

    # Sessions / cookies
    session_ttl_minutes: int = 60 * 8
    cookie_secure: bool = False  # MUST be true behind HTTPS in production
    cookie_samesite: str = "strict"
    session_cookie_name: str = "sd_session"
    csrf_cookie_name: str = "sd_csrf"

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Uploads
    max_upload_mb: int = 10
    max_pages: int = 50
    storage_dir: str = str(BACKEND_DIR / "storage")
    temp_dir: str = str(BACKEND_DIR / "temp")
    temp_file_max_age_minutes: int = 30

    # Groq
    groq_api_key: str = ""
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "qwen/qwen3.8-27b"
    groq_vision_model: str = "qwen/qwen3.8-27b"
    groq_timeout_seconds: float = 45.0
    groq_max_retries: int = 5  # retries on rate limit (429) / server errors, honouring Retry-After
    groq_batch_chars: int = 12000  # max characters of one page sent per extraction call
    # Per-request output cap. Groq rejects any request whose max_tokens exceeds the account's
    # output-tokens-per-minute limit (1000 for qwen/qwen3.8-27b on the on-demand tier).
    groq_max_output_tokens: int = 1000
    groq_reasoning_format: str = ""  # e.g. "hidden" for reasoning models (Qwen3); empty = not sent
    # Optional separate model for the document chatbot. Groq rate limits are PER MODEL, so answering
    # questions with another model leaves the main model's quota for extraction and images.
    # Empty = use groq_model.
    groq_chat_model: str = ""
    # Second chat model with its OWN quota: used automatically when the first one's per-minute or
    # daily budget is used up, instead of waiting. Empty = no fallback.
    groq_chat_fallback_model: str = ""
    groq_chat_reasoning_effort: str = "low"  # for gpt-oss models: fewer reasoning tokens per answer

    # 1.1: masking scope changed to sensitive identifiers only (users must re-confirm consent)
    policy_version: str = "1.1"

    # Categories masked in outputs and before any external AI call. Restricted categories
    # (government IDs, bank/card data, secrets) are ALWAYS masked even if omitted here.
    # Add PERSON, ADDRESS, DOB, APP_REF to also mask names, addresses, birth dates, references.
    mask_categories: str = "PHONE,EMAIL"

    # Rate limits (requests per minute per client IP)
    rate_limit_auth: int = 10
    rate_limit_upload: int = 10
    rate_limit_chat: int = 30
    rate_limit_enabled: bool = True

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def groq_enabled(self) -> bool:
        return bool(self.groq_api_key.strip())


def _load_or_create_dev_secret(settings: Settings, name: str, nbytes: int) -> str:
    """Development-only fallback: keep generated keys in a file outside the DB."""
    key_dir = Path(settings.key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    path = key_dir / name
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = base64.b64encode(secrets.token_bytes(nbytes)).decode()
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    logger.warning("Generated development key file '%s'. Set it via environment in production.", name)
    return value


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.app_env == "production":
        if not s.encryption_key or not s.secret_key:
            raise RuntimeError("ENCRYPTION_KEY and SECRET_KEY must be set in production")
        if not s.cookie_secure:
            raise RuntimeError("COOKIE_SECURE must be true in production (HTTPS)")
    if not s.encryption_key:
        s.encryption_key = _load_or_create_dev_secret(s, "encryption.key", 32)
    if not s.secret_key:
        s.secret_key = _load_or_create_dev_secret(s, "secret.key", 32)
    raw = base64.b64decode(s.encryption_key)
    if len(raw) != 32:
        raise RuntimeError("ENCRYPTION_KEY must be base64 of exactly 32 bytes (AES-256)")
    Path(s.storage_dir).mkdir(parents=True, exist_ok=True)
    Path(s.temp_dir).mkdir(parents=True, exist_ok=True)
    return s
