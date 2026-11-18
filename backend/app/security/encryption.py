"""AES-256-GCM encryption for owner-visible values. The key lives outside the DB
(environment variable or a dev key file). Ciphertexts are bound to user and
document via associated data, so a blob copied to another row will not decrypt."""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import get_settings

_VERSION = "v1"


class DecryptionError(Exception):
    pass


def _key() -> bytes:
    return base64.b64decode(get_settings().encryption_key)


def _aad(user_id: str, document_id: str) -> bytes:
    return f"securedoc|user:{user_id}|doc:{document_id}".encode()


def encrypt_json(data: dict, user_id: str, document_id: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), _aad(user_id, document_id))
    return f"{_VERSION}:{base64.b64encode(nonce + ct).decode()}"


_COL_PREFIX = "enc:v1:"


def encrypt_column(plaintext: str, column: str) -> str:
    """Field-level encryption at rest (AES-256-GCM, column name as associated data)."""
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plaintext.encode(), f"securedoc|col:{column}".encode())
    return _COL_PREFIX + base64.b64encode(nonce + ct).decode()


def decrypt_column(value: str | None, column: str) -> str | None:
    if value is None or not value.startswith(_COL_PREFIX):
        return value  # legacy plaintext row (written before encryption at rest was enabled)
    try:
        raw = base64.b64decode(value[len(_COL_PREFIX):])
        return AESGCM(_key()).decrypt(raw[:12], raw[12:], f"securedoc|col:{column}".encode()).decode()
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError("could not decrypt column") from exc


def decrypt_json(blob: str | None, user_id: str, document_id: str) -> dict:
    if not blob:
        return {}
    try:
        version, payload = blob.split(":", 1)
        if version != _VERSION:
            raise DecryptionError("unsupported version")
        raw = base64.b64decode(payload)
        pt = AESGCM(_key()).decrypt(raw[:12], raw[12:], _aad(user_id, document_id))
        return json.loads(pt)
    except (ValueError, InvalidTag, json.JSONDecodeError) as exc:
        raise DecryptionError("could not decrypt owner fields") from exc
