"""Shared document operations: ownership lookup, deletion, retention purge,
permission-based display filtering and revocation of retained owner values."""
from __future__ import annotations

import copy
import logging
from datetime import datetime, UTC

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Document, UserSession
from ..security import encryption
from ..security.permissions import CONFIGURABLE_FIELDS

logger = logging.getLogger("securedoc.documents")


def get_owned_document(db: Session, user_id: str, document_id: str) -> Document:
    """Ownership check on every access. Returns 404 for both missing and foreign documents."""
    if not document_id or len(document_id) > 64:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = db.scalar(select(Document).where(Document.id == document_id, Document.user_id == user_id))
    if doc is None or _expired(doc):
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


def _expired(doc: Document) -> bool:
    if doc.expires_at is None:
        return False
    exp = doc.expires_at if doc.expires_at.tzinfo else doc.expires_at.replace(tzinfo=UTC)
    return exp <= datetime.now(UTC)


def delete_document(db: Session, doc: Document) -> None:
    db.delete(doc)  # masked PDF is a column; person details, chat sessions and messages cascade
    db.commit()


def purge_ephemeral_documents(db: Session, user_id: str | None = None) -> int:
    """Delete documents whose retention ended (history disabled). With user_id: all of that user's
    session-only documents (used at logout)."""
    q = select(Document).where(Document.expires_at.is_not(None))
    if user_id:
        q = q.where(Document.user_id == user_id)
    removed = 0
    for doc in db.scalars(q).all():
        if user_id or _expired(doc):
            delete_document(db, doc)
            removed += 1
    return removed


def purge_expired_sessions(db: Session) -> int:
    now = datetime.now(UTC)
    rows = db.scalars(select(UserSession)).all()
    n = 0
    for s in rows:
        exp = s.expires_at if s.expires_at.tzinfo else s.expires_at.replace(tzinfo=UTC)
        if exp <= now:
            db.delete(s)
            n += 1
    db.commit()
    return n


def display_masked_data(masked: dict, allowed_fields: dict[str, bool]) -> dict:
    """Masked JSON for viewing/downloading: content categories the user disabled are hidden."""
    data = copy.deepcopy(masked or {})
    hidden = {CONFIGURABLE_FIELDS[k]["category"] for k in ("education", "employment") if not allowed_fields.get(k, False)}
    if hidden:
        for f in data.get("fields", []):
            if f.get("category") in hidden:
                f["value"] = "[HIDDEN_BY_PRIVACY_SETTINGS]"
        for p in data.get("pages", []):
            p["masked_text"] = "[Page text hidden because some content categories are disabled in your privacy settings]"
    return data


def person_rows(doc: Document, allowed_fields: dict[str, bool]) -> list[dict]:
    """Stored person details (decrypted on read), minus categories the user has hidden."""
    hidden = {CONFIGURABLE_FIELDS[k]["category"] for k in ("education", "employment") if not allowed_fields.get(k, False)}
    return [
        {"field": p.field_name, "value": p.value, "category": p.category, "masked": p.is_masked, "page": p.page}
        for p in doc.person_details
        if p.category not in hidden
    ]


def person_json(doc: Document, allowed_fields: dict[str, bool]) -> dict:
    """Person-only JSON output: just the person's details; sensitive identifiers X-masked."""
    rows = person_rows(doc, allowed_fields)
    return {
        "document_name": doc.document_name,
        "document_type": doc.document_type,
        "person_details": {r["field"]: r["value"] for r in rows},
        "masked_fields": [r["field"] for r in rows if r["masked"]],
    }


def revoke_owner_categories(db: Session, user_id: str, categories: set[str]) -> int:
    """Permanently drop retained original values for revoked categories from all of the user's documents."""
    if not categories:
        return 0
    changed = 0
    for doc in db.scalars(select(Document).where(Document.user_id == user_id)).all():
        if not doc.encrypted_owner_fields:
            continue
        try:
            values = encryption.decrypt_json(doc.encrypted_owner_fields, user_id, doc.id)
        except encryption.DecryptionError:
            doc.encrypted_owner_fields = None
            changed += 1
            continue
        kept = {k: v for k, v in values.items() if v.get("category") not in categories}
        if len(kept) != len(values):
            doc.encrypted_owner_fields = encryption.encrypt_json(kept, user_id, doc.id) if kept else None
            changed += 1
    return changed
