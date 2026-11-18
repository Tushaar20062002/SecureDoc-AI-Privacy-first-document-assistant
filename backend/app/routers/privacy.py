from __future__ import annotations

from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import ConsentRecord, Document, PrivacyPreference, User
from ..schemas import ConsentOut, PreferencesIn, PreferencesOut
from ..security.auth import get_current_user, onboarding_complete
from ..security.permissions import (
    CONFIGURABLE_FIELDS,
    CONSENT_TYPES,
    CONTENT_CATEGORIES,
    active_configurable_fields,
    masked_categories,
    FIXED_RESTRICTIONS,
    default_allowed_fields,
    normalize_allowed_fields,
)
from ..services.document_ops import delete_document, revoke_owner_categories

router = APIRouter(prefix="/api/privacy", tags=["privacy"])


@router.get("/policy")
def policy():
    s = get_settings()
    return {
        "policy_version": s.policy_version,
        "configurable_fields": [
            {"key": k, "label": v["label"], "category": v["category"], "default": v["default"]}
            for k, v in active_configurable_fields().items()
        ],
        "fixed_restrictions": FIXED_RESTRICTIONS,
        "masked_categories": sorted(masked_categories()),
        "not_masked": [
            CONFIGURABLE_FIELDS[k]["label"] for k, v in CONFIGURABLE_FIELDS.items()
            if v["category"] not in masked_categories() and v["category"] not in CONTENT_CATEGORIES
        ],
        "consents": CONSENT_TYPES,
        "notice": (
            "SecureDoc AI detects and masks sensitive identifiers locally before any external AI processing: "
            "government IDs (Aadhaar, PAN, passport, voter ID, driving licence), bank and card details, "
            "passwords/PINs/OTPs, mobile numbers and email addresses. Other details (e.g. "
            + (", ".join(
                CONFIGURABLE_FIELDS[k]["label"].lower() for k, v in CONFIGURABLE_FIELDS.items()
                if v["category"] not in masked_categories()
            ) or "none")
            + ") are not masked. Restricted identifiers are never stored, never "
            "sent to external AI and never disclosed. "
            "Consenting here records your preferences; it does not by itself establish legal compliance."
        ),
        "groq_configured": s.groq_enabled,
    }


def _pref_out(user: User) -> PreferencesOut:
    s = get_settings()
    p = user.preferences
    if p is None:
        return PreferencesOut(
            allowed_fields=default_allowed_fields(), external_ai_text=False, external_ai_images=False,
            save_history=True, policy_version=s.policy_version, policy_accepted=False,
            current_policy_version=s.policy_version, updated_at=None, onboarding_complete=False,
        )
    return PreferencesOut(
        allowed_fields=normalize_allowed_fields(p.allowed_fields), external_ai_text=p.external_ai_text,
        external_ai_images=p.external_ai_images, save_history=p.save_history, policy_version=p.policy_version,
        policy_accepted=p.policy_accepted, current_policy_version=s.policy_version, updated_at=p.updated_at,
        onboarding_complete=onboarding_complete(p),
    )


@router.get("/preferences", response_model=PreferencesOut)
def get_preferences(user: User = Depends(get_current_user)):
    return _pref_out(user)


def _record(db: Session, user_id: str, consent_type: str, granted: bool, version: str) -> None:
    now = datetime.now(UTC)
    active = db.scalars(
        select(ConsentRecord).where(
            ConsentRecord.user_id == user_id, ConsentRecord.consent_type == consent_type, ConsentRecord.revoked_at.is_(None)
        )
    ).all()
    for rec in active:
        rec.revoked_at = now
    db.add(ConsentRecord(user_id=user_id, consent_type=consent_type, policy_version=version, granted=granted, accepted_at=now))


@router.put("/preferences", response_model=PreferencesOut)
def update_preferences(body: PreferencesIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = get_settings()
    if body.policy_version != s.policy_version:
        raise HTTPException(status_code=400, detail="Policy version mismatch. Please reload and review the current policy.")
    unknown = set(body.allowed_fields) - set(CONFIGURABLE_FIELDS)
    if unknown:
        raise HTTPException(status_code=422, detail="Unknown permission field(s)")
    pref = user.preferences
    first_time = pref is None or not pref.policy_accepted or pref.policy_version != s.policy_version
    if first_time and not body.accept_policy:
        raise HTTPException(status_code=400, detail="You must acknowledge the privacy notice to continue.")

    new_fields = normalize_allowed_fields(body.allowed_fields)
    old_fields = normalize_allowed_fields(pref.allowed_fields) if pref else {}
    old_flags = (
        {"external_ai_text": pref.external_ai_text, "external_ai_images": pref.external_ai_images, "save_history": pref.save_history}
        if pref else {}
    )
    new_flags = {
        "external_ai_text": body.external_ai_text,
        "external_ai_images": body.external_ai_images,
        "save_history": body.save_history,
    }
    try:
        if pref is None:
            pref = PrivacyPreference(user_id=user.id, policy_version=s.policy_version)
            db.add(pref)
        if first_time:
            _record(db, user.id, "privacy_policy", True, s.policy_version)
        for k, v in new_flags.items():
            if first_time or old_flags.get(k) != v:
                _record(db, user.id, k, v, s.policy_version)
        revoked_categories = set()
        for k, v in new_fields.items():
            if first_time or old_fields.get(k) != v:
                _record(db, user.id, f"display_field:{k}", v, s.policy_version)
            if old_fields.get(k) and not v:
                revoked_categories.add(CONFIGURABLE_FIELDS[k]["category"])
        pref.allowed_fields = new_fields
        pref.external_ai_text = body.external_ai_text
        pref.external_ai_images = body.external_ai_images
        pref.save_history = body.save_history
        pref.policy_version = s.policy_version
        pref.policy_accepted = True
        pref.updated_at = datetime.now(UTC)
        # Revocation applies immediately: retained originals for revoked categories are destroyed.
        revoke_owner_categories(db, user.id, revoked_categories)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(user)
    return _pref_out(user)


@router.get("/consents", response_model=list[ConsentOut])
def consents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(ConsentRecord).where(ConsentRecord.user_id == user.id).order_by(ConsentRecord.id.desc())
    ).all()
    return [
        ConsentOut(consent_type=r.consent_type, policy_version=r.policy_version, granted=r.granted,
                   accepted_at=r.accepted_at, revoked_at=r.revoked_at)
        for r in rows
    ]


@router.delete("/documents", status_code=200)
def delete_all_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    docs = db.scalars(select(Document).where(Document.user_id == user.id)).all()
    for d in docs:
        delete_document(db, d)
    return {"deleted": len(docs)}
