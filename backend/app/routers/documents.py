from __future__ import annotations

import io
import json
import logging
import re
import zipfile
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import Document, PersonDetail, User, UserSession, new_id
from ..schemas import DocumentDetail, DocumentSummary
from ..security import encryption
from ..security.auth import get_current_session, get_current_user, rate_limit, require_onboarded_user
from ..security.permissions import RESTRICTED_CATEGORIES, normalize_allowed_fields
from ..services import extraction_service, image_service, pdf_service, storage_service
from ..services.document_ops import (
    delete_document,
    display_masked_data,
    get_owned_document,
    person_json,
    person_rows,
    purge_ephemeral_documents,
)

logger = logging.getLogger("securedoc.documents")
router = APIRouter(prefix="/api/documents", tags=["documents"])


def _summary(d: Document) -> dict:
    return dict(
        id=d.id, document_name=d.document_name, document_type=d.document_type,
        processing_status=d.processing_status, output_mode=d.output_mode, page_count=d.page_count,
        has_pdf=bool(d.has_masked_pdf), has_json=bool(d.masked_data), retained=d.expires_at is None,
        expires_at=d.expires_at, created_at=d.created_at,
    )


ACCEPTED_CONTENT_TYPES = {
    "application/pdf", "application/x-pdf", "application/octet-stream",
    "image/png", "image/jpeg", "image/jpg", "image/pjpeg", "image/webp",
}
_EXT_RE = re.compile(r"\.(pdf|png|jpe?g|webp)$", re.I)
MAX_ZIP_DOCUMENTS = 50


def _masked_name(document_name: str, ext: str) -> str:
    return _safe_name(_EXT_RE.sub("", document_name) + f"_masked.{ext}")


def _safe_name(name: str | None) -> str:
    base = (name or "document.pdf").replace("\\", "/").split("/")[-1]
    base = re.sub(r"[^A-Za-z0-9 ._()-]+", "_", base).strip() or "document.pdf"
    return base[:120]


async def _read_limited(file: UploadFile, limit: int) -> bytes:
    chunks, total = [], 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"File exceeds the {get_settings().max_upload_mb} MB limit.")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/upload", response_model=DocumentDetail, status_code=201, dependencies=[Depends(rate_limit("upload"))])
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    output_mode: Literal["pdf_and_json", "json_only"] = Form("pdf_and_json"),
    sess: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    s = get_settings()
    user = require_onboarded_user(sess.user)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > s.max_upload_bytes + 64 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds the {s.max_upload_mb} MB limit.")
    if file.content_type not in ACCEPTED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="Only PDF, PNG, JPEG and WebP files are accepted.")

    data = await _read_limited(file, s.max_upload_bytes)
    pref = user.preferences
    # The file type is decided by its CONTENT (signature), never by the name or declared type.
    if image_service.sniff(data):
        if not pref.external_ai_images:
            raise HTTPException(
                status_code=400,
                detail="Image files are read by the external vision AI. Turn on 'external image processing' in "
                       "Privacy & Permissions to upload images (no local OCR is used).",
            )
        if not (s.groq_enabled and s.groq_vision_model):
            raise HTTPException(status_code=400, detail="Image processing is not configured on the server.")
        try:
            data = await run_in_threadpool(image_service.image_to_pdf_bytes, data)  # EXIF/metadata dropped
        except image_service.ImageValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
    try:
        pdf_service.validate_signature(data)
    except pdf_service.PDFValidationError:
        raise HTTPException(status_code=400, detail="Unsupported file. Upload a PDF, PNG, JPEG or WebP file.") from None

    allowed = normalize_allowed_fields(pref.allowed_fields)
    temp_path = storage_service.write_temp_original(data)
    del data
    try:
        result = await run_in_threadpool(
            extraction_service.process_document,
            str(temp_path),
            output_mode=output_mode,
            allowed_fields=allowed,
            consent_external_text=pref.external_ai_text,
            consent_external_images=pref.external_ai_images,
        )
        doc_id = new_id()
        owner = {k: v for k, v in result.owner_fields.items() if v["category"] not in RESTRICTED_CATEGORIES}
        doc = Document(
            id=doc_id, user_id=user.id, document_name=_safe_name(file.filename),
            document_type=result.document_type, masked_data=result.masked_data,
            encrypted_owner_fields=encryption.encrypt_json(owner, user.id, doc_id) if owner else None,
            masked_pdf=result.pdf_bytes or None, has_masked_pdf=bool(result.pdf_bytes),
            output_mode=output_mode, processing_status=result.status,
            page_count=result.page_count,
            # History disabled: keep outputs only for the current session.
            expires_at=None if pref.save_history else sess.expires_at,
        )
        db.add(doc)
        # structured, minimal person details (one row per field, value encrypted at rest)
        for i, pf in enumerate(result.person_fields):
            db.add(PersonDetail(
                document_id=doc_id, user_id=user.id, position=i, field_name=pf["field"][:80],
                category=pf["category"][:40], value=pf["value"], is_masked=pf["masked"], page=pf["page"],
            ))
        db.commit()
        db.refresh(doc)
    except pdf_service.PDFValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        # Log only the exception type: messages/tracebacks may embed document content.
        logger.error("Document processing failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Document processing failed.") from None
    finally:
        storage_service.secure_delete(temp_path)

    return _detail(doc, allowed)


def _detail(doc: Document, allowed: dict) -> dict:
    return {
        **_summary(doc),
        "masked_data": display_masked_data(doc.masked_data, allowed),
        "person_details": person_rows(doc, allowed),
        "person_json": person_json(doc, allowed),
    }


@router.get("", response_model=list[DocumentSummary])
def list_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    purge_ephemeral_documents(db)
    docs = db.scalars(select(Document).where(Document.user_id == user.id).order_by(Document.created_at.desc())).all()
    return [_summary(d) for d in docs]


@router.get("/{document_id}", response_model=DocumentDetail)
def get_document(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    allowed = normalize_allowed_fields(user.preferences.allowed_fields if user.preferences else None)
    return _detail(doc, allowed)


@router.get("/{document_id}/download/json")
def download_json(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    allowed = normalize_allowed_fields(user.preferences.allowed_fields if user.preferences else None)
    payload = person_json(doc, allowed)  # person details only; sensitive identifiers X-masked
    name = _masked_name(doc.document_name, "json")
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/download/zip")
def download_zip(
    ids: str = Query(..., max_length=MAX_ZIP_DOCUMENTS * 40),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Masked PDFs (and person JSON) of several of the user's own documents in one ZIP."""
    wanted = [i for i in dict.fromkeys(x.strip() for x in ids.split(",")) if i][:MAX_ZIP_DOCUMENTS]
    if not wanted:
        raise HTTPException(status_code=400, detail="No documents selected.")
    allowed = normalize_allowed_fields(user.preferences.allowed_fields if user.preferences else None)
    buf, used = io.BytesIO(), set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for doc_id in wanted:
            doc = get_owned_document(db, user.id, doc_id)  # 404 for anything not owned by the user
            base = _EXT_RE.sub("", doc.document_name)
            stem, k = base, 2
            while stem in used:
                stem, k = f"{base} ({k})", k + 1
            used.add(stem)
            if doc.has_masked_pdf and doc.masked_pdf:
                zf.writestr(_safe_name(stem + "_masked.pdf"), doc.masked_pdf)
            zf.writestr(_safe_name(stem + "_masked.json"),
                        json.dumps(person_json(doc, allowed), ensure_ascii=False, indent=2, default=str))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="masked_documents.zip"'})


@router.get("/{document_id}/download/pdf")
def download_pdf(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    name = _masked_name(doc.document_name, "pdf")
    if not (doc.has_masked_pdf and doc.masked_pdf):
        raise HTTPException(status_code=404, detail="No masked PDF is available for this document.")
    return Response(doc.masked_pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.delete("/{document_id}", status_code=200)
def remove_document(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    delete_document(db, doc)
    return {"deleted": True}
