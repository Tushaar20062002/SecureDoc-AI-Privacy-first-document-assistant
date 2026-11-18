from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ChatMessage, ChatSession, User
from ..schemas import ChatIn, ChatOut
from ..security import encryption
from ..security.auth import get_current_user, rate_limit
from ..security.permissions import normalize_allowed_fields
from ..services import chat_service
from ..services.document_ops import get_owned_document

logger = logging.getLogger("securedoc.chat")
router = APIRouter(prefix="/api/documents", tags=["chat"])


def _owner_values(doc) -> dict:
    try:
        return encryption.decrypt_json(doc.encrypted_owner_fields, doc.user_id, doc.id)
    except encryption.DecryptionError:
        logger.warning("Owner field decryption failed for a document")
        return {}


def _msg_out(m: ChatMessage, content: str) -> dict:
    return {
        "id": m.id, "role": m.role, "content": content, "kind": (m.meta or {}).get("kind"),
        "pages": (m.meta or {}).get("pages", []), "created_at": m.created_at,
    }


@router.post("/{document_id}/chat", response_model=ChatOut, dependencies=[Depends(rate_limit("chat"))])
async def chat(document_id: str, body: ChatIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    pref = user.preferences
    allowed = normalize_allowed_fields(pref.allowed_fields if pref else None)
    session = db.scalar(select(ChatSession).where(ChatSession.document_id == doc.id, ChatSession.user_id == user.id))
    if session is None:
        session = ChatSession(user_id=user.id, document_id=doc.id, title=doc.document_name[:200])
        db.add(session)
        db.flush()
    history = [{"role": m.role, "content": m.content} for m in session.messages]
    owner_values = _owner_values(doc)

    answer = await run_in_threadpool(
        chat_service.answer_question,
        question=body.message,
        masked=doc.masked_data,
        owner_values=owner_values,
        allowed_fields=allowed,
        consent_external_text=bool(pref and pref.external_ai_text),
        history=history,
    )
    # Persist sanitized text only (placeholders; never original values).
    user_msg = ChatMessage(chat_session_id=session.id, role="user",
                           content=chat_service.sanitize_user_text(body.message), meta={"kind": "question"})
    bot_msg = ChatMessage(chat_session_id=session.id, role="assistant", content=answer.stored,
                          meta={"kind": answer.kind, "pages": answer.pages})
    db.add_all([user_msg, bot_msg])
    db.commit()
    return {"user_message": _msg_out(user_msg, user_msg.content), "assistant_message": _msg_out(bot_msg, answer.display)}


@router.get("/{document_id}/chat/history")
def chat_history(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = get_owned_document(db, user.id, document_id)
    allowed = normalize_allowed_fields(user.preferences.allowed_fields if user.preferences else None)
    session = db.scalar(select(ChatSession).where(ChatSession.document_id == doc.id, ChatSession.user_id == user.id))
    if session is None:
        return {"document_id": doc.id, "messages": []}
    owner_values = _owner_values(doc)
    msgs = []
    for m in session.messages:
        content = m.content
        if m.role == "assistant" and (m.meta or {}).get("kind") == "owner_field":
            # re-evaluated against CURRENT permissions on every read
            content = chat_service.hydrate(content, owner_values, allowed)
        msgs.append(_msg_out(m, content))
    return {"document_id": doc.id, "messages": msgs}
