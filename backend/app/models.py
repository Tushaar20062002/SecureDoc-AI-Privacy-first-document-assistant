from __future__ import annotations

import uuid
from datetime import datetime, UTC

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .security.encrypted_types import EncryptedJSON, EncryptedText


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan", passive_deletes=True)
    preferences = relationship(
        "PrivacyPreference", back_populates="user", uselist=False, cascade="all, delete-orphan", passive_deletes=True
    )
    documents = relationship("Document", back_populates="user", cascade="all, delete-orphan", passive_deletes=True)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user = relationship("User", back_populates="sessions")


class PrivacyPreference(Base):
    __tablename__ = "privacy_preferences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    allowed_fields: Mapped[dict] = mapped_column(JSON, default=dict)
    external_ai_text: Mapped[bool] = mapped_column(Boolean, default=False)
    external_ai_images: Mapped[bool] = mapped_column(Boolean, default=False)
    save_history: Mapped[bool] = mapped_column(Boolean, default=True)
    policy_version: Mapped[str] = mapped_column(String(20))
    policy_accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user = relationship("User", back_populates="preferences")


class ConsentRecord(Base):
    __tablename__ = "consent_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    consent_type: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(20))
    granted: Mapped[bool] = mapped_column(Boolean)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_consent_user_type", "user_id", "consent_type"),)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    document_name: Mapped[str] = mapped_column(String(255))
    document_type: Mapped[str] = mapped_column(String(64), default="unknown")
    # sanitized document data; encrypted at rest (contains non-sensitive personal data such as names)
    masked_data: Mapped[dict] = mapped_column(EncryptedJSON("documents.masked_data"), default=dict)
    encrypted_owner_fields: Mapped[str | None] = mapped_column(Text, nullable=True)  # AES-256-GCM blob
    masked_pdf_path: Mapped[str | None] = mapped_column(String(255), nullable=True)  # legacy: early file storage, migrated into masked_pdf at startup
    # Masked (sanitized) PDF stored in the database; loaded only when downloaded.
    masked_pdf: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    has_masked_pdf: Mapped[bool] = mapped_column(Boolean, default=False)
    output_mode: Mapped[str] = mapped_column(String(20))
    processing_status: Mapped[str] = mapped_column(String(20), default="processing")
    page_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user = relationship("User", back_populates="documents")
    chat_sessions = relationship(
        "ChatSession", back_populates="document", cascade="all, delete-orphan", passive_deletes=True
    )
    person_details = relationship(
        "PersonDetail", back_populates="document", cascade="all, delete-orphan", passive_deletes=True,
        order_by="PersonDetail.position",
    )


class PersonDetail(Base):
    """One row per extracted person field (structured, minimal). The stored value is the
    DISPLAY value: readable for non-sensitive fields, X-masked for sensitive identifiers
    (originals of restricted identifiers are never stored). Values are encrypted at rest."""

    __tablename__ = "person_details"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    field_name: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(EncryptedText("person_details.value"))
    is_masked: Mapped[bool] = mapped_column(Boolean, default=False)
    page: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    document = relationship("Document", back_populates="person_details")


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200), default="Document chat")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    document = relationship("Document", back_populates="chat_sessions")
    messages = relationship(
        "ChatMessage",
        back_populates="chat_session",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ChatMessage.id",
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chat_session_id: Mapped[str] = mapped_column(ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))
    # sanitized (no restricted originals) and encrypted at rest
    content: Mapped[str] = mapped_column(EncryptedText("chat_messages.content"))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. {"kind": "owner_field", "pages": [1]}
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    chat_session = relationship("ChatSession", back_populates="messages")
