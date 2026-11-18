from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator("password")
    @classmethod
    def _strength(cls, v: str) -> str:
        classes = sum(bool(c) for c in (
            any(ch.islower() for ch in v), any(ch.isupper() for ch in v),
            any(ch.isdigit() for ch in v), any(not ch.isalnum() for ch in v),
        ))
        if classes < 3:
            raise ValueError("Password must include at least 3 of: lowercase, uppercase, digit, symbol")
        return v


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: str
    email: str
    created_at: datetime
    onboarding_complete: bool
    csrf_token: str | None = None


class PreferencesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_fields: dict[str, bool]
    external_ai_text: bool
    external_ai_images: bool
    save_history: bool
    accept_policy: bool = False
    policy_version: str = Field(max_length=20)


class PreferencesOut(BaseModel):
    allowed_fields: dict[str, bool]
    external_ai_text: bool
    external_ai_images: bool
    save_history: bool
    policy_version: str
    policy_accepted: bool
    current_policy_version: str
    updated_at: datetime | None = None
    onboarding_complete: bool


class ConsentOut(BaseModel):
    consent_type: str
    policy_version: str
    granted: bool
    accepted_at: datetime
    revoked_at: datetime | None


class DocumentSummary(BaseModel):
    id: str
    document_name: str
    document_type: str
    processing_status: str
    output_mode: str
    page_count: int
    has_pdf: bool
    has_json: bool
    retained: bool
    expires_at: datetime | None
    created_at: datetime


class DocumentDetail(DocumentSummary):
    masked_data: dict
    person_details: list[dict] = []
    person_json: dict = {}


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=1000)


class ChatMessageOut(BaseModel):
    id: int
    role: Literal["user", "assistant"]
    content: str
    kind: str | None = None
    pages: list[int] = []
    created_at: datetime


class ChatOut(BaseModel):
    user_message: ChatMessageOut
    assistant_message: ChatMessageOut
