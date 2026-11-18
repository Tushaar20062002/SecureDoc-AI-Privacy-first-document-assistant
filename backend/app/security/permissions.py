"""Central privacy policy. The backend is the single source of truth for what
may be disclosed. Neither the frontend nor the LLM can override these rules."""
from __future__ import annotations

from typing import Any

# --- Category B: restricted. Never retained, never sent to Groq, never disclosed.
RESTRICTED_CATEGORIES: frozenset[str] = frozenset(
    {
        "AADHAAR",
        "PAN",
        "PASSPORT",
        "BANK_ACCOUNT",
        "IFSC",
        "CREDIT_CARD",
        "CVV",
        "PASSWORD",
        "PIN",
        "OTP",
        "IP_ADDRESS",
        "OTHER_ID",
    }
)

# --- Category A: owner-visible, user configurable.
# field key -> (label, PII category or None for non-PII content categories, default)
CONFIGURABLE_FIELDS: dict[str, dict[str, Any]] = {
    "name": {"label": "Name", "category": "PERSON", "default": True},
    "address": {"label": "Residential address", "category": "ADDRESS", "default": True},
    "email": {"label": "Email address", "category": "EMAIL", "default": False},
    "phone": {"label": "Phone number", "category": "PHONE", "default": False},
    "dob": {"label": "Date of birth", "category": "DOB", "default": False},
    "education": {"label": "Education / qualification", "category": "EDUCATION", "default": True},
    "employment": {"label": "Employment history", "category": "EMPLOYMENT", "default": True},
    "application_reference": {"label": "Application reference numbers", "category": "APP_REF", "default": True},
}

CATEGORY_TO_FIELD = {v["category"]: k for k, v in CONFIGURABLE_FIELDS.items()}

# All personal-data categories the detector can find.
MASKED_PII_CATEGORIES: frozenset[str] = RESTRICTED_CATEGORIES | {"PERSON", "ADDRESS", "EMAIL", "PHONE", "DOB", "APP_REF"}


def masked_categories() -> frozenset[str]:
    """Categories actually masked (placeholders / X-masks) under the current server policy.
    Restricted categories are always included and cannot be configured away."""
    from ..config import get_settings

    extra = {c.strip().upper() for c in get_settings().mask_categories.split(",") if c.strip()}
    return frozenset(RESTRICTED_CATEGORIES | (extra & MASKED_PII_CATEGORIES))

# Non-PII content categories: kept readable in masked JSON but display is permission-gated.
CONTENT_CATEGORIES: frozenset[str] = frozenset({"EDUCATION", "EMPLOYMENT"})

FIXED_RESTRICTIONS = [
    "Aadhaar numbers",
    "PAN",
    "Passport numbers",
    "Bank account numbers and IFSC codes",
    "Payment card numbers and CVV",
    "Passwords, PINs, OTPs and other authentication secrets",
    "IP addresses and other government identifiers (voter ID, driving licence, etc.)",
]

CONSENT_TYPES = {
    "privacy_policy": "I have read the privacy notice describing how SecureDoc AI processes my documents.",
    "external_ai_text": (
        "Send document text to the external AI provider Groq for structured extraction and question "
        "answering. Sensitive identifiers (Aadhaar, PAN, passport and other government IDs, bank and card "
        "details, passwords/PINs/OTPs, mobile numbers and email addresses) are masked locally first and are "
        "never sent. Non-sensitive details such as names, addresses, dates, education and employment ARE sent."
    ),
    "external_ai_images": (
        "Send ORIGINAL scanned page images to Groq's vision model. Scanned pages may contain "
        "unmasked personal data (including Aadhaar, PAN or bank details) that WILL be visible to "
        "the external provider. Only enable this if you accept that risk."
    ),
    "save_history": "Keep masked documents, masked outputs and chat history after I log out.",
}

RESTRICTED_REFUSAL = (
    "I’m sorry, but I cannot access or reveal sensitive personal information such as Aadhaar "
    "numbers, PAN numbers or bank account details. This information is protected to maintain your privacy."
)
OUT_OF_SCOPE = "I can only answer questions related to your selected document."
NOT_FOUND = "I could not find this information in your uploaded document."


def active_configurable_fields() -> dict[str, dict[str, Any]]:
    """Permission toggles that are meaningful under the current masking policy: masked
    owner-visible categories (e.g. email, phone) and content categories."""
    active = masked_categories()
    return {
        k: v for k, v in CONFIGURABLE_FIELDS.items()
        if v["category"] in active or v["category"] in CONTENT_CATEGORIES
    }


def default_allowed_fields() -> dict[str, bool]:
    return {k: bool(v["default"]) for k, v in CONFIGURABLE_FIELDS.items()}


def normalize_allowed_fields(raw: dict[str, Any] | None) -> dict[str, bool]:
    base = default_allowed_fields()
    if raw:
        for k, v in raw.items():
            if k in base:
                base[k] = bool(v)
    return base


def category_permitted(category: str, allowed_fields: dict[str, bool]) -> bool:
    """True only for owner-visible categories the user enabled. Restricted is always False."""
    category = category.upper()
    if category in RESTRICTED_CATEGORIES:
        return False
    field = CATEGORY_TO_FIELD.get(category)
    if field is None:
        return False
    return bool(allowed_fields.get(field, False))
