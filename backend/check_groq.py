"""Verify the configured Groq models are currently available for your API key.

Usage (from backend/):  .venv/Scripts/python check_groq.py
"""
from app.config import get_settings
from app.services import groq_service


def main() -> None:
    s = get_settings()
    if not s.groq_enabled:
        print("GROQ_API_KEY is not set in backend/.env - the app will use local fallbacks.")
        return
    models = groq_service.list_models()
    print(f"{len(models)} models available for this key.")
    for name, ok in groq_service.verify_configured_models().items():
        print(f"  {'OK     ' if ok else 'MISSING'} {name}")
    if s.groq_model not in models:
        key = s.groq_model.split("/")[-1].lower()[:4]
        close = sorted(m for m in models if key in m.lower() or "qwen" in m.lower())
        print("Configured GROQ_MODEL not found. Similar available IDs:", ", ".join(close) or "(none)")
        print("All available:", ", ".join(sorted(models)))
    vision = [m for m in models if any(k in m for k in ("scout", "maverick", "vision"))]
    if vision:
        print("Vision-capable candidates:", ", ".join(vision))


if __name__ == "__main__":
    main()
