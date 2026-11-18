from __future__ import annotations

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import get_settings
from .database import SessionLocal, init_db
from .routers import auth, chat, documents, privacy
from .services import groq_service, storage_service
from .services.document_ops import purge_ephemeral_documents, purge_expired_sessions


# ------------------------------------------------------------------ sanitized logging
class RedactingFilter(logging.Filter):
    """Safety net: scrub emails and long digit runs from any log message."""

    _EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    _DIGITS = re.compile(r"\d[\d -]{7,}\d")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        clean = self._DIGITS.sub("[REDACTED]", self._EMAIL.sub("[REDACTED]", msg))
        if clean != msg:
            record.msg, record.args = clean, ()
        return True


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
for h in logging.getLogger().handlers:
    h.addFilter(RedactingFilter())
logger = logging.getLogger("securedoc")


async def _maintenance_loop() -> None:
    while True:
        await asyncio.sleep(300)
        try:
            with SessionLocal() as db:
                purge_expired_sessions(db)
                purge_ephemeral_documents(db)
            storage_service.cleanup_stale_temp_files()
        except Exception:  # noqa: BLE001
            logger.warning("Maintenance task failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    init_db()
    storage_service.cleanup_stale_temp_files()
    if s.groq_enabled and s.app_env != "test":
        try:
            status = await asyncio.to_thread(groq_service.verify_configured_models)
            for model, ok in status.items():
                logger.info("Groq model %s available: %s", model, ok)
        except Exception:  # noqa: BLE001
            logger.warning("Could not verify Groq model availability at startup")
    elif not s.groq_enabled:
        logger.warning("GROQ_API_KEY not set: local extraction/answering fallback will be used.")
    task = asyncio.create_task(_maintenance_loop())
    yield
    task.cancel()


settings = get_settings()
app = FastAPI(
    title="SecureDoc AI API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.app_env != "production" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.app_env != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than the upload limit while streaming (ASGI level)."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.max_bytes if scope["path"].endswith("/upload") else 64 * 1024
        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl and cl.isdigit() and int(cl) > limit:
            return await _send_json(send, 413, "Request body too large.")
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await _send_json(send, 413, "Request body too large.")


class _TooLarge(Exception):
    pass


async def _send_json(send, status: int, detail: str) -> None:
    body = ('{"detail":"%s"}' % detail).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + 64 * 1024)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Origin check for state-changing requests (defence in depth alongside CSRF tokens).
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin and origin != "null":
            host = request.headers.get("host", "")
            if origin not in settings.cors_origin_list and urlparse(origin).netloc != host:
                return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/docs"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Never echo submitted values (could contain passwords or PII).
    errors = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg", "Invalid value")} for e in exc.errors()]
    return JSONResponse({"detail": "Invalid request", "errors": errors}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, type(exc).__name__)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/api/health")
def health():
    return {"status": "ok", "groq_configured": settings.groq_enabled}


app.include_router(auth.router)
app.include_router(privacy.router)
app.include_router(documents.router)
app.include_router(chat.router)
