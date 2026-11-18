from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
engine = create_engine(
    _settings.database_url,
    connect_args={"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
    if _settings.database_url.startswith("sqlite"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA secure_delete=ON")  # overwrite deleted content in the DB file
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register models)

    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate() -> None:
    """Minimal additive migration for existing SQLite databases."""
    from sqlalchemy import inspect, text

    cols = {c["name"] for c in inspect(engine).get_columns("documents")}
    with engine.begin() as conn:
        if "masked_pdf" not in cols:
            conn.execute(text("ALTER TABLE documents ADD COLUMN masked_pdf BLOB"))
        if "has_masked_pdf" not in cols:
            conn.execute(text("ALTER TABLE documents ADD COLUMN has_masked_pdf BOOLEAN DEFAULT 0"))
            conn.execute(text("UPDATE documents SET has_masked_pdf = 1 WHERE masked_pdf_path IS NOT NULL"))
        # Early versions kept masked PDFs as files: move them into the database and delete the files.
        legacy = conn.execute(text("SELECT id, masked_pdf_path FROM documents "
                                   "WHERE masked_pdf_path IS NOT NULL AND masked_pdf IS NULL")).fetchall()
        for doc_id, name in legacy:
            _adopt_legacy_pdf(conn, doc_id, name)


def _adopt_legacy_pdf(conn, doc_id: str, name: str) -> None:
    from sqlalchemy import text

    from .services import storage_service

    base = Path(get_settings().storage_dir).resolve()
    path = (base / name).resolve() if name and "/" not in name and "\\" not in name and ".." not in name else None
    if path and path.parent == base and path.is_file():
        conn.execute(text("UPDATE documents SET masked_pdf = :b, has_masked_pdf = 1, masked_pdf_path = NULL "
                          "WHERE id = :i"), {"b": path.read_bytes(), "i": doc_id})
        storage_service.secure_delete(path)
    else:
        conn.execute(text("UPDATE documents SET has_masked_pdf = 0, masked_pdf_path = NULL WHERE id = :i"),
                     {"i": doc_id})
