"""Private filesystem storage. Files use random names, live outside any web root and
are only served through authenticated, ownership-checked endpoints."""
from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path

from ..config import get_settings

logger = logging.getLogger("securedoc.storage")


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_temp_original(data: bytes) -> Path:
    """Original uploads are written only to the private temp dir and deleted after processing."""
    path = Path(get_settings().temp_dir) / f"{secrets.token_hex(16)}.pdf"
    with open(path, "xb") as fh:
        fh.write(data)
    _restrict(path)
    return path


def secure_delete(path: Path | str | None) -> None:
    if not path:
        return
    p = Path(path)
    try:
        if p.exists():
            size = p.stat().st_size
            with open(p, "r+b") as fh:  # best-effort overwrite before unlink
                fh.write(b"\0" * size)
                fh.flush()
            p.unlink()
    except OSError:
        logger.warning("Failed to delete a temporary file")


def cleanup_stale_temp_files() -> int:
    s = get_settings()
    cutoff = time.time() - s.temp_file_max_age_minutes * 60
    removed = 0
    for p in Path(s.temp_dir).glob("*"):
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                secure_delete(p)
                removed += 1
        except OSError:
            continue
    return removed
