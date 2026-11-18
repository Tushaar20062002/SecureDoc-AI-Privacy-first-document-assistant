"""SQLAlchemy column types that transparently encrypt values at rest (AES-256-GCM).

The application reads and writes normal Python values; the database file only ever
contains ciphertext ("enc:v1:..."). Keys live outside the database (env / key file).
Legacy plaintext rows are still readable and are encrypted on their next write.
"""
from __future__ import annotations

import json

from sqlalchemy.types import Text, TypeDecorator

from .encryption import decrypt_column, encrypt_column


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def __init__(self, column: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.column = column

    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt_column(str(value), self.column)

    def process_result_value(self, value, dialect):
        return decrypt_column(value, self.column)


class EncryptedJSON(TypeDecorator):
    impl = Text
    cache_ok = True

    def __init__(self, column: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.column = column

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return encrypt_column(json.dumps(value, ensure_ascii=False, default=str), self.column)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        plain = decrypt_column(value, self.column)
        return json.loads(plain) if isinstance(plain, str) else plain
