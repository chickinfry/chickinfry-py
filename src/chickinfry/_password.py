"""Internal password KDF boundary; the Pyodide implementation is not selected yet."""

import hashlib
import hmac
import re
import secrets
from typing import Protocol

_FORMAT = re.compile(r"scrypt\$32768\$8\$3\$([a-f0-9]{32})\$([a-f0-9]{64})")


class PasswordKDF(Protocol):
    def derive(self, password: bytes, salt: bytes) -> bytes: ...


class CPythonScrypt:
    # shortcut: CPython/OpenSSL only; Pyodide needs a separately measured implementation.
    def derive(self, password: bytes, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password, salt=salt, n=32768, r=8, p=3, maxmem=64 << 20, dklen=32
        )


def hash_password(password: str, kdf: PasswordKDF) -> str:
    salt = secrets.token_bytes(16)
    key = kdf.derive(password.encode("utf-8"), salt)
    if len(key) != 32:
        raise ValueError("Password hashing failed.")
    return f"scrypt$32768$8$3${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str | None, kdf: PasswordKDF) -> bool:
    parts = _FORMAT.fullmatch(stored) if isinstance(stored, str) else None
    salt = bytes.fromhex(parts[1]) if parts else bytes(16)
    expected = bytes.fromhex(parts[2]) if parts else bytes(32)
    actual = kdf.derive(password.encode("utf-8"), salt)
    matched = hmac.compare_digest(actual, expected)
    return parts is not None and matched and len(actual) == 32
