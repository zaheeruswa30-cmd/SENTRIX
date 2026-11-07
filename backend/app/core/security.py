"""Sentrix — password hashing, JWT access tokens and one-time-token hashing."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import get_settings

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(subject: str, tenant_id: str, role: str, minutes: int | None = None) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "tid": tenant_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes or s.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iss": "sentrix",
    }
    return jwt.encode(payload, s.SECRET_KEY, algorithm=s.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    s = get_settings()
    return jwt.decode(token, s.SECRET_KEY, algorithms=[s.JWT_ALGORITHM], issuer="sentrix")


# ── One-time verification secrets ─────────────────────────────────────────────
# Only an HMAC-SHA256 digest (keyed with SECRET_KEY as a pepper) is ever persisted. A database
# leak therefore does not reveal usable tokens, and digests cannot be brute-forced offline
# without the server-side key.

def generate_link_token() -> str:
    """256-bit URL-safe random token for the verification link."""
    return secrets.token_urlsafe(32)


def generate_numeric_code(digits: int = 6) -> str:
    """Uniformly random numeric code (secrets.randbelow avoids modulo bias)."""
    return str(secrets.randbelow(10**digits)).zfill(digits)


def hash_secret(value: str, purpose: str) -> str:
    key = get_settings().SECRET_KEY.encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
