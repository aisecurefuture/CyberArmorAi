"""TOTP (RFC 6238) + backup-code helpers for dashboard-auth.

Secrets are encrypted at rest with Fernet. The key is derived from the
service's SESSION_SECRET via PBKDF2-HMAC-SHA256, so rotating the session
secret also rotates the KEK (existing sessions already invalidate on
that rotation, so this is a consistent story).
"""
from __future__ import annotations

import base64
import hashlib
import io
import secrets
from typing import List

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_BACKUP_CODE_BYTES = 4  # 8 hex chars => "XXXX-XXXX"


def _derive_key(session_secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=120_000)
    return base64.urlsafe_b64encode(kdf.derive(session_secret.encode("utf-8")))


class TOTPCipher:
    """Encrypts TOTP secrets before they touch the DB."""

    def __init__(self, session_secret: str, salt: bytes = b"ca-totp-kek-v1") -> None:
        if not session_secret:
            raise ValueError("session_secret required for TOTP encryption")
        self._fernet = Fernet(_derive_key(session_secret, salt))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def generate_secret() -> str:
    return pyotp.random_base32()


def otpauth_uri(secret: str, label: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)


def qr_svg(uri: str) -> str:
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(uri, image_factory=factory, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def _normalize_code(code: str) -> str:
    return "".join(ch for ch in (code or "") if ch.isalnum())


def verify_totp(secret: str, code: str) -> bool:
    code = _normalize_code(code)
    if not secret or len(code) != 6 or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(n: int = 10) -> List[str]:
    """Plaintext codes returned to the user ONCE (formatted XXXX-XXXX)."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(_BACKUP_CODE_BYTES).upper()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def hash_backup_code(session_secret: str, code: str) -> str:
    normalized = _normalize_code(code).upper()
    return hashlib.sha256(f"{session_secret}:{normalized}".encode("utf-8")).hexdigest()
