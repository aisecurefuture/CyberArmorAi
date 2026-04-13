from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import smtplib
import time
from email.message import EmailMessage
from typing import Annotated, Optional

from fastapi import Cookie, FastAPI, HTTPException, Response, status
from pydantic import BaseModel

logger = logging.getLogger("dashboard_auth")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

SESSION_COOKIE = "ca_dashboard_session"
CODE_TTL_SECONDS = int(os.getenv("ADMIN_DASHBOARD_CODE_TTL_SECONDS", "600"))
SESSION_TTL_SECONDS = int(os.getenv("ADMIN_DASHBOARD_SESSION_TTL_SECONDS", "28800"))
MAX_CODE_ATTEMPTS = int(os.getenv("ADMIN_DASHBOARD_MAX_CODE_ATTEMPTS", "5"))
DEV_CODE_ECHO = os.getenv("ADMIN_DASHBOARD_AUTH_DEV_CODE_ECHO", "false").strip().lower() in {"1", "true", "yes", "on"}
COOKIE_SECURE = os.getenv("ADMIN_DASHBOARD_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}

SESSION_SECRET = os.getenv("ADMIN_DASHBOARD_SESSION_SECRET", "")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(48)
    logger.warning("ADMIN_DASHBOARD_SESSION_SECRET is unset; sessions will reset on container restart")

ALLOWED_EMAILS = {
    item.strip().lower()
    for item in os.getenv("ADMIN_DASHBOARD_ALLOWED_EMAILS", "").split(",")
    if item.strip()
}

_codes: dict[str, tuple[str, float]] = {}
_code_attempts: dict[str, int] = {}
_sessions: dict[str, tuple[str, float]] = {}

app = FastAPI(title="CyberArmor Dashboard Auth", version="0.1.0")


class CodeRequest(BaseModel):
    email: str


class CodeVerify(BaseModel):
    email: str
    code: str


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _valid_email(email: str) -> bool:
    return bool(email) and "@" in email and "." in email.rsplit("@", 1)[-1]


def _hash_code(email: str, code: str) -> str:
    material = f"{email}:{code}:{SESSION_SECRET}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _sign_session(token: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _pack_session(token: str) -> str:
    return f"{token}.{_sign_session(token)}"


def _unpack_session(cookie_value: str | None) -> Optional[str]:
    if not cookie_value or "." not in cookie_value:
        return None
    token, supplied_sig = cookie_value.rsplit(".", 1)
    expected_sig = _sign_session(token)
    if not hmac.compare_digest(supplied_sig, expected_sig):
        return None
    return token


def _session_email(cookie_value: str | None) -> Optional[str]:
    token = _unpack_session(cookie_value)
    if not token:
        return None
    item = _sessions.get(token)
    if not item:
        return None
    email, expires_at = item
    if expires_at < time.time():
        _sessions.pop(token, None)
        return None
    if email not in ALLOWED_EMAILS:
        _sessions.pop(token, None)
        return None
    return email


def _send_code(email: str, code: str) -> None:
    smtp_host = os.getenv("ADMIN_DASHBOARD_SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("ADMIN_DASHBOARD_SMTP_PORT", "587"))
    smtp_user = os.getenv("ADMIN_DASHBOARD_SMTP_USER", "").strip()
    smtp_password = os.getenv("ADMIN_DASHBOARD_SMTP_PASSWORD", "")
    smtp_from = os.getenv("ADMIN_DASHBOARD_SMTP_FROM", smtp_user or "no-reply@localhost").strip()
    use_tls = os.getenv("ADMIN_DASHBOARD_SMTP_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

    if not smtp_host:
        logger.warning("Dashboard login code for %s: %s", email, code)
        return

    msg = EmailMessage()
    msg["Subject"] = "Your CyberArmor admin dashboard login code"
    msg["From"] = smtp_from
    msg["To"] = email
    msg.set_content(
        "Your CyberArmor admin dashboard login code is:\n\n"
        f"{code}\n\n"
        f"This code expires in {CODE_TTL_SECONDS // 60} minutes."
    )
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        if smtp_user:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "allowed_email_count": len(ALLOWED_EMAILS)}


@app.get("/session")
def session_check(ca_dashboard_session: Annotated[str | None, Cookie()] = None) -> Response:
    email = _session_email(ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"x-dashboard-user-email": email})


@app.get("/me")
def me(ca_dashboard_session: Annotated[str | None, Cookie()] = None) -> dict[str, str]:
    email = _session_email(ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"email": email}


@app.post("/request-code")
def request_code(body: CodeRequest) -> dict[str, object]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A valid email is required")
    if email in ALLOWED_EMAILS:
        code = f"{secrets.randbelow(1_000_000):06d}"
        _codes[email] = (_hash_code(email, code), time.time() + CODE_TTL_SECONDS)
        _code_attempts[email] = 0
        _send_code(email, code)
        if DEV_CODE_ECHO:
            return {"ok": True, "message": "Code generated for authorized email.", "dev_code": code}
    else:
        logger.warning("Dashboard login requested for non-allowlisted email: %s", email)
    return {"ok": True, "message": "If this email is authorized, a login code has been sent."}


@app.post("/verify-code")
def verify_code(body: CodeVerify, response: Response) -> dict[str, object]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A valid email is required")
    code = "".join(ch for ch in body.code if ch.isdigit())
    item = _codes.get(email)
    if email not in ALLOWED_EMAILS or not item or len(code) != 6:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")
    expected_hash, expires_at = item
    if expires_at < time.time():
        _codes.pop(email, None)
        _code_attempts.pop(email, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")
    if not hmac.compare_digest(expected_hash, _hash_code(email, code)):
        attempts = _code_attempts.get(email, 0) + 1
        if attempts >= MAX_CODE_ATTEMPTS:
            _codes.pop(email, None)
            _code_attempts.pop(email, None)
        else:
            _code_attempts[email] = attempts
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")

    _codes.pop(email, None)
    _code_attempts.pop(email, None)
    token = secrets.token_urlsafe(48)
    _sessions[token] = (email, time.time() + SESSION_TTL_SECONDS)
    response.set_cookie(
        SESSION_COOKIE,
        _pack_session(token),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"ok": True, "email": email}


@app.post("/logout")
def logout(response: Response, ca_dashboard_session: Annotated[str | None, Cookie()] = None) -> dict[str, bool]:
    token = _unpack_session(ca_dashboard_session)
    if token:
        _sessions.pop(token, None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}
