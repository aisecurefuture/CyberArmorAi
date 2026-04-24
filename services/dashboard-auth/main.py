from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Annotated, List, Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine, ensure_sqlite_dir
from models import AdminUser, DashboardSession, LoginCode
from totp import (
    TOTPCipher,
    generate_backup_codes,
    generate_secret,
    hash_backup_code,
    otpauth_uri,
    qr_svg,
    verify_totp,
)

logger = logging.getLogger("dashboard_auth")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

SESSION_COOKIE = "ca_dashboard_session"
CSRF_COOKIE = "ca_dashboard_csrf"
CSRF_HEADER = "x-csrf-token"
MFA_TICKET_COOKIE = "ca_dashboard_mfa"
MFA_TICKET_TTL_SECONDS = int(os.getenv("ADMIN_DASHBOARD_MFA_TICKET_TTL_SECONDS", "300"))
MFA_ISSUER = os.getenv("ADMIN_DASHBOARD_MFA_ISSUER", "CyberArmor Admin")
MFA_REQUIRED = os.getenv("ADMIN_DASHBOARD_MFA_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"}
CODE_TTL_SECONDS = int(os.getenv("ADMIN_DASHBOARD_CODE_TTL_SECONDS", "600"))
SESSION_TTL_SECONDS = int(os.getenv("ADMIN_DASHBOARD_SESSION_TTL_SECONDS", "28800"))
MAX_CODE_ATTEMPTS = int(os.getenv("ADMIN_DASHBOARD_MAX_CODE_ATTEMPTS", "5"))
DEV_CODE_ECHO = os.getenv("ADMIN_DASHBOARD_AUTH_DEV_CODE_ECHO", "false").strip().lower() in {"1", "true", "yes", "on"}
COOKIE_SECURE = os.getenv("ADMIN_DASHBOARD_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}

SESSION_SECRET = os.getenv("ADMIN_DASHBOARD_SESSION_SECRET", "")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(48)
    logger.warning(
        "ADMIN_DASHBOARD_SESSION_SECRET is unset; cookie signatures will be invalidated on restart"
    )

ALLOWED_EMAILS = {
    item.strip().lower()
    for item in os.getenv("ADMIN_DASHBOARD_ALLOWED_EMAILS", "").split(",")
    if item.strip()
}

ensure_sqlite_dir()
Base.metadata.create_all(bind=engine)

_cipher = TOTPCipher(SESSION_SECRET)

app = FastAPI(title="CyberArmor Dashboard Auth", version="0.2.0")


_CSRF_PROTECTED_PATHS = {
    "/logout",
    "/me/totp/enroll",
    "/me/totp/confirm",
    "/me/totp",
    "/me/totp/backup-codes",
}


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """Double-submit CSRF guard for cookie-authenticated mutating routes.

    Bootstrap paths (request-code, verify-code, verify-totp) are
    intentionally exempt — no full session cookie exists yet at those
    points.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return await call_next(request)
    path = request.url.path
    if path in _CSRF_PROTECTED_PATHS and request.cookies.get(SESSION_COOKIE):
        cookie_token = request.cookies.get(CSRF_COOKIE)
        header_token = request.headers.get(CSRF_HEADER)
        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
            return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
    return await call_next(request)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _session_email(db: Session, cookie_value: str | None) -> Optional[str]:
    token = _unpack_session(cookie_value)
    if not token:
        return None
    row = db.get(DashboardSession, token)
    if not row:
        return None
    now = _utcnow()
    expires = row.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires is None or expires < now:
        db.delete(row)
        db.commit()
        return None
    if row.email not in ALLOWED_EMAILS:
        db.delete(row)
        db.commit()
        return None
    row.last_seen_at = now
    db.commit()
    return row.email


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


def _sign_mfa_ticket(email: str, expires: int) -> str:
    payload = f"{email}|{expires}"
    sig = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        f"mfa:{payload}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}|{sig}"


def _verify_mfa_ticket(ticket: Optional[str]) -> Optional[str]:
    if not ticket:
        return None
    parts = ticket.split("|")
    if len(parts) != 3:
        return None
    email, expires_str, supplied_sig = parts
    try:
        expires = int(expires_str)
    except ValueError:
        return None
    if expires < int(time.time()):
        return None
    expected = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        f"mfa:{email}|{expires}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, supplied_sig):
        return None
    return email


def _load_admin(db: Session, email: str) -> Optional[AdminUser]:
    return db.get(AdminUser, email)


def _ensure_admin_row(db: Session, email: str) -> AdminUser:
    row = _load_admin(db, email)
    if row is None:
        row = AdminUser(email=email)
        db.add(row)
        db.flush()
    return row


def _issue_full_session(db: Session, response: Response, email: str) -> dict:
    token = secrets.token_urlsafe(48)
    now = _utcnow()
    db.add(DashboardSession(
        token=token,
        email=email,
        expires_at=now + timedelta(seconds=SESSION_TTL_SECONDS),
        created_at=now,
        last_seen_at=now,
    ))
    db.commit()
    response.set_cookie(
        SESSION_COOKIE,
        _pack_session(token),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        max_age=SESSION_TTL_SECONDS,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(MFA_TICKET_COOKIE, path="/")
    return {"ok": True, "email": email}


def _issue_mfa_ticket(response: Response, email: str) -> dict:
    expires = int(time.time()) + MFA_TICKET_TTL_SECONDS
    ticket = _sign_mfa_ticket(email, expires)
    response.set_cookie(
        MFA_TICKET_COOKIE,
        ticket,
        max_age=MFA_TICKET_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"ok": True, "mfa_required": True, "email": email}


def _load_backup_hashes(row: AdminUser) -> List[str]:
    if not row.backup_codes_hash:
        return []
    try:
        value = json.loads(row.backup_codes_hash)
        return list(value) if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def _consume_backup_code(row: AdminUser, code: str) -> bool:
    hashes = _load_backup_hashes(row)
    if not hashes:
        return False
    target = hash_backup_code(SESSION_SECRET, code)
    if target not in hashes:
        return False
    hashes.remove(target)
    row.backup_codes_hash = json.dumps(hashes)
    return True


def _purge_expired(db: Session) -> None:
    now = _utcnow()
    db.query(DashboardSession).filter(DashboardSession.expires_at < now).delete(synchronize_session=False)
    db.query(LoginCode).filter(LoginCode.expires_at < now).delete(synchronize_session=False)
    db.commit()


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "allowed_email_count": len(ALLOWED_EMAILS)}


@app.get("/session")
def session_check(
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> Response:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"x-dashboard-user-email": email})


@app.get("/me")
def me(
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict[str, str]:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"email": email}


@app.post("/request-code")
def request_code(
    body: CodeRequest,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A valid email is required")
    _purge_expired(db)
    if email in ALLOWED_EMAILS:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = _utcnow() + timedelta(seconds=CODE_TTL_SECONDS)
        existing = db.get(LoginCode, email)
        if existing is None:
            db.add(LoginCode(
                email=email,
                code_hash=_hash_code(email, code),
                attempts=0,
                expires_at=expires,
            ))
        else:
            existing.code_hash = _hash_code(email, code)
            existing.attempts = 0
            existing.expires_at = expires
        db.commit()
        _send_code(email, code)
        if DEV_CODE_ECHO:
            return {"ok": True, "message": "Code generated for authorized email.", "dev_code": code}
    else:
        logger.warning("Dashboard login requested for non-allowlisted email: %s", email)
    return {"ok": True, "message": "If this email is authorized, a login code has been sent."}


@app.post("/verify-code")
def verify_code(
    body: CodeVerify,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A valid email is required")
    code = "".join(ch for ch in body.code if ch.isdigit())
    row = db.get(LoginCode, email)
    if email not in ALLOWED_EMAILS or row is None or len(code) != 6:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")
    expires = row.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires is None or expires < _utcnow():
        db.delete(row)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")
    if not hmac.compare_digest(row.code_hash, _hash_code(email, code)):
        row.attempts = (row.attempts or 0) + 1
        if row.attempts >= MAX_CODE_ATTEMPTS:
            db.delete(row)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired code")

    db.delete(row)
    db.commit()

    admin = _load_admin(db, email)
    mfa_enabled = bool(admin and admin.totp_enabled and admin.totp_secret_enc)
    if mfa_enabled:
        return _issue_mfa_ticket(response, email)
    if MFA_REQUIRED:
        # Allow a first-time login so the operator can enroll, but the
        # UI routes them directly into the enrollment flow.
        session_payload = _issue_full_session(db, response, email)
        session_payload["mfa_enrollment_required"] = True
        return session_payload
    return _issue_full_session(db, response, email)


class TOTPVerify(BaseModel):
    code: str


@app.post("/verify-totp")
def verify_totp_endpoint(
    body: TOTPVerify,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_mfa: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _verify_mfa_ticket(ca_dashboard_mfa)
    if not email or email not in ALLOWED_EMAILS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA ticket missing or expired")
    admin = _load_admin(db, email)
    if not admin or not admin.totp_enabled or not admin.totp_secret_enc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA not enrolled")

    code = body.code or ""
    secret = _cipher.decrypt(admin.totp_secret_enc)
    if verify_totp(secret, code):
        return _issue_full_session(db, response, email)
    if _consume_backup_code(admin, code):
        db.commit()
        return _issue_full_session(db, response, email)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")


class TOTPConfirm(BaseModel):
    code: str


@app.get("/me/totp/status")
def totp_status(
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin = _load_admin(db, email)
    hashes = _load_backup_hashes(admin) if admin else []
    return {
        "email": email,
        "totp_enabled": bool(admin and admin.totp_enabled),
        "enrollment_in_progress": bool(admin and admin.totp_pending_enc),
        "backup_codes_remaining": len(hashes),
        "mfa_required": MFA_REQUIRED,
    }


@app.post("/me/totp/enroll")
def totp_enroll(
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin = _ensure_admin_row(db, email)
    secret = generate_secret()
    admin.totp_pending_enc = _cipher.encrypt(secret)
    db.commit()
    uri = otpauth_uri(secret, email, MFA_ISSUER)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": qr_svg(uri),
    }


@app.post("/me/totp/confirm")
def totp_confirm(
    body: TOTPConfirm,
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin = _load_admin(db, email)
    if not admin or not admin.totp_pending_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No enrollment in progress")
    pending = _cipher.decrypt(admin.totp_pending_enc)
    if not verify_totp(pending, body.code or ""):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    admin.totp_secret_enc = admin.totp_pending_enc
    admin.totp_pending_enc = None
    admin.totp_enabled = True
    backup_codes = generate_backup_codes()
    admin.backup_codes_hash = json.dumps([hash_backup_code(SESSION_SECRET, c) for c in backup_codes])
    db.commit()
    return {"ok": True, "backup_codes": backup_codes}


class TOTPDisable(BaseModel):
    code: str


@app.delete("/me/totp")
def totp_disable(
    body: TOTPDisable,
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin = _load_admin(db, email)
    if not admin or not admin.totp_enabled or not admin.totp_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    secret = _cipher.decrypt(admin.totp_secret_enc)
    if not (verify_totp(secret, body.code or "") or _consume_backup_code(admin, body.code or "")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    admin.totp_secret_enc = None
    admin.totp_pending_enc = None
    admin.totp_enabled = False
    admin.backup_codes_hash = None
    db.commit()
    return {"ok": True}


@app.post("/me/totp/backup-codes")
def totp_regenerate_backup_codes(
    body: TOTPVerify,
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict:
    email = _session_email(db, ca_dashboard_session)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin = _load_admin(db, email)
    if not admin or not admin.totp_enabled or not admin.totp_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    secret = _cipher.decrypt(admin.totp_secret_enc)
    if not verify_totp(secret, body.code or ""):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    new_codes = generate_backup_codes()
    admin.backup_codes_hash = json.dumps([hash_backup_code(SESSION_SECRET, c) for c in new_codes])
    db.commit()
    return {"ok": True, "backup_codes": new_codes}


@app.post("/logout")
def logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    ca_dashboard_session: Annotated[str | None, Cookie()] = None,
) -> dict[str, bool]:
    token = _unpack_session(ca_dashboard_session)
    if token:
        row = db.get(DashboardSession, token)
        if row is not None:
            db.delete(row)
            db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}
