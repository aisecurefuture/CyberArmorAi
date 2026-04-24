"""Persistent storage for dashboard-auth.

Login codes and sessions live in a small DB instead of in-memory dicts
so the admin dashboard stays signed in across container restarts and
can scale beyond a single replica.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from db import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class LoginCode(Base):
    """One pending email login code per email (upsert on re-request)."""

    __tablename__ = "dashboard_login_codes"

    email = Column(String, primary_key=True)
    code_hash = Column(String, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)


class DashboardSession(Base):
    """Opaque session token -> email. Signed in the cookie via HMAC."""

    __tablename__ = "dashboard_sessions"

    token = Column(String, primary_key=True)
    email = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)


class AdminUser(Base):
    """Per-operator MFA state. Row is lazily created on first enroll."""

    __tablename__ = "dashboard_admin_users"

    email = Column(String, primary_key=True)
    totp_secret_enc = Column(Text, nullable=True)        # active secret, Fernet-encrypted
    totp_pending_enc = Column(Text, nullable=True)       # enrollment-in-progress secret
    totp_enabled = Column(Boolean, nullable=False, default=False)
    backup_codes_hash = Column(Text, nullable=True)      # JSON list of sha256 hashes
    created_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)
