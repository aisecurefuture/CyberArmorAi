"""Persistent storage for dashboard-auth.

Login codes and sessions live in a small DB instead of in-memory dicts
so the admin dashboard stays signed in across container restarts and
can scale beyond a single replica.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

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
