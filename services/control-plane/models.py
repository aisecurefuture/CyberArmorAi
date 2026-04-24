from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB

from db import Base


def now_utc():
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class TenantUser(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_tenant_users_tenant_email"),)

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, default="tenant_viewer")
    status = Column(String, nullable=False, default="active")
    invited_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class CustomerLoginCode(Base):
    __tablename__ = "customer_login_codes"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    email = Column(String, nullable=False, index=True)
    code_hash = Column(String, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class CustomerSession(Base):
    __tablename__ = "customer_sessions"

    token_hash = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    last_seen_at = Column(DateTime(timezone=True), default=now_utc)


class CustomerSsoConfig(Base):
    __tablename__ = "customer_sso_configs"

    tenant_id = Column(String, primary_key=True)
    provider_name = Column(String, nullable=False, default="oidc")
    issuer = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    client_secret = Column(String, nullable=False)
    authorization_endpoint = Column(String, nullable=False)
    token_endpoint = Column(String, nullable=False)
    jwks_uri = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=True)
    scopes = Column(String, nullable=False, default="openid email profile")
    enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class CustomerSsoState(Base):
    __tablename__ = "customer_sso_states"

    state = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)
    email_hint = Column(String, nullable=True)
    nonce = Column(String, nullable=False)
    code_verifier = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class TenantPortalConfig(Base):
    __tablename__ = "tenant_portal_configs"
    __table_args__ = (UniqueConstraint("tenant_id", "section", name="uq_tenant_portal_config_section"),)

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    section = Column(String, nullable=False, index=True)
    config = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    updated_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class ApiKey(Base):
    __tablename__ = "api_keys"
    key = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=True)
    role = Column(String, default="analyst")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, nullable=True)
    principal = Column(String, nullable=True)
    path = Column(String, nullable=False)
    method = Column(String, nullable=False)
    status = Column(String, nullable=False)
    duration_s = Column(String, nullable=False)
    meta = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class TelemetryRecord(Base):
    __tablename__ = "telemetry_records"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    agent_id = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True, index=True)
    user_id = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)
    payload = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    occurred_at = Column(DateTime(timezone=True), default=now_utc, index=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
