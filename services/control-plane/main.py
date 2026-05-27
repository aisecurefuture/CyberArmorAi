import json
import logging
import os
import html as htmlmod
import hashlib
import hmac
import io
import re
import secrets
import smtplib
import time
import base64
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Annotated, Dict, Optional, Any, List, Tuple
from urllib.parse import urlencode
import zipfile

import jwt
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, inspect as sa_inspect, or_
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine
from models import (
    ABOMComponent,
    ABOMComponentVulnerability,
    ABOMObservation,
    ABOMVulnerability,
    ApiKey,
    AuditLog,
    BootstrapInstall,
    BootstrapToken,
    CustomerLoginCode,
    CustomerSession,
    CustomerSsoConfig,
    CustomerSsoState,
    TelemetryRecord,
    Tenant,
    TenantPortalConfig,
    TenantUser,
)
from uuid import uuid4

import httpx
from cyberarmor_core.crypto import build_auth_headers, get_public_key_info, resolve_api_key_header
from cyberarmor_core.crypto.totp import (
    TOTPCipher,
    generate_backup_codes,
    generate_secret,
    hash_backup_code,
    otpauth_uri,
    qr_svg,
    verify_totp,
)
from cyberarmor_core.openbao import OpenBaoClient, OpenBaoConfig, OpenBaoError

# In-memory incident store for demo traceability (tenant_id -> request_id -> incident dict)
_INCIDENTS: Dict[str, Dict[str, Dict[str, Any]]] = {}

# In-memory endpoint-agent registry (agent_id -> agent record)
_AGENTS: Dict[str, Dict[str, Any]] = {}

class ApiKeyOut(BaseModel):
    key: str
    tenant_id: Optional[str]
    role: str
    active: bool

    class Config:
        from_attributes = True

class ApiKeyCreate(BaseModel):
    tenant_id: Optional[str] = None
    role: str = "analyst"

logger = logging.getLogger("control_plane")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

JWT_SECRET = os.getenv("CYBERARMOR_JWT_SECRET", "change-me")
DEFAULT_API_KEY = os.getenv("CYBERARMOR_API_SECRET", "change-me")
SERVICE_STARTED_AT = datetime.now(timezone.utc)
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_MTLS = os.getenv("CYBERARMOR_ENFORCE_MTLS", "false").strip().lower() in {"1", "true", "yes", "on"}
TLS_CA_FILE = os.getenv("CYBERARMOR_TLS_CA_FILE")
TLS_CERT_FILE = os.getenv("CYBERARMOR_TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("CYBERARMOR_TLS_KEY_FILE")

# Internal URL for the compliance service (used by the incident viewer page).
COMPLIANCE_URL = os.getenv("COMPLIANCE_URL", "http://compliance:8006")
INTEGRATION_CONTROL_URL = os.getenv("INTEGRATION_CONTROL_URL", "http://integration-control:8012")
INTEGRATION_CONTROL_API_KEY = os.getenv("INTEGRATION_CONTROL_API_SECRET", DEFAULT_API_KEY)
CUSTOMER_SESSION_COOKIE = "ca_customer_session"
CUSTOMER_CSRF_COOKIE = "ca_customer_csrf"
CUSTOMER_CSRF_HEADER = "x-csrf-token"
CUSTOMER_CODE_TTL_SECONDS = int(os.getenv("CUSTOMER_PORTAL_CODE_TTL_SECONDS", "600"))
CUSTOMER_SESSION_TTL_SECONDS = int(os.getenv("CUSTOMER_PORTAL_SESSION_TTL_SECONDS", "28800"))
CUSTOMER_MAX_CODE_ATTEMPTS = int(os.getenv("CUSTOMER_PORTAL_MAX_CODE_ATTEMPTS", "5"))
CUSTOMER_DEV_CODE_ECHO = os.getenv("CUSTOMER_PORTAL_AUTH_DEV_CODE_ECHO", "false").strip().lower() in {"1", "true", "yes", "on"}
CUSTOMER_COOKIE_SECURE = os.getenv("CUSTOMER_PORTAL_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
CUSTOMER_SESSION_SECRET = os.getenv("CUSTOMER_PORTAL_SESSION_SECRET") or JWT_SECRET
CUSTOMER_PORTAL_PUBLIC_URL = os.getenv("CUSTOMER_PORTAL_PUBLIC_URL", "http://localhost:3001").rstrip("/")
# Per-user TOTP MFA for the customer portal. Tenant_admin toggles per-tenant
# availability via TenantPortalConfig section="mfa". When MFA is required at
# login, we issue a short-lived signed ticket cookie instead of a session and
# require the user to POST to /customer-auth/verify-totp with a code.
CUSTOMER_MFA_TICKET_COOKIE = "ca_customer_mfa"
CUSTOMER_MFA_TICKET_TTL_SECONDS = int(os.getenv("CUSTOMER_PORTAL_MFA_TICKET_TTL_SECONDS", "300"))
CUSTOMER_MFA_ISSUER = os.getenv("CUSTOMER_PORTAL_MFA_ISSUER", "CyberArmor Customer Portal")
CUSTOMER_MFA_MAX_ATTEMPTS = int(os.getenv("CUSTOMER_PORTAL_MFA_MAX_ATTEMPTS", "5"))
CUSTOMER_PORTAL_CONFIG_SECTIONS = {
    "policy-builder",
    "proxy",
    "scan",
    "shadow-ai",
    "compliance",
    "siem",
    "dlp",
    "reports",
    "providers",
    "policy-studio",
    "graph",
    "risk",
    "delegations",
    "onboarding",
}
CONTROL_PLANE_PUBLIC_URL = os.getenv("CYBERARMOR_CONTROL_PLANE_PUBLIC_URL", "http://localhost:8000").rstrip("/")
CYBERARMOR_DISTRIBUTION_ROOT = Path(
    os.getenv("CYBERARMOR_DISTRIBUTION_ROOT", "/workspace/cyberarmor")
).resolve()
BOOTSTRAP_TOKEN_TTL_SECONDS = int(os.getenv("CYBERARMOR_BOOTSTRAP_TOKEN_TTL_SECONDS", "1800"))
BOOTSTRAP_TOKEN_MAX_TTL_SECONDS = int(os.getenv("CYBERARMOR_BOOTSTRAP_TOKEN_MAX_TTL_SECONDS", "86400"))

PACKAGE_CATALOG: Dict[str, Dict[str, Any]] = {
    "endpoint-agent": {
        "title": "Endpoint Agent",
        "category": "agent",
        "path": "agents/endpoint-agent",
        "filename": "cyberarmor-endpoint-agent.zip",
        "description": "Desktop endpoint protection agent with DLP, telemetry, and policy enforcement.",
        "install_hint": "python installer.py --config /etc/cyberarmor/agent.json",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "proxy-agent": {
        "title": "Proxy Agent",
        "category": "agent",
        "path": "agents/proxy-agent",
        "filename": "cyberarmor-proxy-agent.zip",
        "description": "Service-side proxy agent for policy-aware request mediation.",
        "install_hint": "docker build -t cyberarmor-proxy-agent .",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "ros-agent": {
        "title": "ROS Agent",
        "category": "agent",
        "path": "agents/ros-agent",
        "filename": "cyberarmor-ros-agent.zip",
        "description": "ROS / robotics agent package for topic and actuator policy enforcement.",
        "install_hint": "python setup.py install",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "vscode-extension": {
        "title": "VS Code Extension",
        "category": "extension",
        "path": "extensions/vscode",
        "filename": "cyberarmor-vscode-extension.zip",
        "description": "IDE extension for policy checks, DLP scanning, and AI completion monitoring.",
        "install_hint": "npm install && npm run compile",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "cursor-extension": {
        "title": "Cursor Extension",
        "category": "extension",
        "path": "extensions/cursor",
        "filename": "cyberarmor-cursor-extension.zip",
        "description": "Cursor-focused extension package for tenant-scoped AI guardrails.",
        "install_hint": "npm install && npm run build",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "kiro-extension": {
        "title": "Kiro Extension",
        "category": "extension",
        "path": "extensions/kiro",
        "filename": "cyberarmor-kiro-extension.zip",
        "description": "Kiro IDE extension bundle for code and prompt monitoring.",
        "install_hint": "npm install && npm run compile",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "office365-addin": {
        "title": "Microsoft 365 Add-in",
        "category": "extension",
        "path": "extensions/office365",
        "filename": "cyberarmor-office365-addin.zip",
        "description": "Office add-in sources for Outlook / Office workflow protection.",
        "install_hint": "npm install && npm run build",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "edge-extension": {
        # package_key is the stable internal identifier referenced from
        # chromium-shared (options.js + background.js bootstrap redeem),
        # admin-dashboard, customer-portal, and bootstrap_supports docs —
        # renaming it would force every installed extension to re-redeem.
        # Title + filename are the user-visible strings; both reflect that
        # the bundle works in any Chromium-based browser, not just Edge.
        #
        # `path` used to point at extensions/edge/, which is a one-file stub
        # whose manifest references ../chromium-shared/ via relative parent
        # paths — the zip ended up containing literally one manifest plus
        # our generated MANIFEST/BUILD_INFO/README, and the references
        # broke when unzipped standalone. The real extension is
        # extensions/chromium-shared/ (its own manifest, background.js,
        # content.js, icons, etc.) and that's what we now ship.
        "title": "Chromium Browser Extension",
        "category": "browser_extension",
        "path": "extensions/chromium-shared",
        "filename": "cyberarmor-chromium-browser-extension.zip",
        "description": "Shared browser extension bundle for Chromium-based browsers such as Chrome, Edge, Brave, Opera, and similar targets.",
        "install_hint": "Load unpacked extension in the target Chromium-based browser developer mode.",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "firefox-extension": {
        "title": "Firefox Browser Extension",
        "category": "browser_extension",
        "path": "extensions/firefox",
        "filename": "cyberarmor-firefox-extension.zip",
        "description": "Manifest bundle for Mozilla Firefox browser controls.",
        "install_hint": "Load temporary add-on in Firefox developer mode.",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "safari-extension": {
        "title": "Safari Browser Extension",
        "category": "browser_extension",
        "path": "extensions/safari",
        "filename": "cyberarmor-safari-extension.zip",
        "description": "Manifest bundle for Safari browser controls.",
        "install_hint": "Package through the Safari extension toolchain.",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-python": {
        "title": "Python SDK",
        "category": "sdk",
        "path": "sdks/python",
        "filename": "cyberarmor-sdk-python.zip",
        "description": "Python SDK package sources and integration helpers.",
        "install_hint": "pip install -e .",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-nodejs": {
        "title": "Node.js / TypeScript SDK",
        "category": "sdk",
        "path": "sdks/nodejs",
        "filename": "cyberarmor-sdk-nodejs.zip",
        "description": "Node.js SDK sources, providers, and framework helpers.",
        "install_hint": "npm install && npm run build",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-go": {
        "title": "Go SDK",
        "category": "sdk",
        "path": "sdks/go",
        "filename": "cyberarmor-sdk-go.zip",
        "description": "Go SDK sources and runtime helper bindings.",
        "install_hint": "go test ./... && go build ./...",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-java": {
        "title": "Java SDK",
        "category": "sdk",
        "path": "sdks/java",
        "filename": "cyberarmor-sdk-java.zip",
        "description": "Java SDK modules for core, providers, and framework integrations.",
        "install_hint": "mvn -q package",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-dotnet": {
        "title": ".NET SDK",
        "category": "sdk",
        "path": "sdks/dotnet",
        "filename": "cyberarmor-sdk-dotnet.zip",
        "description": ".NET SDK package and integration helpers.",
        "install_hint": "dotnet build",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-ruby": {
        "title": "Ruby SDK",
        "category": "sdk",
        "path": "sdks/ruby",
        "filename": "cyberarmor-sdk-ruby.zip",
        "description": "Ruby SDK gem sources and audit helpers.",
        "install_hint": "bundle install && rake test",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-php": {
        "title": "PHP SDK",
        "category": "sdk",
        "path": "sdks/php",
        "filename": "cyberarmor-sdk-php.zip",
        "description": "PHP SDK sources and provider integrations.",
        "install_hint": "composer install",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "sdk-rust": {
        "title": "Rust SDK",
        "category": "sdk",
        "path": "sdks/rust",
        "filename": "cyberarmor-sdk-rust.zip",
        "description": "Rust SDK crate sources and provider parity tests.",
        "install_hint": "cargo test",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "rasp-python": {
        "title": "Python RASP",
        "category": "rasp",
        "path": "rasp/python",
        "filename": "cyberarmor-rasp-python.zip",
        "description": "Python runtime self-protection instrumentation.",
        "install_hint": "pip install -e .",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "rasp-nodejs": {
        "title": "Node.js RASP",
        "category": "rasp",
        "path": "rasp/nodejs",
        "filename": "cyberarmor-rasp-nodejs.zip",
        "description": "Node.js runtime application self-protection helpers.",
        "install_hint": "npm install",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "rasp-java": {
        "title": "Java RASP",
        "category": "rasp",
        "path": "rasp/java",
        "filename": "cyberarmor-rasp-java.zip",
        "description": "Java runtime application self-protection instrumentation.",
        "install_hint": "mvn -q package",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "rasp-dotnet": {
        "title": ".NET RASP",
        "category": "rasp",
        "path": "rasp/dotnet",
        "filename": "cyberarmor-rasp-dotnet.zip",
        "description": ".NET runtime application self-protection middleware.",
        "install_hint": "dotnet build",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
    "rasp-go": {
        "title": "Go RASP",
        "category": "rasp",
        "path": "rasp/go",
        "filename": "cyberarmor-rasp-go.zip",
        "description": "Go runtime self-protection package.",
        "install_hint": "go build ./...",
        "bootstrap_env": ["CYBERARMOR_BOOTSTRAP_TOKEN", "CYBERARMOR_TENANT_ID", "CYBERARMOR_CONTROL_PLANE_URL"],
    },
}


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return

    def _bad(value: Optional[str]) -> bool:
        if not value:
            return True
        lowered = value.strip().lower()
        return lowered.startswith("change-me") or "changeme" in lowered

    failing = []
    if _bad(JWT_SECRET):
        failing.append("CYBERARMOR_JWT_SECRET")
    if _bad(DEFAULT_API_KEY):
        failing.append("CYBERARMOR_API_SECRET")
    if failing:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            f"Set strong values for: {', '.join(failing)}. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def _enforce_mtls_config() -> None:
    if not ENFORCE_MTLS:
        return
    missing = []
    for env_name, value in [
        ("CYBERARMOR_TLS_CA_FILE", TLS_CA_FILE),
        ("CYBERARMOR_TLS_CERT_FILE", TLS_CERT_FILE),
        ("CYBERARMOR_TLS_KEY_FILE", TLS_KEY_FILE),
    ]:
        if not value:
            missing.append(f"{env_name}(unset)")
        elif not os.path.exists(value):
            missing.append(f"{env_name}({value} missing)")
    if missing:
        raise RuntimeError(
            "Refusing startup: mTLS enforced but TLS artifacts are missing. "
            f"Fix: {', '.join(missing)}"
        )


_enforce_mtls_config()


def _ensure_columns(table_name: str, columns: dict[str, str]) -> None:
    """Idempotent ADD COLUMN for SQLite and Postgres.

    SQLAlchemy's ``create_all`` adds new TABLES but never alters existing
    ones, so adding columns to a long-lived model needs an out-of-band
    step. We keep it minimal: ``ALTER TABLE … ADD COLUMN`` is supported
    on both backends and is a no-op when the column already exists
    (we check via the inspector first to keep the SQL noise-free).

    ``columns`` maps column name → DDL fragment, e.g. ``"BOOLEAN NOT NULL DEFAULT FALSE"``.
    """
    try:
        existing = {c["name"] for c in sa_inspect(engine).get_columns(table_name)}
    except Exception as e:
        # Table doesn't exist yet (fresh DB) — create_all() handles it.
        logger.debug("skip_column_check table=%s err=%s", table_name, e)
        return
    missing = {name: ddl for name, ddl in columns.items() if name not in existing}
    if not missing:
        return
    with engine.begin() as conn:
        for name, ddl in missing.items():
            conn.exec_driver_sql(f'ALTER TABLE {table_name} ADD COLUMN {name} {ddl}')
            logger.info("added_column table=%s column=%s", table_name, name)


def init_db():
    Base.metadata.create_all(bind=engine)
    # Idempotent column adds for models that grew after first deploy.
    # SQLite & Postgres both accept these DDL fragments verbatim.
    _ensure_columns("tenant_users", {
        "totp_secret_enc": "VARCHAR",
        "totp_pending_enc": "VARCHAR",
        "totp_enabled": "BOOLEAN NOT NULL DEFAULT FALSE",
        "backup_codes_hash": "TEXT",
    })
    with SessionLocal() as db:
        if not db.query(ApiKey).filter(ApiKey.key == DEFAULT_API_KEY).first():
            db.add(ApiKey(key=DEFAULT_API_KEY, role="admin", tenant_id=None, active=True))
            db.commit()


def wait_for_db(max_wait_s: int = 45) -> None:
    """Block startup until the DB accepts connections.

    docker-compose often starts app containers before Postgres is actually
    listening (especially during first-time initdb, when Postgres restarts).
    Without a wait loop, the app exits with "connection refused" and the
    reverse proxy returns 502.
    """
    start = time.time()
    attempt = 0
    while True:
        attempt += 1
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except Exception as e:
            elapsed = time.time() - start
            if elapsed >= max_wait_s:
                logger.error("db_not_ready_after_s=%s last_err=%s", int(elapsed), e)
                raise
            # small exponential-ish backoff capped at 2s
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("db_not_ready_yet sleep_s=%.2f err=%s", sleep_s, e)
            time.sleep(sleep_s)


class TelemetryEvent(BaseModel):
    tenant_id: str
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    event_type: str = Field(..., description="e.g., page_visit, form_detected, pii_detected, genai_detected, policy_violation")
    payload: Dict = Field(default_factory=dict)
    source: str = Field(..., description="browser_extension|proxy_agent|endpoint")
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthContext(BaseModel):
    principal: str
    role: str
    tenant_id: Optional[str]


class TenantOut(BaseModel):
    id: str
    name: str
    active: bool

    class Config:
        from_attributes = True


class TenantUserOut(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: str
    status: str
    invited_by: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class CustomerCodeRequest(BaseModel):
    email: str


class CustomerCodeVerify(BaseModel):
    email: str
    code: str


class CustomerUserCreate(BaseModel):
    email: str
    role: str = "tenant_viewer"
    status: str = "active"


class CustomerUserUpdate(BaseModel):
    role: Optional[str] = None
    status: Optional[str] = None


class CustomerSsoConfigIn(BaseModel):
    provider_name: str = "oidc"
    issuer: str
    client_id: str
    client_secret: Optional[str] = None
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    redirect_uri: Optional[str] = None
    scopes: str = "openid email profile"
    enabled: bool = True


class CustomerSsoConfigOut(BaseModel):
    tenant_id: str
    provider_name: str
    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    redirect_uri: Optional[str] = None
    scopes: str
    enabled: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TenantPortalConfigIn(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


class TenantPortalConfigOut(BaseModel):
    tenant_id: str
    section: str
    config: Dict[str, Any] = Field(default_factory=dict)
    updated_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class CustomerContext(BaseModel):
    email: str
    tenant_id: str
    role: str


class BootstrapTokenCreate(BaseModel):
    package_key: str
    ttl_minutes: int = 30
    note: Optional[str] = None
    tenant_id: Optional[str] = None


class BootstrapTokenIssueOut(BaseModel):
    token_id: str
    package_key: str
    tenant_id: str
    bootstrap_token: str
    expires_at: datetime
    download_url: str
    redeem_url: str
    install_hint: str
    bootstrap_env: Dict[str, str]
    note: Optional[str] = None


class BootstrapRedeemIn(BaseModel):
    bootstrap_token: str
    package_key: Optional[str] = None
    subject_type: Optional[str] = None
    subject_name: Optional[str] = None
    hostname: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BootstrapRedeemOut(BaseModel):
    install_id: str
    package_key: str
    tenant_id: str
    subject_type: str
    subject_id: str
    service_api_key: str
    control_plane_url: str
    issued_at: datetime
    api_headers: Dict[str, str]
    runtime_env: Dict[str, str]
    config: Dict[str, Any]


class DownloadCatalogEntry(BaseModel):
    package_key: str
    title: str
    category: str
    description: str
    filename: str
    install_hint: str
    bootstrap_supported: bool = True
    download_url: str


class AuditLogOut(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    principal: Optional[str] = None
    # principal_kind / principal_label: derived UI-friendly forms of the
    # raw principal column. The raw value can be a PQC envelope (1000+
    # chars of base64), a JWT bearer string, or "anonymous"; the kind is
    # the human bucket and the label is a short, safe display string.
    principal_kind: Optional[str] = None
    principal_label: Optional[str] = None
    path: str
    method: str
    status: str
    duration_s: str
    duration_ms: Optional[float] = None
    client_ip: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


def _classify_principal(raw: Optional[str]) -> Tuple[str, str]:
    """Map a raw audit-log principal to (kind, short label).

    Audit middleware writes whatever Authorization / x-api-key header
    arrived on the request — which can be a PQC: envelope, Bearer JWT,
    plaintext API key, or "anonymous". None of those are readable in a
    table cell, so summarise them here and let the frontend show the
    raw value only on the detail modal.
    """
    if not raw or raw == "anonymous":
        return "anonymous", "anonymous"
    s = str(raw)
    if s.lower().startswith("bearer "):
        return "jwt", f"jwt:{s.split(' ', 1)[1][:8]}…"
    if s.startswith("PQC:") or s.startswith("ca_pqc_"):
        # Stable short fingerprint that survives across renders: last 8 of
        # the encoded body, prefixed so it's obvious what we're showing.
        body = s.split(":", 1)[1] if ":" in s else s
        return "pqc_api_key", f"pqc:…{body[-8:]}"
    if s.startswith("ca_"):
        return "api_key", f"api_key:{s[:6]}…{s[-4:]}"
    return "raw", (s[:20] + "…") if len(s) > 24 else s


def _hash_bootstrap_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _resolve_package_spec(package_key: str) -> Dict[str, Any]:
    spec = PACKAGE_CATALOG.get((package_key or "").strip())
    if not spec:
        raise HTTPException(status_code=404, detail="Unknown package key")
    package_path = (CYBERARMOR_DISTRIBUTION_ROOT / spec["path"]).resolve()
    if not package_path.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Package source is not available on this host for {package_key}",
        )
    if CYBERARMOR_DISTRIBUTION_ROOT not in package_path.parents and package_path != CYBERARMOR_DISTRIBUTION_ROOT:
        raise HTTPException(status_code=500, detail="Package path escaped distribution root")
    return {**spec, "package_key": package_key, "package_path": package_path}


def _catalog_entry(package_key: str, tenant_id: str, customer_scope: bool) -> DownloadCatalogEntry:
    spec = _resolve_package_spec(package_key)
    # The customer-portal nginx only proxies /api/customer/* — bare /customer/*
    # falls through to the static-file fallback and the browser renders the
    # portal HTML instead of streaming the zip. Match the URL prefix the
    # frontend's api() helper uses.
    route_prefix = "/api/customer/downloads/packages" if customer_scope else "/bootstrap/packages"
    return DownloadCatalogEntry(
        package_key=package_key,
        title=spec["title"],
        category=spec["category"],
        description=spec["description"],
        filename=spec["filename"],
        install_hint=spec["install_hint"],
        bootstrap_supported=True,
        download_url=f"{route_prefix}/{package_key}",
    )


def _build_catalog(tenant_id: str, customer_scope: bool) -> List[DownloadCatalogEntry]:
    return [_catalog_entry(package_key, tenant_id, customer_scope) for package_key in PACKAGE_CATALOG.keys()]


def _make_bootstrap_issue_out(
    token_row: BootstrapToken,
    plaintext_token: str,
    tenant_id: str,
    customer_scope: bool,
) -> BootstrapTokenIssueOut:
    spec = _resolve_package_spec(token_row.package_key)
    env = {
        "CYBERARMOR_BOOTSTRAP_TOKEN": plaintext_token,
        "CYBERARMOR_TENANT_ID": tenant_id,
        "CYBERARMOR_CONTROL_PLANE_URL": CONTROL_PLANE_PUBLIC_URL,
    }
    route_prefix = "/customer/downloads/packages" if customer_scope else "/bootstrap/packages"
    return BootstrapTokenIssueOut(
        token_id=token_row.id,
        package_key=token_row.package_key,
        tenant_id=tenant_id,
        bootstrap_token=plaintext_token,
        expires_at=token_row.expires_at,
        download_url=f"{route_prefix}/{token_row.package_key}",
        redeem_url=f"{CONTROL_PLANE_PUBLIC_URL}/bootstrap/redeem",
        install_hint=spec["install_hint"],
        bootstrap_env=env,
        note=token_row.note,
    )


def _issue_bootstrap_token(
    db: Session,
    *,
    tenant_id: str,
    package_key: str,
    issued_to: Optional[str],
    note: Optional[str],
    ttl_minutes: int,
) -> tuple[BootstrapToken, str]:
    _resolve_package_spec(package_key)
    ttl_seconds = max(300, min(ttl_minutes * 60, BOOTSTRAP_TOKEN_MAX_TTL_SECONDS))
    plaintext_token = f"cabt_{secrets.token_urlsafe(24)}"
    row = BootstrapToken(
        token_hash=_hash_bootstrap_token(plaintext_token),
        tenant_id=tenant_id,
        package_key=package_key,
        issued_to=issued_to,
        note=note,
        expires_at=_utcnow() + timedelta(seconds=ttl_seconds),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plaintext_token


_BUILD_INFO_CACHE: Optional[Dict[str, str]] = None


def _build_info() -> Dict[str, str]:
    """Return cached {sha, built_at} identifying the source tree the
    control-plane is serving packages from. Used to stamp downloaded
    agent ZIPs so support can correlate "what version is this customer
    running?" without operator detective work.

    Cached at process start — `git rev-parse` doesn't change without a
    container restart since the bind-mount tracks the host repo.
    """
    global _BUILD_INFO_CACHE
    if _BUILD_INFO_CACHE is not None:
        return _BUILD_INFO_CACHE
    sha = "unknown"
    try:
        import subprocess
        sha = subprocess.check_output(
            ["git", "-C", str(CYBERARMOR_DISTRIBUTION_ROOT), "rev-parse", "--short", "HEAD"],
            text=True, stderr=subprocess.DEVNULL, timeout=2.0,
        ).strip() or "unknown"
    except Exception:
        pass
    _BUILD_INFO_CACHE = {
        "sha": sha,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }
    return _BUILD_INFO_CACHE


def _zip_directory_response(spec: Dict[str, Any], tenant_id: str) -> StreamingResponse:
    package_path: Path = spec["package_path"]
    archive_name = spec["filename"]
    buffer = io.BytesIO()
    root_prefix = f"{package_path.name}/"
    ignore_dirs = {"node_modules", ".git", "__pycache__", ".pytest_cache", "dist", "build"}
    ignore_suffixes = {".pyc", ".pyo"}
    build = _build_info()

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        readme = "\n".join([
            f"CyberArmor package: {spec['title']}",
            f"Tenant: {tenant_id}",
            f"Build SHA: {build['sha']}",
            f"Built at:  {build['built_at']}",
            "",
            "This package intentionally does not contain a long-lived API key.",
            "Generate a one-time bootstrap token from the customer portal or admin dashboard",
            "and redeem it into an install-scoped credential instead of baking secrets into source.",
            "",
            f"Bootstrap redeem endpoint: {CONTROL_PLANE_PUBLIC_URL}/bootstrap/redeem",
            f"Suggested install/build command: {spec['install_hint']}",
            "Suggested bootstrap env vars:",
            *[f"  - {name}" for name in spec.get("bootstrap_env", [])],
        ]) + "\n"
        archive.writestr(f"{root_prefix}BOOTSTRAP_README.txt", readme)
        # Machine-readable build info — agents read this on boot and include
        # the SHA in their heartbeats so the dashboard can show per-endpoint
        # version drift at a glance.
        archive.writestr(
            f"{root_prefix}BUILD_INFO.json",
            json.dumps({
                "package_key": spec.get("package_key", ""),
                "title": spec.get("title", ""),
                "tenant_id": tenant_id,
                "sha": build["sha"],
                "built_at": build["built_at"],
            }, indent=2) + "\n",
        )
        for file_path in package_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in ignore_dirs for part in file_path.parts):
                continue
            if file_path.suffix in ignore_suffixes:
                continue
            relative_path = file_path.relative_to(package_path)
            archive.write(file_path, arcname=f"{root_prefix}{relative_path.as_posix()}")

    buffer.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{archive_name}"'}
    return StreamingResponse(buffer, media_type="application/zip", headers=headers)


def _default_subject_type(package_key: str, category: str) -> str:
    if package_key == "endpoint-agent":
        return "endpoint_agent"
    if category == "agent":
        return "service_agent"
    if category == "browser_extension":
        return "browser_extension"
    if category == "extension":
        return "extension"
    if category == "sdk":
        return "sdk_client"
    if category == "rasp":
        return "rasp_runtime"
    return "bootstrap_client"


def _slugify_subject(value: Optional[str], fallback: str) -> str:
    raw = (value or "").strip().lower()
    chars = [ch if ch.isalnum() else "-" for ch in raw]
    slug = "".join(chars).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:48] or fallback


def _subject_prefix(subject_type: str) -> str:
    return {
        "endpoint_agent": "agt",
        "service_agent": "svc",
        "browser_extension": "brx",
        "extension": "ext",
        "sdk_client": "sdk",
        "rasp_runtime": "rasp",
    }.get(subject_type, "inst")


def _redeem_bootstrap_token(db: Session, payload: BootstrapRedeemIn) -> BootstrapRedeemOut:
    token_hash = _hash_bootstrap_token((payload.bootstrap_token or "").strip())
    row = db.query(BootstrapToken).filter(BootstrapToken.token_hash == token_hash).first()
    if not row:
        raise HTTPException(status_code=404, detail="Bootstrap token not found")
    if row.status != "issued":
        raise HTTPException(status_code=409, detail="Bootstrap token has already been used")
    if row.expires_at <= _utcnow():
        row.status = "expired"
        db.commit()
        raise HTTPException(status_code=410, detail="Bootstrap token has expired")
    if payload.package_key and payload.package_key != row.package_key:
        raise HTTPException(status_code=400, detail="Bootstrap token does not match the requested package")

    spec = _resolve_package_spec(row.package_key)
    subject_type = payload.subject_type or _default_subject_type(row.package_key, spec["category"])
    subject_seed = payload.subject_name or payload.hostname or row.package_key
    subject_id = f"{_subject_prefix(subject_type)}_{_slugify_subject(subject_seed, 'install')}_{secrets.token_hex(4)}"
    service_api_key = f"ca_{secrets.token_urlsafe(24)}"
    issued_at = _utcnow()

    db.add(
        ApiKey(
            key=service_api_key,
            tenant_id=row.tenant_id,
            role="service",
            active=True,
        )
    )
    install = BootstrapInstall(
        bootstrap_token_id=row.id,
        tenant_id=row.tenant_id,
        package_key=row.package_key,
        subject_type=subject_type,
        subject_id=subject_id,
        issued_api_key_hash=_hash_bootstrap_token(service_api_key),
    )
    db.add(install)
    row.status = "redeemed"
    row.redeemed_at = issued_at
    db.commit()
    db.refresh(install)

    runtime_env = {
        "CYBERARMOR_API_KEY": service_api_key,
        "CYBERARMOR_TENANT_ID": row.tenant_id,
        "CYBERARMOR_CONTROL_PLANE_URL": CONTROL_PLANE_PUBLIC_URL,
    }
    config = {
        "control_plane_url": CONTROL_PLANE_PUBLIC_URL,
        "api_key": service_api_key,
        "tenant_id": row.tenant_id,
    }
    if row.package_key == "endpoint-agent":
        runtime_env.update(
            {
                "AGENT_API_KEY": service_api_key,
                "TENANT_ID": row.tenant_id,
                "CONTROL_PLANE_URL": CONTROL_PLANE_PUBLIC_URL,
                "AGENT_ID": subject_id,
            }
        )
        config["agent_id"] = subject_id

    return BootstrapRedeemOut(
        install_id=install.id,
        package_key=row.package_key,
        tenant_id=row.tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
        service_api_key=service_api_key,
        control_plane_url=CONTROL_PLANE_PUBLIC_URL,
        issued_at=issued_at,
        api_headers={"x-api-key": service_api_key, "x-tenant-id": row.tenant_id},
        runtime_env=runtime_env,
        config=config,
    )


def _store_telemetry_event(event: Dict[str, Any]) -> None:
    payload = event.get("payload")
    occurred_at = event.get("occurred_at")
    if isinstance(occurred_at, str):
        try:
            occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except Exception:
            occurred_at = datetime.now(timezone.utc)
    elif not isinstance(occurred_at, datetime):
        occurred_at = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(
            TelemetryRecord(
                tenant_id=str(event.get("tenant_id") or "unknown"),
                agent_id=event.get("agent_id"),
                hostname=event.get("hostname"),
                user_id=event.get("user_id"),
                event_type=str(event.get("event_type") or "event"),
                source=str(event.get("source") or "unknown"),
                payload=_encode_meta_for_db(payload if isinstance(payload, dict) else {"value": payload}),
                occurred_at=occurred_at,
            )
        )
        db.commit()


def _coerce_meta(val: Any) -> Optional[Dict[str, Any]]:
    """AuditLog.meta is JSONB in Postgres and Text in SQLite.

    In Postgres it will come back as a dict; in SQLite (or older rows) it may be
    a JSON string.
    """
    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if isinstance(val, (bytes, bytearray)):
        try:
            val = val.decode("utf-8", errors="ignore")
        except Exception:
            return {"raw": str(val)}
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception:
            return {"raw": val}
    return {"raw": str(val)}


def _encode_meta_for_db(val: Optional[Dict[str, Any]]) -> Any:
    """Store meta in a backend-safe way.

    AuditLog.meta is JSONB on Postgres but Text on SQLite (via with_variant).
    SQLAlchemy does not auto-serialize dicts into a Text column, so when the
    DB dialect is SQLite we JSON-encode the dict.
    """
    if val is None:
        return None
    try:
        dialect = engine.dialect.name
    except Exception:
        dialect = "unknown"
    if dialect == "sqlite":
        try:
            return json.dumps(val)
        except Exception:
            return json.dumps({"raw": str(val)})
    return val


def _valid_customer_config_section(section: str) -> str:
    cleaned = (section or "").strip().lower()
    if cleaned not in CUSTOMER_PORTAL_CONFIG_SECTIONS:
        raise HTTPException(status_code=404, detail="Unknown customer portal config section")
    return cleaned


def _tenant_portal_config_out(record: TenantPortalConfig) -> TenantPortalConfigOut:
    return TenantPortalConfigOut(
        tenant_id=record.tenant_id,
        section=record.section,
        config=_coerce_meta(record.config) or {},
        updated_by=record.updated_by,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _valid_email(email: str) -> bool:
    return bool(email) and "@" in email and "." in email.rsplit("@", 1)[-1]


def _valid_customer_role(role: str) -> str:
    normalized = role.strip().lower()
    allowed = {"tenant_admin", "tenant_analyst", "tenant_viewer"}
    if normalized not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed roles: {', '.join(sorted(allowed))}")
    return normalized


def _valid_customer_status(status: str) -> str:
    normalized = status.strip().lower()
    allowed = {"active", "invited", "disabled"}
    if normalized not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed statuses: {', '.join(sorted(allowed))}")
    return normalized


def _hash_customer_code(email: str, code: str) -> str:
    material = f"{email}:{code}:{CUSTOMER_SESSION_SECRET}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _hash_customer_session_token(token: str) -> str:
    return hmac.new(CUSTOMER_SESSION_SECRET.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _base64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _customer_redirect_uri(config: CustomerSsoConfig) -> str:
    return config.redirect_uri or f"{CUSTOMER_PORTAL_PUBLIC_URL}/auth/sso/callback"


def _safe_sso_config(config: CustomerSsoConfig) -> CustomerSsoConfigOut:
    return CustomerSsoConfigOut(
        tenant_id=config.tenant_id,
        provider_name=config.provider_name,
        issuer=config.issuer,
        client_id=config.client_id,
        authorization_endpoint=config.authorization_endpoint,
        token_endpoint=config.token_endpoint,
        jwks_uri=config.jwks_uri,
        redirect_uri=config.redirect_uri,
        scopes=config.scopes,
        enabled=config.enabled,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


def _issue_customer_session(response: Response, db: Session, user: TenantUser) -> None:
    token = secrets.token_urlsafe(48)
    db.add(
        CustomerSession(
            token_hash=_hash_customer_session_token(token),
            tenant_id=user.tenant_id,
            email=user.email,
            role=user.role,
            expires_at=_utcnow() + timedelta(seconds=CUSTOMER_SESSION_TTL_SECONDS),
        )
    )
    user.last_login_at = _utcnow()
    response.set_cookie(
        CUSTOMER_SESSION_COOKIE,
        token,
        max_age=CUSTOMER_SESSION_TTL_SECONDS,
        httponly=True,
        secure=CUSTOMER_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    # Double-submit CSRF token. The SPA reads this cookie via
    # document.cookie and echoes it in the x-csrf-token header on every
    # state-changing request — attackers on another origin can set the
    # session cookie (via stolen credentials) but cannot read the csrf
    # cookie to forge a matching header.
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        CUSTOMER_CSRF_COOKIE,
        csrf_token,
        max_age=CUSTOMER_SESSION_TTL_SECONDS,
        httponly=False,
        secure=CUSTOMER_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def _clear_customer_session_cookies(response: Response) -> None:
    response.delete_cookie(CUSTOMER_SESSION_COOKIE, path="/")
    response.delete_cookie(CUSTOMER_CSRF_COOKIE, path="/")


# ── Customer-portal TOTP MFA helpers ─────────────────────────────────────
# Per-user TOTP secrets sit on TenantUser; the per-tenant "is MFA available
# to this tenant's users?" flag lives in TenantPortalConfig(section="mfa")
# alongside upload-discovery / abom-* configs. Sharing the cipher with
# dashboard-auth would be wrong: the KEK is derived from each service's
# session secret, so an admin's TOTP secret is intentionally undecryptable
# by control-plane and vice versa.
_totp_cipher_instance: Optional[TOTPCipher] = None
# Per-MFA-ticket failed-attempt counter. The MFA ticket cookie is HMAC-signed
# (so the client can't tamper with it), but it's not stored server-side, so
# without a counter an attacker could brute-force 6 digits at unlimited rate
# within the 5-minute ticket TTL. Keying by sha256(ticket) avoids holding
# the raw cookie value in storage.
#
# Backend selection at startup:
#   - REDIS_URL set + reachable → Redis (works across multiple uvicorn workers).
#   - Otherwise → in-process dict (fine for single-worker dev).
# Mid-request Redis errors fail closed (treat as rate-limit hit) so the
# guarantee can't be eroded by tickling the network — better to lock a
# legitimate user out for 5 minutes than to silently disable the limit.
_mfa_failed_attempts: Dict[str, int] = {}
_mfa_redis_client: Any = None  # redis.Redis | None


def _init_mfa_rate_limiter() -> None:
    global _mfa_redis_client
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        logger.info("mfa_rate_limit backend=in-memory reason=REDIS_URL_unset")
        return
    try:
        import redis as _redis_lib  # type: ignore[import-not-found]
        client = _redis_lib.Redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2, decode_responses=True
        )
        client.ping()
        _mfa_redis_client = client
        logger.info("mfa_rate_limit backend=redis url=%s", url)
    except Exception as e:
        logger.warning("mfa_rate_limit redis_unavailable err=%s fallback=in-memory", e)
        _mfa_redis_client = None


_init_mfa_rate_limiter()


def _mfa_redis_key(ticket_hash: str) -> str:
    return f"mfa:fails:{ticket_hash}"


def _mfa_inc_attempts(ticket_hash: str) -> int:
    """Increment and return the post-increment count for this ticket. On Redis
    failure when Redis was configured at startup, raises HTTPException(429)
    rather than silently falling through to no rate limit.
    """
    if _mfa_redis_client is None:
        _mfa_failed_attempts[ticket_hash] = _mfa_failed_attempts.get(ticket_hash, 0) + 1
        return _mfa_failed_attempts[ticket_hash]
    try:
        key = _mfa_redis_key(ticket_hash)
        count = _mfa_redis_client.incr(key)
        if count == 1:
            # Tie the counter's TTL to the ticket's TTL so it auto-clears
            # when the ticket would have expired anyway.
            _mfa_redis_client.expire(key, CUSTOMER_MFA_TICKET_TTL_SECONDS)
        return int(count)
    except Exception as e:
        logger.warning("mfa_rate_limit redis_error_on_incr err=%s fail_closed=True", e)
        # Fail closed: treat as max attempts reached.
        raise HTTPException(status_code=429, detail="MFA service temporarily unavailable, try again shortly")


def _mfa_clear_attempts(ticket_hash: str) -> None:
    if _mfa_redis_client is None:
        _mfa_failed_attempts.pop(ticket_hash, None)
        return
    try:
        _mfa_redis_client.delete(_mfa_redis_key(ticket_hash))
    except Exception as e:
        logger.warning("mfa_rate_limit redis_error_on_clear err=%s", e)


def _mfa_attempts_count(ticket_hash: str) -> int:
    """Read-only peek used for the early-exit check."""
    if _mfa_redis_client is None:
        return _mfa_failed_attempts.get(ticket_hash, 0)
    try:
        val = _mfa_redis_client.get(_mfa_redis_key(ticket_hash))
        return int(val) if val is not None else 0
    except Exception as e:
        logger.warning("mfa_rate_limit redis_error_on_get err=%s fail_closed=True", e)
        raise HTTPException(status_code=429, detail="MFA service temporarily unavailable, try again shortly")


def _get_totp_cipher() -> TOTPCipher:
    global _totp_cipher_instance
    if _totp_cipher_instance is None:
        _totp_cipher_instance = TOTPCipher(CUSTOMER_SESSION_SECRET, salt=b"ca-customer-totp-kek-v1")
    return _totp_cipher_instance


def _sign_customer_mfa_ticket(email: str, tenant_id: str, expires: int) -> str:
    payload = f"{email}|{tenant_id}|{expires}"
    sig = hmac.new(CUSTOMER_SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii').rstrip('=')}.{sig}"


def _verify_customer_mfa_ticket(ticket: Optional[str]) -> Optional[Tuple[str, str]]:
    """Returns (email, tenant_id) if the ticket is valid and unexpired, else None."""
    if not ticket or "." not in ticket:
        return None
    try:
        encoded, sig = ticket.rsplit(".", 1)
        padding = "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        email, tenant_id, expires_str = payload.split("|", 2)
        expected = hmac.new(
            CUSTOMER_SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(expires_str) < int(time.time()):
            return None
        return (email, tenant_id)
    except (ValueError, UnicodeDecodeError):
        return None


def _issue_customer_mfa_ticket(response: Response, email: str, tenant_id: str) -> Dict[str, Any]:
    expires = int(time.time()) + CUSTOMER_MFA_TICKET_TTL_SECONDS
    ticket = _sign_customer_mfa_ticket(email, tenant_id, expires)
    response.set_cookie(
        CUSTOMER_MFA_TICKET_COOKIE,
        ticket,
        max_age=CUSTOMER_MFA_TICKET_TTL_SECONDS,
        httponly=True,
        secure=CUSTOMER_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"ok": True, "mfa_required": True, "email": email}


def _clear_customer_mfa_ticket(response: Response) -> None:
    response.delete_cookie(CUSTOMER_MFA_TICKET_COOKIE, path="/")


def _ticket_attempt_key(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def _tenant_mfa_enabled(db: Session, tenant_id: str) -> bool:
    """Reads TenantPortalConfig(section="mfa") → {"enabled": bool}."""
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "mfa",
        )
        .first()
    )
    if not record:
        return False
    cfg = _coerce_meta(record.config) if hasattr(record, "config") else None
    if not isinstance(cfg, dict):
        return False
    return bool(cfg.get("enabled"))


def _set_tenant_mfa_enabled(db: Session, tenant_id: str, enabled: bool, updated_by: str) -> None:
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "mfa",
        )
        .first()
    )
    payload = {"enabled": bool(enabled)}
    if record:
        record.config = _encode_meta_for_db(payload)
        record.updated_by = updated_by
        record.updated_at = _utcnow()
    else:
        record = TenantPortalConfig(
            tenant_id=tenant_id,
            section="mfa",
            config=_encode_meta_for_db(payload),
            updated_by=updated_by,
            updated_at=_utcnow(),
        )
        db.add(record)
    db.commit()


def _load_customer_backup_hashes(user: TenantUser) -> List[str]:
    if not user.backup_codes_hash:
        return []
    try:
        parsed = json.loads(user.backup_codes_hash)
        if isinstance(parsed, list):
            return [str(h) for h in parsed]
    except (ValueError, TypeError):
        pass
    return []


def _consume_customer_backup_code(user: TenantUser, code: str) -> bool:
    """If ``code`` matches one of the user's backup codes, mutate the
    stored hash list to remove it and return True. Caller must commit.
    """
    hashes = _load_customer_backup_hashes(user)
    if not hashes:
        return False
    candidate = hash_backup_code(CUSTOMER_SESSION_SECRET, code)
    if candidate not in hashes:
        return False
    hashes.remove(candidate)
    user.backup_codes_hash = json.dumps(hashes)
    return True


def _send_customer_login_code(email: str, code: str) -> None:
    smtp_host = os.getenv("CUSTOMER_PORTAL_SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("CUSTOMER_PORTAL_SMTP_PORT", "587"))
    smtp_user = os.getenv("CUSTOMER_PORTAL_SMTP_USER", "").strip()
    smtp_password = os.getenv("CUSTOMER_PORTAL_SMTP_PASSWORD", "")
    smtp_from = os.getenv("CUSTOMER_PORTAL_SMTP_FROM", smtp_user or "no-reply@localhost").strip()
    use_tls = os.getenv("CUSTOMER_PORTAL_SMTP_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

    if not smtp_host:
        logger.warning("Customer portal login code for %s: %s", email, code)
        return

    msg = EmailMessage()
    msg["Subject"] = "Your CyberArmor customer portal login code"
    msg["From"] = smtp_from
    msg["To"] = email
    msg.set_content(
        "Your CyberArmor customer portal login code is:\n\n"
        f"{code}\n\n"
        f"This code expires in {CUSTOMER_CODE_TTL_SECONDS // 60} minutes."
    )
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        if smtp_user:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)


def _active_tenant_users_for_email(db: Session, email: str) -> List[TenantUser]:
    return (
        db.query(TenantUser)
        .filter(TenantUser.email == email, TenantUser.status == "active")
        .order_by(TenantUser.created_at.asc())
        .all()
    )


def _resolve_customer_session(db: Session, token: Optional[str]) -> Optional[CustomerContext]:
    if not token:
        return None
    token_hash = _hash_customer_session_token(token)
    session = db.query(CustomerSession).filter(CustomerSession.token_hash == token_hash).first()
    if not session:
        return None
    if _as_aware_utc(session.expires_at) < _utcnow():
        db.delete(session)
        db.commit()
        return None
    user = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == session.tenant_id,
            TenantUser.email == session.email,
            TenantUser.status == "active",
        )
        .first()
    )
    if not user:
        db.delete(session)
        db.commit()
        return None
    session.role = user.role
    session.last_seen_at = _utcnow()
    db.commit()
    return CustomerContext(email=user.email, tenant_id=user.tenant_id, role=user.role)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_customer_context(
    db: Annotated[Session, Depends(get_db)],
    ca_customer_session: Annotated[Optional[str], Cookie()] = None,
) -> CustomerContext:
    ctx = _resolve_customer_session(db, ca_customer_session)
    if not ctx:
        raise HTTPException(status_code=401, detail="Customer authentication required")
    return ctx


def require_customer_role(*allowed_roles: str):
    allowed = set(allowed_roles)

    def checker(ctx: Annotated[CustomerContext, Depends(get_customer_context)]) -> CustomerContext:
        if ctx.role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return checker


def verify_api_key(
    db: Annotated[Session, Depends(get_db)],
    api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
) -> Optional[Tuple[str, Optional[str]]]:
    """Resolve x-api-key (PQC-wrapped or plaintext) to (role, tenant_id).

    Returning the tenant alongside the role lets get_auth_context bind the
    tenant onto request.state without forcing every client to also send
    x-tenant-id. The audit middleware reads request.state.tenant_id after
    the route handler runs, so this is what causes audit rows to land for
    extension/agent calls that previously came in "tenant-less".
    """
    if not api_key:
        return None
    resolved = resolve_api_key_header(api_key, service_name="control-plane")
    record = db.query(ApiKey).filter(ApiKey.key == resolved.plaintext_key, ApiKey.active.is_(True)).first()
    if record:
        return (record.role, record.tenant_id)
    return None


def verify_bearer_token(authorization: Annotated[Optional[str], Header()] = None) -> Optional[Dict]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return claims
    except jwt.PyJWTError:
        return None


def get_auth_context(
    request: Request,
    api_key_identity: Annotated[Optional[Tuple[str, Optional[str]]], Depends(verify_api_key)],
    bearer_identity: Annotated[Optional[Dict], Depends(verify_bearer_token)],
    tenant_header_id: Annotated[Optional[str], Header(alias="x-tenant-id")] = None,
    role: Annotated[Optional[str], Header(alias="x-role")] = None,
) -> AuthContext:
    api_key_role = api_key_identity[0] if api_key_identity else None
    api_key_tenant = api_key_identity[1] if api_key_identity else None
    identity = bearer_identity or api_key_role
    if not identity:
        raise HTTPException(status_code=401, detail="Unauthorized")
    resolved_role = role or api_key_role or (bearer_identity.get("role") if bearer_identity else None) or "analyst"
    resolved_tenant = (
        tenant_header_id
        or api_key_tenant
        or (bearer_identity.get("tenant") if bearer_identity else None)
    )
    # Bind tenant onto request.state so the audit middleware (which reads
    # this after call_next) writes an audit row even when the caller didn't
    # send x-tenant-id explicitly.
    if resolved_tenant:
        request.state.tenant_id = resolved_tenant
    return AuthContext(principal="api-key" if api_key_role else "jwt-user", role=resolved_role, tenant_id=resolved_tenant)


def require_role(required: str):
    def checker(ctx: Annotated[AuthContext, Depends(get_auth_context)]) -> AuthContext:
        if ctx.role not in {required, "admin"}:
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return checker


def require_any_role(*allowed: str):
    """Dependency that admits any caller whose role is in *allowed* (admin always allowed).

    Use for endpoints where multiple identity kinds are legitimate — e.g.
    /telemetry/ingest accepts both human analysts and the "service" role
    used by browser extensions, proxy agents, and endpoint agents.
    """
    allowed_set = set(allowed) | {"admin"}

    def checker(ctx: Annotated[AuthContext, Depends(get_auth_context)]) -> AuthContext:
        if ctx.role not in allowed_set:
            raise HTTPException(status_code=403, detail="Forbidden")
        return ctx

    return checker


app = FastAPI(title="CyberArmor Control Plane", version="0.1.1")

# Allow browser extension and local agents to POST telemetry with preflight.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _preflight_upstream_dns() -> None:
    """Resolve every upstream service hostname at boot.

    Logs a summary line per dependency. Resolution failures are logged at
    ERROR but do NOT abort startup — that would create a chicken-and-egg
    problem with compose ordering. The point is to surface env-var typos
    (e.g. ``http://policy-service:8001`` when the actual hostname is
    ``policy``) immediately at boot instead of having every downstream
    request silently fail until someone correlates "0 policies" with a
    proxy warning buried in the logs.
    """
    import socket
    from urllib.parse import urlsplit

    deps = [
        ("POLICY_SERVICE_URL",      os.getenv("POLICY_SERVICE_URL", "http://policy:8001")),
        ("DETECTION_SERVICE_URL",   os.getenv("DETECTION_SERVICE_URL", "http://detection:8002")),
        ("RESPONSE_SERVICE_URL",    os.getenv("RESPONSE_SERVICE_URL", "http://response:8003")),
        ("AUDIT_SERVICE_URL",       os.getenv("AUDIT_SERVICE_URL", "http://audit:8011")),
        ("SECRETS_SERVICE_URL",     os.getenv("SECRETS_SERVICE_URL", "http://secrets-service:8013")),
        ("COMPLIANCE_URL",          COMPLIANCE_URL),
        ("INTEGRATION_CONTROL_URL", INTEGRATION_CONTROL_URL),
    ]
    failures: List[str] = []
    for name, url in deps:
        host = urlsplit(url).hostname or "?"
        try:
            ip = socket.gethostbyname(host)
            logger.info("preflight_dns_ok %s host=%s ip=%s", name, host, ip)
        except Exception as exc:
            failures.append(f"{name}={url} ({exc})")
            logger.error("preflight_dns_fail %s host=%s err=%s", name, host, exc)
    if failures:
        logger.error(
            "preflight_dns_summary FAILED count=%d deps=%s — these calls will fail at runtime; check the env file and compose service names",
            len(failures), failures,
        )
    else:
        logger.info("preflight_dns_summary OK count=%d", len(deps))


@app.on_event("startup")
def on_startup():
    wait_for_db()
    init_db()
    _preflight_upstream_dns()
    _start_repo_sync_scheduler()


# ── Repo-collector background scheduler ───────────────────────────────
#
# Same pattern as the endpoint-agent's policy-sync loop: kick a daemon
# thread on startup that walks every tenant with a configured
# repo-collector and runs sync_repos every ``ABOM_REPO_SYNC_INTERVAL``
# (default 6h). Errors per tenant log but don't kill the loop.
#
# Threading rather than asyncio because the underlying sync_repos uses
# blocking httpx.Client calls and we don't want to block the FastAPI
# event loop on a 200-manifest scan.

ABOM_REPO_SYNC_INTERVAL_S = int(os.getenv("ABOM_REPO_SYNC_INTERVAL_S", str(6 * 60 * 60)))
ABOM_REPO_SYNC_ENABLED = os.getenv("ABOM_REPO_SYNC_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
_repo_sync_thread_started = False


def _run_artifact_sync_pass(sync_fn) -> None:
    """Walk every tenant with an enabled artifact-collector and run
    sync_artifact_source. Mirrors the repo path; broken out so the
    same scheduler thread can drive both sections without nesting."""
    with SessionLocal() as db:
        rows = (
            db.query(TenantPortalConfig)
            .filter(TenantPortalConfig.section == "abom-artifact-collector")
            .all()
        )
        for row in rows:
            cfg = _coerce_meta(row.config) or {}
            if not isinstance(cfg, dict) or not cfg.get("enabled", True):
                continue
            refs = cfg.get("refs") or []
            if not isinstance(refs, list) or not refs:
                continue
            provider = str(cfg.get("provider") or "ghcr")
            base_url = str(cfg.get("base_url") or "")
            token = _resolve_artifact_collector_token(row.tenant_id, cfg)
            if not token:
                continue
            try:
                results = sync_fn(provider, token, refs, base_url=base_url)
            except Exception as exc:  # noqa: BLE001
                logger.warning("artifact-sync scheduler tenant=%s provider=%s failed: %s",
                               row.tenant_id, provider, exc)
                continue
            now = datetime.now(timezone.utc)
            per_ref_summaries = []
            total_obs = 0
            for source_id, components in results:
                repo_summary = {"source_id": source_id, "components": len(components), "ingested": 0, "skipped": 0}
                for component in components:
                    if not isinstance(component, dict):
                        repo_summary["skipped"] += 1
                        continue
                    try:
                        comp_row, ikey = _abom_upsert_component(db, row.tenant_id, component, now)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("scheduler artifact upsert failed: %s", exc)
                        repo_summary["skipped"] += 1
                        continue
                    comp_row.observation_count = (comp_row.observation_count or 0) + 1
                    db.add(ABOMObservation(
                        tenant_id=row.tenant_id,
                        component_id=comp_row.id,
                        identity_key=ikey,
                        collector="artifact-collector",
                        collector_version="1.0",
                        source_kind="container",
                        source_id=source_id,
                        hostname=None,
                        path=str(component.get("__path") or "")[:1024] or None,
                        raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                        observed_at=now,
                    ))
                    repo_summary["ingested"] += 1
                db.commit()
                total_obs += repo_summary["ingested"]
                per_ref_summaries.append(repo_summary)
            cfg["last_synced_at"] = now.isoformat()
            cfg["last_sync_summary"] = {
                "refs": len(per_ref_summaries),
                "observations": total_obs,
                "per_ref": per_ref_summaries,
                "source": "scheduler",
            }
            row.config = _encode_meta_for_db(cfg)
            row.updated_at = now
            db.commit()
            logger.info("artifact-sync scheduler tenant=%s provider=%s refs=%d observations=%d",
                        row.tenant_id, provider, len(per_ref_summaries), total_obs)


def _run_cloud_sync_pass(sync_fn) -> None:
    """Cloud-collector equivalent of _run_artifact_sync_pass — walks
    every tenant config row, resolves creds (OpenBao or JSONB
    fallback), runs sync_cloud_source, ingests components."""
    with SessionLocal() as db:
        rows = (
            db.query(TenantPortalConfig)
            .filter(TenantPortalConfig.section == "abom-cloud-collector")
            .all()
        )
        for row in rows:
            cfg = _coerce_meta(row.config) or {}
            if not isinstance(cfg, dict) or not cfg.get("enabled", True):
                continue
            regions = cfg.get("regions") or []
            if not isinstance(regions, list) or not regions:
                continue
            provider = str(cfg.get("provider") or "aws")
            creds = _resolve_cloud_creds(row.tenant_id, cfg)
            # Provider-specific minimum cred check — skip silently when
            # a credential bag is missing rather than logging a noisy
            # error every 6h for tenants that haven't finished setup.
            if provider == "aws":
                if not creds.get("access_key_id") or not creds.get("secret_access_key"):
                    continue
            elif provider == "gcp":
                if not creds.get("service_account_json"):
                    continue
            elif provider == "azure":
                if not (creds.get("azure_tenant_id") and creds.get("azure_client_id") and creds.get("azure_client_secret")):
                    continue
            try:
                results = sync_fn(provider, creds, regions)
            except Exception as exc:  # noqa: BLE001
                logger.warning("cloud-sync scheduler tenant=%s provider=%s failed: %s",
                               row.tenant_id, provider, exc)
                continue
            now = datetime.now(timezone.utc)
            per_region_summaries = []
            total_obs = 0
            for source_id, components in results:
                summary = {"source_id": source_id, "components": len(components), "ingested": 0, "skipped": 0}
                for component in components:
                    if not isinstance(component, dict):
                        summary["skipped"] += 1
                        continue
                    try:
                        comp_row, ikey = _abom_upsert_component(db, row.tenant_id, component, now)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("scheduler cloud upsert failed: %s", exc)
                        summary["skipped"] += 1
                        continue
                    comp_row.observation_count = (comp_row.observation_count or 0) + 1
                    db.add(ABOMObservation(
                        tenant_id=row.tenant_id,
                        component_id=comp_row.id,
                        identity_key=ikey,
                        collector="cloud-collector",
                        collector_version="1.0",
                        source_kind="cloud_resource",
                        source_id=source_id,
                        hostname=None,
                        path=str(component.get("__path") or "")[:1024] or None,
                        raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                        observed_at=now,
                    ))
                    summary["ingested"] += 1
                db.commit()
                total_obs += summary["ingested"]
                per_region_summaries.append(summary)
            cfg["last_synced_at"] = now.isoformat()
            cfg["last_sync_summary"] = {
                "regions": len(per_region_summaries),
                "observations": total_obs,
                "per_region": per_region_summaries,
                "source": "scheduler",
            }
            row.config = _encode_meta_for_db(cfg)
            row.updated_at = now
            db.commit()
            logger.info("cloud-sync scheduler tenant=%s provider=%s regions=%d observations=%d",
                        row.tenant_id, provider, len(per_region_summaries), total_obs)


def _start_repo_sync_scheduler() -> None:
    """Spawn the repo-sync daemon thread. Idempotent — repeat calls
    are no-ops so a reload-friendly process can re-trigger startup."""
    global _repo_sync_thread_started
    if not ABOM_REPO_SYNC_ENABLED:
        logger.info("repo-sync scheduler disabled via ABOM_REPO_SYNC_ENABLED")
        return
    if _repo_sync_thread_started:
        return
    _repo_sync_thread_started = True
    import threading
    threading.Thread(
        target=_repo_sync_loop,
        name="cyberarmor-abom-repo-sync",
        daemon=True,
    ).start()
    logger.info("repo-sync scheduler started (interval=%ds)", ABOM_REPO_SYNC_INTERVAL_S)


def _repo_sync_loop() -> None:
    import time as _time
    # Stagger the first run a bit so we don't pile on a cold-boot DB.
    _time.sleep(30)
    while True:
        try:
            _run_repo_sync_pass()
        except Exception as exc:  # noqa: BLE001
            logger.warning("repo-sync scheduler iteration failed: %s", exc)
        _time.sleep(max(60, ABOM_REPO_SYNC_INTERVAL_S))


def _run_repo_sync_pass() -> None:
    """One pass: find every tenant with a configured + enabled
    repo-collector OR artifact-collector and run the appropriate sync.
    Two sections in one pass to keep the scheduler thread simple — both
    are slow, both want the same cadence, both produce A-BOM rows."""
    from repo_collector import sync_repos  # lazy import: same cold-start optimization as the inline handler
    from artifact_collector import sync_artifact_source
    from cloud_collector import sync_cloud_source

    _run_artifact_sync_pass(sync_artifact_source)
    _run_cloud_sync_pass(sync_cloud_source)

    with SessionLocal() as db:
        rows = (
            db.query(TenantPortalConfig)
            .filter(TenantPortalConfig.section == "abom-repo-collector")
            .all()
        )
        for row in rows:
            cfg = _coerce_meta(row.config) or {}
            if not isinstance(cfg, dict):
                continue
            if not cfg.get("enabled", True):
                continue
            repos = cfg.get("repos") or []
            if not isinstance(repos, list) or not repos:
                continue
            provider = str(cfg.get("provider") or "github")
            token = _resolve_repo_collector_token(row.tenant_id, cfg)
            if not token:
                continue
            try:
                results = sync_repos(provider, token, repos)
            except Exception as exc:  # noqa: BLE001
                logger.warning("repo-sync %s tenant=%s failed: %s", provider, row.tenant_id, exc)
                continue
            now = datetime.now(timezone.utc)
            per_repo_summaries: List[Dict[str, Any]] = []
            total_components = total_observations = 0
            for source_id, components in results:
                repo_summary = {"source_id": source_id, "components": len(components), "ingested": 0, "skipped": 0}
                for component in components:
                    if not isinstance(component, dict):
                        repo_summary["skipped"] += 1
                        continue
                    try:
                        comp_row, ikey = _abom_upsert_component(db, row.tenant_id, component, now)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("scheduler upsert failed: %s", exc)
                        repo_summary["skipped"] += 1
                        continue
                    comp_row.observation_count = (comp_row.observation_count or 0) + 1
                    db.add(ABOMObservation(
                        tenant_id=row.tenant_id,
                        component_id=comp_row.id,
                        identity_key=ikey,
                        collector="repo-collector",
                        collector_version="1.0",
                        source_kind="repo",
                        source_id=source_id,
                        hostname=None,
                        path=str(component.get("__path") or "")[:1024] or None,
                        raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                        observed_at=now,
                    ))
                    repo_summary["ingested"] += 1
                db.commit()
                total_components += repo_summary["components"]
                total_observations += repo_summary["ingested"]
                per_repo_summaries.append(repo_summary)
            cfg["last_synced_at"] = now.isoformat()
            cfg["last_sync_summary"] = {
                "repos": len(per_repo_summaries),
                "components": total_components,
                "observations": total_observations,
                "per_repo": per_repo_summaries,
                "source": "scheduler",
            }
            row.config = _encode_meta_for_db(cfg)
            row.updated_at = now
            db.commit()
            logger.info(
                "repo-sync scheduler tenant=%s repos=%d observations=%d",
                row.tenant_id, len(per_repo_summaries), total_observations,
            )


@app.middleware("http")
async def customer_csrf_middleware(request: Request, call_next):
    """Double-submit CSRF guard for cookie-authenticated customer endpoints.

    Enforced on any state-changing request to /customer/* or to
    /customer-auth/logout when the session cookie is present. Auth
    bootstrap paths (request-code, verify-code) are intentionally
    excluded because no session exists yet.
    """
    path = request.url.path
    method = request.method
    is_mutating = method in {"POST", "PUT", "PATCH", "DELETE"}
    needs_csrf = is_mutating and (
        path.startswith("/customer/") or path == "/customer-auth/logout"
    )
    if needs_csrf and request.cookies.get(CUSTOMER_SESSION_COOKIE):
        cookie_token = request.cookies.get(CUSTOMER_CSRF_COOKIE)
        header_token = request.headers.get(CUSTOMER_CSRF_HEADER)
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or invalid"},
            )
    return await call_next(request)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    # Skip noisy infrastructure paths that have no security value in the audit log.
    _SKIP_PATHS = {"/health", "/ready", "/metrics", "/pki/public-key", "/favicon.ico"}
    if request.url.path in _SKIP_PATHS:
        return await call_next(request)

    start = datetime.now(timezone.utc)
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    principal = request.headers.get("authorization") or request.headers.get("x-api-key", "anonymous")
    response = await call_next(request)
    # Read tenant AFTER call_next so request.state.tenant_id bound by auth
    # dependencies (get_auth_context, get_customer_context) is visible. Prior
    # ordering read state before the handler ran and missed every call that
    # didn't also send an explicit x-tenant-id header.
    tenant = (
        request.headers.get("x-tenant-id")
        or getattr(request.state, "tenant_id", None)
        or None
    )
    # Skip writing if we still have no tenant context (e.g. unauthenticated probes).
    if not tenant:
        return response
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    # Best-effort audit write: never break request handling if the DB is unavailable.
    try:
        with SessionLocal() as db:
            db.add(
                AuditLog(
                    tenant_id=tenant,
                    principal=principal,
                    path=request.url.path,
                    method=request.method,
                    status=str(response.status_code),
                    duration_s=f"{duration:.4f}",
                    meta=_encode_meta_for_db({"client_ip": client_ip}),
                )
            )
            db.commit()
    except Exception as e:
        logger.warning("audit_write_failed err=%s path=%s", e, request.url.path)
    logger.info(
        "audit event=api_call path=%s method=%s status=%s tenant=%s principal=%s duration_s=%.4f client_ip=%s",
        request.url.path,
        request.method,
        response.status_code,
        tenant,
        principal,
        duration,
        client_ip,
    )
    return response


@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}

@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "service": "control-plane",
        "ts": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/metrics")
def metrics():
    uptime = round((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds(), 3)
    text = "\n".join([
        "# HELP cyberarmor_control_plane_uptime_seconds Service uptime in seconds",
        "# TYPE cyberarmor_control_plane_uptime_seconds gauge",
        f"cyberarmor_control_plane_uptime_seconds{{service=\"control-plane\",version=\"1.0.0\"}} {uptime}",
    ])
    return PlainTextResponse(text + "\n", media_type="text/plain")


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("control-plane")


@app.get("/tenants", response_model=list[TenantOut])
def list_tenants(ctx: Annotated[AuthContext, Depends(require_role("analyst"))], db: Annotated[Session, Depends(get_db)]):
    if ctx.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
        return [tenant] if tenant else []
    return db.query(Tenant).all()


class TenantCreate(BaseModel):
    id: str
    name: str
    first_admin_email: Optional[str] = None


@app.post("/tenants", response_model=TenantOut)
def create_tenant(payload: TenantCreate, ctx: Annotated[AuthContext, Depends(require_role("admin"))], db: Annotated[Session, Depends(get_db)]):
    existing = db.query(Tenant).filter(Tenant.id == payload.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant exists")
    tenant = Tenant(id=payload.id, name=payload.name)
    db.add(tenant)
    if payload.first_admin_email:
        email = _normalize_email(payload.first_admin_email)
        if not _valid_email(email):
            raise HTTPException(status_code=400, detail="first_admin_email must be a valid email")
        db.add(
            TenantUser(
                tenant_id=payload.id,
                email=email,
                role="tenant_admin",
                status="active",
                invited_by=ctx.principal,
            )
        )
    db.commit()
    db.refresh(tenant)
    return tenant


@app.get("/tenant-users", response_model=list[TenantUserOut])
def list_tenant_users_admin(
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
    tenant_id: str,
):
    """Platform-admin tenant user view used for tenant bootstrap and support."""
    if ctx.tenant_id and ctx.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    return (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id)
        .order_by(TenantUser.created_at.desc())
        .all()
    )


@app.post("/tenant-users", response_model=TenantUserOut)
def create_tenant_user_admin(
    payload: CustomerUserCreate,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
    tenant_id: str,
):
    """Platform-admin endpoint for adding the first or support-managed tenant users."""
    if ctx.tenant_id and ctx.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    email = _normalize_email(payload.email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required")
    existing = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant user already exists")
    user = TenantUser(
        tenant_id=tenant_id,
        email=email,
        role=_valid_customer_role(payload.role),
        status=_valid_customer_status(payload.status),
        invited_by=ctx.principal,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.get("/tenant-sso/{tenant_id}", response_model=CustomerSsoConfigOut)
def get_tenant_sso_admin(
    tenant_id: str,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    if ctx.tenant_id and ctx.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    config = db.query(CustomerSsoConfig).filter(CustomerSsoConfig.tenant_id == tenant_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="SSO is not configured for this tenant")
    return _safe_sso_config(config)


@app.put("/tenant-sso/{tenant_id}", response_model=CustomerSsoConfigOut)
def upsert_tenant_sso_admin(
    tenant_id: str,
    payload: CustomerSsoConfigIn,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    if ctx.tenant_id and ctx.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    if not db.query(Tenant).filter(Tenant.id == tenant_id).first():
        raise HTTPException(status_code=404, detail="Tenant not found")
    config = db.query(CustomerSsoConfig).filter(CustomerSsoConfig.tenant_id == tenant_id).first()
    if not config:
        if not payload.client_secret:
            raise HTTPException(status_code=400, detail="client_secret is required when creating SSO configuration")
        config = CustomerSsoConfig(tenant_id=tenant_id)
        db.add(config)
    for field, value in payload.model_dump().items():
        if field == "client_secret" and not value:
            continue
        setattr(config, field, value)
    db.commit()
    db.refresh(config)
    return _safe_sso_config(config)


@app.get("/customer-auth/session")
def customer_session_check(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Response:
    return Response(
        status_code=204,
        headers={
            "x-customer-email": ctx.email,
            "x-customer-tenant-id": ctx.tenant_id,
            "x-customer-role": ctx.role,
        },
    )


@app.get("/customer-auth/me")
def customer_me(ctx: Annotated[CustomerContext, Depends(get_customer_context)]) -> Dict[str, str]:
    return {"email": ctx.email, "tenant_id": ctx.tenant_id, "role": ctx.role}


@app.post("/customer-auth/request-code")
def customer_request_code(body: CustomerCodeRequest, db: Annotated[Session, Depends(get_db)]) -> Dict[str, Any]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required")

    active_users = _active_tenant_users_for_email(db, email)
    if active_users:
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.add(
            CustomerLoginCode(
                email=email,
                code_hash=_hash_customer_code(email, code),
                expires_at=_utcnow() + timedelta(seconds=CUSTOMER_CODE_TTL_SECONDS),
            )
        )
        db.commit()
        _send_customer_login_code(email, code)
        if CUSTOMER_DEV_CODE_ECHO:
            return {"ok": True, "message": "Code generated for authorized customer user.", "dev_code": code}
    else:
        logger.warning("Customer portal login requested for unknown or inactive email: %s", email)

    return {"ok": True, "message": "If this email is authorized, a login code has been sent."}


@app.post("/customer-auth/verify-code")
def customer_verify_code(
    body: CustomerCodeVerify,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    email = _normalize_email(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required")
    code = "".join(ch for ch in body.code if ch.isdigit())
    active_users = _active_tenant_users_for_email(db, email)
    if not active_users or len(code) != 6:
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    if len(active_users) > 1:
        raise HTTPException(status_code=409, detail="This email belongs to multiple tenants; tenant selection is not enabled yet")

    login_code = (
        db.query(CustomerLoginCode)
        .filter(CustomerLoginCode.email == email, CustomerLoginCode.consumed_at.is_(None))
        .order_by(CustomerLoginCode.created_at.desc())
        .first()
    )
    if not login_code or _as_aware_utc(login_code.expires_at) < _utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    if not hmac.compare_digest(login_code.code_hash, _hash_customer_code(email, code)):
        login_code.attempts = (login_code.attempts or 0) + 1
        if login_code.attempts >= CUSTOMER_MAX_CODE_ATTEMPTS:
            login_code.consumed_at = _utcnow()
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    login_code.consumed_at = _utcnow()
    user = active_users[0]
    # MFA gate: if THIS tenant has MFA enabled AND this user has enrolled,
    # issue a short-lived MFA ticket instead of a session and require the
    # client to POST to /customer-auth/verify-totp. Otherwise issue the
    # session straight away — tenants that haven't turned MFA on never see
    # this branch, and enrolled users in disabled tenants don't either
    # (per the per-tenant gating contract).
    if _tenant_mfa_enabled(db, user.tenant_id) and user.totp_enabled and user.totp_secret_enc:
        db.commit()  # persist login_code.consumed_at + any prior changes
        return _issue_customer_mfa_ticket(response, user.email, user.tenant_id)
    _issue_customer_session(response, db, user)
    db.commit()
    return {"ok": True, "email": user.email, "tenant_id": user.tenant_id, "role": user.role}


@app.post("/customer-auth/verify-totp")
def customer_verify_totp(
    body: Dict[str, Any],
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    ca_customer_mfa: Annotated[Optional[str], Cookie()] = None,
) -> Dict[str, Any]:
    """Second factor of the customer-portal login. Consumes the short-lived
    ``ca_customer_mfa`` ticket issued by /customer-auth/verify-code and, on
    success, issues the real session cookie. Accepts either a 6-digit TOTP
    code or one of the user's backup codes — the backend tries both, the
    UI is one input field.
    """
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Code required")
    code = str(body.get("code") or "").strip()
    if not code:
        raise HTTPException(status_code=400, detail="Code required")
    if not ca_customer_mfa:
        raise HTTPException(status_code=401, detail="MFA ticket missing or expired")

    parsed = _verify_customer_mfa_ticket(ca_customer_mfa)
    if not parsed:
        _clear_customer_mfa_ticket(response)
        raise HTTPException(status_code=401, detail="MFA ticket missing or expired")
    email, tenant_id = parsed

    attempt_key = _ticket_attempt_key(ca_customer_mfa)
    if _mfa_attempts_count(attempt_key) >= CUSTOMER_MFA_MAX_ATTEMPTS:
        _clear_customer_mfa_ticket(response)
        _mfa_clear_attempts(attempt_key)
        raise HTTPException(status_code=429, detail="Too many failed MFA attempts — start over")

    user = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.email == email,
            TenantUser.status == "active",
        )
        .first()
    )
    if not user or not user.totp_enabled or not user.totp_secret_enc:
        _clear_customer_mfa_ticket(response)
        raise HTTPException(status_code=401, detail="MFA not enrolled")

    secret = _get_totp_cipher().decrypt(user.totp_secret_enc)
    ok = verify_totp(secret, code) or _consume_customer_backup_code(user, code)
    if not ok:
        _mfa_inc_attempts(attempt_key)
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    _mfa_clear_attempts(attempt_key)
    _issue_customer_session(response, db, user)
    _clear_customer_mfa_ticket(response)
    db.commit()
    return {"ok": True, "email": user.email, "tenant_id": user.tenant_id, "role": user.role}


@app.post("/customer-auth/logout")
def customer_logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    ca_customer_session: Annotated[Optional[str], Cookie()] = None,
) -> Dict[str, bool]:
    if ca_customer_session:
        token_hash = _hash_customer_session_token(ca_customer_session)
        session = db.query(CustomerSession).filter(CustomerSession.token_hash == token_hash).first()
        if session:
            db.delete(session)
            db.commit()
    _clear_customer_session_cookies(response)
    return {"ok": True}


# ── Per-user TOTP MFA management (any authenticated tenant user) ─────────
def _load_customer_user(db: Session, ctx: CustomerContext) -> TenantUser:
    user = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == ctx.tenant_id,
            TenantUser.email == ctx.email,
            TenantUser.status == "active",
        )
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/customer/me/totp/status")
def customer_totp_status(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    user = _load_customer_user(db, ctx)
    return {
        "email": user.email,
        "tenant_id": user.tenant_id,
        "totp_enabled": bool(user.totp_enabled),
        "enrollment_in_progress": bool(user.totp_pending_enc),
        "backup_codes_remaining": len(_load_customer_backup_hashes(user)),
        "mfa_available_for_tenant": _tenant_mfa_enabled(db, user.tenant_id),
    }


@app.post("/customer/me/totp/enroll")
def customer_totp_enroll(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    if not _tenant_mfa_enabled(db, ctx.tenant_id):
        raise HTTPException(status_code=403, detail="MFA is not enabled for this tenant")
    user = _load_customer_user(db, ctx)
    secret = generate_secret()
    user.totp_pending_enc = _get_totp_cipher().encrypt(secret)
    db.commit()
    uri = otpauth_uri(secret, f"{user.email} ({user.tenant_id})", CUSTOMER_MFA_ISSUER)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}


@app.post("/customer/me/totp/confirm")
def customer_totp_confirm(
    body: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    code = str((body or {}).get("code") or "").strip()
    user = _load_customer_user(db, ctx)
    if not user.totp_pending_enc:
        raise HTTPException(status_code=400, detail="No enrollment in progress")
    pending = _get_totp_cipher().decrypt(user.totp_pending_enc)
    if not verify_totp(pending, code):
        raise HTTPException(status_code=401, detail="Invalid code")
    user.totp_secret_enc = user.totp_pending_enc
    user.totp_pending_enc = None
    user.totp_enabled = True
    backup_codes = generate_backup_codes()
    user.backup_codes_hash = json.dumps([hash_backup_code(CUSTOMER_SESSION_SECRET, c) for c in backup_codes])
    db.commit()
    return {"ok": True, "backup_codes": backup_codes}


@app.delete("/customer/me/totp")
def customer_totp_disable(
    body: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, bool]:
    code = str((body or {}).get("code") or "").strip()
    user = _load_customer_user(db, ctx)
    if not user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    secret = _get_totp_cipher().decrypt(user.totp_secret_enc)
    if not (verify_totp(secret, code) or _consume_customer_backup_code(user, code)):
        raise HTTPException(status_code=401, detail="Invalid code")
    user.totp_secret_enc = None
    user.totp_pending_enc = None
    user.totp_enabled = False
    user.backup_codes_hash = None
    db.commit()
    return {"ok": True}


@app.post("/customer/me/totp/backup-codes")
def customer_totp_regenerate_backup_codes(
    body: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    code = str((body or {}).get("code") or "").strip()
    user = _load_customer_user(db, ctx)
    if not user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    secret = _get_totp_cipher().decrypt(user.totp_secret_enc)
    if not verify_totp(secret, code):
        raise HTTPException(status_code=401, detail="Invalid code")
    new_codes = generate_backup_codes()
    user.backup_codes_hash = json.dumps([hash_backup_code(CUSTOMER_SESSION_SECRET, c) for c in new_codes])
    db.commit()
    return {"ok": True, "backup_codes": new_codes}


# ── Per-tenant MFA availability toggle (tenant_admin only) ──────────────
@app.get("/customer/config/mfa")
def customer_get_mfa_config(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    return {"enabled": _tenant_mfa_enabled(db, ctx.tenant_id)}


@app.put("/customer/config/mfa")
def customer_set_mfa_config(
    body: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    enabled = bool((body or {}).get("enabled"))
    _set_tenant_mfa_enabled(db, ctx.tenant_id, enabled, updated_by=ctx.email)
    return {"ok": True, "enabled": enabled}


@app.get("/customer-auth/sso/start")
def customer_sso_start(
    db: Annotated[Session, Depends(get_db)],
    email: str = Query(...),
) -> RedirectResponse:
    email = _normalize_email(email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required")
    active_users = _active_tenant_users_for_email(db, email)
    if not active_users:
        raise HTTPException(status_code=404, detail="No active customer user found for this email")
    if len(active_users) > 1:
        raise HTTPException(status_code=409, detail="This email belongs to multiple tenants; tenant selection is not enabled yet")
    user = active_users[0]
    config = (
        db.query(CustomerSsoConfig)
        .filter(CustomerSsoConfig.tenant_id == user.tenant_id, CustomerSsoConfig.enabled.is_(True))
        .first()
    )
    if not config:
        raise HTTPException(status_code=404, detail="SSO is not configured for this tenant")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    redirect_uri = _customer_redirect_uri(config)
    db.add(
        CustomerSsoState(
            state=state,
            tenant_id=user.tenant_id,
            email_hint=email,
            nonce=nonce,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            expires_at=_utcnow() + timedelta(minutes=10),
        )
    )
    db.commit()
    auth_params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "scope": config.scopes,
        "state": state,
        "nonce": nonce,
        "login_hint": email,
        "code_challenge": _base64url_sha256(code_verifier),
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{config.authorization_endpoint}?{urlencode(auth_params)}", status_code=302)


@app.get("/customer-auth/sso/callback")
def customer_sso_callback(
    db: Annotated[Session, Depends(get_db)],
    code: str = Query(...),
    state: str = Query(...),
) -> RedirectResponse:
    state_record = db.query(CustomerSsoState).filter(CustomerSsoState.state == state).first()
    if not state_record or _as_aware_utc(state_record.expires_at) < _utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired SSO state")
    config = (
        db.query(CustomerSsoConfig)
        .filter(CustomerSsoConfig.tenant_id == state_record.tenant_id, CustomerSsoConfig.enabled.is_(True))
        .first()
    )
    if not config:
        raise HTTPException(status_code=404, detail="SSO is not configured for this tenant")

    try:
        with httpx.Client(timeout=10.0) as client:
            token_resp = client.post(
                config.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": state_record.redirect_uri,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "code_verifier": state_record.code_verifier,
                },
                headers={"Accept": "application/json"},
            )
        if token_resp.status_code >= 300:
            logger.warning("customer_sso_token_exchange_failed tenant=%s status=%s body=%s", config.tenant_id, token_resp.status_code, token_resp.text[:500])
            raise HTTPException(status_code=502, detail="SSO token exchange failed")
        token_body = token_resp.json()
        id_token = token_body.get("id_token")
        if not id_token:
            raise HTTPException(status_code=502, detail="SSO provider did not return an ID token")
        signing_key = jwt.PyJWKClient(config.jwks_uri).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=config.client_id,
            issuer=config.issuer,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("customer_sso_callback_failed tenant=%s err=%s", config.tenant_id, exc)
        raise HTTPException(status_code=502, detail="SSO verification failed")

    if claims.get("nonce") != state_record.nonce:
        raise HTTPException(status_code=401, detail="SSO nonce mismatch")
    email = _normalize_email(str(claims.get("email") or claims.get("preferred_username") or state_record.email_hint or ""))
    if not _valid_email(email):
        raise HTTPException(status_code=401, detail="SSO response did not include a valid email")
    user = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == state_record.tenant_id,
            TenantUser.email == email,
            TenantUser.status == "active",
        )
        .first()
    )
    if not user:
        raise HTTPException(status_code=403, detail="SSO user is not registered for this tenant")

    db.delete(state_record)
    response = RedirectResponse("/", status_code=302)
    _issue_customer_session(response, db, user)
    db.commit()
    return response


@app.get("/customer/settings")
def customer_settings(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "tenant": {"id": tenant.id, "name": tenant.name, "active": tenant.active},
        "user": {"email": ctx.email, "role": ctx.role},
        "tenant_scope": "server_enforced",
    }


def _fetch_policy_service(path: str, tenant_id: str) -> Any:
    policy_url = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
    policy_key = os.getenv("POLICY_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.get(
            f"{policy_url.rstrip('/')}{path}",
            headers={**build_auth_headers(policy_url, policy_key), "x-tenant-id": tenant_id},
            timeout=6.0,
        )
        if resp.status_code >= 300:
            logger.warning("customer_policy_proxy_failed tenant=%s path=%s status=%s", tenant_id, path, resp.status_code)
            return []
        return resp.json()
    except Exception as exc:
        logger.warning("customer_policy_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        return []


def _fetch_ai_router(path: str, tenant_id: str) -> Any:
    router_url = os.getenv("AI_ROUTER_URL", "http://ai-router:8009")
    router_key = os.getenv("AI_ROUTER_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.get(
            f"{router_url.rstrip('/')}{path}",
            headers={**build_auth_headers(router_url, router_key), "x-tenant-id": tenant_id},
            timeout=6.0,
        )
        if resp.status_code >= 300:
            logger.warning("customer_ai_router_proxy_failed tenant=%s path=%s status=%s", tenant_id, path, resp.status_code)
            return {}
        return resp.json()
    except Exception as exc:
        logger.warning("customer_ai_router_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        return {}


def _call_detection_service(
    method: str,
    path: str,
    tenant_id: str,
    json_body: Optional[Dict[str, Any]] = None,
    timeout_s: float = 20.0,
) -> Any:
    """General-purpose proxy call to the detection service for tenant-scoped
    operations (scan endpoints, redact targets, etc.). Raises HTTPException
    on non-2xx so customer-portal clients see accurate upstream errors
    instead of a silent empty response.
    """
    det_url = os.getenv("DETECTION_SERVICE_URL", "http://detection:8002")
    det_key = os.getenv("DETECTION_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.request(
            method.upper(),
            f"{det_url.rstrip('/')}{path}",
            headers={**build_auth_headers(det_url, det_key), "x-tenant-id": tenant_id},
            json=json_body,
            timeout=timeout_s,
        )
    except Exception as exc:
        logger.warning("customer_detection_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        raise HTTPException(status_code=502, detail="detection service unavailable")
    if resp.status_code >= 300:
        logger.warning(
            "customer_detection_proxy_upstream_error tenant=%s path=%s status=%s body=%s",
            tenant_id, path, resp.status_code, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"detection service returned {resp.status_code}")
    try:
        return resp.json()
    except Exception as exc:
        logger.warning("customer_detection_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="detection service returned invalid JSON")


def _call_policy_service(
    method: str,
    path: str,
    tenant_id: str,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """General-purpose proxy call to the policy service.

    Raises HTTPException on non-2xx so customer-portal clients see accurate
    upstream errors instead of a silent empty response.
    """
    policy_url = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
    policy_key = os.getenv("POLICY_API_SECRET", DEFAULT_API_KEY)
    target = f"{policy_url.rstrip('/')}{path}"
    headers = {**build_auth_headers(policy_url, policy_key), "x-tenant-id": tenant_id}
    try:
        resp = httpx.request(
            method,
            target,
            headers=headers,
            params=params,
            json=json_body,
            timeout=10.0,
        )
    except Exception as exc:
        logger.warning("policy_proxy_error tenant=%s method=%s path=%s err=%s", tenant_id, method, path, exc)
        raise HTTPException(status_code=502, detail="policy service unavailable")
    if resp.status_code >= 400:
        detail: Any
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=detail)
    if resp.status_code == 204 or not resp.content:
        return {"status": "ok"}
    return resp.json()


def _classify_agent_health(last_seen_iso: Optional[str], now: datetime) -> Tuple[str, Optional[float]]:
    """Map last_seen to (health bucket, minutes_since_heartbeat).

    Buckets sized for a 30-60s heartbeat cadence:
      healthy        — last heartbeat within 5 min
      warn           — within 1 hour (something is throttling but agent's alive)
      stale          — within 24 hours (operator should investigate)
      offline        — older than 24 hours (likely uninstalled or laptop closed)
      never_reported — registered but no telemetry / heartbeat ever
    """
    if not last_seen_iso:
        return "never_reported", None
    try:
        last_seen = datetime.fromisoformat(str(last_seen_iso).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return "unknown", None
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    minutes = max(0.0, (now - last_seen).total_seconds() / 60.0)
    if minutes < 5:
        return "healthy", minutes
    if minutes < 60:
        return "warn", minutes
    if minutes < 24 * 60:
        return "stale", minutes
    return "offline", minutes


def _tenant_agent_rows(db: Session, tenant_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    agents_by_id: Dict[str, Dict[str, Any]] = {
        a.get("agent_id"): dict(a)
        for a in _AGENTS.values()
        if a.get("agent_id") and a.get("tenant_id") == tenant_id
    }
    # Telemetry-derived agents: include all sources, not just "endpoint".
    # Browser extensions, proxy agents, SDK runtimes, and the clipboard
    # helper all generate distinct agent_ids that the Delegation Manager
    # needs to see. The Agent Directory's Kind column already disambiguates
    # which flavor each row is.
    telemetry_rows = (
        db.query(
            TelemetryRecord.agent_id,
            func.max(TelemetryRecord.occurred_at).label("last_seen"),
        )
        .filter(TelemetryRecord.tenant_id == tenant_id)
        .filter(TelemetryRecord.agent_id.isnot(None))
        .group_by(TelemetryRecord.agent_id)
        .all()
    )
    for row in telemetry_rows:
        if not row.agent_id or row.agent_id in agents_by_id:
            continue
        latest = (
            db.query(TelemetryRecord)
            .filter(TelemetryRecord.tenant_id == tenant_id, TelemetryRecord.agent_id == row.agent_id)
            .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
            .first()
        )
        payload = _coerce_meta(latest.payload) or {} if latest else {}
        agents_by_id[row.agent_id] = {
            "agent_id": row.agent_id,
            "tenant_id": tenant_id,
            "hostname": latest.hostname if latest and latest.hostname else payload.get("hostname", ""),
            "username": latest.user_id if latest and latest.user_id else payload.get("username", ""),
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "status": "telemetry_only",
            "source": latest.source if latest else None,
            "os": payload.get("os", ""),
            "version": payload.get("version") or payload.get("agent_version", ""),
        }

    # Per-agent 24h event volume — single grouped query rather than N+1.
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    event_counts: Dict[str, int] = {}
    if agents_by_id:
        event_count_rows = (
            db.query(
                TelemetryRecord.agent_id,
                func.count(TelemetryRecord.id),
            )
            .filter(TelemetryRecord.tenant_id == tenant_id)
            .filter(TelemetryRecord.occurred_at >= day_ago)
            .filter(TelemetryRecord.agent_id.isnot(None))
            .group_by(TelemetryRecord.agent_id)
            .all()
        )
        event_counts = {aid: count for aid, count in event_count_rows}

    # Enrich each row with the derived fields the customer-portal renders.
    for aid, rec in agents_by_id.items():
        health, mins = _classify_agent_health(rec.get("last_seen"), now)
        rec["health"] = health
        rec["minutes_since_heartbeat"] = round(mins, 1) if mins is not None else None
        rec["event_count_24h"] = event_counts.get(aid, 0)
        # active_monitors arrives as a list on heartbeat; normalise to count too
        am = rec.get("active_monitors")
        if isinstance(am, list):
            rec["active_monitor_count"] = len(am)
        elif isinstance(am, int):
            rec["active_monitor_count"] = am
        else:
            rec["active_monitor_count"] = None

    agents = list(agents_by_id.values())
    agents.sort(key=lambda a: a.get("last_seen", ""), reverse=True)
    return agents[:limit]


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return value


def _readiness_summary(overview: Dict[str, Any]) -> Dict[str, Any]:
    checks = [
        {"key": "policies", "label": "At least one policy exists", "complete": int(overview.get("policy_count") or 0) > 0},
        {"key": "endpoints", "label": "At least one endpoint or agent is enrolled", "complete": int(overview.get("agent_count") or 0) > 0},
        {"key": "telemetry", "label": "Tenant telemetry is flowing", "complete": int(overview.get("telemetry_count") or 0) > 0},
        {
            "key": "evidence",
            "label": "Audit or incident evidence exists",
            "complete": int(overview.get("audit_count") or 0) + int(overview.get("incident_count") or 0) > 0,
        },
        {"key": "providers", "label": "Provider posture has been reviewed", "complete": int(overview.get("provider_count") or 0) > 0},
    ]
    complete = sum(1 for item in checks if item["complete"])
    return {"score": round((complete / len(checks)) * 100), "complete": complete, "total": len(checks), "checks": checks}


def _classify_action(event_type: str) -> str:
    """Bucket a telemetry event_type into a coarse action class.

    The Mission Control "Threat Posture" panel groups events by what the
    policy engine effectively did. We don't carry an explicit action field
    on every telemetry row, but most event types name the action in their
    prefix/suffix (policy_block, clipboard_sensitive_data_redacted, etc.),
    so a substring match is reliable.
    """
    et = (event_type or "").lower()
    # block_upload events surface as block-tier so risk metrics and the
    # Incidents view treat them the same as a hard block. Check the more
    # specific token first because "block" is a substring of "block_upload".
    if "block_upload" in et or "upload_block" in et:
        return "block"
    if "block" in et:
        return "block"
    if "redact" in et:
        return "redact"
    if "warn" in et:
        return "warn"
    if "allow" in et:
        return "allow"
    if "detect" in et or "sensitive" in et or "injection" in et:
        return "detect"
    return "monitor"


@app.get("/customer/overview")
def customer_overview(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    policies = _fetch_policy_service(f"/policies/{ctx.tenant_id}", ctx.tenant_id)
    agents = _tenant_agent_rows(db, ctx.tenant_id, limit=1000)
    audit_count = db.query(AuditLog).filter(AuditLog.tenant_id == ctx.tenant_id).count()
    telemetry_count = db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == ctx.tenant_id).count()
    incidents = list(_INCIDENTS.get(ctx.tenant_id, {}).values())
    providers = _fetch_ai_router("/ai/providers", ctx.tenant_id)

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    recent_rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
        .limit(10)
        .all()
    )
    recent_events: List[Dict[str, Any]] = []
    for r in recent_rows:
        payload = _coerce_meta(r.payload) or {}
        # Mirror the shape /customer/telemetry returns so the Mission Control
        # "raw JSON" view shows identical data — same id, full payload, and
        # both timestamps — plus our derived action_class for the pill badge.
        recent_events.append({
            "id": r.id,
            "tenant_id": r.tenant_id,
            "agent_id": r.agent_id,
            "hostname": r.hostname,
            "user_id": r.user_id,
            "event_type": r.event_type,
            "source": r.source,
            "payload": payload,
            "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "severity": payload.get("severity") if isinstance(payload, dict) else None,
            "action_class": _classify_action(r.event_type),
        })

    # 24h hourly series + action / type counts in a single pass over the
    # last day's telemetry. Bounded by the existing tenant_id index.
    day_rows = (
        db.query(TelemetryRecord.event_type, TelemetryRecord.occurred_at)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .filter(TelemetryRecord.occurred_at >= since)
        .all()
    )
    series_24h = [0] * 24
    action_24h = {"allow": 0, "monitor": 0, "warn": 0, "detect": 0, "redact": 0, "block": 0}
    type_counts: Dict[str, int] = {}
    for event_type, occurred_at in day_rows:
        if occurred_at is not None:
            # Cast naive timestamps (SQLite) to UTC so the math is consistent.
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=timezone.utc)
            hours_ago = int((now - occurred_at).total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                series_24h[23 - hours_ago] += 1
        bucket = _classify_action(event_type)
        action_24h[bucket] = action_24h.get(bucket, 0) + 1
        type_counts[event_type or "unknown"] = type_counts.get(event_type or "unknown", 0) + 1
    top_event_types_24h = [
        {"event_type": et, "count": ct}
        for et, ct in sorted(type_counts.items(), key=lambda kv: -kv[1])[:5]
    ]

    return {
        "tenant_id": ctx.tenant_id,
        "policy_count": len(policies) if isinstance(policies, list) else 0,
        "agent_count": len(agents),
        "audit_count": audit_count,
        "telemetry_count": telemetry_count,
        "incident_count": len(incidents),
        "provider_count": len((providers or {}).get("providers", [])) if isinstance(providers, dict) else 0,
        # New mission-control payload
        "recent_events": recent_events,
        "telemetry_series_24h": series_24h,
        "action_breakdown_24h": action_24h,
        "top_event_types_24h": top_event_types_24h,
    }


@app.get("/customer/policies")
def customer_policies(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    enabled_only: bool = False,
    action: Optional[str] = None,
    scope: Optional[str] = None,
    include_archived: bool = False,
    tag: Optional[str] = None,
) -> Any:
    params: Dict[str, Any] = {
        "enabled_only": enabled_only,
        "include_archived": include_archived,
    }
    if action:
        params["action"] = action
    if scope:
        params["scope"] = scope
    if tag:
        params["tag"] = tag
    return _call_policy_service("GET", f"/policies/{ctx.tenant_id}", ctx.tenant_id, params=params)


@app.post("/customer/policies")
def customer_create_policy(
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    payload = dict(payload or {})
    payload["tenant_id"] = ctx.tenant_id
    return _call_policy_service("POST", "/policies", ctx.tenant_id, json_body=payload)


def _customer_policy_owned(ctx: CustomerContext, policy_id: str, include_archived: bool = True) -> bool:
    policies = _call_policy_service(
        "GET",
        f"/policies/{ctx.tenant_id}",
        ctx.tenant_id,
        params={"include_archived": include_archived},
    )
    return any(p.get("id") == policy_id for p in policies if isinstance(p, dict))


@app.put("/customer/policies/id/{policy_id}")
def customer_update_policy(
    policy_id: str,
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    if not _customer_policy_owned(ctx, policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    payload = dict(payload or {})
    payload.pop("tenant_id", None)
    return _call_policy_service("PUT", f"/policies/id/{policy_id}", ctx.tenant_id, json_body=payload)


@app.patch("/customer/policies/id/{policy_id}/toggle")
def customer_toggle_policy(
    policy_id: str,
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    if not _customer_policy_owned(ctx, policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return _call_policy_service(
        "PATCH",
        f"/policies/id/{policy_id}/toggle",
        ctx.tenant_id,
        json_body=payload,
    )


@app.patch("/customer/policies/id/{policy_id}/archive")
def customer_archive_policy(
    policy_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    if not _customer_policy_owned(ctx, policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return _call_policy_service("PATCH", f"/policies/id/{policy_id}/archive", ctx.tenant_id)


@app.patch("/customer/policies/id/{policy_id}/unarchive")
def customer_unarchive_policy(
    policy_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    if not _customer_policy_owned(ctx, policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return _call_policy_service("PATCH", f"/policies/id/{policy_id}/unarchive", ctx.tenant_id)


@app.post("/customer/policies/evaluate")
def customer_evaluate_policy(
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    body = dict(payload or {})
    context = body.get("context", {})
    if not isinstance(context, dict):
        context = {}
    context["tenant_id"] = ctx.tenant_id
    body["context"] = context
    return _call_policy_service(
        "POST",
        f"/policies/{ctx.tenant_id}/evaluate",
        ctx.tenant_id,
        json_body=body,
    )


@app.get("/customer/agents")
def customer_agents(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 200,
) -> List[Dict[str, Any]]:
    return _tenant_agent_rows(db, ctx.tenant_id, limit=max(1, min(limit, 1000)))


@app.get("/customer/downloads/catalog", response_model=List[DownloadCatalogEntry])
def customer_download_catalog(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> List[DownloadCatalogEntry]:
    return _build_catalog(ctx.tenant_id, customer_scope=True)


@app.get("/customer/downloads/packages/{package_key}")
def customer_download_package(
    package_key: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> StreamingResponse:
    spec = _resolve_package_spec(package_key)
    return _zip_directory_response(spec, ctx.tenant_id)


@app.post("/customer/bootstrap-tokens", response_model=BootstrapTokenIssueOut)
def customer_issue_bootstrap_token(
    payload: BootstrapTokenCreate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> BootstrapTokenIssueOut:
    row, plaintext_token = _issue_bootstrap_token(
        db,
        tenant_id=ctx.tenant_id,
        package_key=payload.package_key,
        issued_to=ctx.email,
        note=payload.note,
        ttl_minutes=payload.ttl_minutes,
    )
    return _make_bootstrap_issue_out(row, plaintext_token, ctx.tenant_id, customer_scope=True)


@app.get("/customer/telemetry")
def customer_telemetry(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 200,
    before: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List telemetry rows newest-first. ``before`` (ISO-8601 timestamp)
    is a cursor against ``occurred_at`` — pass the oldest occurred_at you
    have seen to get the next page strictly older than it.
    """
    limit = max(1, min(limit, 1000))
    q = db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == ctx.tenant_id)
    if before:
        try:
            before_dt = datetime.fromisoformat(before.replace("Z", "+00:00"))
            q = q.filter(TelemetryRecord.occurred_at < before_dt)
        except ValueError:
            pass
    rows = q.order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at)).limit(limit).all()
    out: List[Dict[str, Any]] = []
    for r in rows:
        payload = _coerce_meta(r.payload) or {}
        teaser = _telemetry_teaser(r.event_type, payload) if isinstance(payload, dict) else ""
        severity = payload.get("severity") if isinstance(payload, dict) else None
        out.append({
            "id": r.id,
            "tenant_id": r.tenant_id,
            "agent_id": r.agent_id,
            "hostname": r.hostname,
            "user_id": r.user_id,
            "event_type": r.event_type,
            "source": r.source,
            "payload": payload,
            "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            # Derived fields, so the frontend gets a consistent view without
            # rummaging in payload itself.
            "action_class": _classify_action(r.event_type),
            "severity": severity,
            "payload_teaser": teaser,
        })
    return out


def _telemetry_teaser(event_type: Optional[str], payload: Dict[str, Any]) -> str:
    """Build a one-line "what happened" summary for the list view so the
    operator can scan without opening the modal. Pulls the most useful
    payload fields per event family.
    """
    et = (event_type or "").lower()
    parts: List[str] = []
    def push(label: str, value: Any) -> None:
        if value in (None, "", [], {}):
            return
        s = str(value)
        if len(s) > 80:
            s = s[:77] + "…"
        parts.append(f"{label}={s}")

    # Browser-extension / proxy navigation & enforcement events
    if "policy_block" in et or "policy_redact" in et or "policy_warn" in et:
        push("policy", payload.get("policy"))
        push("url", payload.get("url"))
        if isinstance(payload.get("pii_classes"), list) and payload["pii_classes"]:
            push("pii", ",".join(payload["pii_classes"]))
        if payload.get("redacted_url"):
            push("→", payload["redacted_url"])
    # Clipboard helper events
    elif "clipboard_sensitive_data" in et:
        if isinstance(payload.get("labels"), list) and payload["labels"]:
            push("labels", ",".join(payload["labels"]))
        push("len", payload.get("length") or payload.get("original_length"))
        push("action", payload.get("action"))
    # PII detection events (input/paste/URL scanning)
    elif "pii_" in et or "prompt_injection" in et:
        findings = payload.get("findings")
        if isinstance(findings, list):
            push("classes", ",".join(f.get("label", "?") for f in findings if isinstance(f, dict)))
        push("url", payload.get("url"))
        push("hostname", payload.get("hostname"))
    # AI / process detection (endpoint agent)
    elif et.startswith("ai_tool_") or "ai_service_connection" in et:
        push("tool", payload.get("tool_name") or payload.get("process_name") or payload.get("provider"))
        push("user", payload.get("username") or payload.get("user_id"))
        push("pid", payload.get("pid"))
        push("domain", payload.get("domain") or payload.get("remote_ip"))
    # Generic fallback — surface the highest-signal keys we see often.
    else:
        for key in ("policy", "url", "hostname", "domain", "tool_name", "process_name", "user_id", "username", "agent_id", "method", "action"):
            push(key, payload.get(key))
            if len(parts) >= 3:
                break

    return " · ".join(parts[:4])


@app.get("/customer/audit", response_model=List[AuditLogOut])
def customer_audit(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 100,
    before: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List audit rows newest-first. ``before`` (ISO-8601 timestamp) is a
    cursor for "Load more" pagination — pass the oldest ``created_at``
    you've already seen and you get the next page strictly older than it.
    Cursor-based rather than offset-based so a fresh write between pages
    can't cause duplicates or skipped rows.
    """
    limit = max(1, min(limit, 500))
    q = db.query(AuditLog).filter(AuditLog.tenant_id == ctx.tenant_id)
    if before:
        try:
            before_dt = datetime.fromisoformat(before.replace("Z", "+00:00"))
            q = q.filter(AuditLog.created_at < before_dt)
        except ValueError:
            pass  # bad cursor → ignore and return the first page
    rows = q.order_by(AuditLog.created_at.desc()).limit(limit).all()
    out: List[Dict[str, Any]] = []
    for r in rows:
        meta = _coerce_meta(r.meta) or {}
        kind, label = _classify_principal(r.principal)
        # duration_s was stored as a string. Convert to float ms for the UI;
        # if it's malformed we surface None rather than crash.
        try:
            duration_ms = float(r.duration_s) * 1000.0 if r.duration_s else None
        except (TypeError, ValueError):
            duration_ms = None
        out.append({
            "id": r.id,
            "tenant_id": r.tenant_id,
            "principal": r.principal,
            "principal_kind": kind,
            "principal_label": label,
            "path": r.path,
            "method": r.method,
            "status": r.status,
            "duration_s": r.duration_s,
            "duration_ms": duration_ms,
            "client_ip": meta.get("client_ip") if isinstance(meta, dict) else None,
            "meta": meta,
            "created_at": r.created_at,
        })
    return out


# ---- Customer-scope detection / scan proxies ---------------------------
# Customer portal's Scan Tools view (and any future SDK helper) calls these
# instead of hitting the detection service directly. Tenant is taken from
# the session, body is forwarded unchanged.

class _ScanRequest(BaseModel):
    text: str = ""
    context: Optional[Dict[str, Any]] = None


@app.post("/customer/scan/prompt-injection")
def customer_scan_prompt_injection(
    payload: _ScanRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    return _call_detection_service("POST", "/scan/prompt-injection", ctx.tenant_id, json_body=payload.model_dump())


@app.post("/customer/scan/sensitive-data")
def customer_scan_sensitive_data(
    payload: _ScanRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    return _call_detection_service("POST", "/scan/sensitive-data", ctx.tenant_id, json_body=payload.model_dump())


@app.post("/customer/scan/output-safety")
def customer_scan_output_safety(
    payload: _ScanRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    return _call_detection_service("POST", "/scan/output-safety", ctx.tenant_id, json_body=payload.model_dump())


@app.post("/customer/scan/all")
def customer_scan_all(
    payload: _ScanRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    return _call_detection_service("POST", "/scan/all", ctx.tenant_id, json_body=payload.model_dump())


def _telemetry_to_incident(
    r: "TelemetryRecord",
    agent_directory: Optional[Dict[str, Dict[str, Any]]] = None,
    host_to_agent: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """Project a TelemetryRecord row into the incident shape, but only for
    events that represent an actual enforcement decision (block/redact/warn).

    Endpoint agents and browser extensions emit block/redact/warn events as
    telemetry — they never call /incidents/ingest. The Incidents view
    needs to surface them anyway, so we merge a projection in at read time
    just like /customer/risk/events does.

    ``agent_directory`` is an optional ``agent_id -> agent row`` map from
    ``_tenant_agent_rows``. When provided, we resolve the user/hostname
    from the live registry rather than from the row, so re-associating an
    agent to a user retroactively reflects in the Incidents view.
    """
    bucket = _classify_action(r.event_type)
    if bucket not in ("block", "redact", "warn"):
        return None
    payload = _coerce_meta(r.payload) or {}

    # Findings: prefer explicit list, else build one from the classes that
    # fired so the Incidents inspector has structured rows to show.
    findings: List[Dict[str, Any]] = []
    raw_findings = payload.get("findings") if isinstance(payload, dict) else None
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if isinstance(f, dict):
                findings.append(f)
    if not findings:
        for key in ("redaction_classes", "classes", "finding_types", "pii_classes"):
            value = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(value, list):
                for c in value:
                    findings.append({"label": str(c), "type": str(c)})

    reasons: List[str] = []
    teaser = _telemetry_teaser(r.event_type, payload) if isinstance(payload, dict) else ""
    if teaser:
        reasons.append(teaser)
    if payload.get("policy_name") or payload.get("policy_id"):
        reasons.append(f"policy={payload.get('policy_name') or payload.get('policy_id')}")

    severity = payload.get("severity") if isinstance(payload, dict) else None
    metadata: Dict[str, Any] = {"derived_from": "telemetry", "source": r.source}
    if severity:
        metadata["severity"] = severity

    # Endpoint helpers (clipboard, etc.) sometimes write telemetry without
    # stamping agent_id — they only know their hostname. Recover the agent
    # binding via hostname → agent_id when the row's agent_id is null.
    resolved_agent_id = r.agent_id
    if not resolved_agent_id:
        host_candidate = r.hostname or (payload.get("hostname") if isinstance(payload, dict) else None)
        if host_candidate and host_to_agent:
            resolved_agent_id = host_to_agent.get(host_candidate)

    # Prefer the live agent registry over what was stamped on the row, so
    # re-associating an agent → user shows up on past events too.
    dir_entry = (agent_directory or {}).get(resolved_agent_id) if resolved_agent_id else None
    resolved_user = (
        (dir_entry.get("username") if dir_entry else None)
        or r.user_id
        or (payload.get("username") if isinstance(payload, dict) else None)
    )
    resolved_host = (
        (dir_entry.get("hostname") if dir_entry else None)
        or r.hostname
        or (payload.get("hostname") if isinstance(payload, dict) else None)
    )

    return {
        "tenant_id":    r.tenant_id,
        "request_id":   r.id,
        "event_type":   r.event_type,
        "decision":     bucket,
        "reasons":      reasons,
        "findings":     findings,
        "metadata":     metadata,
        "received_at":  r.occurred_at.isoformat() if r.occurred_at else None,
        "agent_id":     resolved_agent_id,
        "user_id":      resolved_user,
        "hostname":     resolved_host,
        "source":       r.source,
    }


def _tenant_agent_user_map(db: Session, tenant_id: str) -> Dict[str, str]:
    """Build agent_id → user_id for this tenant by union of sources:

    1. Active delegations from agent-identity (parent_human_id is the user).
       The Delegation Manager is the canonical place a tenant admin
       associates a human with an agent, so this wins.
    2. The agent registry's ``username`` field (heartbeat / bootstrap).

    Revoked or expired delegations are skipped — they shouldn't drive
    attribution. If multiple active delegations point to the same agent,
    we keep the most recently created one.
    """
    out: Dict[str, str] = {}

    # Source 1: active delegations.
    try:
        params = {"limit": 1000, "status": "active"}
        resp = _call_agent_identity("GET", "/delegations", tenant_id, params=params)
    except HTTPException:
        resp = None
    rows = []
    if isinstance(resp, dict):
        rows = resp.get("delegations") or []
    elif isinstance(resp, list):
        rows = resp
    tenant_agents = {a.get("agent_id") for a in _tenant_agent_rows(db, tenant_id, limit=1000) if a.get("agent_id")}
    # Index by agent_id and prefer the newest active chain so an admin can
    # rotate the human → agent binding without revoking the old chain first.
    rows_sorted = sorted(rows, key=lambda d: str(d.get("created_at") or ""), reverse=True)
    now = datetime.now(timezone.utc)
    for d in rows_sorted:
        if not isinstance(d, dict):
            continue
        aid = d.get("agent_id")
        human = d.get("parent_human_id")
        if not aid or not human or aid not in tenant_agents:
            continue
        # Skip explicitly-revoked even if upstream still returns them with
        # status=active (defensive), and drop expired chains.
        if str(d.get("status") or "active").lower() == "revoked":
            continue
        exp_raw = d.get("expires_at")
        if exp_raw:
            try:
                exp_dt = datetime.fromisoformat(str(exp_raw).replace("Z", "+00:00"))
                if exp_dt < now:
                    continue
            except (ValueError, TypeError):
                pass
        out.setdefault(aid, str(human))

    # Source 2: registry usernames (fallback).
    for a in _tenant_agent_rows(db, tenant_id, limit=1000):
        aid = a.get("agent_id")
        uname = a.get("username")
        if aid and uname and aid not in out:
            out[aid] = uname
    return out


@app.post("/customer/admin/backfill-agent-users")
def customer_backfill_agent_users(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
    overwrite: bool = False,
) -> Dict[str, Any]:
    """One-shot backfill: stamp telemetry rows + ingested incidents with the
    user/hostname from the live agent registry.

    Read-time enrichment in /customer/incidents already shows the current
    user, but other consumers (evidence export, SIEM forwarding, audit
    review) read the underlying TelemetryRecord rows directly. This admin
    endpoint persists the mapping so downstream systems see the same
    association.

    By default we only fill rows whose ``user_id`` / ``hostname`` are
    empty. Pass ``overwrite=true`` to replace existing values too — use
    sparingly; it can clobber per-request user attribution emitted by the
    proxy / SDK.
    """
    directory: Dict[str, Dict[str, Any]] = {
        a["agent_id"]: a for a in _tenant_agent_rows(db, ctx.tenant_id, limit=1000)
        if a.get("agent_id")
    }
    # Layer in active delegations: parent_human_id is the canonical user
    # binding (set via the Delegation Manager). Wins over the registry
    # username so a freshly-issued chain takes effect immediately.
    user_map = _tenant_agent_user_map(db, ctx.tenant_id)
    if not directory:
        return {"tenant_id": ctx.tenant_id, "agents_in_registry": 0,
                "telemetry_updated": 0, "incidents_updated": 0,
                "note": "agent registry is empty — nothing to backfill from"}

    # hostname → agent_id index, same as the read-time enrichment, so rows
    # without agent_id (endpoint helper writes) can still be backfilled.
    host_to_agent: Dict[str, str] = {}
    for aid, row in directory.items():
        h = row.get("hostname")
        if h and h not in host_to_agent:
            host_to_agent[h] = aid

    # Pull rows with agent_id in the registry OR with hostname in the
    # registry. Build conditions dynamically so an empty host_to_agent
    # doesn't produce a broken filter expression.
    conds = [TelemetryRecord.agent_id.in_(list(directory.keys()))]
    if host_to_agent:
        conds.append(TelemetryRecord.hostname.in_(list(host_to_agent.keys())))
    telemetry_rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .filter(or_(*conds))
        .all()
    )
    tel_updated = 0
    for r in telemetry_rows:
        # Resolve agent first: registry hit by agent_id, then by hostname.
        resolved_aid = r.agent_id if r.agent_id in directory else (host_to_agent.get(r.hostname) if r.hostname else None)
        if not resolved_aid:
            continue
        dir_entry = directory.get(resolved_aid) or {}
        new_user = user_map.get(resolved_aid) or dir_entry.get("username") or None
        new_host = dir_entry.get("hostname") or None
        changed = False
        if not r.agent_id and resolved_aid:
            r.agent_id = resolved_aid
            changed = True
        if new_user and (overwrite or not r.user_id):
            if r.user_id != new_user:
                r.user_id = new_user
                changed = True
        if new_host and (overwrite or not r.hostname):
            if r.hostname != new_host:
                r.hostname = new_host
                changed = True
        if changed:
            tel_updated += 1
    if tel_updated:
        db.commit()

    inc_updated = 0
    tenant_incidents = _INCIDENTS.get(ctx.tenant_id, {})
    for req_id, inc in tenant_incidents.items():
        aid = inc.get("agent_id")
        if not aid or aid not in directory:
            continue
        dir_entry = directory[aid]
        changed = False
        new_user = user_map.get(aid) or dir_entry.get("username") or None
        new_host = dir_entry.get("hostname") or None
        if new_user and (overwrite or not inc.get("user_id")):
            if inc.get("user_id") != new_user:
                inc["user_id"] = new_user
                changed = True
        if new_host and (overwrite or not inc.get("hostname")):
            if inc.get("hostname") != new_host:
                inc["hostname"] = new_host
                changed = True
        if changed:
            inc_updated += 1

    logger.info(
        "backfill_agent_users tenant=%s overwrite=%s telemetry_updated=%s incidents_updated=%s agents=%s",
        ctx.tenant_id, overwrite, tel_updated, inc_updated, len(directory),
    )
    return {
        "tenant_id": ctx.tenant_id,
        "agents_in_registry": len(directory),
        "telemetry_updated": tel_updated,
        "incidents_updated": inc_updated,
        "overwrite": overwrite,
    }


@app.get("/customer/incidents")
def customer_incidents(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Tenant-scoped incident feed.

    Merges two sources:
      - _INCIDENTS: proxy / AI router runtime decisions ingested via
        /incidents/ingest. May be empty for tenants that don't run the
        proxy or runtime SDK.
      - TelemetryRecord rows with an enforcement action class
        (block/redact/warn), projected into the incident shape so endpoint
        and browser-extension enforcement still surfaces here.
    """
    limit = max(1, min(limit, 500))

    # Build agent_id → agent row map once so projections (and re-decoration
    # of already-ingested incidents) reflect the *current* agent→user
    # association rather than what was stamped at event time.
    agent_directory: Dict[str, Dict[str, Any]] = {
        a["agent_id"]: a for a in _tenant_agent_rows(db, ctx.tenant_id, limit=1000)
        if a.get("agent_id")
    }
    # Delegation Manager bindings are the canonical source of truth for the
    # agent → human mapping; fold them onto the directory rows so downstream
    # code sees a single map to query.
    user_map = _tenant_agent_user_map(db, ctx.tenant_id)
    for aid, uname in user_map.items():
        if aid in agent_directory:
            # Win over the registry's username when a delegation exists.
            agent_directory[aid] = {**agent_directory[aid], "username": uname}
        else:
            # Agent only known to agent-identity / delegations — still
            # surface its username so the projection picks it up.
            agent_directory[aid] = {"agent_id": aid, "username": uname}

    # hostname → agent_id index for endpoint helpers that write telemetry
    # without stamping agent_id (e.g. endpoint_clipboard_helper).
    host_to_agent: Dict[str, str] = {}
    for aid, row in agent_directory.items():
        h = row.get("hostname")
        if h and h not in host_to_agent:
            host_to_agent[h] = aid

    def _enrich(inc: Dict[str, Any]) -> Dict[str, Any]:
        aid = inc.get("agent_id")
        if not aid:
            host = inc.get("hostname") or (inc.get("metadata") or {}).get("hostname")
            if host:
                aid = host_to_agent.get(host)
        if not aid or aid not in agent_directory:
            return inc
        dir_entry = agent_directory[aid]
        out = dict(inc)
        if not out.get("agent_id"):
            out["agent_id"] = aid
        if not out.get("user_id") and dir_entry.get("username"):
            out["user_id"] = dir_entry["username"]
        if not out.get("hostname") and dir_entry.get("hostname"):
            out["hostname"] = dir_entry["hostname"]
        return out

    ingested = [_enrich(i) for i in _INCIDENTS.get(ctx.tenant_id, {}).values()]

    telemetry_rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
        .limit(limit * 2)  # over-fetch since we filter to block/redact/warn
        .all()
    )
    projected = [p for p in (_telemetry_to_incident(r, agent_directory, host_to_agent) for r in telemetry_rows) if p]

    def ts_key(inc: Dict[str, Any]) -> float:
        ts = inc.get("received_at")
        if not ts:
            return 0.0
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return 0.0

    merged = sorted(ingested + projected, key=ts_key, reverse=True)[:limit]
    return merged


@app.get("/customer/evidence/export")
def customer_evidence_export(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    scope: str = Query("summary", pattern="^(summary|full)$"),
) -> Dict[str, Any]:
    """Create a tenant-scoped evidence export pack for reports, demos, and audits."""
    full = scope == "full"
    telemetry_limit = 500 if full else 50
    audit_limit = 500 if full else 50
    incident_limit = 250 if full else 25

    tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
    policies = _fetch_policy_service(f"/policies/{ctx.tenant_id}", ctx.tenant_id)
    providers = _fetch_ai_router("/ai/providers", ctx.tenant_id)
    agents = _tenant_agent_rows(db, ctx.tenant_id, limit=500 if full else 50)
    telemetry_rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
        .limit(telemetry_limit)
        .all()
    )
    audit_rows = (
        db.query(AuditLog)
        .filter(AuditLog.tenant_id == ctx.tenant_id)
        .order_by(AuditLog.created_at.desc())
        .limit(audit_limit)
        .all()
    )
    incidents = sorted(
        _INCIDENTS.get(ctx.tenant_id, {}).values(),
        key=lambda x: x.get("received_at", ""),
        reverse=True,
    )[:incident_limit]
    overview = {
        "tenant_id": ctx.tenant_id,
        "policy_count": len(policies) if isinstance(policies, list) else 0,
        "agent_count": len(agents),
        "audit_count": db.query(AuditLog).filter(AuditLog.tenant_id == ctx.tenant_id).count(),
        "telemetry_count": db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == ctx.tenant_id).count(),
        "incident_count": len(_INCIDENTS.get(ctx.tenant_id, {})),
        "provider_count": len((providers or {}).get("providers", [])) if isinstance(providers, dict) else 0,
    }

    return {
        "export_type": "cyberarmor_tenant_evidence",
        "schema_version": "2026-05-06",
        "scope": scope,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": {"email": ctx.email, "role": ctx.role},
        "tenant": {
            "id": ctx.tenant_id,
            "name": tenant.name if tenant else ctx.tenant_id,
        },
        "overview": overview,
        "readiness": _readiness_summary(overview),
        "policies": _json_safe(policies if isinstance(policies, list) else []),
        "agents": _json_safe(agents),
        "providers": _json_safe(providers if isinstance(providers, dict) else {}),
        "telemetry": [
            {
                "id": row.id,
                "agent_id": row.agent_id,
                "hostname": row.hostname,
                "user_id": row.user_id,
                "event_type": row.event_type,
                "source": row.source,
                "payload": _coerce_meta(row.payload) or {},
                "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in telemetry_rows
        ],
        "audit": [
            {
                "id": row.id,
                "method": row.method,
                "path": row.path,
                "status": row.status,
                "meta": _coerce_meta(row.meta) or {},
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in audit_rows
        ],
        "incidents": _json_safe(incidents),
        "notes": [
            "This export is tenant-scoped and generated from the customer portal session.",
            "Secrets and write-only configuration fields are not included.",
        ],
    }


class ReportRequest(BaseModel):
    """Request payload for /customer/reports/generate.

    ``report_type`` selects which named report to assemble; ``since`` /
    ``until`` are ISO-8601 timestamps that bound the data window. If both
    are omitted, the report covers all tenant data on hand.
    """
    report_type: str
    since: Optional[str] = None
    until: Optional[str] = None


_REPORT_CATALOG = [
    {"id": "executive",            "title": "Executive Summary",       "description": "High-level posture and top recommendations for leadership."},
    {"id": "ai_risk",              "title": "AI Risk Report",          "description": "Top-risk agents, blocked actions, providers, and models."},
    {"id": "dlp",                  "title": "DLP Activity Report",     "description": "Sensitive-data findings by class and most-affected events."},
    {"id": "endpoint_health",      "title": "Endpoint Health Report",  "description": "Agent reachability, heartbeat freshness, and version mix."},
    {"id": "policy_effectiveness", "title": "Policy Effectiveness",    "description": "Per-policy hit rate, blocked/allowed split, and unused policies."},
]


def _parse_window(since: Optional[str], until: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    """Parse ISO-8601 timestamps tolerant of trailing Z. Returns (since, until)."""
    def _one(v: Optional[str]) -> Optional[datetime]:
        if not v:
            return None
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    return _one(since), _one(until)


def _events_in_window(
    db: Session,
    tenant_id: str,
    since: Optional[datetime],
    until: Optional[datetime],
    limit: int = 2000,
) -> tuple[list["TelemetryRecord"], list["AuditLog"], list[Dict[str, Any]]]:
    """Pull telemetry + audit + incidents for the tenant inside the window."""
    tq = db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == tenant_id)
    if since is not None:
        tq = tq.filter(TelemetryRecord.occurred_at >= since)
    if until is not None:
        tq = tq.filter(TelemetryRecord.occurred_at <= until)
    telemetry = tq.order_by(desc(TelemetryRecord.occurred_at)).limit(limit).all()

    aq = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if since is not None:
        aq = aq.filter(AuditLog.created_at >= since)
    if until is not None:
        aq = aq.filter(AuditLog.created_at <= until)
    audit = aq.order_by(desc(AuditLog.created_at)).limit(limit).all()

    all_incidents = list(_INCIDENTS.get(tenant_id, {}).values())
    incidents: list[Dict[str, Any]] = []
    for inc in all_incidents:
        ts_raw = inc.get("received_at") or inc.get("created_at")
        ts_dt: Optional[datetime] = None
        if ts_raw:
            try:
                ts_dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                ts_dt = None
        if since is not None and (ts_dt is None or ts_dt < since):
            continue
        if until is not None and (ts_dt is None or ts_dt > until):
            continue
        incidents.append(inc)
    incidents.sort(key=lambda x: x.get("received_at", ""), reverse=True)
    return telemetry, audit, incidents


def _build_executive_report(
    *,
    overview: Dict[str, Any],
    telemetry: list["TelemetryRecord"],
    audit: list["AuditLog"],
    incidents: list[Dict[str, Any]],
    policies: Any,
    agents: list[Dict[str, Any]],
    providers: Any,
) -> list[Dict[str, Any]]:
    buckets: Dict[str, int] = {}
    for r in telemetry:
        b = _classify_action(r.event_type)
        buckets[b] = buckets.get(b, 0) + 1
    blocked = buckets.get("block", 0)
    redacted = buckets.get("redact", 0)
    detected = buckets.get("detect", 0)
    online_agents = sum(1 for a in agents if str(a.get("status") or "").lower() in ("running", "online", "ok"))
    provider_count = len((providers or {}).get("providers", [])) if isinstance(providers, dict) else 0
    policy_count = len(policies) if isinstance(policies, list) else 0
    enabled_policies = sum(1 for p in (policies or []) if isinstance(p, dict) and p.get("enabled") is not False)

    recs: list[str] = []
    if blocked > 0:
        recs.append(f"{blocked} blocked actions in window — review top agents and tighten policies as needed.")
    if detected > redacted + blocked and detected > 5:
        recs.append(f"{detected} detect-tier events not yet enforced — consider promoting common detections to redact/block.")
    if provider_count == 0:
        recs.append("No AI providers configured — connect at least one to enable runtime decisioning.")
    if policy_count and enabled_policies == 0:
        recs.append("All tenant policies are disabled — enable at least one to enforce decisions.")
    if not recs:
        recs.append("Posture is healthy in this window. Continue monitoring.")

    return [
        {"id": "summary", "title": "Summary", "type": "metrics", "metrics": [
            {"label": "Telemetry events", "value": len(telemetry), "tone": "slate"},
            {"label": "Audit events",     "value": len(audit),     "tone": "slate"},
            {"label": "Incidents",        "value": len(incidents), "tone": "amber" if incidents else "emerald"},
            {"label": "Blocked actions",  "value": blocked,        "tone": "rose"  if blocked else "emerald"},
            {"label": "Redacted",         "value": redacted,       "tone": "amber" if redacted else "emerald"},
            {"label": "Online agents",    "value": f"{online_agents}/{len(agents)}", "tone": "emerald" if online_agents == len(agents) and agents else "amber"},
            {"label": "AI providers",     "value": provider_count, "tone": "slate"},
            {"label": "Enabled policies", "value": f"{enabled_policies}/{policy_count}", "tone": "slate"},
        ]},
        {"id": "recommendations", "title": "Recommendations", "type": "list", "items": recs},
        {"id": "action_mix", "title": "Action class mix", "type": "table",
         "columns": ["Class", "Events"],
         "rows": sorted(
             [[k, v] for k, v in buckets.items()],
             key=lambda r: r[1], reverse=True,
         )},
    ]


def _build_ai_risk_report(
    *,
    telemetry: list["TelemetryRecord"],
    incidents: list[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    agent_stats: Dict[str, Dict[str, Any]] = {}
    provider_stats: Dict[str, int] = {}
    model_stats: Dict[str, int] = {}
    blocked = 0
    for r in telemetry:
        bucket = _classify_action(r.event_type)
        payload = _coerce_meta(r.payload) or {}
        aid = r.agent_id or payload.get("agent_id") or "unknown"
        a = agent_stats.setdefault(aid, {"events": 0, "blocked": 0, "redacted": 0})
        a["events"] += 1
        if bucket == "block":
            a["blocked"] += 1
            blocked += 1
        if bucket == "redact":
            a["redacted"] += 1
        prov = payload.get("provider") or r.source
        if prov:
            provider_stats[prov] = provider_stats.get(prov, 0) + 1
        model = payload.get("model")
        if model:
            model_stats[model] = model_stats.get(model, 0) + 1

    top_agents = sorted(
        agent_stats.items(),
        key=lambda kv: (kv[1]["blocked"], kv[1]["events"]),
        reverse=True,
    )[:10]
    top_providers = sorted(provider_stats.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_models = sorted(model_stats.items(), key=lambda kv: kv[1], reverse=True)[:10]
    block_incidents = [i for i in incidents if str(i.get("decision") or "").lower() in ("block", "deny")]

    return [
        {"id": "summary", "title": "Summary", "type": "metrics", "metrics": [
            {"label": "Telemetry events", "value": len(telemetry), "tone": "slate"},
            {"label": "Blocked actions",  "value": blocked,        "tone": "rose"  if blocked else "emerald"},
            {"label": "Distinct agents",  "value": len(agent_stats), "tone": "slate"},
            {"label": "Block incidents",  "value": len(block_incidents), "tone": "rose" if block_incidents else "emerald"},
        ]},
        {"id": "top_agents", "title": "Top agents by risk", "type": "table",
         "columns": ["Agent", "Events", "Blocked", "Redacted"],
         "rows": [[aid, s["events"], s["blocked"], s["redacted"]] for aid, s in top_agents]},
        {"id": "top_providers", "title": "AI providers seen", "type": "table",
         "columns": ["Provider", "Events"],
         "rows": [[p, n] for p, n in top_providers]},
        {"id": "top_models", "title": "Models seen", "type": "table",
         "columns": ["Model", "Events"],
         "rows": [[m, n] for m, n in top_models]},
    ]


def _build_dlp_report(*, telemetry: list["TelemetryRecord"]) -> list[Dict[str, Any]]:
    class_hits: Dict[str, int] = {}
    redact_events = 0
    detect_events = 0
    by_event_type: Dict[str, int] = {}
    by_hostname: Dict[str, int] = {}
    for r in telemetry:
        bucket = _classify_action(r.event_type)
        payload = _coerce_meta(r.payload) or {}
        if bucket in ("redact", "detect", "block"):
            by_event_type[r.event_type] = by_event_type.get(r.event_type, 0) + 1
            if r.hostname:
                by_hostname[r.hostname] = by_hostname.get(r.hostname, 0) + 1
        if bucket == "redact":
            redact_events += 1
        if bucket == "detect":
            detect_events += 1
        # Telemetry payloads may carry the classes that fired in
        # ``redaction_classes`` / ``classes`` / ``finding_types``.
        for key in ("redaction_classes", "classes", "finding_types", "pii_classes"):
            value = payload.get(key)
            if isinstance(value, list):
                for c in value:
                    s = str(c)
                    class_hits[s] = class_hits.get(s, 0) + 1
        findings = payload.get("findings")
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    t = f.get("type") or f.get("class") or f.get("name")
                    if t:
                        s = str(t)
                        class_hits[s] = class_hits.get(s, 0) + 1

    top_classes = sorted(class_hits.items(), key=lambda kv: kv[1], reverse=True)[:15]
    top_event_types = sorted(by_event_type.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_hosts = sorted(by_hostname.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return [
        {"id": "summary", "title": "Summary", "type": "metrics", "metrics": [
            {"label": "Redact events",  "value": redact_events, "tone": "amber" if redact_events else "emerald"},
            {"label": "Detect events",  "value": detect_events, "tone": "amber" if detect_events else "emerald"},
            {"label": "Class hits",     "value": sum(class_hits.values()), "tone": "slate"},
            {"label": "Affected hosts", "value": len(by_hostname), "tone": "slate"},
        ]},
        {"id": "top_classes", "title": "Top sensitive-data classes", "type": "table",
         "columns": ["Class", "Hits"],
         "rows": [[k, v] for k, v in top_classes]},
        {"id": "top_event_types", "title": "Top DLP event types", "type": "table",
         "columns": ["Event type", "Count"],
         "rows": [[k, v] for k, v in top_event_types]},
        {"id": "top_hosts", "title": "Most-affected hosts", "type": "table",
         "columns": ["Hostname", "Events"],
         "rows": [[k, v] for k, v in top_hosts]},
    ]


def _build_endpoint_health_report(
    *,
    agents: list[Dict[str, Any]],
    telemetry: list["TelemetryRecord"],
    until: Optional[datetime],
) -> list[Dict[str, Any]]:
    cutoff = until or datetime.now(timezone.utc)
    status_counts: Dict[str, int] = {}
    version_counts: Dict[str, int] = {}
    stale: list[list[Any]] = []
    by_host: Dict[str, int] = {}
    for a in agents:
        st = str(a.get("status") or "unknown").lower()
        status_counts[st] = status_counts.get(st, 0) + 1
        version = str(a.get("version") or "—")
        version_counts[version] = version_counts.get(version, 0) + 1
        last_seen_raw = a.get("last_seen")
        try:
            last_seen = datetime.fromisoformat(str(last_seen_raw).replace("Z", "+00:00")) if last_seen_raw else None
        except (ValueError, TypeError):
            last_seen = None
        if last_seen is None or (cutoff - last_seen) > timedelta(hours=1):
            stale.append([a.get("agent_id"), a.get("hostname"), st, str(last_seen_raw or "—")])
    for r in telemetry:
        if r.hostname:
            by_host[r.hostname] = by_host.get(r.hostname, 0) + 1
    top_hosts = sorted(by_host.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return [
        {"id": "summary", "title": "Summary", "type": "metrics", "metrics": [
            {"label": "Agents",        "value": len(agents), "tone": "slate"},
            {"label": "Online",        "value": status_counts.get("running", 0) + status_counts.get("online", 0) + status_counts.get("ok", 0), "tone": "emerald"},
            {"label": "Stale (>1h)",   "value": len(stale), "tone": "amber" if stale else "emerald"},
            {"label": "Versions",      "value": len(version_counts), "tone": "amber" if len(version_counts) > 1 else "emerald"},
        ]},
        {"id": "status_mix", "title": "Status mix", "type": "table",
         "columns": ["Status", "Agents"],
         "rows": sorted([[k, v] for k, v in status_counts.items()], key=lambda r: r[1], reverse=True)},
        {"id": "version_mix", "title": "Version mix", "type": "table",
         "columns": ["Version", "Agents"],
         "rows": sorted([[k, v] for k, v in version_counts.items()], key=lambda r: r[1], reverse=True)},
        {"id": "stale", "title": "Stale agents (no heartbeat in last hour)", "type": "table",
         "columns": ["Agent", "Hostname", "Status", "Last seen"],
         "rows": stale[:20]},
        {"id": "top_hosts", "title": "Most-active hosts (telemetry)", "type": "table",
         "columns": ["Hostname", "Events"],
         "rows": [[k, v] for k, v in top_hosts]},
    ]


def _build_policy_effectiveness_report(
    *,
    policies: Any,
    telemetry: list["TelemetryRecord"],
) -> list[Dict[str, Any]]:
    policy_list = policies if isinstance(policies, list) else []
    # Map telemetry hits onto policies by name when payload carries a policy
    # reference. This isn't perfect but covers the proxy / RASP path that
    # stamps ``policy_id`` / ``policy_name`` on the event.
    hits_by_policy: Dict[str, Dict[str, int]] = {}
    for r in telemetry:
        payload = _coerce_meta(r.payload) or {}
        key = payload.get("policy_name") or payload.get("policy_id") or payload.get("policy")
        if not key:
            continue
        bucket = _classify_action(r.event_type)
        h = hits_by_policy.setdefault(str(key), {"events": 0, "blocked": 0, "redacted": 0})
        h["events"] += 1
        if bucket == "block":   h["blocked"] += 1
        if bucket == "redact":  h["redacted"] += 1

    rows: list[list[Any]] = []
    unused: list[list[Any]] = []
    for p in policy_list:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or p.get("id") or "")
        pid = str(p.get("id") or "")
        action = str(p.get("action") or "monitor")
        enabled = "yes" if p.get("enabled") is not False else "no"
        stats = hits_by_policy.get(name) or hits_by_policy.get(pid) or {"events": 0, "blocked": 0, "redacted": 0}
        rows.append([name or pid, action, enabled, stats["events"], stats["blocked"], stats["redacted"]])
        if stats["events"] == 0 and p.get("enabled") is not False:
            unused.append([name or pid, action])
    rows.sort(key=lambda r: r[3], reverse=True)

    return [
        {"id": "summary", "title": "Summary", "type": "metrics", "metrics": [
            {"label": "Policies",         "value": len(policy_list), "tone": "slate"},
            {"label": "With hits",        "value": sum(1 for r in rows if r[3] > 0), "tone": "emerald"},
            {"label": "Unused (enabled)", "value": len(unused), "tone": "amber" if unused else "emerald"},
        ]},
        {"id": "by_policy", "title": "Policy hits", "type": "table",
         "columns": ["Policy", "Action", "Enabled", "Events", "Blocked", "Redacted"],
         "rows": rows},
        {"id": "unused", "title": "Unused enabled policies", "type": "table",
         "columns": ["Policy", "Action"],
         "rows": unused},
    ]


# ── Upload endpoint discovery ─────────────────────────────────────────
#
# Browser extensions emit "upload_endpoint_discovered" telemetry when a
# multipart upload passes through to an AI-service host that isn't in the
# built-in pattern catalog. This endpoint aggregates those events into
# promotion candidates: same path-pattern grouped together, ranked by
# observation count. Promoted patterns land in the tenant's
# upload-discovery portal config and are returned by /customer/upload-
# patterns/extras so extensions can merge them into their runtime
# catalog at policy sync time.

# Built-in catalog. Mirrors AI_UPLOAD_PATTERNS in
# extensions/chromium-shared/background.js — the server uses this to
# de-dup candidates the extensions already know about, so a tenant only
# sees genuinely-new endpoints.
_BUILTIN_UPLOAD_PATTERNS = [
    "chatgpt.com/backend-api/files",
    "chat.openai.com/backend-api/files",
    "claude.ai/api/*/upload_file",
    "claude.ai/api/organizations/",
    "claude.ai/api/convert_document",
    "gemini.google.com/_/upload",
    "gemini.google.com/_/uploads",
    "copilot.microsoft.com/c/api/files",
    "perplexity.ai/rest/uploads",
    "/upload/files",
    "/api/files/upload",
]

_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_HEX24_RE = re.compile(r"\b[0-9a-f]{24,}\b", re.IGNORECASE)
_LONG_DIGITS_RE = re.compile(r"\b\d{6,}\b")


def _collapse_path_pattern(path: str) -> str:
    """Collapse high-entropy segments to ``*`` so distinct upload URLs
    aggregate into a single promotion candidate.

    Examples:
      /api/conversations/01934abc-…-cdef/files  -> /api/conversations/*/files
      /uploads/4f9c4e44af86bfa0/contents        -> /uploads/*/contents
      /api/files/123456789                      -> /api/files/*
    """
    if not path:
        return path
    out = _UUID_RE.sub("*", path)
    out = _HEX24_RE.sub("*", out)
    out = _LONG_DIGITS_RE.sub("*", out)
    return out


def _matches_pattern(hostpath: str, pattern: str) -> bool:
    """Ordered-segment match — same algorithm the extension uses for its
    AI_UPLOAD_PATTERNS catalog. ``*`` is a wildcard between segments."""
    if not pattern:
        return False
    segments = pattern.split("*")
    cursor = 0
    for seg in segments:
        if not seg:
            continue
        idx = hostpath.find(seg, cursor)
        if idx < 0:
            return False
        cursor = idx + len(seg)
    return True


def _is_in_any_catalog(hostpath: str, extras: List[str]) -> bool:
    for p in _BUILTIN_UPLOAD_PATTERNS:
        if _matches_pattern(hostpath, p):
            return True
    for p in extras:
        if _matches_pattern(hostpath, p):
            return True
    return False


def _load_tenant_extra_patterns(db: Session, tenant_id: str) -> List[str]:
    """Read promoted upload patterns from the tenant's portal config.
    Returns a list; tolerant of legacy shapes that may have stored the
    patterns as a dict.
    """
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "upload-discovery",
        )
        .first()
    )
    if not record:
        return []
    cfg = _coerce_meta(record.config) if hasattr(record, "config") else None
    if not isinstance(cfg, dict):
        return []
    raw = cfg.get("patterns")
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for entry in raw:
        if isinstance(entry, str) and entry.strip():
            out.append(entry.strip())
    return out


def _save_tenant_extra_patterns(db: Session, tenant_id: str, patterns: List[str], updated_by: str) -> None:
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "upload-discovery",
        )
        .first()
    )
    config = {"patterns": patterns}
    if record:
        record.config = _encode_meta_for_db(config)
        record.updated_by = updated_by
        record.updated_at = datetime.now(timezone.utc)
    else:
        record = TenantPortalConfig(
            tenant_id=tenant_id,
            section="upload-discovery",
            config=_encode_meta_for_db(config),
            updated_by=updated_by,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(record)
    db.commit()


@app.get("/customer/upload-discovery/candidates")
def customer_upload_discovery_candidates(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    days: int = 30,
    limit: int = 100,
) -> Dict[str, Any]:
    """Return aggregated upload-endpoint candidates the extensions have
    observed but that aren't yet covered by the catalog (built-in +
    tenant extras).

    Grouping key: (hostname, collapsed_path). The collapsed path replaces
    UUIDs / long hex / long digit runs with ``*`` so per-conversation
    paths roll up into a single pattern an admin can promote in one
    click.
    """
    days = max(1, min(days, 90))
    limit = max(1, min(limit, 500))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .filter(TelemetryRecord.event_type == "upload_endpoint_discovered")
        .filter(TelemetryRecord.occurred_at >= since)
        .order_by(desc(TelemetryRecord.occurred_at))
        .limit(2000)  # cap raw set; we aggregate down anyway
        .all()
    )

    extras = _load_tenant_extra_patterns(db, ctx.tenant_id)

    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rows:
        payload = _coerce_meta(r.payload) or {}
        host = str(payload.get("hostname") or "")
        path = str(payload.get("path") or "")
        if not host or not path:
            continue
        collapsed = _collapse_path_pattern(path)
        suggested = f"{host}{collapsed}"
        # Already covered by catalog (built-in or tenant extra)? Skip — the
        # discovery surface should only show NEW endpoints.
        if _is_in_any_catalog(host + path, extras):
            continue
        key = (host, collapsed)
        g = groups.get(key)
        if not g:
            g = {
                "hostname": host,
                "path_pattern": collapsed,
                "suggested_pattern": suggested,
                "count": 0,
                "total_bytes": 0,
                "first_seen": r.occurred_at.isoformat() if r.occurred_at else None,
                "last_seen": r.occurred_at.isoformat() if r.occurred_at else None,
                "file_types": set(),
                "sample_urls": [],
            }
            groups[key] = g
        g["count"] += 1
        g["total_bytes"] += int(payload.get("total_bytes") or 0)
        for ft in (payload.get("file_types") or []):
            g["file_types"].add(str(ft))
        if len(g["sample_urls"]) < 3:
            sample = str(payload.get("url") or "")
            if sample and sample not in g["sample_urls"]:
                g["sample_urls"].append(sample)
        ts = r.occurred_at.isoformat() if r.occurred_at else None
        if ts:
            if not g["last_seen"] or ts > g["last_seen"]:
                g["last_seen"] = ts
            if not g["first_seen"] or ts < g["first_seen"]:
                g["first_seen"] = ts

    candidates = []
    for g in groups.values():
        g["file_types"] = sorted(g["file_types"])
        candidates.append(g)
    candidates.sort(key=lambda c: (c["count"], c["last_seen"] or ""), reverse=True)
    return {
        "candidates": candidates[:limit],
        "total": len(candidates),
        "window_days": days,
        "promoted_patterns": extras,
    }


class UploadPatternRequest(BaseModel):
    pattern: str


@app.post("/customer/upload-discovery/promote")
def customer_upload_discovery_promote(
    payload: UploadPatternRequest,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Add a pattern to the tenant's promoted upload-discovery list.
    Extensions pull these via /customer/upload-patterns/extras and merge
    them into their runtime catalog at policy-sync time.
    """
    pat = payload.pattern.strip()
    if not pat:
        raise HTTPException(status_code=400, detail="empty pattern")
    if len(pat) > 200:
        raise HTTPException(status_code=400, detail="pattern too long")
    extras = _load_tenant_extra_patterns(db, ctx.tenant_id)
    if pat in extras:
        return {"patterns": extras, "added": False}
    extras.append(pat)
    _save_tenant_extra_patterns(db, ctx.tenant_id, extras, updated_by=ctx.email)
    return {"patterns": extras, "added": True}


@app.post("/customer/upload-discovery/remove")
def customer_upload_discovery_remove(
    payload: UploadPatternRequest,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    pat = payload.pattern.strip()
    extras = _load_tenant_extra_patterns(db, ctx.tenant_id)
    if pat not in extras:
        return {"patterns": extras, "removed": False}
    extras = [p for p in extras if p != pat]
    _save_tenant_extra_patterns(db, ctx.tenant_id, extras, updated_by=ctx.email)
    return {"patterns": extras, "removed": True}


@app.get("/customer/upload-patterns/extras")
def customer_upload_patterns_extras(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Tenant-promoted upload patterns. Extension pulls this at policy
    sync time and unions with its built-in AI_UPLOAD_PATTERNS for the
    runtime catalog used by both DNR rule synthesis and the MAIN-world
    fetch wrapper's catalog check.
    """
    return {"patterns": _load_tenant_extra_patterns(db, ctx.tenant_id)}


@app.get("/customer/reports/catalog")
def customer_reports_catalog(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Dict[str, Any]:
    """Catalog of named reports the customer can generate.

    Returned shape mirrors what the portal needs to render the gallery —
    {id, title, description} per entry. Static for now; once we have
    per-tenant report templates this becomes per-tenant.
    """
    return {"reports": list(_REPORT_CATALOG)}


@app.post("/customer/reports/generate")
def customer_reports_generate(
    payload: ReportRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Assemble a named tenant report over an optional ISO-8601 window."""
    rid = payload.report_type
    if rid not in {r["id"] for r in _REPORT_CATALOG}:
        raise HTTPException(status_code=400, detail=f"unknown report_type: {rid}")
    since_dt, until_dt = _parse_window(payload.since, payload.until)
    telemetry, audit, incidents = _events_in_window(db, ctx.tenant_id, since_dt, until_dt, limit=2000)
    policies = _fetch_policy_service(f"/policies/{ctx.tenant_id}", ctx.tenant_id)
    agents = _tenant_agent_rows(db, ctx.tenant_id, limit=500)
    providers = _fetch_ai_router("/ai/providers", ctx.tenant_id)

    if rid == "executive":
        overview = {
            "policy_count": len(policies) if isinstance(policies, list) else 0,
            "audit_count": len(audit),
            "telemetry_count": len(telemetry),
            "incident_count": len(incidents),
            "agent_count": len(agents),
        }
        sections = _build_executive_report(
            overview=overview,
            telemetry=telemetry,
            audit=audit,
            incidents=incidents,
            policies=policies,
            agents=agents,
            providers=providers,
        )
    elif rid == "ai_risk":
        sections = _build_ai_risk_report(telemetry=telemetry, incidents=incidents)
    elif rid == "dlp":
        sections = _build_dlp_report(telemetry=telemetry)
    elif rid == "endpoint_health":
        sections = _build_endpoint_health_report(agents=agents, telemetry=telemetry, until=until_dt)
    elif rid == "policy_effectiveness":
        sections = _build_policy_effectiveness_report(policies=policies, telemetry=telemetry)
    else:
        # Defensive — _REPORT_CATALOG validation above should make this
        # unreachable, but keep so adding catalog entries before handlers
        # surfaces a clean 501 rather than a NameError.
        raise HTTPException(status_code=501, detail=f"report builder for {rid} not implemented")

    catalog_entry = next(r for r in _REPORT_CATALOG if r["id"] == rid)
    return {
        "report_type": rid,
        "title": catalog_entry["title"],
        "description": catalog_entry["description"],
        "tenant": {"id": ctx.tenant_id},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {
            "since": since_dt.isoformat() if since_dt else None,
            "until": until_dt.isoformat() if until_dt else None,
        },
        "counts": {
            "telemetry": len(telemetry),
            "audit": len(audit),
            "incidents": len(incidents),
            "agents": len(agents),
        },
        "sections": sections,
    }


@app.get("/customer/providers")
def customer_providers(ctx: Annotated[CustomerContext, Depends(get_customer_context)]) -> Any:
    return _fetch_ai_router("/ai/providers", ctx.tenant_id)


def _call_agent_identity(
    method: str,
    path: str,
    tenant_id: str,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Proxy to the agent-identity service.

    Used by Agent Directory and Delegation Manager. The service is
    multi-tenant via the ``tenant_id`` column on AgentModel; delegations
    themselves don't carry tenant_id, so callers must filter delegations
    against the tenant's agent_id set before returning them to the portal.
    """
    base_url = os.getenv("AGENT_IDENTITY_URL", "http://agent-identity:8008")
    key = os.getenv("AGENT_IDENTITY_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.request(
            method.upper(),
            f"{base_url.rstrip('/')}{path}",
            headers={**build_auth_headers(base_url, key), "x-tenant-id": tenant_id},
            json=json_body,
            params=params,
            timeout=8.0,
        )
    except Exception as exc:
        logger.warning("customer_agent_identity_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        raise HTTPException(status_code=502, detail="agent-identity service unavailable")
    if resp.status_code >= 300:
        logger.warning(
            "customer_agent_identity_proxy_upstream_error tenant=%s path=%s status=%s body=%s",
            tenant_id, path, resp.status_code, resp.text[:200],
        )
        raise HTTPException(status_code=resp.status_code, detail=f"agent-identity returned {resp.status_code}")
    try:
        return resp.json()
    except Exception as exc:
        logger.warning("customer_agent_identity_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="agent-identity returned invalid JSON")


def _tenant_agent_id_set(db: Session, tenant_id: str) -> set[str]:
    """Return the set of agent_ids known to belong to ``tenant_id``.

    Source of truth is the control-plane's own agent registry — the same
    one /customer/agents and the Agent Directory read from. The
    agent-identity service has its own AgentModel for SDK-registered
    agents, but endpoint-bootstrap agents live in ``_AGENTS`` /
    TelemetryRecord and never enter agent-identity, so checking only
    upstream would reject every dropdown choice the portal offers.

    We union both sources: any agent the portal can show the user should
    be a valid delegation target.
    """
    out: set[str] = set()
    for row in _tenant_agent_rows(db, tenant_id, limit=1000):
        aid = row.get("agent_id")
        if aid:
            out.add(str(aid))
    # Layer in agent-identity's view too, so SDK-registered agents that
    # never emit telemetry through this control-plane are still valid.
    try:
        rows = _call_agent_identity("GET", "/agents", tenant_id, params={"tenant_id": tenant_id, "limit": 1000})
    except HTTPException:
        rows = []
    if isinstance(rows, dict):
        rows = rows.get("agents") or []
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict) and r.get("agent_id"):
                out.add(str(r["agent_id"]))
    return out


class CustomerDelegationCreate(BaseModel):
    parent_human_id: str
    agent_id: str
    scope: List[str] = Field(default_factory=lambda: ["*"])
    expires_at: Optional[str] = None


@app.get("/customer/delegations")
def customer_list_delegations(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    status: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """List delegations for agents owned by this tenant.

    The upstream ``/delegations`` listing isn't natively tenant-scoped,
    so we fetch the tenant's agent_id set and filter. Returns the
    filtered list plus the total upstream count so the operator can
    see whether anything was hidden.
    """
    tenant_agents = _tenant_agent_id_set(db, ctx.tenant_id)
    params: Dict[str, Any] = {"limit": max(1, min(limit, 1000))}
    if status:
        params["status"] = status
    try:
        resp = _call_agent_identity("GET", "/delegations", ctx.tenant_id, params=params)
    except HTTPException as exc:
        # 502 → degraded: return empty list rather than crashing the view.
        logger.info("customer_delegations_upstream_unavailable tenant=%s detail=%s", ctx.tenant_id, exc.detail)
        return {"delegations": [], "total": 0, "scoped_to_agents": len(tenant_agents), "upstream_unavailable": True}
    all_rows = resp.get("delegations", []) if isinstance(resp, dict) else (resp or [])
    filtered = [d for d in all_rows if isinstance(d, dict) and str(d.get("agent_id") or "") in tenant_agents]
    return {
        "delegations": filtered,
        "total": len(filtered),
        "upstream_total": resp.get("total") if isinstance(resp, dict) else len(all_rows),
        "scoped_to_agents": len(tenant_agents),
    }


@app.post("/customer/delegations", status_code=201)
def customer_create_delegation(
    payload: CustomerDelegationCreate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Create a delegation. The agent must belong to this tenant."""
    tenant_agents = _tenant_agent_id_set(db, ctx.tenant_id)
    if payload.agent_id not in tenant_agents:
        raise HTTPException(status_code=403, detail="agent_id is not owned by this tenant")
    body: Dict[str, Any] = {
        "parent_human_id": payload.parent_human_id,
        "agent_id": payload.agent_id,
        "scope": payload.scope,
    }
    if payload.expires_at:
        body["expires_at"] = payload.expires_at
    return _call_agent_identity("POST", "/delegations", ctx.tenant_id, json_body=body)


@app.delete("/customer/delegations/{chain_id}")
def customer_revoke_delegation(
    chain_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Revoke a delegation. The delegation must reference an agent owned by this tenant."""
    tenant_agents = _tenant_agent_id_set(db, ctx.tenant_id)
    try:
        existing = _call_agent_identity("GET", f"/delegations/{chain_id}", ctx.tenant_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(status_code=404, detail="delegation not found")
        raise
    if not isinstance(existing, dict) or str(existing.get("agent_id") or "") not in tenant_agents:
        # Don't leak existence of cross-tenant chains. Both states return 404.
        raise HTTPException(status_code=404, detail="delegation not found")
    return _call_agent_identity("DELETE", f"/delegations/{chain_id}", ctx.tenant_id)


def _call_audit_graph(
    method: str,
    path: str,
    tenant_id: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Proxy to the audit-graph service for tenant-scoped event queries.
    Used by the Risk Dashboard and Action Graph views; the audit service
    natively filters by tenant_id query param so we forward it explicitly
    on every call.
    """
    audit_url = os.getenv("AUDIT_SERVICE_URL", "http://audit:8005")
    audit_key = os.getenv("AUDIT_API_SECRET", DEFAULT_API_KEY)
    merged = {"tenant_id": tenant_id, **(params or {})}
    try:
        resp = httpx.request(
            method.upper(),
            f"{audit_url.rstrip('/')}{path}",
            headers={**build_auth_headers(audit_url, audit_key), "x-tenant-id": tenant_id},
            params=merged,
            timeout=8.0,
        )
    except Exception as exc:
        logger.warning("customer_audit_graph_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        raise HTTPException(status_code=502, detail="audit-graph service unavailable")
    if resp.status_code >= 300:
        logger.warning(
            "customer_audit_graph_proxy_upstream_error tenant=%s path=%s status=%s body=%s",
            tenant_id, path, resp.status_code, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"audit-graph returned {resp.status_code}")
    try:
        return resp.json()
    except Exception as exc:
        logger.warning("customer_audit_graph_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="audit-graph returned invalid JSON")


def _telemetry_to_risk_event(r: "TelemetryRecord") -> Dict[str, Any]:
    """Project a TelemetryRecord into the audit-graph event shape the
    Risk Dashboard expects. Endpoint agents and browser extensions write
    to TelemetryRecord, while SDK/RASP/proxy-agent write to the audit
    service. Until we unify the streams server-side, the dashboard reads
    both and the projection lets us merge them.
    """
    payload = _coerce_meta(r.payload) or {}
    bucket = _classify_action(r.event_type)
    # outcome mirrors the action-class bucket so the dashboard's heuristic
    # risk_score derivation (blocked → 0.85, warn → 0.55, …) works for
    # endpoint events that don't carry an explicit risk_score.
    outcome_map = {
        "block":   "blocked",
        "redact":  "redacted",
        "warn":    "warn",
        "allow":   "allow",
        "detect":  "warn",       # detect events surface as warn-tier risk
        "monitor": "ok",
    }
    return {
        "event_id":   r.id,
        "tenant_id":  r.tenant_id,
        "agent_id":   r.agent_id or payload.get("agent_id"),
        "human_id":   r.user_id or payload.get("user_id") or payload.get("username"),
        "model":      payload.get("model") or payload.get("tool_name") or payload.get("provider"),
        "provider":   payload.get("provider") or payload.get("source") or r.source,
        "event_type": r.event_type,
        "action":     r.event_type,
        "outcome":    outcome_map.get(bucket, "ok"),
        "timestamp":  r.occurred_at.isoformat() if r.occurred_at else None,
        "details":    payload,
        # carry the derived risk class so the frontend can apply a tighter
        # default risk_score for known-bad event types without re-deriving
        "action_class": bucket,
    }


def _call_compliance(
    method: str,
    path: str,
    tenant_id: str,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Proxy to the compliance service for tenant-scoped operations."""
    url = os.getenv("COMPLIANCE_URL", "http://compliance:8004")
    key = os.getenv("COMPLIANCE_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.request(
            method.upper(),
            f"{url.rstrip('/')}{path}",
            headers={**build_auth_headers(url, key), "x-tenant-id": tenant_id},
            json=json_body,
            params=params,
            timeout=30.0,
        )
    except Exception as exc:
        logger.warning("customer_compliance_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        raise HTTPException(status_code=502, detail="compliance service unavailable")
    if resp.status_code >= 300:
        logger.warning(
            "customer_compliance_proxy_upstream_error tenant=%s path=%s status=%s body=%s",
            tenant_id, path, resp.status_code, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"compliance service returned {resp.status_code}")
    try:
        return resp.json()
    except Exception as exc:
        logger.warning("customer_compliance_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="compliance service returned invalid JSON")


@app.get("/customer/compliance/frameworks")
def customer_compliance_frameworks(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    """List supported compliance frameworks. Same shape as the compliance
    service's /frameworks but proxied so the customer portal can call it
    without a separate API key."""
    return _call_compliance("GET", "/frameworks", ctx.tenant_id)


def _build_compliance_evidence(
    db: Session,
    tenant_id: str,
    since: Optional[datetime],
    until: Optional[datetime],
) -> Dict[str, Any]:
    """Build a compliance evidence dict from the tenant's current state.

    Compliance frameworks evaluate each control by checking whether
    specific keys in the evidence dict are present and truthy. Without
    this builder the customer-portal would have to ship a static evidence
    dict and assessments would always say "no evidence — every control
    fails." Here we generate evidence from what the platform observes
    in the requested window: active policies, telemetry volume by class,
    audit log presence, and incident count.

    The keys we set are the union of evidence_keys actually referenced
    by the bundled frameworks (see services/compliance/frameworks/*.py).
    Adding more mappings is additive; controls whose keys we don't set
    here remain "fail" with a "Missing: <key>" message, which is the
    honest signal.
    """
    evidence: Dict[str, Any] = {}

    # --- Policies (always current; ignore window) ---
    try:
        policies_resp = _fetch_policy_service(f"/policies/{tenant_id}", tenant_id)
        policies = policies_resp if isinstance(policies_resp, list) else []
    except Exception:
        policies = []
    enabled_policies = [p for p in policies if p.get("enabled") is not False]
    actions = {str(p.get("action", "")).lower() for p in enabled_policies}
    redact_classes_union: set = set()
    for p in enabled_policies:
        for c in p.get("redact_classes") or []:
            redact_classes_union.add(str(c))

    if enabled_policies:
        evidence["access_control_policy"] = True
        evidence["acceptable_use_policy"] = True
        evidence["cybersecurity_policy_documented"] = True
        evidence["cybersecurity_program"] = True
    if "block" in actions or "warn" in actions:
        evidence["anomaly_detection"] = True
    if "redact" in actions or any(c.startswith("pii.") for c in redact_classes_union):
        evidence["data_classification"] = True
        evidence["data_flow_controls"] = True
    if any(c.startswith("secret.") for c in redact_classes_union):
        evidence["credential_management"] = True

    # --- Telemetry-derived signals (windowed) ---
    tq = db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == tenant_id)
    if since is not None:
        tq = tq.filter(TelemetryRecord.occurred_at >= since)
    if until is not None:
        tq = tq.filter(TelemetryRecord.occurred_at <= until)
    tq = tq.with_entities(TelemetryRecord.event_type, TelemetryRecord.source)
    type_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    for event_type, source in tq.all():
        type_counts[event_type or ""] = type_counts.get(event_type or "", 0) + 1
        source_counts[source or ""] = source_counts.get(source or "", 0) + 1

    if sum(type_counts.values()) > 0:
        evidence["continuous_monitoring"] = True
        evidence["audit_review_process"] = True
    if any(et.startswith("ai_") for et in type_counts):
        evidence["ai_service_monitoring"] = True
        evidence["ai_system_inventory"] = True
        evidence["ai_output_monitoring"] = True
    if source_counts.get("endpoint", 0) > 0:
        evidence["network_monitoring"] = True
        evidence["asset_inventory"] = True
    if any("pii_" in et or "sensitive_data" in et for et in type_counts):
        evidence["data_classification"] = True
        evidence["data_flow_controls"] = True
    if any("policy_block" in et or "policy_redact" in et for et in type_counts):
        evidence["api_authorization_checks"] = True

    # --- Audit logs ---
    audit_q = db.query(func.count(AuditLog.id)).filter(AuditLog.tenant_id == tenant_id)
    if since is not None:
        audit_q = audit_q.filter(AuditLog.created_at >= since)
    if until is not None:
        audit_q = audit_q.filter(AuditLog.created_at <= until)
    audit_count = audit_q.scalar() or 0
    if audit_count > 0:
        evidence["audit_logging_enabled"] = True
        evidence["cybersecurity_audit"] = True

    # --- Incidents (in-memory, no timestamp filter — best-effort) ---
    incident_count = len(_INCIDENTS.get(tenant_id, {}))
    if incident_count > 0:
        evidence["incident_response_plan"] = True
        evidence["ai_incident_response_plan"] = True
        evidence["breach_notification_process"] = True

    return evidence


@app.post("/customer/compliance/assess")
def customer_compliance_assess(
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    """Tenant admins only — run a compliance assessment scoped to the
    session tenant.

    Accepts a ``since`` / ``until`` (ISO-8601) time window; the control
    plane builds an evidence dict from the tenant's observed state in
    that window — active policies, telemetry by class, audit log presence,
    incident count — and merges it with any explicit evidence the caller
    passed. The assessment therefore reflects what actually happened in
    the requested period, not just a static stored evidence record.
    """
    body = dict(payload or {})
    since_dt = until_dt = None
    if body.get("since"):
        try:
            since_dt = datetime.fromisoformat(str(body["since"]).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            since_dt = None
    if body.get("until"):
        try:
            until_dt = datetime.fromisoformat(str(body["until"]).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            until_dt = None

    derived_evidence = _build_compliance_evidence(db, ctx.tenant_id, since_dt, until_dt)
    # Caller-provided evidence wins; the derived view fills the gaps.
    merged_evidence = {**derived_evidence, **(body.get("evidence") or {})}

    forward_body = {
        "framework": body.get("framework"),
        "evidence": merged_evidence,
    }
    result = _call_compliance("POST", f"/assess/{ctx.tenant_id}", ctx.tenant_id, json_body=forward_body)
    # Attach the window + evidence dict to the response so the frontend can
    # show what evidence drove the result. Non-standard field, additive.
    if isinstance(result, dict):
        result.setdefault("window", {})
        result["window"]["since"] = since_dt.isoformat() if since_dt else None
        result["window"]["until"] = until_dt.isoformat() if until_dt else None
        result["evidence_used"] = sorted(merged_evidence.keys())
    return result


@app.get("/customer/compliance/report")
def customer_compliance_report(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    """Fetch the most recent assessment report for the session tenant."""
    return _call_compliance("GET", f"/assess/{ctx.tenant_id}/report", ctx.tenant_id)


@app.get("/customer/risk/events")
def customer_risk_events(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 500,
) -> Any:
    """Tenant-scoped event feed for the AI Risk Dashboard and Action Graph.

    Reads from both event streams:
      - audit-graph service (`AuditEventModel`) — SDK / RASP / proxy-agent
        writes. May be empty for tenants that only run endpoint agents.
      - control-plane TelemetryRecord — endpoint agent + browser extension
        writes. Projected into the audit-graph event shape so the
        frontend doesn't have to merge formats.

    Both queries are tenant-scoped. Events are returned newest-first up
    to ``limit`` total; the dashboard re-aggregates regardless of source.
    """
    limit = max(1, min(limit, 1000))

    # 1) audit-graph events (may be empty / unreachable; non-fatal)
    audit_events: List[Dict[str, Any]] = []
    try:
        audit_resp = _call_audit_graph("GET", "/events", ctx.tenant_id, params={"limit": limit})
        audit_events = audit_resp.get("events", []) if isinstance(audit_resp, dict) else (audit_resp or [])
    except HTTPException as exc:
        # 502 from the proxy — log and continue with telemetry only
        logger.info("risk_events_audit_graph_unavailable tenant=%s detail=%s", ctx.tenant_id, exc.detail)

    # 2) control-plane telemetry projected into the same shape
    telemetry_rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == ctx.tenant_id)
        .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
        .limit(limit)
        .all()
    )
    projected = [_telemetry_to_risk_event(r) for r in telemetry_rows]

    # 3) Merge newest-first. event_id collisions don't happen across stores
    #    (different ID schemes) so a simple concat + resort is correct.
    def ts_key(ev: Dict[str, Any]) -> float:
        ts = ev.get("timestamp")
        if not ts:
            return 0.0
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return 0.0

    combined = sorted(audit_events + projected, key=ts_key, reverse=True)[:limit]
    return {
        "events": combined,
        "total": len(combined),
        "sources": {
            "audit_graph": len(audit_events),
            "telemetry":   len(projected),
        },
    }


def _call_ai_router(
    method: str,
    path: str,
    tenant_id: str,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Proxy call to the AI router for customer-scope operations. Like the
    detection / policy helpers — raises HTTPException on non-2xx so the
    frontend sees the upstream error instead of a silent empty response."""
    router_url = os.getenv("AI_ROUTER_URL", "http://ai-router:8009")
    router_key = os.getenv("AI_ROUTER_API_SECRET", DEFAULT_API_KEY)
    merged_params = {"tenant_id": tenant_id, **(params or {})}
    try:
        resp = httpx.request(
            method.upper(),
            f"{router_url.rstrip('/')}{path}",
            headers={**build_auth_headers(router_url, router_key), "x-tenant-id": tenant_id},
            json=json_body,
            params=merged_params,
            timeout=12.0,
        )
    except Exception as exc:
        logger.warning("customer_ai_router_proxy_error tenant=%s path=%s err=%s", tenant_id, path, exc)
        raise HTTPException(status_code=502, detail="AI router unavailable")
    if resp.status_code >= 300:
        logger.warning(
            "customer_ai_router_proxy_upstream_error tenant=%s path=%s status=%s body=%s",
            tenant_id, path, resp.status_code, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"AI router returned {resp.status_code}: {resp.text[:200]}")
    try:
        return resp.json()
    except Exception as exc:
        logger.warning("customer_ai_router_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="AI router returned invalid JSON")


class _ProviderConfigureRequest(BaseModel):
    api_key: str
    base_url: Optional[str] = None
    region: Optional[str] = None
    org_id: Optional[str] = None
    deployment_name: Optional[str] = None
    default_model: Optional[str] = None
    rate_limit_per_minute: Optional[int] = None
    monthly_budget_usd: Optional[float] = None


@app.post("/customer/providers/{provider_id}/configure")
def customer_configure_provider(
    provider_id: str,
    payload: _ProviderConfigureRequest,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    """Tenant admins only — writes provider credentials scoped to this
    tenant. The api_key here is the *provider's* key (OpenAI, Anthropic, …)
    not a CyberArmor key; it goes into the secrets service via the AI
    router and never echoes back."""
    body = payload.model_dump(exclude_none=False)
    return _call_ai_router("POST", f"/credentials/providers/{provider_id}/configure", ctx.tenant_id, json_body=body)


@app.get("/customer/providers/{provider_id}/status")
def customer_provider_status(
    provider_id: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    """Lightweight "is this provider wired up?" check — surfaces whether
    credentials are present + the resolved base URL. No traffic to the
    provider; that costs money and rate-limit budget. The frontend uses
    this as the Test-button outcome."""
    return _call_ai_router("GET", f"/credentials/providers/{provider_id}/status", ctx.tenant_id)


@app.get("/customer/config/{section}", response_model=TenantPortalConfigOut)
def customer_get_portal_config(
    section: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TenantPortalConfigOut:
    section = _valid_customer_config_section(section)
    record = (
        db.query(TenantPortalConfig)
        .filter(TenantPortalConfig.tenant_id == ctx.tenant_id, TenantPortalConfig.section == section)
        .first()
    )
    if not record:
        return TenantPortalConfigOut(tenant_id=ctx.tenant_id, section=section, config={})
    return _tenant_portal_config_out(record)


@app.put("/customer/config/{section}", response_model=TenantPortalConfigOut)
def customer_put_portal_config(
    section: str,
    payload: TenantPortalConfigIn,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> TenantPortalConfigOut:
    section = _valid_customer_config_section(section)
    record = (
        db.query(TenantPortalConfig)
        .filter(TenantPortalConfig.tenant_id == ctx.tenant_id, TenantPortalConfig.section == section)
        .first()
    )
    if not record:
        record = TenantPortalConfig(tenant_id=ctx.tenant_id, section=section)
        db.add(record)
    record.config = _encode_meta_for_db(payload.config or {})
    record.updated_by = ctx.email
    db.commit()
    db.refresh(record)
    return _tenant_portal_config_out(record)


@app.get("/customer/api-keys", response_model=list[ApiKeyOut])
def customer_list_api_keys(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiKey]:
    return (
        db.query(ApiKey)
        .filter(ApiKey.tenant_id == ctx.tenant_id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )


@app.post("/customer/api-keys", response_model=ApiKeyOut)
def customer_create_api_key(
    payload: ApiKeyCreate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> ApiKey:
    role = payload.role if payload.role in {"analyst", "admin", "service"} else "analyst"
    record = ApiKey(key=str(uuid4()).replace("-", ""), tenant_id=ctx.tenant_id, role=role, active=True)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@app.patch("/customer/api-keys/{key}/disable", response_model=ApiKeyOut)
def customer_disable_api_key(
    key: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> ApiKey:
    record = db.query(ApiKey).filter(ApiKey.key == key, ApiKey.tenant_id == ctx.tenant_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="API key not found")
    record.active = False
    db.commit()
    db.refresh(record)
    return record


# --- Customer: Artifacts (tenant-scoped lists and regex) --------------------


@app.get("/customer/artifacts/kinds")
def customer_artifact_kinds(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Any:
    return _call_policy_service("GET", "/artifacts/kinds", ctx.tenant_id)


@app.get("/customer/artifacts")
def customer_list_artifacts(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    kind: Optional[str] = None,
    enabled_only: bool = False,
    include_archived: bool = False,
) -> Any:
    params = {"enabled_only": enabled_only, "include_archived": include_archived}
    if kind:
        params["kind"] = kind
    return _call_policy_service(
        "GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id, params=params,
    )


@app.post("/customer/artifacts")
def customer_upsert_artifact(
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    payload = dict(payload or {})
    payload["tenant_id"] = ctx.tenant_id  # tenant-scoping is non-negotiable
    return _call_policy_service("POST", "/artifacts", ctx.tenant_id, json_body=payload)


@app.put("/customer/artifacts/id/{artifact_id}")
def customer_update_artifact(
    artifact_id: str,
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    # Upstream endpoint doesn't use the tenant header for auth, but verify
    # tenant scope by reading the artifact first to prevent cross-tenant PUT.
    existing = _call_policy_service(
        "GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id,
    )
    if not any(a.get("id") == artifact_id for a in existing if isinstance(a, dict)):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _call_policy_service(
        "PUT", f"/artifacts/id/{artifact_id}", ctx.tenant_id, json_body=payload,
    )


@app.patch("/customer/artifacts/id/{artifact_id}/toggle")
def customer_toggle_artifact(
    artifact_id: str,
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    existing = _call_policy_service("GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id)
    if not any(a.get("id") == artifact_id for a in existing if isinstance(a, dict)):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _call_policy_service(
        "PATCH", f"/artifacts/id/{artifact_id}/toggle", ctx.tenant_id, json_body=payload,
    )


@app.patch("/customer/artifacts/id/{artifact_id}/archive")
def customer_archive_artifact(
    artifact_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    existing = _call_policy_service("GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id)
    if not any(a.get("id") == artifact_id for a in existing if isinstance(a, dict)):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _call_policy_service(
        "PATCH", f"/artifacts/id/{artifact_id}/archive", ctx.tenant_id,
    )


@app.patch("/customer/artifacts/id/{artifact_id}/unarchive")
def customer_unarchive_artifact(
    artifact_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    existing = _call_policy_service(
        "GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id,
        params={"include_archived": True},
    )
    if not any(a.get("id") == artifact_id for a in existing if isinstance(a, dict)):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _call_policy_service(
        "PATCH", f"/artifacts/id/{artifact_id}/unarchive", ctx.tenant_id,
    )


@app.delete("/customer/artifacts/id/{artifact_id}")
def customer_delete_artifact(
    artifact_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
) -> Any:
    existing = _call_policy_service(
        "GET", f"/artifacts/{ctx.tenant_id}", ctx.tenant_id,
        params={"include_archived": True},
    )
    if not any(a.get("id") == artifact_id for a in existing if isinstance(a, dict)):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _call_policy_service("DELETE", f"/artifacts/id/{artifact_id}", ctx.tenant_id)


@app.get("/customer/sso", response_model=CustomerSsoConfigOut)
def customer_get_sso(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    config = db.query(CustomerSsoConfig).filter(CustomerSsoConfig.tenant_id == ctx.tenant_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="SSO is not configured for this tenant")
    return _safe_sso_config(config)


@app.put("/customer/sso", response_model=CustomerSsoConfigOut)
def customer_upsert_sso(
    payload: CustomerSsoConfigIn,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    config = db.query(CustomerSsoConfig).filter(CustomerSsoConfig.tenant_id == ctx.tenant_id).first()
    if not config:
        if not payload.client_secret:
            raise HTTPException(status_code=400, detail="client_secret is required when creating SSO configuration")
        config = CustomerSsoConfig(tenant_id=ctx.tenant_id)
        db.add(config)
    for field, value in payload.model_dump().items():
        if field == "client_secret" and not value:
            continue
        setattr(config, field, value)
    db.commit()
    db.refresh(config)
    return _safe_sso_config(config)


@app.get("/customer/users", response_model=list[TenantUserOut])
def customer_list_users(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    return (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == ctx.tenant_id)
        .order_by(TenantUser.created_at.desc())
        .all()
    )


@app.post("/customer/users", response_model=TenantUserOut)
def customer_create_user(
    payload: CustomerUserCreate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    email = _normalize_email(payload.email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required")
    existing = db.query(TenantUser).filter(TenantUser.tenant_id == ctx.tenant_id, TenantUser.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant user already exists")
    user = TenantUser(
        tenant_id=ctx.tenant_id,
        email=email,
        role=_valid_customer_role(payload.role),
        status=_valid_customer_status(payload.status),
        invited_by=ctx.email,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.patch("/customer/users/{user_id}", response_model=TenantUserOut)
def customer_update_user(
    user_id: str,
    payload: CustomerUserUpdate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    user = db.query(TenantUser).filter(TenantUser.id == user_id, TenantUser.tenant_id == ctx.tenant_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Tenant user not found")
    if payload.role is not None:
        user.role = _valid_customer_role(payload.role)
    if payload.status is not None:
        user.status = _valid_customer_status(payload.status)
    db.commit()
    db.refresh(user)
    return user


@app.post("/customer/users/{user_id}/disable-mfa", response_model=TenantUserOut)
def customer_force_disable_mfa(
    user_id: str,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
):
    """Tenant-admin escape hatch when a user has lost BOTH their authenticator
    app and all backup codes. Clears the four TOTP fields so the user can
    sign in with the email code alone and re-enroll. Tenant-scoped — an
    admin in tenant A cannot touch users in tenant B (the .filter on
    tenant_id == ctx.tenant_id enforces this). The audit middleware logs
    the call via the URL path; no extra audit row needed.
    """
    user = (
        db.query(TenantUser)
        .filter(TenantUser.id == user_id, TenantUser.tenant_id == ctx.tenant_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="Tenant user not found")
    if not user.totp_enabled and not user.totp_secret_enc and not user.totp_pending_enc:
        # Already off — surface a 400 so the UI can show "nothing to do".
        raise HTTPException(status_code=400, detail="MFA is not enabled for this user")
    if user.email == ctx.email:
        # Tenant admins must use the regular self-service /me/totp endpoint
        # to disable their own MFA — that flow requires a current code,
        # which this endpoint deliberately bypasses.
        raise HTTPException(status_code=400, detail="Use Account Security to disable MFA on your own account")
    user.totp_secret_enc = None
    user.totp_pending_enc = None
    user.totp_enabled = False
    user.backup_codes_hash = None
    logger.warning(
        "mfa_force_disabled tenant=%s by_admin=%s target_user=%s",
        ctx.tenant_id, ctx.email, user.email,
    )
    db.commit()
    db.refresh(user)
    return user


@app.get("/apikeys", response_model=list[ApiKeyOut])
def list_apikeys(
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
):
    return db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()

@app.post("/apikeys", response_model=ApiKeyOut)
def create_apikey(
    payload: ApiKeyCreate,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
):
    new_key = str(uuid4()).replace("-", "")
    record = ApiKey(key=new_key, tenant_id=payload.tenant_id, role=payload.role, active=True)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

@app.patch("/apikeys/{key}/disable", response_model=ApiKeyOut)
def disable_apikey(
    key: str,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)]
    ):
    record = db.query(ApiKey).filter(ApiKey.key == key).first()
    if not record:
        raise HTTPException(status_code=404, detail="Not found")
    record.active = False
    db.commit()
    db.refresh(record)
    return record


@app.get("/bootstrap/catalog", response_model=list[DownloadCatalogEntry])
def bootstrap_catalog(
    ctx: Annotated[AuthContext, Depends(require_role("analyst"))],
    tenant_id: Optional[str] = None,
) -> list[DownloadCatalogEntry]:
    resolved_tenant = tenant_id or ctx.tenant_id or "default"
    return _build_catalog(resolved_tenant, customer_scope=False)


@app.get("/bootstrap/packages/{package_key}")
def bootstrap_download_package(
    package_key: str,
    ctx: Annotated[AuthContext, Depends(require_role("analyst"))],
    tenant_id: Optional[str] = None,
) -> StreamingResponse:
    resolved_tenant = tenant_id or ctx.tenant_id or "default"
    spec = _resolve_package_spec(package_key)
    return _zip_directory_response(spec, resolved_tenant)


@app.post("/bootstrap/tokens", response_model=BootstrapTokenIssueOut)
def bootstrap_issue_token(
    payload: BootstrapTokenCreate,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> BootstrapTokenIssueOut:
    resolved_tenant = payload.tenant_id or ctx.tenant_id or "default"
    row, plaintext_token = _issue_bootstrap_token(
        db,
        tenant_id=resolved_tenant,
        package_key=payload.package_key,
        issued_to=ctx.principal,
        note=payload.note,
        ttl_minutes=payload.ttl_minutes,
    )
    return _make_bootstrap_issue_out(row, plaintext_token, resolved_tenant, customer_scope=False)


@app.post("/bootstrap/redeem", response_model=BootstrapRedeemOut)
def bootstrap_redeem_token(
    payload: BootstrapRedeemIn,
    db: Annotated[Session, Depends(get_db)],
) -> BootstrapRedeemOut:
    return _redeem_bootstrap_token(db, payload)


@app.post("/telemetry/ingest")
def ingest_event(event: TelemetryEvent, ctx: Annotated[AuthContext, Depends(require_any_role("analyst", "service"))]):
    if ctx.tenant_id and ctx.tenant_id != event.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")
    # Fall back to payload values when the top-level fields aren't sent —
    # older helpers stuffed identity into the payload dict only.
    p = event.payload or {}
    stored_event = {
        "tenant_id": event.tenant_id,
        "agent_id": event.agent_id or p.get("agent_id"),
        "hostname": event.hostname or p.get("hostname"),
        "user_id": event.user_id or p.get("username") or p.get("user_id"),
        "event_type": event.event_type,
        "payload": event.payload,
        "source": event.source,
        "occurred_at": event.occurred_at.isoformat(),
    }
    _store_telemetry_event(stored_event)
    logger.info(
        "telemetry tenant=%s user=%s event_type=%s source=%s",
        event.tenant_id,
        event.user_id,
        event.event_type,
        event.source,
    )
    return JSONResponse({"status": "accepted"}, status_code=202)


# ---------------------------------------------------------------------------
# Endpoint-agent lifecycle endpoints
# Called by the endpoint agent (agent.py) on the machine being protected.
# ---------------------------------------------------------------------------

@app.post("/agents/register")
def agent_register(
    payload: Dict[str, Any],
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Register (or re-register) an endpoint agent."""
    _dev_or_key_ok(x_api_key)
    agent_id = payload.get("agent_id") or str(uuid4())
    record = {
        **payload,
        "agent_id": agent_id,
        "registered_at": payload.get("registered_at", datetime.now(timezone.utc).isoformat()),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "registered",
    }
    _AGENTS[agent_id] = record
    logger.info("agent_register agent_id=%s tenant=%s", agent_id, payload.get("tenant_id"))
    return {"status": "registered", "agent_id": agent_id}


@app.post("/agents/{agent_id}/heartbeat")
def agent_heartbeat(
    agent_id: str,
    payload: Dict[str, Any],
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Receive a periodic heartbeat from an endpoint agent."""
    _dev_or_key_ok(x_api_key)
    now = datetime.now(timezone.utc).isoformat()
    if agent_id in _AGENTS:
        rec = _AGENTS[agent_id]
        rec["last_seen"] = now
        rec["status"] = payload.get("status", "running")
        rec["uptime_seconds"] = payload.get("uptime_seconds")
        rec["active_monitors"] = payload.get("active_monitors")
        # Refresh identity fields every heartbeat so they stay current
        for field in ("hostname", "username", "os", "version", "tenant_id"):
            if payload.get(field):
                rec[field] = payload[field]
    else:
        # Agent wasn't registered (e.g. control-plane restarted) – auto-create
        _AGENTS[agent_id] = {
            **payload,
            "agent_id": agent_id,
            "last_seen": now,
            "status": payload.get("status", "running"),
        }
    return {"status": "ok", "agent_id": agent_id}


# ── A-BOM ingest + read + export ───────────────────────────────────────
#
# See docs/architecture/a-bom-design.md for the data model. The ingest
# endpoint accepts a CycloneDX 1.6 components list (or a full BOM); each
# component is normalized, identity-keyed, upserted into ABOMComponent,
# and an ABOMObservation row is appended carrying provenance.

# CycloneDX component.type values we accept. Anything outside this set
# is coerced to "library" so a misconfigured collector can't pollute the
# store with arbitrary strings. Mirror docs/architecture/a-bom-design.md §2.
_ABOM_VALID_TYPES = {
    "application", "framework", "library", "container", "platform",
    "operating-system", "device", "device-driver", "firmware", "file",
    "machine-learning-model", "data", "cryptographic-asset",
}


def _abom_normalize_type(raw: Any) -> str:
    t = str(raw or "").strip().lower()
    return t if t in _ABOM_VALID_TYPES else "library"


def _abom_identity_key(component: Dict[str, Any]) -> str:
    """Stable identity hash for dedup across collectors. Mirrors the
    design doc's identity_key formula: type + primary identifier
    (purl ≻ cpe ≻ name@version) + vendor + sha256 hash when present.
    """
    type_ = _abom_normalize_type(component.get("type"))
    purl = str(component.get("purl") or "").strip()
    cpe = str(component.get("cpe") or "").strip()
    name = str(component.get("name") or "").strip()
    version = str(component.get("version") or "").strip()
    manufacturer = str(
        component.get("manufacturer")
        or component.get("publisher")
        or component.get("supplier")
        or ""
    ).strip()
    primary = purl or cpe or (f"{name}@{version}" if version else name)
    file_hash = ""
    hashes = component.get("hashes")
    if isinstance(hashes, list):
        for h in hashes:
            if isinstance(h, dict):
                alg = str(h.get("alg") or "").upper()
                if alg in ("SHA-256", "SHA256"):
                    file_hash = str(h.get("content") or "")
                    break
    elif isinstance(hashes, dict):
        file_hash = str(hashes.get("SHA-256") or hashes.get("sha256") or "")
    payload = f"{type_}:{primary}:{manufacturer}:{file_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _abom_extract_licenses(component: Dict[str, Any]) -> List[str]:
    """CycloneDX licenses can be a list of {license: {id}} or {license: {name}}
    or {expression}; flatten to plain string list."""
    raw = component.get("licenses")
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            v = lic.get("id") or lic.get("name") or ""
            if v:
                out.append(str(v))
        expr = entry.get("expression")
        if isinstance(expr, str) and expr:
            out.append(expr)
    return out


def _abom_normalize_hashes(component: Dict[str, Any]) -> Dict[str, str]:
    raw = component.get("hashes")
    out: Dict[str, str] = {}
    if isinstance(raw, list):
        for h in raw:
            if isinstance(h, dict) and h.get("alg") and h.get("content"):
                out[str(h["alg"]).upper()] = str(h["content"])
    elif isinstance(raw, dict):
        for k, v in raw.items():
            if k and v:
                out[str(k).upper()] = str(v)
    return out


class ABOMIngestRequest(BaseModel):
    """Collector → server. Send either a flat ``components`` list or a
    nested ``bom`` (full CycloneDX document) — we accept either for
    convenience.
    """
    tenant_id: Optional[str] = None
    collector: str
    collector_version: Optional[str] = None
    source_kind: str = "agent"            # agent | repo | container | cloud_resource | ide_workspace
    source_id: str                        # agent_id, repo_id, cloud_arn, …
    hostname: Optional[str] = None
    observed_at: Optional[str] = None
    components: Optional[List[Dict[str, Any]]] = None
    bom: Optional[Dict[str, Any]] = None


def _abom_upsert_component(
    db: Session,
    tenant_id: str,
    component: Dict[str, Any],
    now: datetime,
) -> Tuple[ABOMComponent, str]:
    """Upsert one component row keyed on identity_key. Returns (row,
    identity_key)."""
    ikey = _abom_identity_key(component)
    type_ = _abom_normalize_type(component.get("type"))
    name = str(component.get("name") or "").strip() or "unknown"
    version = (str(component.get("version") or "").strip() or None)
    purl = (str(component.get("purl") or "").strip() or None)
    cpe = (str(component.get("cpe") or "").strip() or None)
    manufacturer = (
        str(component.get("manufacturer") or component.get("publisher") or component.get("supplier") or "").strip()
        or None
    )
    licenses = _abom_extract_licenses(component)
    hashes = _abom_normalize_hashes(component)
    properties = component.get("properties") if isinstance(component.get("properties"), list) else None

    row = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == tenant_id, ABOMComponent.identity_key == ikey)
        .first()
    )
    if row is None:
        row = ABOMComponent(
            tenant_id=tenant_id,
            identity_key=ikey,
            type=type_,
            name=name,
            version=version,
            purl=purl,
            cpe=cpe,
            manufacturer=manufacturer,
            licenses=_encode_meta_for_db(licenses) if licenses else None,
            hashes=_encode_meta_for_db(hashes) if hashes else None,
            properties=_encode_meta_for_db(properties) if properties else None,
            observation_count=0,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)
        db.flush()
    else:
        # Refresh facts that may have improved (name/version on first sight
        # may have been unknown). Never demote — keep the strongest known
        # value if the new observation is weaker.
        if version and not row.version:
            row.version = version
        if purl and not row.purl:
            row.purl = purl
        if cpe and not row.cpe:
            row.cpe = cpe
        if manufacturer and not row.manufacturer:
            row.manufacturer = manufacturer
        if licenses:
            row.licenses = _encode_meta_for_db(licenses)
        if hashes:
            row.hashes = _encode_meta_for_db(hashes)
        if now > row.last_seen_at:
            row.last_seen_at = now
    return row, ikey


@app.post("/agents/{agent_id}/abom/ingest")
def agent_abom_ingest(
    agent_id: str,
    payload: ABOMIngestRequest,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Endpoint-agent / RASP / IDE / repo-worker ingest path.

    Idempotent on (tenant_id, identity_key): rerunning the same component
    set produces no duplicate component rows. Observations always append
    so we keep history.
    """
    _dev_or_key_ok(x_api_key)
    tenant_id = (payload.tenant_id or _AGENTS.get(agent_id, {}).get("tenant_id") or "unknown")
    components = payload.components or []
    if payload.bom and isinstance(payload.bom, dict):
        bom_components = payload.bom.get("components")
        if isinstance(bom_components, list):
            components = components + bom_components

    if payload.observed_at:
        try:
            observed_at = datetime.fromisoformat(payload.observed_at.replace("Z", "+00:00"))
        except ValueError:
            observed_at = datetime.now(timezone.utc)
    else:
        observed_at = datetime.now(timezone.utc)

    inserted = 0
    upserted_components = 0
    skipped = 0
    with SessionLocal() as db:
        for component in components:
            if not isinstance(component, dict):
                skipped += 1
                continue
            try:
                row, ikey = _abom_upsert_component(db, tenant_id, component, observed_at)
            except Exception as exc:  # noqa: BLE001
                logger.warning("abom_ingest upsert failed: %s", exc)
                skipped += 1
                continue
            row.observation_count = (row.observation_count or 0) + 1
            obs = ABOMObservation(
                tenant_id=tenant_id,
                component_id=row.id,
                identity_key=ikey,
                collector=payload.collector,
                collector_version=payload.collector_version,
                source_kind=payload.source_kind,
                source_id=payload.source_id,
                hostname=payload.hostname,
                path=str(component.get("__path") or "")[:1024] or None,
                raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                observed_at=observed_at,
            )
            db.add(obs)
            inserted += 1
            upserted_components += 1
        db.commit()

    logger.info(
        "abom_ingest agent=%s tenant=%s collector=%s components=%d skipped=%d",
        agent_id, tenant_id, payload.collector, inserted, skipped,
    )
    return JSONResponse(
        {"status": "accepted", "components_ingested": inserted, "skipped": skipped},
        status_code=202,
    )


# ── OpenBao integration for tenant secrets ────────────────────────────
#
# Repo-collector PATs (and any future tenant secrets the control-plane
# needs to handle directly) live in OpenBao at
# ``cyberarmor-kv/data/tenants/{tenant_id}/abom/repo-collector``.
#
# We hit OpenBao straight rather than going through the secrets-service
# to avoid an extra network hop on every repo-sync; the shared
# OpenBaoClient owns transport / auth / retry. When OpenBao isn't
# configured (dev / single-node demos) the helpers transparently fall
# back to JSONB storage in TenantPortalConfig so the existing flow
# keeps working. We log loudly when that happens.

_OPENBAO_ADDR = os.getenv("OPENBAO_ADDR", "")
_OPENBAO_TOKEN = os.getenv("OPENBAO_TOKEN", "")
_OPENBAO_NAMESPACE = os.getenv("OPENBAO_NAMESPACE")
_OPENBAO_KV_MOUNT = os.getenv("OPENBAO_KV_MOUNT", "cyberarmor-kv")
_OPENBAO_TIMEOUT = float(os.getenv("OPENBAO_TIMEOUT_SECONDS", "5"))


def _openbao_client_or_none() -> Optional[OpenBaoClient]:
    """Return a configured OpenBaoClient, or None if OpenBao isn't
    available. Callers must handle the None path."""
    if not _OPENBAO_ADDR or not _OPENBAO_TOKEN:
        return None
    return OpenBaoClient(OpenBaoConfig(
        addr=_OPENBAO_ADDR,
        token=_OPENBAO_TOKEN,
        namespace=_OPENBAO_NAMESPACE,
        kv_mount=_OPENBAO_KV_MOUNT,
        timeout_seconds=_OPENBAO_TIMEOUT,
    ))


def _tenant_secret_path(tenant_id: str, key: str) -> str:
    return f"tenants/{tenant_id}/abom/{key}"


def _save_tenant_secret(tenant_id: str, key: str, value: str) -> bool:
    """Persist a tenant-scoped secret. Returns True if it went into
    OpenBao, False if we fell back to in-band storage (caller should
    handle by stashing in the JSONB config row)."""
    client = _openbao_client_or_none()
    if client is None:
        logger.warning("OpenBao not configured — repo-collector token will be stored in Postgres (dev fallback)")
        return False
    try:
        client.kv_write(
            _tenant_secret_path(tenant_id, key),
            {"value": value, "updated_at": datetime.now(timezone.utc).isoformat()},
        )
        return True
    except OpenBaoError as exc:
        logger.warning("OpenBao write failed for tenant=%s key=%s: %s — falling back to Postgres", tenant_id, key, exc)
        return False


def _load_tenant_secret(tenant_id: str, key: str) -> Optional[str]:
    """Read a tenant-scoped secret from OpenBao. Returns None if
    OpenBao is unconfigured or the path doesn't exist; callers fall
    back to checking the JSONB config row."""
    client = _openbao_client_or_none()
    if client is None:
        return None
    try:
        data = client.kv_read_secret(_tenant_secret_path(tenant_id, key))
    except OpenBaoError as exc:
        # 404s come back as 400-class errors; log at debug since "not
        # found" is the common case before a tenant has configured.
        logger.debug("OpenBao read miss for tenant=%s key=%s: %s", tenant_id, key, exc)
        return None
    val = data.get("value") if isinstance(data, dict) else None
    return str(val) if val else None


def _delete_tenant_secret(tenant_id: str, key: str) -> None:
    client = _openbao_client_or_none()
    if client is None:
        return
    try:
        client.kv_delete_latest(_tenant_secret_path(tenant_id, key))
    except OpenBaoError as exc:
        logger.warning("OpenBao delete failed for tenant=%s key=%s: %s", tenant_id, key, exc)


class RepoCollectorConfig(BaseModel):
    """Tenant config for the repo-collector. Stored under
    TenantPortalConfig section ``abom-repo-collector``."""
    provider: str = Field(default="github", description="github | gitlab | azure_devops")
    token: Optional[str] = Field(default=None, description="PAT; write-only — never echoed back")
    repos: List[str] = Field(default_factory=list, description="org/repo entries")
    enabled: bool = True


def _repo_collector_config(db: Session, tenant_id: str) -> Dict[str, Any]:
    """Read the tenant's repo-collector config row. Returns the stored
    dict directly so the caller can decide what to redact."""
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-repo-collector",
        )
        .first()
    )
    if not record:
        return {}
    cfg = _coerce_meta(record.config) if hasattr(record, "config") else None
    return cfg if isinstance(cfg, dict) else {}


def _save_repo_collector_config(
    db: Session, tenant_id: str, payload: Dict[str, Any], updated_by: str
) -> Dict[str, Any]:
    """Upsert the tenant's repo-collector config.

    PAT handling:
      - When the caller supplies a token, write it to OpenBao under
        ``tenants/{tenant_id}/abom/repo-collector-token`` and DROP it
        from the JSONB row entirely.
      - When the caller omits the token, keep whatever's already in
        OpenBao (or JSONB on the fallback path).
      - Track ``token_in_openbao`` on the JSONB row so the GET path
        can answer ``token_configured`` without a Vault round-trip.
    """
    existing = _repo_collector_config(db, tenant_id)
    # Strip token before merging — it never belongs in the JSONB row
    # when OpenBao is healthy.
    raw_token = payload.pop("token", None) if isinstance(payload, dict) else None
    merged = {**existing, **{k: v for k, v in payload.items() if v is not None}}

    if raw_token:
        if _save_tenant_secret(tenant_id, "repo-collector-token", raw_token):
            merged["token_in_openbao"] = True
            merged.pop("token", None)
        else:
            # OpenBao unavailable — fall back so the demo single-node
            # path still works.
            merged["token_in_openbao"] = False
            merged["token"] = raw_token
    else:
        # Caller didn't supply one — preserve prior state.
        if "token" in existing:
            merged["token"] = existing["token"]
            merged.setdefault("token_in_openbao", False)

    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-repo-collector",
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    if record:
        record.config = _encode_meta_for_db(merged)
        record.updated_by = updated_by
        record.updated_at = now
    else:
        record = TenantPortalConfig(
            tenant_id=tenant_id,
            section="abom-repo-collector",
            config=_encode_meta_for_db(merged),
            updated_by=updated_by,
            updated_at=now,
        )
        db.add(record)
    db.commit()
    return merged


def _resolve_repo_collector_token(tenant_id: str, cfg: Dict[str, Any]) -> str:
    """Get the PAT from OpenBao when ``token_in_openbao`` is set;
    otherwise fall back to the JSONB ``token`` field (dev path)."""
    if cfg.get("token_in_openbao"):
        secret = _load_tenant_secret(tenant_id, "repo-collector-token")
        if secret:
            return secret
        logger.warning("repo-collector token marked in_openbao but vault read returned empty for tenant=%s", tenant_id)
    return str(cfg.get("token") or "")


# ── Artifact-repo collector (phase 4 — GHCR + JFrog) ──────────────────


class CloudCollectorConfig(BaseModel):
    """Tenant config for the cloud-inventory collector. ``regions`` is
    overloaded across providers: AWS region codes, GCP project IDs,
    Azure subscription IDs. Stored under TenantPortalConfig section
    ``abom-cloud-collector``."""
    provider: str = Field(default="aws", description="aws | gcp | azure")
    # AWS credentials.
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    # GCP credentials (the literal contents of a service-account JSON key).
    service_account_json: Optional[str] = None
    # Azure credentials — AAD tenant for the service principal, NOT
    # the CyberArmor tenant.
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    regions: List[str] = Field(default_factory=list)
    enabled: bool = True


def _cloud_collector_config(db: Session, tenant_id: str) -> Dict[str, Any]:
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-cloud-collector",
        )
        .first()
    )
    if not record:
        return {}
    cfg = _coerce_meta(record.config) if hasattr(record, "config") else None
    return cfg if isinstance(cfg, dict) else {}


def _save_cloud_collector_config(
    db: Session, tenant_id: str, payload: Dict[str, Any], updated_by: str
) -> Dict[str, Any]:
    """Persist tenant cloud-collector config across all three providers.

    Secret handling per provider:
      aws    → access_key_id + secret_access_key + session_token
      gcp    → service_account_json
      azure  → azure_tenant_id + azure_client_id + azure_client_secret
    All write to ``tenants/{tenant}/abom/cloud-collector-<provider>``
    in OpenBao as one JSON-encoded secret so a rotation re-encrypts
    one path. Falls back to JSONB with a clear ``creds_storage`` chip
    when vault is unreachable. The list of regions/projects/subs and
    the enabled flag stay in the JSONB row regardless.
    """
    existing = _cloud_collector_config(db, tenant_id)
    secret_keys = (
        "access_key_id", "secret_access_key", "session_token",
        "service_account_json",
        "azure_tenant_id", "azure_client_id", "azure_client_secret",
    )
    raw_secrets: Dict[str, Optional[str]] = {
        k: (payload.pop(k, None) if isinstance(payload, dict) else None) for k in secret_keys
    }
    merged = {**existing, **{k: v for k, v in payload.items() if v is not None}}
    provider = str(merged.get("provider") or "aws")

    # The secret bag we'll attempt to persist: only fields the caller
    # actually supplied (so a partial save preserves the rest of the
    # prior bag in OpenBao).
    bag_supplied = {k: v for k, v in raw_secrets.items() if v}
    if bag_supplied:
        # Pull the existing bag from OpenBao so we merge instead of
        # clobbering when the operator only updated one field.
        existing_bag: Dict[str, Any] = {}
        if existing.get("creds_in_openbao"):
            raw = _load_tenant_secret(tenant_id, f"cloud-collector-{provider}")
            if raw:
                try:
                    existing_bag = json.loads(raw)
                except (ValueError, TypeError):
                    existing_bag = {}
        merged_bag = {**existing_bag, **bag_supplied}
        secret_value = json.dumps(merged_bag)
        if _save_tenant_secret(tenant_id, f"cloud-collector-{provider}", secret_value):
            merged["creds_in_openbao"] = True
            for k in secret_keys:
                merged.pop(k, None)
        else:
            merged["creds_in_openbao"] = False
            for k, v in bag_supplied.items():
                merged[k] = v
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-cloud-collector",
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    if record:
        record.config = _encode_meta_for_db(merged)
        record.updated_by = updated_by
        record.updated_at = now
    else:
        record = TenantPortalConfig(
            tenant_id=tenant_id,
            section="abom-cloud-collector",
            config=_encode_meta_for_db(merged),
            updated_by=updated_by,
            updated_at=now,
        )
        db.add(record)
    db.commit()
    return merged


def _resolve_cloud_creds(tenant_id: str, cfg: Dict[str, Any]) -> Dict[str, str]:
    """Return the credential bag for whichever provider this tenant
    configured. OpenBao wins when ``creds_in_openbao`` is set; falls
    back to the JSONB row otherwise. The returned dict carries every
    field for every provider — sync_cloud_source picks the ones it
    cares about based on ``provider``."""
    provider = str(cfg.get("provider") or "aws")
    bag: Dict[str, Any] = {}
    if cfg.get("creds_in_openbao"):
        raw = _load_tenant_secret(tenant_id, f"cloud-collector-{provider}")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    bag = parsed
            except (json.JSONDecodeError, ValueError):
                logger.warning("cloud-collector openbao payload not JSON for tenant=%s provider=%s",
                               tenant_id, provider)
    # Fall back to JSONB row fields when OpenBao didn't yield a value.
    keys = (
        "access_key_id", "secret_access_key", "session_token",
        "service_account_json",
        "azure_tenant_id", "azure_client_id", "azure_client_secret",
    )
    out: Dict[str, str] = {}
    for k in keys:
        out[k] = str(bag.get(k) or cfg.get(k) or "")
    return out


@app.get("/customer/abom/cloud-config")
def customer_abom_cloud_config_get(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    cfg = _cloud_collector_config(db, ctx.tenant_id)
    creds_in_vault = bool(cfg.get("creds_in_openbao"))
    # Provider-specific "is there a JSONB-side secret?" check so the
    # UI still reports "configured" on the dev fallback path.
    has_local = bool(
        cfg.get("access_key_id")
        or cfg.get("service_account_json")
        or cfg.get("azure_client_id")
    )
    storage = "openbao" if creds_in_vault else ("postgres" if has_local else "unconfigured")
    return {
        "provider": cfg.get("provider", "aws"),
        "regions": cfg.get("regions") or [],
        "enabled": cfg.get("enabled", True),
        "creds_configured": creds_in_vault or has_local,
        "creds_storage": storage,
        "last_synced_at": cfg.get("last_synced_at"),
        "last_sync_summary": cfg.get("last_sync_summary"),
    }


@app.put("/customer/abom/cloud-config")
def customer_abom_cloud_config_put(
    payload: CloudCollectorConfig,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    merged = _save_cloud_collector_config(
        db, ctx.tenant_id, payload.model_dump(), updated_by=ctx.email,
    )
    return {
        "provider": merged.get("provider", "aws"),
        "regions": merged.get("regions") or [],
        "enabled": merged.get("enabled", True),
        "creds_configured": bool(merged.get("creds_in_openbao") or merged.get("access_key_id")),
    }


@app.post("/customer/abom/cloud-sync")
def customer_abom_cloud_sync(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    cfg = _cloud_collector_config(db, ctx.tenant_id)
    if not cfg:
        raise HTTPException(status_code=400, detail="cloud collector not configured")
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=400, detail="cloud collector disabled")
    regions = cfg.get("regions") or []
    if not isinstance(regions, list) or not regions:
        raise HTTPException(status_code=400, detail="no regions configured")
    provider = str(cfg.get("provider") or "aws")
    creds = _resolve_cloud_creds(ctx.tenant_id, cfg)
    if provider == "aws" and (not creds.get("access_key_id") or not creds.get("secret_access_key")):
        raise HTTPException(status_code=400, detail="aws credentials missing")
    if provider == "gcp" and not creds.get("service_account_json"):
        raise HTTPException(status_code=400, detail="gcp service account JSON missing")
    if provider == "azure" and not (creds.get("azure_tenant_id") and creds.get("azure_client_id") and creds.get("azure_client_secret")):
        raise HTTPException(status_code=400, detail="azure service principal credentials missing")

    from cloud_collector import sync_cloud_source

    now = datetime.now(timezone.utc)
    try:
        results = sync_cloud_source(provider, creds, regions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("cloud-sync tenant=%s provider=%s", ctx.tenant_id, provider)
        raise HTTPException(status_code=502, detail=f"{provider} sync failed: {exc.__class__.__name__}: {exc}")

    summaries: List[Dict[str, Any]] = []
    total_obs = 0
    for source_id, components in results:
        summary = {"source_id": source_id, "components": len(components), "ingested": 0, "skipped": 0}
        for component in components:
            if not isinstance(component, dict):
                summary["skipped"] += 1
                continue
            try:
                row, ikey = _abom_upsert_component(db, ctx.tenant_id, component, now)
            except Exception as exc:  # noqa: BLE001
                logger.warning("cloud-sync upsert failed: %s", exc)
                summary["skipped"] += 1
                continue
            row.observation_count = (row.observation_count or 0) + 1
            db.add(ABOMObservation(
                tenant_id=ctx.tenant_id,
                component_id=row.id,
                identity_key=ikey,
                collector="cloud-collector",
                collector_version="1.0",
                source_kind="cloud_resource",
                source_id=source_id,
                hostname=None,
                path=str(component.get("__path") or "")[:1024] or None,
                raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                observed_at=now,
            ))
            summary["ingested"] += 1
        db.commit()
        total_obs += summary["ingested"]
        summaries.append(summary)

    summary_payload = {
        "regions": len(summaries),
        "observations": total_obs,
        "per_region": summaries,
    }
    cfg["last_synced_at"] = now.isoformat()
    cfg["last_sync_summary"] = summary_payload
    _save_cloud_collector_config(db, ctx.tenant_id, cfg, updated_by=ctx.email)
    return {"status": "ok", "synced_at": now.isoformat(), "summary": summary_payload}


class ArtifactCollectorConfig(BaseModel):
    """Tenant config for an artifact-repo collector (GHCR / JFrog).
    Stored under TenantPortalConfig section ``abom-artifact-collector``."""
    provider: str = Field(default="ghcr", description="ghcr | jfrog")
    token: Optional[str] = Field(default=None, description="PAT / API token (write-only)")
    base_url: Optional[str] = Field(default=None, description="JFrog only — Artifactory host URL")
    refs: List[str] = Field(default_factory=list, description="ghcr:org/img, jfrog:repo_name, etc.")
    enabled: bool = True


def _artifact_collector_config(db: Session, tenant_id: str) -> Dict[str, Any]:
    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-artifact-collector",
        )
        .first()
    )
    if not record:
        return {}
    cfg = _coerce_meta(record.config) if hasattr(record, "config") else None
    return cfg if isinstance(cfg, dict) else {}


def _save_artifact_collector_config(
    db: Session, tenant_id: str, payload: Dict[str, Any], updated_by: str
) -> Dict[str, Any]:
    existing = _artifact_collector_config(db, tenant_id)
    raw_token = payload.pop("token", None) if isinstance(payload, dict) else None
    merged = {**existing, **{k: v for k, v in payload.items() if v is not None}}

    if raw_token:
        if _save_tenant_secret(tenant_id, "artifact-collector-token", raw_token):
            merged["token_in_openbao"] = True
            merged.pop("token", None)
        else:
            merged["token_in_openbao"] = False
            merged["token"] = raw_token
    else:
        if "token" in existing:
            merged["token"] = existing["token"]
            merged.setdefault("token_in_openbao", False)

    record = (
        db.query(TenantPortalConfig)
        .filter(
            TenantPortalConfig.tenant_id == tenant_id,
            TenantPortalConfig.section == "abom-artifact-collector",
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    if record:
        record.config = _encode_meta_for_db(merged)
        record.updated_by = updated_by
        record.updated_at = now
    else:
        record = TenantPortalConfig(
            tenant_id=tenant_id,
            section="abom-artifact-collector",
            config=_encode_meta_for_db(merged),
            updated_by=updated_by,
            updated_at=now,
        )
        db.add(record)
    db.commit()
    return merged


def _resolve_artifact_collector_token(tenant_id: str, cfg: Dict[str, Any]) -> str:
    if cfg.get("token_in_openbao"):
        secret = _load_tenant_secret(tenant_id, "artifact-collector-token")
        if secret:
            return secret
        logger.warning("artifact-collector token marked in_openbao but vault read empty for tenant=%s", tenant_id)
    return str(cfg.get("token") or "")


@app.get("/customer/abom/artifact-config")
def customer_abom_artifact_config_get(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    cfg = _artifact_collector_config(db, ctx.tenant_id)
    token_in_vault = bool(cfg.get("token_in_openbao"))
    has_local = bool(cfg.get("token"))
    token_storage = (
        "openbao" if token_in_vault else ("postgres" if has_local else "unconfigured")
    )
    return {
        "provider": cfg.get("provider", "ghcr"),
        "base_url": cfg.get("base_url", ""),
        "refs": cfg.get("refs") or [],
        "enabled": cfg.get("enabled", True),
        "token_configured": token_in_vault or has_local,
        "token_storage": token_storage,
        "last_synced_at": cfg.get("last_synced_at"),
        "last_sync_summary": cfg.get("last_sync_summary"),
    }


@app.put("/customer/abom/artifact-config")
def customer_abom_artifact_config_put(
    payload: ArtifactCollectorConfig,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    merged = _save_artifact_collector_config(
        db, ctx.tenant_id, payload.model_dump(), updated_by=ctx.email,
    )
    return {
        "provider": merged.get("provider", "ghcr"),
        "base_url": merged.get("base_url", ""),
        "refs": merged.get("refs") or [],
        "enabled": merged.get("enabled", True),
        "token_configured": bool(merged.get("token_in_openbao") or merged.get("token")),
    }


@app.post("/customer/abom/artifact-sync")
def customer_abom_artifact_sync(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Trigger a one-shot artifact-repo sweep using the stored config."""
    cfg = _artifact_collector_config(db, ctx.tenant_id)
    if not cfg:
        raise HTTPException(status_code=400, detail="artifact collector not configured")
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=400, detail="artifact collector disabled")
    refs = cfg.get("refs") or []
    if not isinstance(refs, list) or not refs:
        raise HTTPException(status_code=400, detail="no refs configured")
    provider = str(cfg.get("provider") or "ghcr")
    base_url = str(cfg.get("base_url") or "")
    token = _resolve_artifact_collector_token(ctx.tenant_id, cfg)
    if not token:
        raise HTTPException(status_code=400, detail="artifact collector token missing")

    from artifact_collector import sync_artifact_source

    now = datetime.now(timezone.utc)
    try:
        results = sync_artifact_source(provider, token, refs, base_url=base_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("artifact-sync tenant=%s provider=%s", ctx.tenant_id, provider)
        raise HTTPException(status_code=502, detail=f"{provider} sync failed: {exc.__class__.__name__}: {exc}")

    summaries: List[Dict[str, Any]] = []
    total_obs = 0
    for source_id, components in results:
        repo_summary = {
            "source_id": source_id,
            "components": len(components),
            "ingested": 0,
            "skipped": 0,
        }
        for component in components:
            if not isinstance(component, dict):
                repo_summary["skipped"] += 1
                continue
            try:
                row, ikey = _abom_upsert_component(db, ctx.tenant_id, component, now)
            except Exception as exc:  # noqa: BLE001
                logger.warning("artifact-sync upsert failed: %s", exc)
                repo_summary["skipped"] += 1
                continue
            row.observation_count = (row.observation_count or 0) + 1
            db.add(ABOMObservation(
                tenant_id=ctx.tenant_id,
                component_id=row.id,
                identity_key=ikey,
                collector="artifact-collector",
                collector_version="1.0",
                source_kind="container",
                source_id=source_id,
                hostname=None,
                path=str(component.get("__path") or "")[:1024] or None,
                raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                observed_at=now,
            ))
            repo_summary["ingested"] += 1
        db.commit()
        total_obs += repo_summary["ingested"]
        summaries.append(repo_summary)

    summary_payload = {
        "refs": len(summaries),
        "observations": total_obs,
        "per_ref": summaries,
    }
    cfg["last_synced_at"] = now.isoformat()
    cfg["last_sync_summary"] = summary_payload
    _save_artifact_collector_config(db, ctx.tenant_id, cfg, updated_by=ctx.email)
    return {
        "status": "ok",
        "synced_at": now.isoformat(),
        "summary": summary_payload,
    }


@app.get("/customer/abom/repo-config")
def customer_abom_repo_config_get(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Return the tenant repo-collector config with the PAT redacted.

    ``token_configured`` is true when *either* OpenBao holds the
    secret or the JSONB row has one (dev fallback). ``token_storage``
    tells the operator which path is in use so they can move secrets
    out of Postgres before going to prod.
    """
    cfg = _repo_collector_config(db, ctx.tenant_id)
    token_in_vault = bool(cfg.get("token_in_openbao"))
    has_local = bool(cfg.get("token"))
    token_storage = (
        "openbao" if token_in_vault else ("postgres" if has_local else "unconfigured")
    )
    return {
        "provider": cfg.get("provider", "github"),
        "repos": cfg.get("repos") or [],
        "enabled": cfg.get("enabled", True),
        "token_configured": token_in_vault or has_local,
        "token_storage": token_storage,
        "last_synced_at": cfg.get("last_synced_at"),
        "last_sync_summary": cfg.get("last_sync_summary"),
    }


@app.put("/customer/abom/repo-config")
def customer_abom_repo_config_put(
    payload: RepoCollectorConfig,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Admin-only: persist provider / token / repos. PAT is never
    echoed back."""
    merged = _save_repo_collector_config(
        db, ctx.tenant_id,
        payload.model_dump(),
        updated_by=ctx.email,
    )
    return {
        "provider": merged.get("provider", "github"),
        "repos": merged.get("repos") or [],
        "enabled": merged.get("enabled", True),
        "token_configured": bool(merged.get("token")),
    }


@app.post("/customer/abom/repo-sync")
def customer_abom_repo_sync(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Trigger a one-shot repo sweep using the stored config. Sync runs
    inline — bounded by GITHUB_API_BUDGET per repo so the handler
    latency stays predictable. Background scheduling is a follow-up
    (FastAPI background task or a dedicated worker).
    """
    cfg = _repo_collector_config(db, ctx.tenant_id)
    if not cfg:
        raise HTTPException(status_code=400, detail="repo collector not configured")
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=400, detail="repo collector disabled")
    repos = cfg.get("repos") or []
    if not isinstance(repos, list) or not repos:
        raise HTTPException(status_code=400, detail="no repos configured")
    provider = str(cfg.get("provider") or "github")
    token = _resolve_repo_collector_token(ctx.tenant_id, cfg)
    if not token:
        raise HTTPException(status_code=400, detail="repo collector token missing")

    from repo_collector import sync_repos, GitHubError  # lazy: keeps cold-start fast

    summaries: List[Dict[str, Any]] = []
    total_components = 0
    total_observations = 0
    now = datetime.now(timezone.utc)

    try:
        results = sync_repos(provider, token, repos)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 — convert provider crashes to a
        # 502 so the portal shows "sync failed" instead of a generic 500.
        # The provider clients (GitHubError / GitLabError / AzureRepoError)
        # are already caught per-repo inside sync_repos; this catch is for
        # anything more exotic — JSON decode, unexpected transport,
        # OpenBao reaching out of scope, etc.
        logger.exception("repo-sync provider call failed tenant=%s provider=%s", ctx.tenant_id, provider)
        raise HTTPException(status_code=502, detail=f"{provider} sync failed: {exc.__class__.__name__}: {exc}")

    for source_id, components in results:
        repo_summary = {
            "source_id": source_id,
            "components": len(components),
            "ingested": 0,
            "skipped": 0,
        }
        for component in components:
            if not isinstance(component, dict):
                repo_summary["skipped"] += 1
                continue
            try:
                row, ikey = _abom_upsert_component(db, ctx.tenant_id, component, now)
            except Exception as exc:  # noqa: BLE001
                logger.warning("repo-sync upsert failed: %s", exc)
                repo_summary["skipped"] += 1
                continue
            row.observation_count = (row.observation_count or 0) + 1
            obs = ABOMObservation(
                tenant_id=ctx.tenant_id,
                component_id=row.id,
                identity_key=ikey,
                collector="repo-collector",
                collector_version="1.0",
                source_kind="repo",
                source_id=source_id,
                hostname=None,
                path=str(component.get("__path") or "")[:1024] or None,
                raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                observed_at=now,
            )
            db.add(obs)
            repo_summary["ingested"] += 1
        db.commit()
        total_components += repo_summary["components"]
        total_observations += repo_summary["ingested"]
        summaries.append(repo_summary)

    # Cache the summary on the config row so the portal can show
    # "Last sync: 2 repos, 47 components, 23 minutes ago" without
    # walking the observation history.
    summary_payload = {
        "repos": len(summaries),
        "components": total_components,
        "observations": total_observations,
        "per_repo": summaries,
    }
    cfg["last_synced_at"] = now.isoformat()
    cfg["last_sync_summary"] = summary_payload
    _save_repo_collector_config(db, ctx.tenant_id, cfg, updated_by=ctx.email)

    return {
        "status": "ok",
        "synced_at": now.isoformat(),
        "summary": summary_payload,
    }


@app.post("/rasp/abom/ingest")
def rasp_abom_ingest(
    payload: ABOMIngestRequest,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """RASP-runtime A-BOM ingest. Different shape from the agent endpoint
    because RASP isn't enrolled as an agent — there's no agent_id to put
    in the path. ``source_id`` carries the workload identifier
    (workload:<host>:<pid> by convention) so multiple processes on the
    same host stay distinguishable in observations.

    Validates ``source_kind`` is "workload" (or one of the other A-BOM
    kinds) so a misconfigured caller can't pollute the agent path.
    """
    _dev_or_key_ok(x_api_key)
    if not payload.tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id required for RASP ingest")
    if payload.source_kind not in ("workload", "container", "agent", "repo", "cloud_resource", "ide_workspace"):
        raise HTTPException(status_code=400, detail="unsupported source_kind")
    components = payload.components or []
    if payload.bom and isinstance(payload.bom, dict):
        bom_components = payload.bom.get("components")
        if isinstance(bom_components, list):
            components = components + bom_components

    if payload.observed_at:
        try:
            observed_at = datetime.fromisoformat(payload.observed_at.replace("Z", "+00:00"))
        except ValueError:
            observed_at = datetime.now(timezone.utc)
    else:
        observed_at = datetime.now(timezone.utc)

    inserted, skipped = 0, 0
    with SessionLocal() as db:
        for component in components:
            if not isinstance(component, dict):
                skipped += 1
                continue
            try:
                row, ikey = _abom_upsert_component(db, payload.tenant_id, component, observed_at)
            except Exception as exc:  # noqa: BLE001
                logger.warning("rasp_abom_ingest upsert failed: %s", exc)
                skipped += 1
                continue
            row.observation_count = (row.observation_count or 0) + 1
            obs = ABOMObservation(
                tenant_id=payload.tenant_id,
                component_id=row.id,
                identity_key=ikey,
                collector=payload.collector,
                collector_version=payload.collector_version,
                source_kind=payload.source_kind,
                source_id=payload.source_id,
                hostname=payload.hostname,
                path=str(component.get("__path") or "")[:1024] or None,
                raw_properties=_encode_meta_for_db(component.get("properties") or {}),
                observed_at=observed_at,
            )
            db.add(obs)
            inserted += 1
        db.commit()

    logger.info(
        "rasp_abom_ingest tenant=%s source=%s collector=%s ingested=%d",
        payload.tenant_id, payload.source_id, payload.collector, inserted,
    )
    return JSONResponse(
        {"status": "accepted", "components_ingested": inserted, "skipped": skipped},
        status_code=202,
    )


# ── A-BOM customer-facing reads ────────────────────────────────────────

@app.get("/customer/abom/components")
def customer_abom_components(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 100,
    offset: int = 0,
    type: Optional[str] = None,
    q: Optional[str] = None,
    source_kind: Optional[str] = None,
    has_license: Optional[str] = None,
    stale_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Paginated component list with filters. Joins to observations only
    when ``source_kind`` is set so the common path stays fast.

    ``stale_days`` filters to components whose ``last_seen_at`` is older
    than the cutoff — useful for "what used to be here that's gone?"
    queries the Drift view doesn't cover.
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    base = db.query(ABOMComponent).filter(ABOMComponent.tenant_id == ctx.tenant_id)
    if type:
        base = base.filter(ABOMComponent.type == type)
    if q:
        like = f"%{q.lower()}%"
        base = base.filter(func.lower(ABOMComponent.name).like(like))
    if stale_days is not None and stale_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        base = base.filter(ABOMComponent.last_seen_at < cutoff)
    if source_kind:
        # Pull component_ids that have an observation matching the kind.
        sub = (
            db.query(ABOMObservation.component_id)
            .filter(ABOMObservation.tenant_id == ctx.tenant_id)
            .filter(ABOMObservation.source_kind == source_kind)
            .distinct()
            .subquery()
        )
        base = base.filter(ABOMComponent.id.in_(sub))
    total = base.count()
    rows = base.order_by(desc(ABOMComponent.last_seen_at)).offset(offset).limit(limit).all()
    items: List[Dict[str, Any]] = []
    for r in rows:
        licenses = _coerce_meta(r.licenses) or []
        if has_license and (not isinstance(licenses, list) or not any(
            has_license.lower() in str(l).lower() for l in licenses
        )):
            continue
        items.append({
            "id": r.id,
            "identity_key": r.identity_key,
            "type": r.type,
            "name": r.name,
            "version": r.version,
            "purl": r.purl,
            "cpe": r.cpe,
            "manufacturer": r.manufacturer,
            "licenses": licenses if isinstance(licenses, list) else [],
            "hashes": _coerce_meta(r.hashes) or {},
            "observation_count": r.observation_count,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        })
    return {"components": items, "total": total, "limit": limit, "offset": offset}


@app.get("/customer/abom/components/{component_id}")
def customer_abom_component_detail(
    component_id: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    row = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == ctx.tenant_id, ABOMComponent.id == component_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="component not found")
    observations = (
        db.query(ABOMObservation)
        .filter(ABOMObservation.tenant_id == ctx.tenant_id, ABOMObservation.component_id == component_id)
        .order_by(desc(ABOMObservation.observed_at))
        .limit(100)
        .all()
    )
    obs_out = [{
        "id": o.id,
        "collector": o.collector,
        "collector_version": o.collector_version,
        "source_kind": o.source_kind,
        "source_id": o.source_id,
        "hostname": o.hostname,
        "path": o.path,
        "observed_at": o.observed_at.isoformat() if o.observed_at else None,
    } for o in observations]
    return {
        "id": row.id,
        "identity_key": row.identity_key,
        "type": row.type,
        "name": row.name,
        "version": row.version,
        "purl": row.purl,
        "cpe": row.cpe,
        "manufacturer": row.manufacturer,
        "licenses": _coerce_meta(row.licenses) or [],
        "hashes": _coerce_meta(row.hashes) or {},
        "properties": _coerce_meta(row.properties) or [],
        "observation_count": row.observation_count,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "observations": obs_out,
    }


@app.get("/customer/abom/drift")
def customer_abom_drift(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    since: Optional[str] = None,
    days: int = 1,
) -> Dict[str, Any]:
    """What's changed in the tenant's component set in the last window?

    Buckets:
      - ``added``:   ``first_seen_at`` falls inside the window (still active).
      - ``removed``: ``last_seen_at`` is older than the window start — we
                     haven't seen the component in any sweep since.
      - ``version_changed``: pairs where ``(type, name, manufacturer)`` is
                     the same but ``identity_key`` differs and one entry
                     went stale while another appeared inside the window.

    Identity-key changes are the only way we detect version churn since
    we never demote a component row's version — a new version is a new
    identity_key per the design doc.
    """
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be ISO-8601")
    else:
        days = max(1, min(days, 365))
        since_dt = datetime.now(timezone.utc) - timedelta(days=days)

    # Pull every component once; the drift view operates on the full set.
    # Component counts are usually <10k per tenant — keeping it simple.
    rows = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == ctx.tenant_id)
        .all()
    )

    added: list[Dict[str, Any]] = []
    removed: list[Dict[str, Any]] = []
    # Group by (type, name, manufacturer) so we can pair an old version's
    # disappearance with a new version's appearance.
    by_key: Dict[Tuple[str, str, str], list[ABOMComponent]] = {}

    for r in rows:
        key = (r.type or "", (r.name or "").lower(), (r.manufacturer or "").lower())
        by_key.setdefault(key, []).append(r)
        first = r.first_seen_at
        last = r.last_seen_at
        if first is not None and first >= since_dt:
            added.append(_abom_row_to_drift_dict(r))
        elif last is not None and last < since_dt:
            removed.append(_abom_row_to_drift_dict(r))

    version_changed: list[Dict[str, Any]] = []
    for key, entries in by_key.items():
        if len(entries) < 2:
            continue
        # Pair every recently-appearing row with every recently-stale row
        # in the same name/manufacturer cluster. Drop pairs that share an
        # identity_key (shouldn't happen, but defensive).
        new_ones = [e for e in entries if e.first_seen_at and e.first_seen_at >= since_dt]
        old_ones = [e for e in entries if e.last_seen_at and e.last_seen_at < since_dt]
        for new in new_ones:
            for old in old_ones:
                if new.identity_key == old.identity_key:
                    continue
                version_changed.append({
                    "type": new.type,
                    "name": new.name,
                    "manufacturer": new.manufacturer,
                    "from_version": old.version,
                    "from_purl": old.purl,
                    "from_identity_key": old.identity_key,
                    "from_last_seen_at": old.last_seen_at.isoformat() if old.last_seen_at else None,
                    "to_version": new.version,
                    "to_purl": new.purl,
                    "to_identity_key": new.identity_key,
                    "to_first_seen_at": new.first_seen_at.isoformat() if new.first_seen_at else None,
                    "to_id": new.id,
                })

    # A row showing up as version_changed is by definition also in
    # added/removed; drop those copies so the three lists don't double-count.
    vc_to_ids = {v["to_identity_key"] for v in version_changed}
    vc_from_ids = {v["from_identity_key"] for v in version_changed}
    added = [a for a in added if a["identity_key"] not in vc_to_ids]
    removed = [r for r in removed if r["identity_key"] not in vc_from_ids]

    return {
        "since": since_dt.isoformat(),
        "until": datetime.now(timezone.utc).isoformat(),
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "version_changed": len(version_changed),
        },
    }


def _abom_row_to_drift_dict(r: "ABOMComponent") -> Dict[str, Any]:
    return {
        "id": r.id,
        "identity_key": r.identity_key,
        "type": r.type,
        "name": r.name,
        "version": r.version,
        "purl": r.purl,
        "manufacturer": r.manufacturer,
        "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
    }


@app.get("/customer/abom/stats")
def customer_abom_stats(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Tiny summary used by Mission Control + the BOM nav badge. Cheap
    queries only — never walks observations."""
    base = db.query(ABOMComponent).filter(ABOMComponent.tenant_id == ctx.tenant_id)
    total = base.count()

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    added_24h = base.filter(ABOMComponent.first_seen_at >= day_ago).count()
    added_7d = base.filter(ABOMComponent.first_seen_at >= week_ago).count()
    stale_7d = base.filter(ABOMComponent.last_seen_at < week_ago).count()

    by_type_rows = (
        db.query(ABOMComponent.type, func.count(ABOMComponent.id))
        .filter(ABOMComponent.tenant_id == ctx.tenant_id)
        .group_by(ABOMComponent.type)
        .all()
    )
    by_type = {str(t or "unknown"): int(c) for t, c in by_type_rows}
    return {
        "total": total,
        "added_24h": added_24h,
        "added_7d": added_7d,
        "stale_7d": stale_7d,
        "by_type": by_type,
    }


class ABOMIocScanRequest(BaseModel):
    """IOC scan input. ``iocs`` accepts one entry per IOC; ``raw`` is a
    convenience for portal paste boxes that just tile a list of names /
    name@version / pkg:purl lines. Either or both may be set; the
    server parses each line of ``raw`` into iocs[] entries before
    matching."""
    iocs: Optional[List[Dict[str, Any]]] = None
    raw: Optional[str] = None


_PURL_RE = re.compile(r"^pkg:[a-z][a-z0-9.+\-]*/", re.IGNORECASE)


def _parse_ioc_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one IOC text line into a structured query.

    Accepted forms (highest precision first):
      ``pkg:npm/@scope/name@1.2.3``     → match by full purl prefix
      ``pkg:pypi/name@1.2.3``           → match by full purl prefix
      ``@scope/name@1.2.3``             → name + version (any package
                                          manager)
      ``name@1.2.3``                    → name + version
      ``@scope/name`` or ``name``       → name-only, any version
    """
    s = (line or "").strip()
    # Strip CycloneDX-VEX-style suffixes a user might paste verbatim,
    # like ``pkg:npm/foo@1.2.3?type=tar`` or trailing comments.
    s = s.split("#", 1)[0].split("//", 1)[0].strip()
    if not s:
        return None
    if _PURL_RE.match(s):
        return {"purl": s}
    # name@version. Scoped names start with @ which complicates "find
    # the last @" — split on the last @ that isn't index 0.
    if "@" in s[1:]:
        name, _, version = s.rpartition("@")
        name = name.strip()
        version = version.strip()
        if name and version:
            return {"name": name, "version": version}
    return {"name": s}


def _parse_iocs(payload: ABOMIocScanRequest) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for entry in (payload.iocs or []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or ""
        version = entry.get("version") or ""
        purl = entry.get("purl") or ""
        if purl:
            parsed.append({"purl": str(purl)})
        elif name:
            row = {"name": str(name)}
            if version:
                row["version"] = str(version)
            parsed.append(row)
    if payload.raw:
        for line in payload.raw.splitlines():
            row = _parse_ioc_line(line)
            if row:
                parsed.append(row)
    # Dedup; preserve order of first appearance for predictable UX.
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for r in parsed:
        key = (r.get("purl") or "", r.get("name") or "", r.get("version") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


@app.post("/customer/abom/ioc-scan")
def customer_abom_ioc_scan(
    payload: ABOMIocScanRequest,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Cross-reference a list of IOCs against the tenant's components.

    Matching strategy per IOC:
      - ``purl``: prefix match on ``ABOMComponent.purl`` (so a
        ``pkg:npm/foo@1.2.3`` IOC catches ``pkg:npm/foo@1.2.3?arch=amd64``).
      - ``name + version``: exact match on both columns.
      - ``name`` only: match every version we've seen.

    For each match we attach the most recent 5 observations so the
    portal can show ``which agents / which repos / which hosts`` for
    incident-response triage.
    """
    iocs = _parse_iocs(payload)
    if not iocs:
        raise HTTPException(status_code=400, detail="no iocs provided")
    if len(iocs) > 2000:
        raise HTTPException(status_code=400, detail="too many iocs (limit 2000)")

    # Collect component matches per IOC. We run one targeted query per
    # IOC so a single typo doesn't cause an O(N*M) join; component counts
    # per tenant top out in the low-thousands and the IOC list is
    # usually <500, so the per-row cost is fine.
    matches: List[Dict[str, Any]] = []
    total_components = 0
    total_observations = 0

    base = db.query(ABOMComponent).filter(ABOMComponent.tenant_id == ctx.tenant_id)

    for ioc in iocs:
        q = base
        ioc_label = ioc.get("purl") or (
            f"{ioc.get('name','')}@{ioc.get('version','')}" if ioc.get("version") else ioc.get("name", "")
        )
        if "purl" in ioc:
            q = q.filter(ABOMComponent.purl.like(ioc["purl"] + "%"))
        else:
            q = q.filter(ABOMComponent.name == ioc["name"])
            if "version" in ioc:
                q = q.filter(ABOMComponent.version == ioc["version"])
        rows = q.all()

        if not rows:
            matches.append({"ioc": ioc, "label": ioc_label, "components": []})
            continue

        component_blocks: List[Dict[str, Any]] = []
        for r in rows:
            obs = (
                db.query(ABOMObservation)
                .filter(
                    ABOMObservation.tenant_id == ctx.tenant_id,
                    ABOMObservation.component_id == r.id,
                )
                .order_by(desc(ABOMObservation.observed_at))
                .limit(5)
                .all()
            )
            total_observations += len(obs)
            component_blocks.append({
                "id": r.id,
                "identity_key": r.identity_key,
                "type": r.type,
                "name": r.name,
                "version": r.version,
                "purl": r.purl,
                "manufacturer": r.manufacturer,
                "observation_count": r.observation_count,
                "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "observations": [
                    {
                        "collector": o.collector,
                        "source_kind": o.source_kind,
                        "source_id": o.source_id,
                        "hostname": o.hostname,
                        "path": o.path,
                        "observed_at": o.observed_at.isoformat() if o.observed_at else None,
                    }
                    for o in obs
                ],
            })
        total_components += len(component_blocks)
        matches.append({"ioc": ioc, "label": ioc_label, "components": component_blocks})

    hit_count = sum(1 for m in matches if m["components"])
    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "iocs_total": len(iocs),
        "iocs_with_hits": hit_count,
        "components_matched": total_components,
        "observations_matched": total_observations,
        "matches": matches,
    }


@app.get("/customer/abom/loaded-vs-installed")
def customer_abom_loaded_vs_installed(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    hostname: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """RASP-vs-endpoint overlay. The endpoint agent reports what's
    *installed* on a host; RASP reports what's *actually loaded* in a
    running process. The intersection / set-difference between the two
    observation sets per hostname is the demo signal — "log4j 2.14.1 is
    installed AND loaded in PID 4231" vs "installed but never loaded".

    Returns three buckets keyed off identity_key:
      - ``loaded_only``: RASP saw it; endpoint agent didn't surface it.
      - ``installed_only``: endpoint saw it; no workload has loaded it.
      - ``both``: matched on identity_key from both sources.

    Endpoints / containers can ship many components; cap raw + dedup so
    a single call stays predictable.
    """
    limit = max(1, min(limit, 2000))

    # Pull observations grouped by source_kind. Limit per kind so a noisy
    # collector doesn't push the other off the result set.
    base = db.query(ABOMObservation).filter(ABOMObservation.tenant_id == ctx.tenant_id)
    if hostname:
        base = base.filter(ABOMObservation.hostname == hostname)
    agent_obs = (
        base.filter(ABOMObservation.source_kind == "agent")
        .order_by(desc(ABOMObservation.observed_at)).limit(limit).all()
    )
    workload_obs = (
        base.filter(ABOMObservation.source_kind.in_(["workload", "container"]))
        .order_by(desc(ABOMObservation.observed_at)).limit(limit).all()
    )

    agent_keys = {o.identity_key for o in agent_obs}
    workload_keys = {o.identity_key for o in workload_obs}
    # Pull rolled-up component rows in one query per key set, indexed for
    # lookup so we can shape each bucket without N+1 queries.
    all_keys = agent_keys | workload_keys
    if not all_keys:
        return {
            "loaded_only": [],
            "installed_only": [],
            "both": [],
            "hostname": hostname,
            "summary": {"loaded_only": 0, "installed_only": 0, "both": 0},
        }
    rows = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == ctx.tenant_id)
        .filter(ABOMComponent.identity_key.in_(list(all_keys)))
        .all()
    )
    by_key = {r.identity_key: r for r in rows}

    def fmt(r: ABOMComponent) -> Dict[str, Any]:
        return {
            "id": r.id,
            "identity_key": r.identity_key,
            "type": r.type,
            "name": r.name,
            "version": r.version,
            "purl": r.purl,
            "manufacturer": r.manufacturer,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        }

    loaded_only = [fmt(by_key[k]) for k in (workload_keys - agent_keys) if k in by_key]
    installed_only = [fmt(by_key[k]) for k in (agent_keys - workload_keys) if k in by_key]
    both = [fmt(by_key[k]) for k in (agent_keys & workload_keys) if k in by_key]

    # Sort each bucket newest-first by last_seen_at so the demo lands on
    # something the operator just produced.
    for bucket in (loaded_only, installed_only, both):
        bucket.sort(key=lambda c: c.get("last_seen_at") or "", reverse=True)

    return {
        "hostname": hostname,
        "loaded_only": loaded_only,
        "installed_only": installed_only,
        "both": both,
        "summary": {
            "loaded_only": len(loaded_only),
            "installed_only": len(installed_only),
            "both": len(both),
        },
    }


# ── A-BOM vulnerability surface (phase 5 part 1) ──────────────────────


def _upsert_advisory(db: Session, row: Dict[str, Any], raw: Dict[str, Any]) -> Optional[ABOMVulnerability]:
    """Idempotent upsert keyed on ``vuln_id``. Returns the persisted
    row so the caller can use its fields when stamping the junction
    table."""
    vuln_id = str(row.get("vuln_id") or "")
    if not vuln_id:
        return None
    existing = db.query(ABOMVulnerability).filter(ABOMVulnerability.vuln_id == vuln_id).first()
    payload = {
        "vuln_id":      vuln_id,
        "aliases":      _encode_meta_for_db(row.get("aliases") or []),
        "summary":      row.get("summary") or "",
        "severity":     row.get("severity") or "unknown",
        "cvss_score":   row.get("cvss_score"),
        "cvss_vector":  row.get("cvss_vector"),
        "references_":  _encode_meta_for_db(row.get("references") or []),
        "ecosystem":    row.get("ecosystem") or "",
        "published_at": row.get("published_at"),
        "modified_at":  row.get("modified_at"),
        "raw":          _encode_meta_for_db(raw or {}),
    }
    # KEV overlay fields — only set when the caller provided them so an
    # OSV-only pass doesn't clobber prior KEV state. The vuln-scan
    # handler always passes them when running with threat intel enabled.
    for kev_key in ("is_kev", "kev_added_at", "kev_due_date", "kev_action", "kev_ransomware"):
        if kev_key in row:
            payload[kev_key] = row[kev_key]
    if existing is None:
        # Use kwargs-with-column-name (references_ → references on disk).
        existing = ABOMVulnerability(**payload)
        db.add(existing)
        db.flush()
    else:
        for k, v in payload.items():
            setattr(existing, k, v)
    return existing


def _upsert_component_vuln(
    db: Session,
    tenant_id: str,
    component: ABOMComponent,
    advisory: ABOMVulnerability,
    now: datetime,
) -> ABOMComponentVulnerability:
    """Idempotent junction-row upsert. Severity / cvss are denormalized
    so the Vulnerabilities filter can sort and chip without joining
    every query."""
    existing = (
        db.query(ABOMComponentVulnerability)
        .filter(
            ABOMComponentVulnerability.tenant_id == tenant_id,
            ABOMComponentVulnerability.component_id == component.id,
            ABOMComponentVulnerability.vuln_id == advisory.vuln_id,
        )
        .first()
    )
    if existing is None:
        existing = ABOMComponentVulnerability(
            tenant_id=tenant_id,
            component_id=component.id,
            identity_key=component.identity_key,
            vuln_id=advisory.vuln_id,
            severity=advisory.severity,
            cvss_score=advisory.cvss_score,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(existing)
    else:
        existing.last_seen_at = now
        # Severity may have been upgraded after a re-scan.
        existing.severity = advisory.severity
        existing.cvss_score = advisory.cvss_score
    return existing


@app.post("/customer/abom/vuln-scan")
def customer_abom_vuln_scan(
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Walk the tenant's components, query OSV per PURL in batches,
    upsert advisories + per-component findings. Runs inline; bounded
    by the OSV batch size + a max-purls cap so the handler latency
    stays predictable. Background scheduling layers on top later.
    """
    from vulnerability_scanner import (
        osv_batch_query, osv_fetch_vuln, shape_advisory_row,
    )
    from threat_intel import fetch_kev_catalog, fetch_epss_scores, collect_cve_ids

    purl_to_component: Dict[str, ABOMComponent] = {}
    rows = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == ctx.tenant_id)
        .all()
    )
    for r in rows:
        if r.purl and r.purl.startswith("pkg:"):
            # First-component-wins per PURL — duplicates would be a
            # bug elsewhere (identity_key collisions should already
            # have merged them).
            purl_to_component.setdefault(r.purl, r)

    purls = list(purl_to_component.keys())
    if not purls:
        return {
            "status": "ok",
            "components_scanned": 0,
            "findings": 0,
            "advisories_seen": 0,
            "note": "no components with a PURL — install collectors first",
        }

    now = datetime.now(timezone.utc)
    batch_results = osv_batch_query(purls)

    # Pull the KEV catalog once per scan — it's a small file that we
    # full-replace overlay. EPSS is queried lazily per CVE batch
    # after we know which advisories actually matched.
    kev_catalog = fetch_kev_catalog()

    # OSV's batch endpoint returns IDs + modified timestamps only; we
    # need to fetch the full advisory per id to extract severity /
    # references / etc. Cache by id so duplicate findings across
    # components don't hammer the API.
    advisory_cache: Dict[str, Optional[Dict[str, Any]]] = {}
    findings = 0
    seen_ids: set = set()
    kev_hits = 0
    # Collect CVE ids we'll EPSS-score later. We can't query EPSS for
    # every CVE in the world; only the ones that matched a tenant
    # component get scored.
    cves_to_score: set = set()
    advisory_to_cves: Dict[str, List[str]] = {}

    for purl, vuln_briefs in batch_results.items():
        component = purl_to_component.get(purl)
        if component is None:
            continue
        for brief in vuln_briefs:
            if not isinstance(brief, dict):
                continue
            vuln_id = str(brief.get("id") or "")
            if not vuln_id:
                continue
            seen_ids.add(vuln_id)
            advisory = advisory_cache.get(vuln_id)
            if vuln_id not in advisory_cache:
                advisory = osv_fetch_vuln(vuln_id)
                advisory_cache[vuln_id] = advisory
            if not advisory:
                continue
            shaped = shape_advisory_row(advisory, purl=purl)
            # Enrich with KEV before the upsert so the row carries
            # is_kev / kev_added_at on first insert.
            aliases = advisory.get("aliases") or []
            cve_ids = collect_cve_ids(vuln_id, aliases if isinstance(aliases, list) else [])
            for cve in cve_ids:
                cves_to_score.add(cve)
            advisory_to_cves[vuln_id] = cve_ids
            kev_entry = None
            for cve in cve_ids:
                if cve in kev_catalog:
                    kev_entry = kev_catalog[cve]
                    break
            if kev_entry:
                shaped["is_kev"] = True
                shaped["kev_added_at"] = kev_entry.get("kev_added_at")
                shaped["kev_due_date"] = kev_entry.get("kev_due_date")
                shaped["kev_action"] = kev_entry.get("kev_action") or ""
                shaped["kev_ransomware"] = kev_entry.get("kev_ransomware") or ""
                kev_hits += 1
            advisory_row = _upsert_advisory(db, shaped, advisory)
            if advisory_row is None:
                continue
            _upsert_component_vuln(db, ctx.tenant_id, component, advisory_row, now)
            findings += 1
    db.commit()

    # EPSS pass — query in batches for every CVE the scan turned up,
    # then patch the score onto the corresponding ABOMVulnerability
    # rows. Doing this after the upsert keeps the OSV path
    # uncoupled — an EPSS API hiccup leaves the rest of the scan intact.
    epss_scores = fetch_epss_scores(cves_to_score) if cves_to_score else {}
    epss_updates = 0
    if epss_scores:
        for vuln_id, cves in advisory_to_cves.items():
            # Highest score across this advisory's aliases wins.
            best = None
            for cve in cves:
                entry = epss_scores.get(cve)
                if not entry:
                    continue
                if best is None or (entry.get("epss_score") or 0) > (best.get("epss_score") or 0):
                    best = entry
            if not best:
                continue
            adv_row = db.query(ABOMVulnerability).filter(ABOMVulnerability.vuln_id == vuln_id).first()
            if adv_row is None:
                continue
            adv_row.epss_score = best.get("epss_score")
            adv_row.epss_percentile = best.get("epss_percentile")
            adv_row.epss_updated_at = best.get("epss_updated_at") or now
            epss_updates += 1
        db.commit()

    logger.info(
        "abom_vuln_scan tenant=%s purls=%d findings=%d advisories=%d kev=%d epss=%d",
        ctx.tenant_id, len(purls), findings, len(seen_ids), kev_hits, epss_updates,
    )
    return {
        "status": "ok",
        "scanned_at": now.isoformat(),
        "components_scanned": len(purls),
        "findings": findings,
        "advisories_seen": len(seen_ids),
        "kev_matches": kev_hits,
        "epss_scored": epss_updates,
    }


@app.get("/customer/abom/vulnerabilities")
def customer_abom_vulnerabilities(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    vex_status: Optional[str] = None,
    only_kev: bool = False,
) -> Dict[str, Any]:
    """Paginated list of advisories that hit at least one tenant
    component. Group-by ``vuln_id`` on the junction table; counts of
    affected components surface in each row so an operator can sort by
    blast radius. ``only_kev=true`` filters to CISA-listed exploited
    vulns — typically the operator's first triage stop."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    base = (
        db.query(ABOMComponentVulnerability)
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
    )
    if severity:
        base = base.filter(ABOMComponentVulnerability.severity == severity)
    # ``vex_status=open`` is the synthetic value that maps to "no VEX
    # decision yet" — the most common admin workflow filter. The
    # taxonomy values pass through unchanged.
    if vex_status:
        if vex_status == "open":
            base = base.filter(ABOMComponentVulnerability.vex_status.is_(None))
        else:
            base = base.filter(ABOMComponentVulnerability.vex_status == vex_status)

    # Group counts per advisory.
    grouped = (
        db.query(
            ABOMComponentVulnerability.vuln_id,
            ABOMComponentVulnerability.severity,
            func.count(ABOMComponentVulnerability.id).label("component_count"),
            func.max(ABOMComponentVulnerability.last_seen_at).label("last_seen_at"),
        )
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
    )
    if severity:
        grouped = grouped.filter(ABOMComponentVulnerability.severity == severity)
    if vex_status:
        if vex_status == "open":
            grouped = grouped.filter(ABOMComponentVulnerability.vex_status.is_(None))
        else:
            grouped = grouped.filter(ABOMComponentVulnerability.vex_status == vex_status)
    grouped = grouped.group_by(
        ABOMComponentVulnerability.vuln_id,
        ABOMComponentVulnerability.severity,
    ).order_by(desc("component_count"))

    rows = grouped.offset(offset).limit(limit).all()
    advisory_ids = [r.vuln_id for r in rows]
    advisories = {
        a.vuln_id: a
        for a in db.query(ABOMVulnerability).filter(ABOMVulnerability.vuln_id.in_(advisory_ids)).all()
    }
    items: List[Dict[str, Any]] = []
    for r in rows:
        advisory = advisories.get(r.vuln_id)
        if only_kev and not (advisory and advisory.is_kev):
            continue
        if q:
            haystack = f"{r.vuln_id} {advisory.summary if advisory else ''}".lower()
            if q.lower() not in haystack:
                continue
        items.append({
            "vuln_id": r.vuln_id,
            "severity": r.severity,
            "component_count": int(r.component_count or 0),
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            "summary": (advisory.summary if advisory else "") or "",
            "cvss_score": advisory.cvss_score if advisory else None,
            "aliases": _coerce_meta(advisory.aliases) if advisory and advisory.aliases else [],
            "ecosystem": advisory.ecosystem if advisory else "",
            "published_at": advisory.published_at.isoformat() if advisory and advisory.published_at else None,
            "is_kev": bool(advisory.is_kev) if advisory else False,
            "kev_due_date": advisory.kev_due_date.isoformat() if advisory and advisory.kev_due_date else None,
            "kev_ransomware": advisory.kev_ransomware if advisory else None,
            "epss_score": advisory.epss_score if advisory else None,
            "epss_percentile": advisory.epss_percentile if advisory else None,
        })

    # Severity tile counts — one query so the metric strip stays cheap.
    severity_counts = dict(
        db.query(
            ABOMComponentVulnerability.severity,
            func.count(ABOMComponentVulnerability.id),
        )
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
        .group_by(ABOMComponentVulnerability.severity)
        .all()
    )
    total = (
        db.query(func.count(func.distinct(ABOMComponentVulnerability.vuln_id)))
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
        .scalar() or 0
    )
    # VEX coverage rollup: each (component, vuln) pair counted once.
    # ``open`` is the no-VEX-yet bucket — the ones the operator still
    # owes a decision on, the demo-visible workflow signal.
    vex_counts_raw = dict(
        db.query(
            ABOMComponentVulnerability.vex_status,
            func.count(ABOMComponentVulnerability.id),
        )
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
        .group_by(ABOMComponentVulnerability.vex_status)
        .all()
    )
    vex_counts = {"open": 0}
    for k, v in vex_counts_raw.items():
        vex_counts[k or "open"] = int(v)

    # KEV roll-up: distinct advisories the tenant has that are in
    # the catalog. Single query, scoped to advisories that hit
    # at least one tenant component.
    kev_total = (
        db.query(func.count(func.distinct(ABOMComponentVulnerability.vuln_id)))
        .join(ABOMVulnerability, ABOMVulnerability.vuln_id == ABOMComponentVulnerability.vuln_id)
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
        .filter(ABOMVulnerability.is_kev.is_(True))
        .scalar() or 0
    )
    return {
        "advisories": items,
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "severity_counts": {k or "unknown": int(v) for k, v in severity_counts.items()},
        "vex_counts": vex_counts,
        "kev_total": int(kev_total),
    }


@app.get("/customer/abom/vulnerabilities/{vuln_id}")
def customer_abom_vulnerability_detail(
    vuln_id: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    advisory = db.query(ABOMVulnerability).filter(ABOMVulnerability.vuln_id == vuln_id).first()
    if advisory is None:
        raise HTTPException(status_code=404, detail="advisory not found")
    findings = (
        db.query(ABOMComponentVulnerability, ABOMComponent)
        .join(ABOMComponent, ABOMComponent.id == ABOMComponentVulnerability.component_id)
        .filter(
            ABOMComponentVulnerability.tenant_id == ctx.tenant_id,
            ABOMComponentVulnerability.vuln_id == vuln_id,
        )
        .order_by(desc(ABOMComponentVulnerability.last_seen_at))
        .limit(500)
        .all()
    )
    return {
        "vuln_id": advisory.vuln_id,
        "severity": advisory.severity,
        "cvss_score": advisory.cvss_score,
        "cvss_vector": advisory.cvss_vector,
        "summary": advisory.summary or "",
        "aliases": _coerce_meta(advisory.aliases) or [],
        "references": _coerce_meta(advisory.references_) or [],
        "ecosystem": advisory.ecosystem or "",
        "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
        "modified_at": advisory.modified_at.isoformat() if advisory.modified_at else None,
        "is_kev": bool(advisory.is_kev),
        "kev_added_at": advisory.kev_added_at.isoformat() if advisory.kev_added_at else None,
        "kev_due_date": advisory.kev_due_date.isoformat() if advisory.kev_due_date else None,
        "kev_action": advisory.kev_action or "",
        "kev_ransomware": advisory.kev_ransomware or "",
        "epss_score": advisory.epss_score,
        "epss_percentile": advisory.epss_percentile,
        "epss_updated_at": advisory.epss_updated_at.isoformat() if advisory.epss_updated_at else None,
        "components": [
            {
                "id": comp.id,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
                "type": comp.type,
                "manufacturer": comp.manufacturer,
                "first_seen_at": j.first_seen_at.isoformat() if j.first_seen_at else None,
                "last_seen_at": j.last_seen_at.isoformat() if j.last_seen_at else None,
                "vex_status": j.vex_status,
                "vex_justification": j.vex_justification,
                "vex_updated_by": j.vex_updated_by,
                "vex_updated_at": j.vex_updated_at.isoformat() if j.vex_updated_at else None,
            }
            for j, comp in findings
        ],
    }


# VEX status values follow the CycloneDX VEX taxonomy:
#   not_affected         — explicit "we're safe" with a justification
#   affected             — confirmed exposed (the default if no VEX set)
#   under_investigation  — admin triaging
#   fixed                — upgrade landed and the finding is no longer present
#   false_positive       — OSV match was incorrect (tells the scanner to
#                          suppress on future runs for this specific pair)
_VEX_STATUS_VALUES = {"not_affected", "affected", "under_investigation", "fixed", "false_positive"}

# CycloneDX VEX justification codes for ``not_affected`` findings.
# The portal renders these as the picklist when an admin picks
# "not_affected"; we accept any string but warn unknowns so a typo
# doesn't silently corrupt a compliance export.
_VEX_JUSTIFICATIONS = {
    "code_not_present", "code_not_reachable",
    "requires_configuration", "requires_dependency", "requires_environment",
    "protected_by_compiler", "protected_at_runtime",
    "protected_at_perimeter", "protected_by_mitigating_control",
}


class VEXUpdate(BaseModel):
    """Per-(component, vuln) VEX annotation. Status is required;
    justification is required when status=not_affected (per CycloneDX
    VEX rules) and optional otherwise. Response carries free-form
    operator notes for the auditor."""
    component_id: str
    vuln_id: str
    status: str
    justification: Optional[str] = None
    response: Optional[str] = None


@app.put("/customer/abom/vex")
def customer_abom_vex_put(
    payload: VEXUpdate,
    ctx: Annotated[CustomerContext, Depends(require_customer_role("tenant_admin"))],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Admin-only: annotate one (component, vuln) finding with VEX
    metadata. Validates status against the CycloneDX taxonomy; warns
    on non-standard justifications but accepts them so a customer can
    extend the picklist for internal taxonomy without us blocking the
    save."""
    status = payload.status.strip().lower()
    if status not in _VEX_STATUS_VALUES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(_VEX_STATUS_VALUES)}",
        )
    if status == "not_affected" and not (payload.justification and payload.justification.strip()):
        raise HTTPException(
            status_code=400,
            detail="justification is required when status=not_affected",
        )
    if payload.justification and payload.justification.strip() not in _VEX_JUSTIFICATIONS:
        # Non-fatal: log so an audit catches the deviation but don't
        # block the save. Some customers carry an internal taxonomy.
        logger.info(
            "vex non-standard justification tenant=%s component=%s vuln=%s justification=%s",
            ctx.tenant_id, payload.component_id, payload.vuln_id, payload.justification,
        )

    row = (
        db.query(ABOMComponentVulnerability)
        .filter(
            ABOMComponentVulnerability.tenant_id == ctx.tenant_id,
            ABOMComponentVulnerability.component_id == payload.component_id,
            ABOMComponentVulnerability.vuln_id == payload.vuln_id,
        )
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")

    row.vex_status = status
    # Free-form fields: justification picklist + operator response.
    # Both are stored as-is so the export carries the original text.
    row.vex_justification = (payload.justification or "").strip() or None
    # ``response`` is stored alongside justification using a sentinel
    # prefix so we don't need a new column. Pragmatic for the demo;
    # phase 6 can split into its own column if customers want.
    if payload.response and payload.response.strip():
        prefix = row.vex_justification or ""
        sep = " | " if prefix else ""
        row.vex_justification = f"{prefix}{sep}response: {payload.response.strip()}"
    row.vex_updated_by = ctx.email
    row.vex_updated_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "status": "ok",
        "component_id": row.component_id,
        "vuln_id": row.vuln_id,
        "vex_status": row.vex_status,
        "vex_justification": row.vex_justification,
        "vex_updated_by": row.vex_updated_by,
        "vex_updated_at": row.vex_updated_at.isoformat() if row.vex_updated_at else None,
    }


@app.get("/customer/abom/components/{component_id}/vulnerabilities")
def customer_abom_component_vulnerabilities(
    component_id: str,
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Used by the Components Inspector panel — every advisory that
    matched a single component, ordered worst-first."""
    rows = (
        db.query(ABOMComponentVulnerability, ABOMVulnerability)
        .join(ABOMVulnerability, ABOMVulnerability.vuln_id == ABOMComponentVulnerability.vuln_id)
        .filter(
            ABOMComponentVulnerability.tenant_id == ctx.tenant_id,
            ABOMComponentVulnerability.component_id == component_id,
        )
        .all()
    )
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    rows.sort(key=lambda pair: (rank.get((pair[0].severity or "unknown").lower(), 0),
                                 pair[0].cvss_score or 0), reverse=True)
    return {
        "vulnerabilities": [
            {
                "vuln_id": j.vuln_id,
                "severity": j.severity,
                "cvss_score": j.cvss_score,
                "vex_status": j.vex_status,
                "vex_justification": j.vex_justification,
                "vex_updated_by": j.vex_updated_by,
                "vex_updated_at": j.vex_updated_at.isoformat() if j.vex_updated_at else None,
                "summary": (adv.summary or "")[:240],
                "aliases": _coerce_meta(adv.aliases) or [],
                "published_at": adv.published_at.isoformat() if adv.published_at else None,
                "is_kev": bool(adv.is_kev),
                "kev_due_date": adv.kev_due_date.isoformat() if adv.kev_due_date else None,
                "epss_score": adv.epss_score,
                "epss_percentile": adv.epss_percentile,
            }
            for j, adv in rows
        ],
    }


@app.get("/customer/abom/risk-policy")
def customer_abom_risk_policy(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Evaluate tenant policies against the BOM's current vuln state.

    Returns a list of "policy verdicts" — for each enabled tenant
    policy with a vulnerability-aware condition, we surface the
    matched components, the worst severity, and the action the policy
    would take. The portal renders these as actionable banners on the
    BOM tab; downstream surfaces (block_upload DNR, repo-promotion
    gates) consume the same verdicts.

    Supported condition fields (any-of):
      - ``content.has_critical_vuln`` (bool)
      - ``content.has_high_or_critical_vuln`` (bool)
      - ``content.max_cvss_score`` (numeric; comparison ops via
        ``operator: gte`` / ``gt`` / ``equals``)

    All other policy condition fields fall through unchanged so the
    existing block / redact / warn evaluator is unaffected.
    """
    # Pull active VEX-aware findings per component. Anything VEX'd as
    # ``not_affected`` or ``fixed`` is excluded — that's the whole
    # point of VEX, and skipping it here means the operator can
    # silence false positives that policies would otherwise fire on.
    # Join the junction to ABOMVulnerability so we can roll up KEV +
    # EPSS facts per component without a second pass.
    findings = (
        db.query(ABOMComponentVulnerability, ABOMVulnerability)
        .join(ABOMVulnerability, ABOMVulnerability.vuln_id == ABOMComponentVulnerability.vuln_id)
        .filter(ABOMComponentVulnerability.tenant_id == ctx.tenant_id)
        .filter(
            (ABOMComponentVulnerability.vex_status.is_(None))
            | (ABOMComponentVulnerability.vex_status.notin_(["not_affected", "fixed"]))
        )
        .all()
    )
    by_component: Dict[str, Dict[str, Any]] = {}
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    for f, adv in findings:
        agg = by_component.setdefault(f.component_id, {
            "component_id": f.component_id,
            "vuln_count": 0,
            "max_severity": "unknown",
            "max_cvss_score": 0.0,
            "max_epss_score": 0.0,
            "is_kev": False,
            "kev_vuln_ids": [],
            "vuln_ids": [],
        })
        agg["vuln_count"] += 1
        agg["vuln_ids"].append(f.vuln_id)
        if rank.get((f.severity or "unknown").lower(), 0) > rank.get(agg["max_severity"], 0):
            agg["max_severity"] = (f.severity or "unknown").lower()
        if (f.cvss_score or 0) > agg["max_cvss_score"]:
            agg["max_cvss_score"] = float(f.cvss_score or 0)
        if adv and adv.is_kev:
            agg["is_kev"] = True
            agg["kev_vuln_ids"].append(f.vuln_id)
        if adv and (adv.epss_score or 0) > agg["max_epss_score"]:
            agg["max_epss_score"] = float(adv.epss_score or 0)

    # Annotate each affected component with its name/version so the
    # portal banner can render something useful without a second hop.
    component_ids = list(by_component.keys())
    if component_ids:
        comp_rows = (
            db.query(ABOMComponent)
            .filter(ABOMComponent.tenant_id == ctx.tenant_id)
            .filter(ABOMComponent.id.in_(component_ids))
            .all()
        )
        for r in comp_rows:
            agg = by_component.get(r.id)
            if not agg:
                continue
            agg["name"] = r.name
            agg["version"] = r.version
            agg["purl"] = r.purl
            agg["type"] = r.type

    # Pull tenant policies via the existing policy service proxy.
    try:
        policies = _fetch_policy_service(f"/policies/{ctx.tenant_id}", ctx.tenant_id)
    except Exception:  # noqa: BLE001 — degraded path returns no verdicts
        policies = []
    policy_list = policies if isinstance(policies, list) else []

    verdicts: List[Dict[str, Any]] = []
    summary = {
        "policies_evaluated": 0,
        "policies_matched": 0,
        "components_affected": len(by_component),
        "max_severity_seen": "unknown",
    }
    rank_summary = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    for c in by_component.values():
        if rank_summary.get(c["max_severity"], 0) > rank_summary.get(summary["max_severity_seen"], 0):
            summary["max_severity_seen"] = c["max_severity"]

    for policy in policy_list:
        if not isinstance(policy, dict) or policy.get("enabled") is False:
            continue
        conditions = policy.get("conditions") or {}
        if not _policy_has_vuln_condition(conditions):
            continue
        summary["policies_evaluated"] += 1
        matched_components: List[Dict[str, Any]] = []
        for c in by_component.values():
            if _eval_vuln_conditions(conditions, c):
                matched_components.append({
                    "component_id": c["component_id"],
                    "name": c.get("name") or "",
                    "version": c.get("version") or "",
                    "purl": c.get("purl") or "",
                    "max_severity": c["max_severity"],
                    "max_cvss_score": c["max_cvss_score"],
                    "max_epss_score": c.get("max_epss_score", 0.0),
                    "is_kev": c.get("is_kev", False),
                    "kev_vuln_ids": c.get("kev_vuln_ids", [])[:5],
                    "vuln_ids": c["vuln_ids"][:5],
                })
        if matched_components:
            summary["policies_matched"] += 1
            verdicts.append({
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name") or "",
                "action": policy.get("action") or "monitor",
                "redact_classes": policy.get("redact_classes") or [],
                "components": matched_components,
                "component_count": len(matched_components),
            })

    return {
        "summary": summary,
        "verdicts": verdicts,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def _policy_has_vuln_condition(conditions: Any) -> bool:
    """Return True when the policy references any vuln-aware field.
    Walks the conditions tree so nested groups still trigger."""
    if not isinstance(conditions, dict):
        return False
    for rule in conditions.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        if "rules" in rule:
            if _policy_has_vuln_condition(rule):
                return True
        field = str(rule.get("field") or "")
        if field in (
            "content.has_vuln",
            "content.has_critical_vuln",
            "content.has_high_or_critical_vuln",
            "content.max_cvss_score",
            "content.max_severity",
            "content.vuln_count",
            "content.is_kev",
            "content.max_epss_score",
        ):
            return True
    return False


def _eval_vuln_conditions(conditions: Any, component_vuln: Dict[str, Any]) -> bool:
    """Tiny evaluator scoped to the vuln-aware fields. Mirrors the
    extension's policy_engine for shape compatibility — operators
    can write the same conditions block once and have it run
    consistently in both places.
    """
    if not isinstance(conditions, dict):
        return True
    op = (conditions.get("operator") or "AND").upper()
    rules = conditions.get("rules") or []
    if not rules:
        return True
    results: List[bool] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if "rules" in rule:
            results.append(_eval_vuln_conditions(rule, component_vuln))
            continue
        field = str(rule.get("field") or "")
        expected = rule.get("value")
        operator = str(rule.get("operator") or "").lower()
        actual: Any
        if field == "content.has_vuln":
            actual = component_vuln.get("vuln_count", 0) > 0
        elif field == "content.has_critical_vuln":
            actual = component_vuln.get("max_severity") == "critical"
        elif field == "content.has_high_or_critical_vuln":
            actual = component_vuln.get("max_severity") in ("critical", "high")
        elif field == "content.max_cvss_score":
            actual = float(component_vuln.get("max_cvss_score", 0) or 0)
        elif field == "content.max_severity":
            actual = component_vuln.get("max_severity") or "unknown"
        elif field == "content.vuln_count":
            actual = int(component_vuln.get("vuln_count", 0))
        elif field == "content.is_kev":
            actual = bool(component_vuln.get("is_kev", False))
        elif field == "content.max_epss_score":
            actual = float(component_vuln.get("max_epss_score", 0) or 0)
        else:
            # Non-vuln field — neutral pass so a policy can mix
            # vuln rules with non-vuln rules without short-circuiting.
            results.append(True)
            continue
        # Op semantics: equals / not_equals / gt / gte / lt / lte / in.
        if operator == "equals":
            results.append(_loose_eq(actual, expected))
        elif operator == "not_equals":
            results.append(not _loose_eq(actual, expected))
        elif operator in ("gt", "gte", "lt", "lte"):
            try:
                a, e = float(actual), float(expected)
            except (TypeError, ValueError):
                results.append(False)
                continue
            if operator == "gt":  results.append(a > e)
            if operator == "gte": results.append(a >= e)
            if operator == "lt":  results.append(a < e)
            if operator == "lte": results.append(a <= e)
        elif operator == "in":
            try:
                results.append(actual in (expected or []))
            except TypeError:
                results.append(False)
        else:
            results.append(False)
    if not results:
        return True
    return any(results) if op == "OR" else all(results)


def _loose_eq(actual: Any, expected: Any) -> bool:
    """Same shape as the clipboard-helper evaluator — string-coerce
    booleans so a policy author can write
    ``content.has_vuln equals true`` without quoting."""
    if actual is None or expected is None:
        return actual == expected
    if isinstance(actual, bool) or isinstance(expected, bool):
        a = "true" if bool(actual) else "false"
        e = str(expected).strip().lower()
        return a == e
    return str(actual) == str(expected)


@app.get("/customer/abom/coverage")
def customer_abom_coverage(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Per-collector freshness summary. Surfaces silent-collector
    failures: if endpoint-agent hasn't reported in 24h, that's a problem.
    """
    rows = (
        db.query(
            ABOMObservation.collector,
            ABOMObservation.source_kind,
            func.count(ABOMObservation.id).label("count"),
            func.max(ABOMObservation.observed_at).label("latest"),
            func.min(ABOMObservation.observed_at).label("earliest"),
        )
        .filter(ABOMObservation.tenant_id == ctx.tenant_id)
        .group_by(ABOMObservation.collector, ABOMObservation.source_kind)
        .all()
    )
    out = []
    for r in rows:
        out.append({
            "collector": r.collector,
            "source_kind": r.source_kind,
            "observation_count": r.count,
            "first_seen_at": r.earliest.isoformat() if r.earliest else None,
            "last_seen_at": r.latest.isoformat() if r.latest else None,
        })
    out.sort(key=lambda x: x["last_seen_at"] or "", reverse=True)
    return {"collectors": out}


def _abom_signing_key(tenant_id: str) -> bytes:
    """Derive a tenant-scoped signing key. Prefer the explicit
    ``ABOM_SIGNING_KEY`` env var when set; otherwise mix the existing
    customer-session secret with the tenant_id so a tenant can verify
    their own exports without us shipping a new key-management surface.
    """
    explicit = os.environ.get("ABOM_SIGNING_KEY")
    if explicit:
        return hashlib.sha256((explicit + ":" + tenant_id).encode("utf-8")).digest()
    base = (CUSTOMER_SESSION_SECRET or "abom").encode("utf-8")
    return hmac.new(base, ("abom:" + tenant_id).encode("utf-8"), hashlib.sha256).digest()


def _abom_canonical_bytes(bom: Dict[str, Any]) -> bytes:
    """Stable byte representation of the BOM for signing. Sort keys so a
    reordered round-trip still verifies."""
    return json.dumps(bom, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# A-BOM signing via OpenBao Transit
# ---------------------------------------------------------------------------
#
# Phase 6 §9.1 — the original HMAC envelope was per-tenant-verifiable but
# rooted only in our own session secret; customer security teams want a
# signature anchored in something they can pin externally. OpenBao Transit
# gives us ed25519 sign/verify against a key that never leaves the vault.
# When OpenBao isn't reachable (dev, single-node demos) we fall back to
# the HMAC envelope and stamp ``key_provider`` so a consumer can tell
# which path produced the signature.

_ABOM_TRANSIT_KEY = os.getenv("ABOM_TRANSIT_KEY", "abom-export")
_ABOM_TRANSIT_HASH = "sha2-256"


def _ensure_abom_transit_key(client: OpenBaoClient) -> None:
    """Lazy-create the ed25519 signing key. Idempotent: a 400 from
    OpenBao on a name that already exists is swallowed so services can
    call this on every export without coordinating."""
    try:
        client.transit_key_read(_ABOM_TRANSIT_KEY)
        return
    except OpenBaoError:
        pass
    try:
        client.transit_key_create(_ABOM_TRANSIT_KEY, key_type="ed25519", exportable=False)
    except OpenBaoError as exc:
        # If the key was created concurrently, transit_key_read will now
        # succeed; re-check before giving up so we don't false-fail.
        try:
            client.transit_key_read(_ABOM_TRANSIT_KEY)
            return
        except OpenBaoError:
            raise exc


def _transit_sign_abom_bytes(canonical: bytes) -> Optional[Dict[str, Any]]:
    """Sign canonical BOM bytes with the tenant-wide Transit ed25519
    key. Returns the signature envelope or None if OpenBao isn't
    reachable / configured — caller is expected to fall back to HMAC.
    """
    client = _openbao_client_or_none()
    if client is None:
        return None
    try:
        _ensure_abom_transit_key(client)
        input_b64 = base64.b64encode(canonical).decode("ascii")
        result = client.transit_sign(_ABOM_TRANSIT_KEY, input_b64, hash_algorithm=_ABOM_TRANSIT_HASH)
    except OpenBaoError as exc:
        logger.warning("Transit sign failed for abom export, falling back to HMAC: %s", exc)
        return None
    signature = result.get("signature") or ""
    # Transit returns ``vault:v<n>:<base64-sig>``; pull the version out so
    # consumers can pin a key generation.
    key_version: Optional[int] = None
    if signature.startswith("vault:v"):
        try:
            key_version = int(signature.split(":", 2)[1][1:])
        except (ValueError, IndexError):
            key_version = None
    return {
        "alg": "ed25519",
        "key_name": _ABOM_TRANSIT_KEY,
        "key_id": f"{_ABOM_TRANSIT_KEY}:v{key_version}" if key_version is not None else _ABOM_TRANSIT_KEY,
        "key_version": key_version,
        "value": signature,
        "hash": _ABOM_TRANSIT_HASH,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "canonical_bytes_len": len(canonical),
        "key_provider": "openbao-transit",
    }


def _hmac_sign_abom_bytes(tenant_id: str, canonical: bytes) -> Dict[str, Any]:
    """Legacy HMAC-SHA256 envelope. Used as the dev-mode fallback when
    OpenBao isn't configured or returns an error."""
    key = _abom_signing_key(tenant_id)
    sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return {
        "alg": "HMAC-SHA256",
        "key_id": f"tenant:{tenant_id}:abom-v1",
        "value": sig,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "canonical_bytes_len": len(canonical),
        "key_provider": "hmac-fallback",
    }


@app.get("/customer/abom/signing-key")
def customer_abom_signing_key(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Dict[str, Any]:
    """Expose the Transit signing key metadata + public key so external
    consumers can verify an exported BOM offline. Falls back to a
    descriptor of the HMAC fallback when OpenBao isn't configured —
    HMAC has no public half, so the caller has to use the
    ``/abom/export/verify`` endpoint round-trip instead.
    """
    _ = ctx  # tenant context guards the route; the signing key itself is platform-wide
    client = _openbao_client_or_none()
    if client is None:
        return {
            "key_provider": "hmac-fallback",
            "alg": "HMAC-SHA256",
            "note": "OpenBao Transit not configured; verify via POST /customer/abom/export/verify",
        }
    try:
        _ensure_abom_transit_key(client)
        info = client.transit_key_read(_ABOM_TRANSIT_KEY)
    except OpenBaoError as exc:
        logger.warning("Transit key read failed: %s", exc)
        return {
            "key_provider": "hmac-fallback",
            "alg": "HMAC-SHA256",
            "error": str(exc),
        }
    keys = info.get("keys") or {}
    # ``keys`` is a dict {version: {creation_time, public_key, ...}}.
    versions: List[Dict[str, Any]] = []
    for ver, meta in sorted(keys.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 0):
        if isinstance(meta, dict):
            versions.append({
                "version": int(ver) if str(ver).isdigit() else ver,
                "public_key": meta.get("public_key"),
                "creation_time": meta.get("creation_time"),
            })
        else:
            versions.append({"version": ver, "public_key": str(meta)})
    return {
        "key_provider": "openbao-transit",
        "alg": "ed25519",
        "key_name": _ABOM_TRANSIT_KEY,
        "latest_version": info.get("latest_version"),
        "min_decryption_version": info.get("min_decryption_version"),
        "min_encryption_version": info.get("min_encryption_version"),
        "versions": versions,
    }


@app.post("/customer/abom/export/verify")
def customer_abom_export_verify(
    payload: Dict[str, Any],
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
) -> Dict[str, Any]:
    """Verify a previously-exported signed BOM envelope. Accepts the
    full ``{bom, signature}`` document the export endpoint returns and
    confirms the signature matches the canonical bytes of the embedded
    BOM. Transit and HMAC envelopes both supported.
    """
    bom = payload.get("bom")
    sig = payload.get("signature")
    if not isinstance(bom, dict) or not isinstance(sig, dict):
        raise HTTPException(status_code=400, detail="payload must be {bom, signature}")
    canonical = _abom_canonical_bytes(bom)
    alg = (sig.get("alg") or "").lower()
    provider = sig.get("key_provider") or ("openbao-transit" if alg == "ed25519" else "hmac-fallback")
    value = sig.get("value") or ""
    if provider == "openbao-transit" or alg == "ed25519":
        client = _openbao_client_or_none()
        if client is None:
            return {"valid": False, "reason": "OpenBao Transit not configured on this control-plane", "key_provider": provider}
        try:
            input_b64 = base64.b64encode(canonical).decode("ascii")
            key_name = sig.get("key_name") or _ABOM_TRANSIT_KEY
            hash_alg = sig.get("hash") or _ABOM_TRANSIT_HASH
            result = client.transit_verify(key_name, input_b64, value, hash_algorithm=hash_alg)
        except OpenBaoError as exc:
            return {"valid": False, "reason": str(exc), "key_provider": provider}
        return {
            "valid": bool(result.get("valid")),
            "key_provider": "openbao-transit",
            "alg": "ed25519",
            "key_id": sig.get("key_id"),
            "canonical_bytes_len": len(canonical),
        }
    # HMAC fallback path — recompute and constant-time compare.
    key = _abom_signing_key(ctx.tenant_id)
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, str(value))
    return {
        "valid": valid,
        "key_provider": "hmac-fallback",
        "alg": "HMAC-SHA256",
        "key_id": sig.get("key_id"),
        "canonical_bytes_len": len(canonical),
    }


@app.get("/customer/abom/export")
def customer_abom_export(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    db: Annotated[Session, Depends(get_db)],
    format: str = Query("cyclonedx", pattern="^(cyclonedx)$"),
    type: Optional[str] = None,
    sign: bool = False,
) -> Dict[str, Any]:
    """Generate a CycloneDX 1.6 document for the tenant. Streams every
    component (no pagination) — the export is meant to drop into evidence
    packs verbatim. Signing hook is reserved for a follow-up commit.
    """
    rows = (
        db.query(ABOMComponent)
        .filter(ABOMComponent.tenant_id == ctx.tenant_id)
        .order_by(ABOMComponent.type, ABOMComponent.name)
        .all()
    )
    if type:
        rows = [r for r in rows if r.type == type]
    components_out: List[Dict[str, Any]] = []
    for r in rows:
        c: Dict[str, Any] = {"type": r.type, "name": r.name}
        if r.version:      c["version"] = r.version
        if r.purl:         c["purl"] = r.purl
        if r.cpe:          c["cpe"] = r.cpe
        if r.manufacturer: c["manufacturer"] = {"name": r.manufacturer}
        licenses = _coerce_meta(r.licenses) or []
        if isinstance(licenses, list) and licenses:
            c["licenses"] = [{"license": {"id": str(l)}} for l in licenses]
        hashes = _coerce_meta(r.hashes) or {}
        if isinstance(hashes, dict) and hashes:
            c["hashes"] = [{"alg": k, "content": v} for k, v in hashes.items()]
        c["properties"] = [
            {"name": "cyberarmor:identity_key", "value": r.identity_key},
            {"name": "cyberarmor:observation_count", "value": str(r.observation_count or 0)},
            {"name": "cyberarmor:first_seen_at", "value": r.first_seen_at.isoformat() if r.first_seen_at else ""},
            {"name": "cyberarmor:last_seen_at", "value": r.last_seen_at.isoformat() if r.last_seen_at else ""},
        ]
        components_out.append(c)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "CyberArmor", "name": "abom-exporter", "version": "1.0"}],
            "component": {"type": "platform", "name": f"tenant:{ctx.tenant_id}"},
        },
        "components": components_out,
    }
    if not sign:
        return bom
    # Signed envelope: prefer OpenBao Transit ed25519 over the canonical
    # (sort_keys + compact) bytes of the BOM. Falls back to HMAC-SHA256
    # when OpenBao isn't reachable so dev / demo flows still work. The
    # envelope carries ``key_provider`` so a consumer can tell which path
    # produced it.
    canonical = _abom_canonical_bytes(bom)
    signature = _transit_sign_abom_bytes(canonical)
    if signature is None:
        signature = _hmac_sign_abom_bytes(ctx.tenant_id, canonical)
    return {"bom": bom, "signature": signature}


@app.post("/agents/{agent_id}/telemetry")
def agent_telemetry(
    agent_id: str,
    payload: Dict[str, Any],
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Accept a batch of telemetry events from an endpoint agent."""
    _dev_or_key_ok(x_api_key)
    events = payload.get("events", [])
    tenant_id = payload.get("tenant_id") or (_AGENTS.get(agent_id, {}).get("tenant_id", "unknown"))
    logger.info("agent_telemetry agent_id=%s tenant=%s events=%d", agent_id, tenant_id, len(events))
    if agent_id in _AGENTS:
        _AGENTS[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
    agent_rec = _AGENTS.get(agent_id, {})
    for event in events:
        if not isinstance(event, dict):
            continue
        raw_ts = event.get("timestamp") or event.get("occurred_at") or datetime.now(timezone.utc).isoformat()
        stored_event = {
            "tenant_id": event.get("tenant_id") or tenant_id,
            "agent_id": agent_id,
            "hostname": event.get("hostname") or agent_rec.get("hostname"),
            "user_id": event.get("user_id") or event.get("username"),
            "event_type": event.get("event_type") or "endpoint_event",
            "payload": event,
            "source": "endpoint",
            "occurred_at": raw_ts,
        }
        _store_telemetry_event(stored_event)
    return JSONResponse({"status": "accepted", "count": len(events)}, status_code=202)


@app.get("/agents")
def list_agents(
    tenant_id: Optional[str] = None,
    limit: int = 100,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """List registered endpoint agents, optionally filtered by tenant."""
    _dev_or_key_ok(x_api_key)
    agents_by_id: Dict[str, Dict[str, Any]] = {
        a.get("agent_id"): dict(a) for a in _AGENTS.values() if a.get("agent_id")
    }

    with SessionLocal() as db:
        telemetry_rows = (
            db.query(
                TelemetryRecord.agent_id,
                func.max(TelemetryRecord.occurred_at).label("last_seen"),
            )
            .filter(TelemetryRecord.source == "endpoint")
            .filter(TelemetryRecord.agent_id.isnot(None))
            .group_by(TelemetryRecord.agent_id)
            .all()
        )

        for row in telemetry_rows:
            agent_id = row.agent_id
            if not agent_id or agent_id in agents_by_id:
                continue
            latest = (
                db.query(TelemetryRecord)
                .filter(
                    TelemetryRecord.source == "endpoint",
                    TelemetryRecord.agent_id == agent_id,
                )
                .order_by(desc(TelemetryRecord.occurred_at), desc(TelemetryRecord.created_at))
                .first()
            )
            payload = _coerce_meta(latest.payload) or {} if latest else {}
            agents_by_id[agent_id] = {
                "agent_id": agent_id,
                "tenant_id": latest.tenant_id if latest else "unknown",
                "hostname": latest.hostname if latest and latest.hostname else payload.get("hostname", ""),
                "username": latest.user_id if latest and latest.user_id else payload.get("username", ""),
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                "status": "telemetry_only",
                "os": payload.get("os", ""),
                "version": payload.get("version", "") or payload.get("agent_version", ""),
            }

    agents = list(agents_by_id.values())
    if tenant_id:
        agents = [a for a in agents if a.get("tenant_id") == tenant_id]
    agents.sort(key=lambda a: a.get("last_seen", ""), reverse=True)
    return agents[:limit]


@app.get("/telemetry/{tenant_id}")
def list_telemetry_events(
    tenant_id: str,
    limit: int = 200,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    _dev_or_key_ok(x_api_key)
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000
    with SessionLocal() as db:
        q = db.query(TelemetryRecord).filter(TelemetryRecord.tenant_id == tenant_id)
        if source:
            q = q.filter(TelemetryRecord.source == source)
        if event_type:
            q = q.filter(TelemetryRecord.event_type == event_type)
        rows = q.order_by(desc(TelemetryRecord.occurred_at)).limit(limit).all()
        return [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "agent_id": r.agent_id,
                "hostname": r.hostname,
                "user_id": r.user_id,
                "event_type": r.event_type,
                "source": r.source,
                "payload": _coerce_meta(r.payload) or {},
                "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]


@app.get("/policies/{tenant_id}")
def proxy_policies_for_tenant(
    tenant_id: str,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Proxy policy lookup to the Policy Service for endpoint-agent policy sync.

    The endpoint agent is configured with a single control_plane_url and calls
    GET /policies/{tenant_id} to sync its local policy cache.  The actual
    policies are stored in the Policy Service (port 8001), so we proxy here.

    Returns 502 on upstream failure rather than swallowing errors as an empty
    list — silent success on failure caused agents to see "0 policies" while
    real policies existed in the database (see commit history for prior bug).
    Successful proxy calls log the policy count at INFO so operators can
    tell from one log line whether the chain is healthy end-to-end.
    """
    _dev_or_key_ok(x_api_key)
    policy_url = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
    policy_key = os.getenv("POLICY_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.get(
            f"{policy_url}/policies/{tenant_id}",
            headers=build_auth_headers(policy_url, policy_key),
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("policy_proxy_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="policy service unavailable")
    if resp.status_code != 200:
        logger.warning(
            "policy_proxy_upstream_error status=%s tenant=%s body=%s",
            resp.status_code, tenant_id, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"policy service returned {resp.status_code}")
    try:
        data = resp.json()
    except Exception as exc:
        logger.warning("policy_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="policy service returned invalid JSON")
    count = len(data) if isinstance(data, list) else "?"
    logger.info("policy_proxy_ok tenant=%s count=%s", tenant_id, count)
    return data


@app.get("/policies/{tenant_id}/export")
def proxy_policies_export_for_tenant(
    tenant_id: str,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """Proxy the agent-shaped policy export to the Policy Service.

    The browser extension and endpoint agents call /policies/{tenant_id}/export
    to receive the sanitized, evaluation-ready shape (id, name, enabled, action,
    priority, conditions, rules, compliance_frameworks, tags, version) defined
    by the policy service. Returns 502 on upstream failure for parity with the
    sibling proxy above.
    """
    _dev_or_key_ok(x_api_key)
    policy_url = os.getenv("POLICY_SERVICE_URL", "http://policy:8001")
    policy_key = os.getenv("POLICY_API_SECRET", DEFAULT_API_KEY)
    try:
        resp = httpx.get(
            f"{policy_url}/policies/{tenant_id}/export",
            headers=build_auth_headers(policy_url, policy_key),
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("policy_export_proxy_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="policy service unavailable")
    if resp.status_code != 200:
        logger.warning(
            "policy_export_proxy_upstream_error status=%s tenant=%s body=%s",
            resp.status_code, tenant_id, resp.text[:200],
        )
        raise HTTPException(status_code=502, detail=f"policy service returned {resp.status_code}")
    try:
        data = resp.json()
    except Exception as exc:
        logger.warning("policy_export_proxy_decode_error tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(status_code=502, detail="policy service returned invalid JSON")
    count = len(data) if isinstance(data, list) else "?"
    logger.info("policy_export_proxy_ok tenant=%s count=%s", tenant_id, count)
    return data


class IncidentIngest(BaseModel):
    tenant_id: str
    request_id: str
    event_type: str = "runtime_decision"
    decision: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence_snapshot: Optional[Dict[str, Any]] = None
    ts: Optional[float] = None


class IntegrationOnboardRequest(BaseModel):
    provider: str
    tenant_id: str
    config: Dict[str, Any] = Field(default_factory=dict)
    include_events: bool = True
    enforce_policy: bool = True
    fail_on_warn: bool = False


def _integration_headers() -> Dict[str, str]:
    return build_auth_headers(INTEGRATION_CONTROL_URL, INTEGRATION_CONTROL_API_KEY)


def _integration_configure_path(provider: str) -> str:
    p = provider.strip().lower()
    mapping = {
        "microsoft365": "/integrations/providers/microsoft365/configure",
        "google_workspace": "/integrations/providers/google-workspace/configure",
        "salesforce": "/integrations/providers/salesforce/configure",
        "agentic_ai": "/integrations/providers/agentic-ai/configure",
    }
    if p not in mapping:
        raise HTTPException(status_code=400, detail=f"Unsupported integration provider: {provider}")
    return mapping[p]


def _dev_or_key_ok(x_api_key: Optional[str]) -> None:
    """Allow dev-mode unauth; otherwise accept the default key or any active API key."""
    if (not x_api_key) and (not DEFAULT_API_KEY or DEFAULT_API_KEY == "change-me"):
        return
    resolved = resolve_api_key_header(x_api_key, service_name="control-plane")
    if DEFAULT_API_KEY and resolved.plaintext_key == DEFAULT_API_KEY:
        return
    with SessionLocal() as db:
        record = db.query(ApiKey).filter(ApiKey.key == resolved.plaintext_key, ApiKey.active.is_(True)).first()
        if record:
            return
    raise HTTPException(status_code=401, detail="Invalid API key")


@app.post("/incidents/ingest")
def ingest_incident(payload: IncidentIngest, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    """Ingest a request-scoped incident.

    This is intentionally lightweight and demo-friendly: it enables exact
    request_id lookups without needing full SIEM storage.
    """
    _dev_or_key_ok(x_api_key)
    tenant_map = _INCIDENTS.setdefault(payload.tenant_id, {})
    incident = payload.model_dump()
    incident.setdefault("received_at", datetime.now(timezone.utc).isoformat())
    tenant_map[payload.request_id] = incident
    return {"status": "stored", "tenant_id": payload.tenant_id, "request_id": payload.request_id}


@app.get("/incidents/{tenant_id}")
def list_incidents(
    tenant_id: str,
    limit: int = 100,
    x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None,
):
    """List all incidents for a tenant, newest first."""
    _dev_or_key_ok(x_api_key)
    tenant_incidents = _INCIDENTS.get(tenant_id, {})
    items = sorted(
        tenant_incidents.values(),
        key=lambda x: x.get("received_at", ""),
        reverse=True,
    )
    return items[:limit]


@app.get("/incidents/{tenant_id}/{request_id}")
def get_incident(tenant_id: str, request_id: str, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    _dev_or_key_ok(x_api_key)
    inc = _INCIDENTS.get(tenant_id, {}).get(request_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.get("/viewer/{tenant_id}/{request_id}")
def incident_viewer(tenant_id: str, request_id: str, x_api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    """Sales-friendly incident viewer page.

    This renders a single HTML page that shows:
    - The request-scoped incident stored in control-plane
    - The compliance evidence snapshot for the same request_id
    - The compliance report for the same request_id

    It avoids CORS hassles by fetching evidence/report server-side.
    """
    _dev_or_key_ok(x_api_key)
    inc = _INCIDENTS.get(tenant_id, {}).get(request_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = None
    report = None
    ev_err = None
    rep_err = None
    try:
        with httpx.Client(timeout=3.0) as client:
            ev = client.get(f"{COMPLIANCE_URL}/evidence/{tenant_id}/{request_id}")
            if ev.status_code == 200:
                evidence = ev.json()
            else:
                ev_err = f"evidence status={ev.status_code}"
            rp = client.get(f"{COMPLIANCE_URL}/assess/{tenant_id}/{request_id}/report")
            if rp.status_code == 200:
                report = rp.json()
            else:
                rep_err = f"report status={rp.status_code}"
    except Exception as exc:
        ev_err = ev_err or f"evidence fetch error: {exc}"
        rep_err = rep_err or f"report fetch error: {exc}"

    def _pre(obj: Any) -> str:
        return htmlmod.escape(json.dumps(obj, indent=2, sort_keys=True))

    incident_json = _pre(inc)
    evidence_json = _pre(evidence) if evidence is not None else htmlmod.escape(ev_err or "No evidence available")
    report_json = _pre(report) if report is not None else htmlmod.escape(rep_err or "No report available")

    html = f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>Incident Viewer — {tenant_id} / {request_id}</title>
    <style>
      body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 32px; color:#111; }}
      .grid {{ display:grid; grid-template-columns: 1fr; gap: 18px; max-width: 1100px; }}
      .card {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 18px; box-shadow: 0 2px 14px rgba(0,0,0,0.06); }}
      .muted {{ color:#6b7280; }}
      pre {{ overflow:auto; background:#0b1020; color:#e5e7eb; padding: 14px; border-radius: 12px; font-size: 12px; line-height: 1.4; }}
      code {{ background:#f3f4f6; padding:2px 6px; border-radius: 6px; }}
      a {{ color:#111; }}
      .links a {{ margin-right: 12px; }}
    </style>
  </head>
  <body>
    <h1>Incident Viewer</h1>
    <p class=\"muted\">Tenant: <code>{tenant_id}</code> &nbsp; Request ID: <code>{request_id}</code></p>
    <div class=\"links\">
      <a href=\"/incidents/{tenant_id}/{request_id}\" target=\"_blank\">Incident JSON</a>
      <a href=\"{COMPLIANCE_URL}/evidence/{tenant_id}/{request_id}\" target=\"_blank\">Evidence JSON</a>
      <a href=\"{COMPLIANCE_URL}/assess/{tenant_id}/{request_id}/report\" target=\"_blank\">Compliance report JSON</a>
    </div>
    <div class=\"grid\" style=\"margin-top:18px\">
      <div class=\"card\">
        <h2>Incident</h2>
        <pre>{incident_json}</pre>
      </div>
      <div class=\"card\">
        <h2>Evidence snapshot</h2>
        <pre>{evidence_json}</pre>
      </div>
      <div class=\"card\">
        <h2>Compliance report</h2>
        <pre>{report_json}</pre>
      </div>
    </div>
  </body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get("/authz/check")
def authz_check(ctx: Annotated[AuthContext, Depends(get_auth_context)]):
    return {"principal": ctx.principal, "role": ctx.role, "tenant": ctx.tenant_id, "exp": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}


@app.post("/integrations/onboard")
def onboard_integration(
    payload: IntegrationOnboardRequest,
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
):
    if ctx.tenant_id and ctx.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")

    provider = payload.provider.strip().lower()
    configure_path = _integration_configure_path(provider)
    configure_body = {"tenant_id": payload.tenant_id, **payload.config}
    discovery_body = {"provider": provider, "tenant_id": payload.tenant_id, "include_events": payload.include_events}
    policy_body = {"tenant_id": payload.tenant_id, "provider": provider}

    try:
        with httpx.Client(timeout=12.0) as client:
            cfg_resp = client.post(
                f"{INTEGRATION_CONTROL_URL}{configure_path}",
                json=configure_body,
                headers=_integration_headers(),
            )
            if cfg_resp.status_code >= 300:
                raise HTTPException(
                    status_code=502,
                    detail=f"Integration configure failed provider={provider} status={cfg_resp.status_code}",
                )
            configure_result = cfg_resp.json()

            disc_resp = client.post(
                f"{INTEGRATION_CONTROL_URL}/integrations/discovery/run",
                json=discovery_body,
                headers=_integration_headers(),
            )
            if disc_resp.status_code >= 300:
                raise HTTPException(
                    status_code=502,
                    detail=f"Integration discovery failed provider={provider} status={disc_resp.status_code}",
                )
            discovery_result = disc_resp.json()

            policy_result = None
            if payload.enforce_policy:
                pol_resp = client.post(
                    f"{INTEGRATION_CONTROL_URL}/integrations/policy/evaluate",
                    json=policy_body,
                    headers=_integration_headers(),
                )
                if pol_resp.status_code >= 300:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Integration policy evaluate failed provider={provider} status={pol_resp.status_code}",
                    )
                policy_result = pol_resp.json()
            else:
                policy_result = {"action": "allow", "reason": "policy_enforcement_disabled", "violations": []}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Integration-control communication failed: {exc}")

    action = str((policy_result or {}).get("action", "allow")).lower()
    if action == "block":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Integration onboarding blocked by policy.",
                "provider": provider,
                "tenant_id": payload.tenant_id,
                "policy": policy_result,
                "discovery_counts": discovery_result.get("counts", {}),
            },
        )
    if action == "warn" and payload.fail_on_warn:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Integration onboarding warning treated as failure.",
                "provider": provider,
                "tenant_id": payload.tenant_id,
                "policy": policy_result,
                "discovery_counts": discovery_result.get("counts", {}),
            },
        )

    return {
        "status": "enabled",
        "provider": provider,
        "tenant_id": payload.tenant_id,
        "configure": configure_result,
        "discovery": {"counts": discovery_result.get("counts", {}), "findings": discovery_result.get("findings", [])},
        "policy": policy_result,
    }


@app.get("/audit", response_model=List[AuditLogOut])
def list_audit_logs(
    ctx: Annotated[AuthContext, Depends(require_role("admin"))],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
    tenant_id: Optional[str] = None,
    before: Optional[datetime] = None,
):
    """Return recent API-call audit log entries.

    - limit: number of rows (max 500)
    - tenant_id: optional filter (ignored if caller is already tenant-scoped)
    - before: optional cursor (created_at < before)

    The admin dashboard uses this endpoint to populate the Audit Logs table.
    """
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    effective_tenant = ctx.tenant_id or tenant_id
    if ctx.tenant_id and tenant_id and tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant scope mismatch")

    q = db.query(AuditLog)
    if effective_tenant:
        q = q.filter(AuditLog.tenant_id == effective_tenant)
    if before:
        q = q.filter(AuditLog.created_at < before)

    rows = q.order_by(AuditLog.created_at.desc()).limit(limit).all()
    # Normalize meta across DB backends.
    for r in rows:
        r.meta = _coerce_meta(r.meta)
    return rows


@app.options("/telemetry/ingest")
def options_ingest():
    return JSONResponse({"status": "ok"}, status_code=200)
