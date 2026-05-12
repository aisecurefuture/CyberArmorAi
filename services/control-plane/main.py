import json
import logging
import os
import html as htmlmod
import hashlib
import hmac
import io
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
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from db import Base, SessionLocal, engine
from models import (
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


def init_db():
    Base.metadata.create_all(bind=engine)
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
    _issue_customer_session(response, db, user)
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
    telemetry_rows = (
        db.query(
            TelemetryRecord.agent_id,
            func.max(TelemetryRecord.occurred_at).label("last_seen"),
        )
        .filter(TelemetryRecord.tenant_id == tenant_id)
        .filter(TelemetryRecord.source == "endpoint")
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


@app.get("/customer/incidents")
def customer_incidents(
    ctx: Annotated[CustomerContext, Depends(get_customer_context)],
    limit: int = 100,
) -> List[Dict[str, Any]]:
    incidents = sorted(
        _INCIDENTS.get(ctx.tenant_id, {}).values(),
        key=lambda x: x.get("received_at", ""),
        reverse=True,
    )
    return incidents[: max(1, min(limit, 500))]


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


@app.get("/customer/providers")
def customer_providers(ctx: Annotated[CustomerContext, Depends(get_customer_context)]) -> Any:
    return _fetch_ai_router("/ai/providers", ctx.tenant_id)


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
    stored_event = {
        "tenant_id": event.tenant_id,
        "user_id": event.user_id,
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
