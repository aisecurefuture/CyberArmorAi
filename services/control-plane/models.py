from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint
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
    # Per-user TOTP MFA. See libs/cyberarmor-core/cyberarmor_core/crypto/totp.py.
    # All nullable so existing rows survive the ALTER TABLE migration in init_db().
    totp_secret_enc = Column(String, nullable=True)
    totp_pending_enc = Column(String, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    backup_codes_hash = Column(Text, nullable=True)  # JSON list of sha256 hashes


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


class BootstrapToken(Base):
    __tablename__ = "bootstrap_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    token_hash = Column(String, nullable=False, unique=True, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    package_key = Column(String, nullable=False, index=True)
    issued_to = Column(String, nullable=True)
    note = Column(String, nullable=True)
    status = Column(String, nullable=False, default="issued")
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class BootstrapInstall(Base):
    __tablename__ = "bootstrap_installs"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    bootstrap_token_id = Column(String, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    package_key = Column(String, nullable=False, index=True)
    subject_type = Column(String, nullable=False, index=True)
    subject_id = Column(String, nullable=False, index=True)
    issued_api_key_hash = Column(String, nullable=False, unique=True, index=True)
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


class ABOMComponent(Base):
    """Tenant-scoped rolled-up component row. Collisions on identity_key
    merge observations; one row per logical component per tenant.

    identity_key is the sha256 of an ordered tuple — see
    docs/architecture/a-bom-design.md §3.1 — so distinct collectors that
    report the same library / device land on the same row.
    """
    __tablename__ = "abom_components"
    __table_args__ = (UniqueConstraint("tenant_id", "identity_key", name="uq_abom_components_tenant_identity"),)

    id            = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id     = Column(String, nullable=False, index=True)
    identity_key  = Column(String, nullable=False, index=True)
    type          = Column(String, nullable=False, index=True)   # CycloneDX component.type
    name          = Column(String, nullable=False, index=True)
    version       = Column(String, nullable=True)
    purl          = Column(String, nullable=True, index=True)
    cpe           = Column(String, nullable=True, index=True)
    manufacturer  = Column(String, nullable=True)
    licenses      = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)  # list[str]
    hashes        = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)  # {alg: digest}
    properties    = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)  # CycloneDX properties
    observation_count = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    last_seen_at  = Column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)


class ABOMVulnerability(Base):
    """Vulnerability advisory pulled from OSV (which aggregates GHSA,
    PyPA, RustSec, OSS-Fuzz, etc.). Tenant-agnostic — one row per
    CVE/GHSA ID; the per-tenant impact lives on
    ABOMComponentVulnerability.

    Identity is the canonical advisory id (CVE-… or GHSA-…). Aliases
    are stored so a portal lookup by either form hits the same row.

    Threat-intel fields (``is_kev``, ``kev_*``, ``epss_score``,
    ``epss_percentile``) overlay CISA's Known Exploited Vulnerabilities
    catalog and FIRST.org's Exploit Prediction Scoring System on top
    of the raw advisory. They're refreshed by the threat_intel module
    on a daily cadence and inform the vuln-aware policy evaluator.
    """
    __tablename__ = "abom_vulnerabilities"

    id            = Column(String, primary_key=True, default=lambda: str(uuid4()))
    vuln_id       = Column(String, nullable=False, unique=True, index=True)
    aliases       = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)  # list[str]
    summary       = Column(Text, nullable=True)
    severity      = Column(String, nullable=True, index=True)   # critical | high | medium | low | unknown
    cvss_score    = Column(Float, nullable=True)
    cvss_vector   = Column(String, nullable=True)
    references_   = Column("references", JSONB().with_variant(Text, "sqlite"), nullable=True)
    ecosystem     = Column(String, nullable=True, index=True)
    published_at  = Column(DateTime(timezone=True), nullable=True)
    modified_at   = Column(DateTime(timezone=True), nullable=True)
    raw           = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    # KEV — CISA Known Exploited Vulnerabilities catalog.
    is_kev          = Column(Boolean, nullable=False, default=False, index=True)
    kev_added_at    = Column(DateTime(timezone=True), nullable=True)
    kev_due_date    = Column(DateTime(timezone=True), nullable=True)
    kev_action      = Column(Text, nullable=True)
    kev_ransomware  = Column(String, nullable=True)  # "Known" | "Unknown" per CISA
    # EPSS — FIRST.org Exploit Prediction Scoring System.
    epss_score      = Column(Float, nullable=True, index=True)
    epss_percentile = Column(Float, nullable=True)
    epss_updated_at = Column(DateTime(timezone=True), nullable=True)
    created_at      = Column(DateTime(timezone=True), default=now_utc)


class ABOMComponentVulnerability(Base):
    """Per-tenant junction between a component and an advisory.

    VEX fields (status / justification / updated_by) let an admin
    annotate a particular finding as "not_affected" / "under_investigation"
    / "fixed" with a reason. Stays nullable until VEX management lands
    in phase 5 part 2.
    """
    __tablename__ = "abom_component_vulnerabilities"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "component_id", "vuln_id",
            name="uq_abom_comp_vuln_tenant_component_vuln",
        ),
    )

    id                = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id         = Column(String, nullable=False, index=True)
    component_id      = Column(String, nullable=False, index=True)
    identity_key      = Column(String, nullable=False, index=True)  # denormalized for fast filter
    vuln_id           = Column(String, nullable=False, index=True)
    severity          = Column(String, nullable=True, index=True)
    cvss_score        = Column(Float, nullable=True)
    first_seen_at     = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    last_seen_at      = Column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)
    # VEX surface (phase 5 part 2 will write to these via the portal).
    vex_status        = Column(String, nullable=True, index=True)   # not_affected | affected | under_investigation | fixed
    vex_justification = Column(Text, nullable=True)
    vex_updated_by    = Column(String, nullable=True)
    vex_updated_at    = Column(DateTime(timezone=True), nullable=True)


class ABOMObservation(Base):
    """Append-only history of who saw what when. One row per collector
    sighting; rolls up to ABOMComponent via identity_key. Keep the raw
    payload so we can replay if the rollup logic changes."""
    __tablename__ = "abom_observations"

    id                = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id         = Column(String, nullable=False, index=True)
    component_id      = Column(String, nullable=False, index=True)
    identity_key      = Column(String, nullable=False, index=True)
    collector         = Column(String, nullable=False, index=True)   # endpoint-agent | rasp | ide | github | cloud-aws | …
    collector_version = Column(String, nullable=True)
    source_kind       = Column(String, nullable=False, index=True)   # agent | repo | container | cloud_resource | ide_workspace
    source_id         = Column(String, nullable=False, index=True)   # agent_id | repo_id | cloud_arn | …
    hostname          = Column(String, nullable=True, index=True)
    path              = Column(String, nullable=True)
    raw_properties    = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    observed_at       = Column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)
    created_at        = Column(DateTime(timezone=True), default=now_utc)
