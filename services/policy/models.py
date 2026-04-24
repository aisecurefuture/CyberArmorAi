"""Enhanced Policy models with AND/OR conditions, action modes, and enable/disable."""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB

from db import Base


def now_utc():
    return datetime.now(timezone.utc)


# Valid artifact kinds. "regex" and "keyword_list" are evaluated as patterns;
# everything else is treated as a membership list.
ARTIFACT_KINDS = {
    "user_list",
    "email_list",
    "group_list",
    "domain_list",
    "host_list",
    "ip_list",
    "cidr_list",
    "keyword_list",
    "regex",
}


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    tenant_id = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    action = Column(String, default="monitor", nullable=False)  # monitor, block, warn, allow
    scope = Column(String, default="general", nullable=False, index=True)  # general, proxy, ...
    priority = Column(Integer, default=100, nullable=False)
    conditions = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    rules = Column(JSONB().with_variant(Text, "sqlite"), nullable=False)
    compliance_frameworks = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    tags = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    created_by = Column(String, nullable=True)


class Artifact(Base):
    """Tenant-scoped reusable lists and regex patterns.

    Referenced from policy rules via the value ``$artifact:<name>``. The
    policy engine resolves the reference at evaluation time and applies the
    artifact's contents to the rule's operator (``in``, ``regex``, etc.).
    """

    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_artifact_tenant_name"),)

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    kind = Column(String, nullable=False, index=True)  # one of ARTIFACT_KINDS
    items = Column(JSONB().with_variant(Text, "sqlite"), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    version = Column(String, nullable=False)
    tags = Column(JSONB().with_variant(Text, "sqlite"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    created_by = Column(String, nullable=True)
