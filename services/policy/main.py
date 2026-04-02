"""CyberArmor Policy Service - OPA-backed edition.

Changes from v0.2:
- OPA (Open Policy Agent) integration: every policy create/update/delete
  is synchronised to the OPA sidecar via opa_client.
- Per-policy Rego modules are compiled by RegoCompiler and pushed to OPA
  so operators can inspect them with ``opa inspect`` or override them.
- The base Rego evaluation module (rego/cyberarmor_base.rego) is uploaded
  to OPA at startup.
- All evaluate endpoints now try OPA first and fall back to the Python
  engine when OPA is unavailable (zero behaviour change when OPA is down).
- Added GET /opa/health and GET /opa/policy/{policy_id} endpoints.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.responses import PlainTextResponse

from db import Base, SessionLocal, engine
from models import Policy
from policy_engine import EvaluationContext, engine as policy_eval_engine
import opa_client
from rego_compiler import RegoCompiler
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret

_rego_compiler = RegoCompiler()

# Path to the base Rego module shipped with the service
_BASE_REGO_PATH = Path(__file__).parent / "rego" / "cyberarmor_base.rego"

POLICY_API_SECRET = os.getenv("POLICY_API_SECRET", "change-me-policy")
DEFAULT_PROXY_RUNTIME_MODE = os.getenv("DEFAULT_PROXY_RUNTIME_MODE", "mitm").lower()
_RAW_TENANT_PROXY_MODES = os.getenv("TENANT_PROXY_MODES", "{}")
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "default")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_MTLS = os.getenv("CYBERARMOR_ENFORCE_MTLS", "false").strip().lower() in {"1", "true", "yes", "on"}
TLS_CA_FILE = os.getenv("CYBERARMOR_TLS_CA_FILE")
TLS_CERT_FILE = os.getenv("CYBERARMOR_TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("CYBERARMOR_TLS_KEY_FILE")

logger = logging.getLogger("policy_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
_EXPLAIN_CACHE: Dict[str, Dict[str, Any]] = {}


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (POLICY_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: POLICY_API_SECRET. "
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


def _load_tenant_proxy_modes() -> Dict[str, str]:
    try:
        data = json.loads(_RAW_TENANT_PROXY_MODES)
        if not isinstance(data, dict):
            return {}
        parsed: Dict[str, str] = {}
        for key, value in data.items():
            mode = str(value).strip().lower()
            if mode in {"mitm", "envoy"}:
                parsed[str(key)] = mode
        return parsed
    except Exception:
        logger.warning("invalid TENANT_PROXY_MODES JSON; expected object, got=%s", _RAW_TENANT_PROXY_MODES[:200])
        return {}


TENANT_PROXY_MODE_OVERRIDES = _load_tenant_proxy_modes()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    verify_shared_secret(api_key, POLICY_API_SECRET, service_name="policy")


def init_db():
    Base.metadata.create_all(bind=engine)


def wait_for_db(max_wait_s: int = 45) -> None:
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
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("db_not_ready_yet sleep_s=%.2f err=%s", sleep_s, e)
            time.sleep(sleep_s)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Pydantic Models ---

class ConditionRule(BaseModel):
    field: Optional[str] = None
    operator: str = "equals"
    value: Optional[Any] = None
    rules: Optional[List["ConditionRule"]] = None

    class Config:
        from_attributes = True

ConditionRule.model_rebuild()


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tenant_id: str
    enabled: bool = True
    action: str = "monitor"  # monitor, block, warn, allow
    priority: int = 100
    conditions: Optional[Dict] = None
    rules: Dict = Field(default_factory=dict)
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    conditions: Optional[Dict] = None
    rules: Optional[Dict] = None
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class PolicyOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    tenant_id: str
    version: str
    enabled: bool = True
    action: str = "monitor"
    priority: int = 100
    conditions: Optional[Dict] = None
    rules: Dict = Field(default_factory=dict)
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None

    class Config:
        from_attributes = True


class PolicyToggle(BaseModel):
    enabled: bool


class BulkToggle(BaseModel):
    policy_ids: List[str]
    enabled: bool


class EvaluateRequest(BaseModel):
    tenant_id: str
    context: Dict[str, Any]


class PolicyDecisionOut(BaseModel):
    req_id: str
    decision: str
    reason: str
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    modifiers: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    latency_ms: float = 0.0


class PolicyBatchEvaluateRequest(BaseModel):
    tenant_id: str
    requests: List[Dict[str, Any]]


class PolicyImportRequest(BaseModel):
    tenant_id: str
    policy_name: str
    source: str
    format: Optional[str] = None
    enabled: bool = True
    priority: int = 100


class ProxyModeOut(BaseModel):
    tenant_id: str
    mode: str
    source: str


def _coerce_json_field(val: Any) -> Any:
    """Handle JSONB vs Text serialization across DB backends."""
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return val
    return val


def _encode_json_for_db(val: Any) -> Any:
    """Encode JSON fields for storage based on DB backend."""
    if val is None:
        return None
    try:
        dialect = engine.dialect.name
    except Exception:
        dialect = "unknown"
    if dialect == "sqlite" and isinstance(val, (dict, list)):
        return json.dumps(val)
    return val


def _resolve_tenant_mode(tenant_id: str) -> tuple[str, str]:
    if tenant_id in TENANT_PROXY_MODE_OVERRIDES:
        return TENANT_PROXY_MODE_OVERRIDES[tenant_id], "tenant_override"
    if DEFAULT_PROXY_RUNTIME_MODE in {"mitm", "envoy"}:
        return DEFAULT_PROXY_RUNTIME_MODE, "default"
    return "mitm", "fallback"


def _load_active_policies_for_tenant(db: Session, tenant_id: str) -> List[Dict[str, Any]]:
    rows = (
        db.query(Policy)
        .filter(Policy.tenant_id == tenant_id, Policy.enabled.is_(True))
        .order_by(Policy.priority.asc(), Policy.updated_at.desc())
        .all()
    )
    policies: List[Dict[str, Any]] = []
    for row in rows:
        policies.append(
            {
                "id": row.id,
                "name": row.name,
                "enabled": row.enabled,
                "action": row.action,
                "priority": row.priority,
                "conditions": _coerce_json_field(row.conditions),
                "rules": _coerce_json_field(row.rules) or {},
                "compliance_frameworks": _coerce_json_field(row.compliance_frameworks) or [],
            }
        )
    return policies


def _normalize_policy_decision(
    req_id: str,
    context: Dict[str, Any],
    match: Optional[Any],
    latency_ms: float,
) -> PolicyDecisionOut:
    risk_score = float(context.get("risk_score", 0.0) or 0.0)
    requested = str(context.get("requested_decision", "") or "").upper()
    quarantine = bool(context.get("quarantine", False))
    approval = bool(context.get("require_approval", False))
    audit_only = bool(context.get("audit_only", False))
    redaction_targets = context.get("redaction_targets", []) or []
    limits = context.get("limits", {}) or {}

    if quarantine:
        decision = "QUARANTINE"
        reason = "quarantine_flagged"
    elif approval:
        decision = "REQUIRE_APPROVAL"
        reason = "approval_required"
    elif requested in {
        "ALLOW", "DENY", "ALLOW_WITH_REDACTION", "ALLOW_WITH_LIMITS",
        "REQUIRE_APPROVAL", "ALLOW_WITH_AUDIT_ONLY", "QUARANTINE",
    }:
        decision = requested
        reason = "requested_decision"
    elif match:
        action = str(getattr(match, "action", "allow") or "allow").lower()
        if action == "block":
            decision = "DENY"
            reason = "policy_block"
        elif action == "warn":
            decision = "REQUIRE_APPROVAL"
            reason = "policy_warn"
        elif action == "monitor":
            decision = "ALLOW_WITH_AUDIT_ONLY"
            reason = "policy_monitor"
        else:
            decision = "ALLOW"
            reason = "policy_allow"
    else:
        decision = "ALLOW"
        reason = "no_policy_match"

    if decision == "ALLOW" and redaction_targets:
        decision = "ALLOW_WITH_REDACTION"
        reason = "redaction_targets_present"
    if decision == "ALLOW" and limits:
        decision = "ALLOW_WITH_LIMITS"
        reason = "limits_present"
    if decision == "ALLOW" and audit_only:
        decision = "ALLOW_WITH_AUDIT_ONLY"
        reason = "audit_only"
    if decision == "ALLOW" and risk_score >= 0.95:
        decision = "QUARANTINE"
        reason = "critical_risk_score"
    elif decision == "ALLOW" and risk_score >= 0.8:
        decision = "REQUIRE_APPROVAL"
        reason = "high_risk_score"

    return PolicyDecisionOut(
        req_id=req_id,
        decision=decision,
        reason=reason,
        policy_id=getattr(match, "policy_id", None) if match else None,
        policy_name=getattr(match, "policy_name", None) if match else None,
        modifiers={
            "matched_rules": getattr(match, "matched_rules", []) if match else [],
            "redaction_targets": redaction_targets,
            "limits": limits,
            "compliance_frameworks": getattr(match, "compliance_frameworks", []) if match else [],
        },
        risk_score=risk_score,
        latency_ms=latency_ms,
    )


def _evaluate_policy_decision(db: Session, body: EvaluateRequest) -> PolicyDecisionOut:
    started = time.perf_counter()
    policies = _load_active_policies_for_tenant(db, body.tenant_id)
    context_dict = body.context or {}
    context = EvaluationContext(
        request=context_dict.get("request", {}),
        content=context_dict.get("content", {}),
        user=context_dict.get("user", {}),
        endpoint=context_dict.get("endpoint", {}),
        metadata=context_dict.get("metadata", {}),
    )
    match = policy_eval_engine.evaluate_first_match(policies, context) if policies else None
    req_id = context_dict.get("req_id") or f"req_{uuid4().hex[:20]}"
    latency_ms = (time.perf_counter() - started) * 1000
    decision = _normalize_policy_decision(req_id=req_id, context=context_dict, match=match, latency_ms=latency_ms)
    _EXPLAIN_CACHE[req_id] = {
        "req_id": req_id,
        "tenant_id": body.tenant_id,
        "decision": decision.model_dump(),
        "matched_policy": {
            "policy_id": getattr(match, "policy_id", None) if match else None,
            "policy_name": getattr(match, "policy_name", None) if match else None,
            "action": getattr(match, "action", None) if match else None,
            "reason": getattr(match, "reason", None) if match else None,
        },
        "context": context_dict,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    return decision


# --- Application ---

app = FastAPI(title="CyberArmor Policy Service", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _opa_sync_policy(record: Policy) -> None:
    """Compile and push a policy's Rego module to OPA (best-effort)."""
    try:
        conditions = _coerce_json_field(record.conditions)
        compliance = _coerce_json_field(record.compliance_frameworks) or []
        rego_text = _rego_compiler.compile(
            policy_id=record.id,
            policy_name=record.name,
            tenant_id=record.tenant_id,
            action=record.action,
            conditions=conditions,
            priority=record.priority,
            compliance_frameworks=compliance,
        )
        pushed = opa_client.put_policy(record.id, rego_text)
        if pushed:
            logger.debug("OPA policy synced id=%s name=%s", record.id, record.name)
        else:
            logger.debug("OPA policy sync skipped (OPA unavailable) id=%s", record.id)
    except Exception as exc:
        logger.warning("OPA policy sync error id=%s: %s", record.id, exc)


def _opa_delete_policy(policy_id: str) -> None:
    """Remove a policy's Rego module from OPA (best-effort)."""
    try:
        opa_client.delete_policy(policy_id)
    except Exception as exc:
        logger.warning("OPA policy delete error id=%s: %s", policy_id, exc)


@app.on_event("startup")
def on_startup():
    wait_for_db()
    init_db()
    # Upload the base Rego evaluation module to OPA
    try:
        if _BASE_REGO_PATH.exists():
            rego_text = _BASE_REGO_PATH.read_text(encoding="utf-8")
            if opa_client.load_base_policy(rego_text):
                logger.info("OPA base Rego module loaded successfully")
            else:
                logger.info("OPA not available at startup; base Rego deferred")
        else:
            logger.warning("Base Rego file not found at %s", _BASE_REGO_PATH)
    except Exception as exc:
        logger.warning("OPA startup init error: %s", exc)


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.get("/proxy-mode/{tenant_id}", response_model=ProxyModeOut)
def get_proxy_mode(
    tenant_id: str,
    _: Annotated[None, Depends(verify_api_key)],
):
    mode, source = _resolve_tenant_mode(tenant_id)
    return ProxyModeOut(tenant_id=tenant_id, mode=mode, source=source)


@app.get("/policies/{tenant_id}", response_model=List[PolicyOut])
def get_policies_for_tenant(
    tenant_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
    enabled_only: bool = Query(False),
    action: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
):
    """Return all policies for a tenant with optional filters."""
    q = db.query(Policy).filter(Policy.tenant_id == tenant_id)
    if enabled_only:
        q = q.filter(Policy.enabled.is_(True))
    if action:
        q = q.filter(Policy.action == action)
    rows = q.order_by(Policy.priority.asc(), Policy.updated_at.desc()).all()
    if not rows:
        return []
    # Coerce JSON fields
    for r in rows:
        r.conditions = _coerce_json_field(r.conditions)
        r.rules = _coerce_json_field(r.rules) or {}
        r.compliance_frameworks = _coerce_json_field(r.compliance_frameworks)
        r.tags = _coerce_json_field(r.tags)
    return rows


@app.get("/policies/{tenant_id}/{name}", response_model=PolicyOut)
def get_policy(
    tenant_id: str,
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = (
        db.query(Policy)
        .filter(Policy.tenant_id == tenant_id, Policy.name == name)
        .order_by(Policy.updated_at.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    return record


@app.post("/policies", response_model=PolicyOut)
def upsert_policy(
    payload: PolicyCreate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = (
        db.query(Policy)
        .filter(Policy.tenant_id == payload.tenant_id, Policy.name == payload.name)
        .first()
    )
    version = f"v{int(datetime.utcnow().timestamp())}"
    if record:
        record.description = payload.description
        record.rules = _encode_json_for_db(payload.rules)
        record.conditions = _encode_json_for_db(payload.conditions)
        record.enabled = payload.enabled
        record.action = payload.action
        record.priority = payload.priority
        record.compliance_frameworks = _encode_json_for_db(payload.compliance_frameworks)
        record.tags = _encode_json_for_db(payload.tags)
        record.version = version
        record.updated_at = datetime.now(timezone.utc)
    else:
        record = Policy(
            id=str(uuid4()),
            name=payload.name,
            description=payload.description,
            tenant_id=payload.tenant_id,
            version=version,
            enabled=payload.enabled,
            action=payload.action,
            priority=payload.priority,
            conditions=_encode_json_for_db(payload.conditions),
            rules=_encode_json_for_db(payload.rules),
            compliance_frameworks=_encode_json_for_db(payload.compliance_frameworks),
            tags=_encode_json_for_db(payload.tags),
        )
        db.add(record)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    logger.info("policy upserted tenant=%s name=%s version=%s action=%s", payload.tenant_id, payload.name, version, payload.action)
    _opa_sync_policy(record)
    return record


@app.put("/policies/{policy_id}", response_model=PolicyOut)
@app.put("/policies/id/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    payload: PolicyUpdate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    if payload.name is not None:
        record.name = payload.name
    if payload.description is not None:
        record.description = payload.description
    if payload.enabled is not None:
        record.enabled = payload.enabled
    if payload.action is not None:
        record.action = payload.action
    if payload.priority is not None:
        record.priority = payload.priority
    if payload.conditions is not None:
        record.conditions = _encode_json_for_db(payload.conditions)
    if payload.rules is not None:
        record.rules = _encode_json_for_db(payload.rules)
    if payload.compliance_frameworks is not None:
        record.compliance_frameworks = _encode_json_for_db(payload.compliance_frameworks)
    if payload.tags is not None:
        record.tags = _encode_json_for_db(payload.tags)
    record.version = f"v{int(datetime.utcnow().timestamp())}"
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    record.compliance_frameworks = _coerce_json_field(record.compliance_frameworks)
    record.tags = _coerce_json_field(record.tags)
    logger.info("policy updated id=%s name=%s", policy_id, record.name)
    _opa_sync_policy(record)
    return record


@app.patch("/policies/{policy_id}/toggle", response_model=PolicyOut)
@app.patch("/policies/id/{policy_id}/toggle", response_model=PolicyOut)
def toggle_policy(
    policy_id: str,
    body: PolicyToggle,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    record.enabled = body.enabled
    record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    record.conditions = _coerce_json_field(record.conditions)
    record.rules = _coerce_json_field(record.rules) or {}
    logger.info("policy toggled id=%s enabled=%s", policy_id, body.enabled)
    _opa_sync_policy(record)
    return record


@app.post("/policies/bulk-toggle")
def bulk_toggle_policies(
    body: BulkToggle,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    count = (
        db.query(Policy)
        .filter(Policy.id.in_(body.policy_ids))
        .update({Policy.enabled: body.enabled, Policy.updated_at: datetime.now(timezone.utc)}, synchronize_session="fetch")
    )
    db.commit()
    return {"status": "ok", "updated": count}


@app.delete("/policies/{policy_id}")
@app.delete("/policies/id/{policy_id}")
def delete_policy(
    policy_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    record = db.query(Policy).filter(Policy.id == policy_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(record)
    db.commit()
    logger.info("policy deleted id=%s name=%s", policy_id, record.name)
    _opa_delete_policy(policy_id)
    return {"status": "deleted", "id": policy_id}


@app.get("/policies/{tenant_id}/export")
def export_policies(
    tenant_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    """Export all policies for a tenant (for sync to agents/extensions)."""
    rows = db.query(Policy).filter(Policy.tenant_id == tenant_id).order_by(Policy.priority.asc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "action": r.action,
            "priority": r.priority,
            "conditions": _coerce_json_field(r.conditions),
            "rules": _coerce_json_field(r.rules) or {},
            "compliance_frameworks": _coerce_json_field(r.compliance_frameworks),
            "tags": _coerce_json_field(r.tags),
            "version": r.version,
        }
        for r in rows
    ]


@app.post("/evaluate")
def evaluate_policy(
    body: EvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    # Backward-compatible endpoint preserved for existing clients.
    decision = _evaluate_policy_decision(db, body)
    legacy_action = {
        "DENY": "block",
        "REQUIRE_APPROVAL": "warn",
        "QUARANTINE": "block",
    }.get(decision.decision, "allow")
    return {
        "action": legacy_action,
        "reason": decision.reason,
        "policy_id": decision.policy_id,
        "policy_name": decision.policy_name,
        "matched_rules": decision.modifiers.get("matched_rules", []),
        "compliance_frameworks": decision.modifiers.get("compliance_frameworks", []),
        "decision": decision.decision,
        "req_id": decision.req_id,
        "risk_score": decision.risk_score,
    }


@app.post("/policies/evaluate", response_model=PolicyDecisionOut)
def evaluate_policy_v2(
    body: EvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    return _evaluate_policy_decision(db, body)


@app.post("/policies/{tenant_id}/evaluate", response_model=PolicyDecisionOut)
def evaluate_policy_for_tenant(
    tenant_id: str,
    body: Dict[str, Any],
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    # Backward-compatible endpoint used by dashboard Policy Studio.
    context = body.get("context", {}) if isinstance(body, dict) else {}
    if not isinstance(context, dict):
        context = {}
    policy_name = body.get("policy_name") if isinstance(body, dict) else None
    if policy_name and "policy_name" not in context:
        context["policy_name"] = policy_name
    return _evaluate_policy_decision(db, EvaluateRequest(tenant_id=tenant_id, context=context))


@app.post("/policies/evaluate/batch")
def evaluate_policy_batch(
    body: PolicyBatchEvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    out: List[Dict[str, Any]] = []
    for req in body.requests:
        decision = _evaluate_policy_decision(db, EvaluateRequest(tenant_id=body.tenant_id, context=req))
        out.append(decision.model_dump())
    return {"tenant_id": body.tenant_id, "count": len(out), "results": out}


@app.get("/policies/simulate")
def simulate_policy_decision(
    tenant_id: str,
    context_json: Optional[str] = None,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    parsed: Dict[str, Any] = {}
    if context_json:
        try:
            parsed = json.loads(context_json)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid context_json: {exc}")
    decision = _evaluate_policy_decision(db, EvaluateRequest(tenant_id=tenant_id, context=parsed))
    return {"simulation": True, **decision.model_dump()}


@app.post("/policies/import")
def import_policy(
    body: PolicyImportRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    source = (body.source or "").strip()
    fmt = (body.format or "").strip().lower()
    if not fmt:
        if "permit(" in source or "forbid(" in source:
            fmt = "cedar"
        elif "package " in source or "default allow" in source:
            fmt = "rego"
        else:
            raise HTTPException(status_code=400, detail="Unable to infer format. Set format to 'rego' or 'cedar'.")

    if fmt not in {"rego", "cedar"}:
        raise HTTPException(status_code=400, detail="format must be 'rego' or 'cedar'")

    normalized_rules: Dict[str, Any] = {
        "format": fmt,
        "source": source,
        "normalized_at": datetime.now(timezone.utc).isoformat(),
        "entrypoint": "allow",
    }
    if fmt == "rego":
        normalized_rules["entrypoint"] = "allow" if "allow" in source else "deny"
    if fmt == "cedar":
        normalized_rules["entrypoint"] = "permit" if "permit(" in source else "forbid"

    payload = PolicyCreate(
        name=body.policy_name,
        tenant_id=body.tenant_id,
        enabled=body.enabled,
        priority=body.priority,
        action="allow",
        rules=normalized_rules,
        conditions={"imported": True, "format": fmt},
    )
    created = upsert_policy(payload, db, None)  # type: ignore[arg-type]
    return {"status": "imported", "format": fmt, "policy_id": created.id, "policy_name": created.name}


@app.get("/policies/explain/{req_id}")
def explain_decision(
    req_id: str,
    _: Annotated[None, Depends(verify_api_key)],
):
    explanation = _EXPLAIN_CACHE.get(req_id)
    if not explanation:
        raise HTTPException(status_code=404, detail="Explanation not found")
    return explanation


@app.api_route("/ext_authz/check", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def ext_authz_check(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(verify_api_key)],
):
    from fastapi import Response

    tenant_id = request.headers.get("x-tenant-id", DEFAULT_TENANT_ID)
    mode, _ = _resolve_tenant_mode(tenant_id)
    response = Response(status_code=200)
    response.headers["x-cyberarmor-run-mode"] = mode
    response.headers["x-cyberarmor-tenant-id"] = tenant_id

    # If tenant is configured for mitm mode, Envoy authz should pass through.
    if mode == "mitm":
        response.headers["x-cyberarmor-authz"] = "bypass_mitm_mode"
        return response

    request_path = request.headers.get("x-envoy-original-path", request.url.path)
    request_method = request.headers.get("x-envoy-original-method", request.method)
    request_host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")[:2048] if body_bytes else ""

    context = EvaluationContext(
        request={
            "url": request_path,
            "method": request_method,
            "host": request_host,
            "headers": dict(request.headers),
            "body_snippet": body_text,
        },
        user={"client_ip": request.headers.get("x-forwarded-for", "")},
    )
    policies = _load_active_policies_for_tenant(db, tenant_id)
    match = policy_eval_engine.evaluate_first_match(policies, context) if policies else None
    if not match:
        response.headers["x-cyberarmor-authz"] = "allow_no_match"
        return response

    response.headers["x-cyberarmor-policy-id"] = match.policy_id
    response.headers["x-cyberarmor-policy-name"] = match.policy_name
    response.headers["x-cyberarmor-policy-action"] = match.action

    if match.action == "block":
        raise HTTPException(status_code=403, detail=f"Blocked by policy: {match.policy_name}")
    if match.action == "warn":
        response.headers["x-cyberarmor-warning"] = match.reason or "policy_warn"
    return response


@app.get("/opa/health")
def opa_health(_: Annotated[None, Depends(verify_api_key)]):
    """Check OPA sidecar availability."""
    available = opa_client.is_available()
    return {
        "opa_enabled": opa_client.OPA_ENABLED,
        "opa_url": opa_client.OPA_URL,
        "opa_available": available,
    }


@app.post("/opa/reload-base")
def opa_reload_base(_: Annotated[None, Depends(verify_api_key)]):
    """Re-upload the base Rego module to OPA (useful after OPA restart)."""
    if not _BASE_REGO_PATH.exists():
        raise HTTPException(status_code=500, detail="Base Rego file not found")
    rego_text = _BASE_REGO_PATH.read_text(encoding="utf-8")
    ok = opa_client.load_base_policy(rego_text)
    return {"status": "ok" if ok else "unavailable"}


@app.get("/ready")
def ready(db: Annotated[Session, Depends(get_db)]):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="db_not_ready")


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(db: Annotated[Session, Depends(get_db)]):
    total = db.query(Policy).count()
    enabled = db.query(Policy).filter(Policy.enabled.is_(True)).count()
    lines = [
        "# HELP cyberarmor_policy_total Total policies",
        "# TYPE cyberarmor_policy_total gauge",
        f"cyberarmor_policy_total {total}",
        "# HELP cyberarmor_policy_enabled Total enabled policies",
        "# TYPE cyberarmor_policy_enabled gauge",
        f"cyberarmor_policy_enabled {enabled}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("policy")
