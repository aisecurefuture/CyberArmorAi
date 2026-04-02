"""CyberArmor Secrets Service.

Thin CyberArmor control layer in front of OpenBao.
This first scaffold focuses on:
- service health/readiness
- OpenBao status visibility
- tenant/provider credential storage
- transit crypto wrappers
"""

from __future__ import annotations

import base64
import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret
from cyberarmor_core.openbao import OpenBaoClient, OpenBaoConfig, OpenBaoError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("secrets_service")

SECRETS_SERVICE_API_SECRET = os.getenv("SECRETS_SERVICE_API_SECRET", "change-me-secrets-service")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
OPENBAO_ADDR = os.getenv("OPENBAO_ADDR", "http://openbao:8200")
OPENBAO_TOKEN = os.getenv("OPENBAO_TOKEN", "")
OPENBAO_NAMESPACE = os.getenv("OPENBAO_NAMESPACE")
OPENBAO_KV_MOUNT = os.getenv("OPENBAO_KV_MOUNT", "cyberarmor-kv")
OPENBAO_TRANSIT_MOUNT = os.getenv("OPENBAO_TRANSIT_MOUNT", "cyberarmor-transit")
OPENBAO_TIMEOUT_SECONDS = float(os.getenv("OPENBAO_TIMEOUT_SECONDS", "5"))
SERVICE_STARTED_AT = datetime.now(timezone.utc)
SERVICE_VERSION = "0.1.0"


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return

    def _bad(value: Optional[str]) -> bool:
        if not value:
            return True
        lowered = value.strip().lower()
        return lowered.startswith("change-me") or "changeme" in lowered

    failing = []
    if _bad(SECRETS_SERVICE_API_SECRET):
        failing.append("SECRETS_SERVICE_API_SECRET")
    if not OPENBAO_TOKEN:
        failing.append("OPENBAO_TOKEN")
    if failing:
        raise RuntimeError(
            "Refusing startup with insecure defaults or missing OpenBao config. "
            f"Fix: {', '.join(failing)}"
        )


_enforce_secure_secrets()


def _tenant_provider_path(tenant_id: str, provider: str) -> str:
    return f"tenants/{tenant_id}/integrations/{provider}"


def _service_url(service_name: str) -> str:
    prefix = "".join(ch if ch.isalnum() else "_" for ch in service_name.upper())
    env_name = f"{prefix}_URL"
    value = os.getenv(env_name)
    if value:
        return value
    defaults = {
        "control-plane": "http://control-plane:8000",
        "policy": "http://policy:8001",
        "detection": "http://detection:8002",
        "response": "http://response:8003",
        "identity": "http://identity:8004",
        "siem-connector": "http://siem-connector:8005",
        "compliance": "http://compliance:8006",
        "agent-identity": "http://agent-identity:8008",
        "ai-router": "http://ai-router:8009",
        "proxy-agent": "http://proxy-agent:8010",
        "audit": "http://audit:8011",
        "integration-control": "http://integration-control:8012",
        "secrets-service": "http://secrets-service:8013",
    }
    return defaults.get(service_name, f"http://{service_name}:8000")


def _initialize_pqc_state(service_name: str) -> None:
    service_url = _service_url(service_name).rstrip("/")
    try:
        response = httpx.get(f"{service_url}/pki/public-key", timeout=5.0)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to initialize PQC state for {service_name}: {exc}")
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to initialize PQC state for {service_name}: service returned {response.status_code}",
        )


def _store_provider_credentials(tenant_id: str, provider: str, body: ProviderCredentialWrite) -> Dict[str, Any]:
    path = _tenant_provider_path(tenant_id, provider)
    payload = {
        "api_key": body.api_key,
        "base_url": body.base_url or "",
        "region": body.region or "",
        "org_id": body.org_id or "",
        "deployment_name": body.deployment_name or "",
        "metadata": body.metadata,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = _client().kv_write(path, payload)
    return {
        "status": "stored",
        "tenant_id": tenant_id,
        "provider": provider,
        "path": path,
        "openbao": result,
    }


def _client() -> OpenBaoClient:
    return OpenBaoClient(
        OpenBaoConfig(
            addr=OPENBAO_ADDR,
            token=OPENBAO_TOKEN,
            namespace=OPENBAO_NAMESPACE,
            kv_mount=OPENBAO_KV_MOUNT,
            transit_mount=OPENBAO_TRANSIT_MOUNT,
            timeout_seconds=OPENBAO_TIMEOUT_SECONDS,
        )
    )


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    verify_shared_secret(api_key, SECRETS_SERVICE_API_SECRET, service_name="secrets-service")


class ProviderCredentialWrite(BaseModel):
    api_key: str
    base_url: Optional[str] = None
    region: Optional[str] = None
    org_id: Optional[str] = None
    deployment_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProviderCredentialMetadata(BaseModel):
    tenant_id: str
    provider: str
    path: str
    current_version: Optional[int] = None
    created_time: Optional[str] = None
    updated_time: Optional[str] = None
    custom_metadata: Dict[str, str] = Field(default_factory=dict)


class ProviderCredentialSecret(BaseModel):
    tenant_id: str
    provider: str
    path: str
    api_key: str
    base_url: Optional[str] = None
    region: Optional[str] = None
    org_id: Optional[str] = None
    deployment_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    updated_at: Optional[str] = None


class PQCKeyStatePayload(BaseModel):
    service_name: str
    state: Dict[str, Any]


class TransitEncryptRequest(BaseModel):
    key_name: str
    plaintext: str
    context: Optional[str] = None
    key_version: Optional[int] = None


class TransitDecryptRequest(BaseModel):
    key_name: str
    ciphertext: str
    context: Optional[str] = None


class TransitSignRequest(BaseModel):
    key_name: str
    input: str
    hash_algorithm: str = "sha2-256"
    key_version: Optional[int] = None


app = FastAPI(title="CyberArmor Secrets Service", version=SERVICE_VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "secrets-service",
        "version": SERVICE_VERSION,
    }


@app.get("/ready")
def ready() -> Dict[str, Any]:
    try:
        seal = _client().seal_status()
        return {
            "status": "ready",
            "service": "secrets-service",
            "version": SERVICE_VERSION,
            "openbao_initialized": seal.get("initialized"),
            "openbao_sealed": seal.get("sealed"),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
    except OpenBaoError as exc:
        raise HTTPException(status_code=503, detail=f"OpenBao not ready: {exc}")


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    uptime = round((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds(), 3)
    return PlainTextResponse(
        "\n".join([
            "# HELP cyberarmor_secrets_service_uptime_seconds Service uptime in seconds",
            "# TYPE cyberarmor_secrets_service_uptime_seconds gauge",
            f"cyberarmor_secrets_service_uptime_seconds{{service=\"secrets-service\",version=\"{SERVICE_VERSION}\"}} {uptime}",
        ]) + "\n",
        media_type="text/plain",
    )


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("secrets-service")


@app.get("/v1/meta/openbao/status")
def openbao_status(_: Annotated[None, Depends(verify_api_key)]):
    try:
        client = _client()
        return {
            "health": client.health(),
            "seal_status": client.seal_status(),
            "kv_mount": OPENBAO_KV_MOUNT,
            "transit_mount": OPENBAO_TRANSIT_MOUNT,
        }
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/secrets/tenant/{tenant_id}/provider-credentials/{provider}")
def write_provider_credentials(
    tenant_id: str,
    provider: str,
    body: ProviderCredentialWrite,
    _: Annotated[None, Depends(verify_api_key)],
):
    try:
        return _store_provider_credentials(tenant_id, provider, body)
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/v1/secrets/tenant/{tenant_id}/provider-credentials/{provider}/metadata", response_model=ProviderCredentialMetadata)
def read_provider_credentials_metadata(
    tenant_id: str,
    provider: str,
    _: Annotated[None, Depends(verify_api_key)],
):
    path = _tenant_provider_path(tenant_id, provider)
    try:
        meta = _client().kv_metadata(path)
        return ProviderCredentialMetadata(
            tenant_id=tenant_id,
            provider=provider,
            path=path,
            current_version=meta.get("current_version"),
            created_time=meta.get("created_time"),
            updated_time=meta.get("updated_time"),
            custom_metadata=meta.get("custom_metadata") or {},
        )
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/v1/secrets/tenant/{tenant_id}/provider-credentials/{provider}", response_model=ProviderCredentialSecret)
def read_provider_credentials_secret(
    tenant_id: str,
    provider: str,
    _: Annotated[None, Depends(verify_api_key)],
):
    path = _tenant_provider_path(tenant_id, provider)
    try:
        secret = _client().kv_read_secret(path)
        if not secret:
            raise HTTPException(status_code=404, detail=f"No secret found at {path}")
        return ProviderCredentialSecret(
            tenant_id=tenant_id,
            provider=provider,
            path=path,
            api_key=secret.get("api_key", ""),
            base_url=secret.get("base_url") or None,
            region=secret.get("region") or None,
            org_id=secret.get("org_id") or None,
            deployment_name=secret.get("deployment_name") or None,
            metadata=secret.get("metadata") or {},
            updated_at=secret.get("updated_at"),
        )
    except HTTPException:
        raise
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/secrets/tenant/{tenant_id}/provider-credentials/{provider}/rotate")
def rotate_provider_credentials(
    tenant_id: str,
    provider: str,
    body: ProviderCredentialWrite,
    _: Annotated[None, Depends(verify_api_key)],
):
    try:
        return _store_provider_credentials(tenant_id, provider, body)
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/v1/keys/pqc/{service_name}/state")
def read_pqc_key_state(
    service_name: str,
    _: Annotated[None, Depends(verify_api_key)],
    initialize_if_missing: bool = False,
):
    path = f"platform/service/{service_name}/pqc-key-state"
    try:
        secret = _client().kv_read_secret(path)
        if not secret:
            if not initialize_if_missing:
                raise HTTPException(status_code=404, detail=f"No PQC key state found for {service_name}")
            _initialize_pqc_state(service_name)
            secret = _client().kv_read_secret(path)
            if not secret:
                raise HTTPException(status_code=404, detail=f"No PQC key state found for {service_name}")
        return {
            "service_name": service_name,
            "path": path,
            "state": secret.get("state") or {},
            "updated_at": secret.get("updated_at"),
        }
    except HTTPException:
        raise
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/keys/pqc/{service_name}/state")
def write_pqc_key_state(
    service_name: str,
    body: PQCKeyStatePayload,
    _: Annotated[None, Depends(verify_api_key)],
):
    path = f"platform/service/{service_name}/pqc-key-state"
    payload = {
        "state": body.state,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        result = _client().kv_write(path, payload)
        return {
            "status": "stored",
            "service_name": service_name,
            "path": path,
            "openbao": result,
        }
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/crypto/encrypt")
def transit_encrypt(body: TransitEncryptRequest, _: Annotated[None, Depends(verify_api_key)]):
    try:
        plaintext_b64 = base64.b64encode(body.plaintext.encode()).decode()
        context_b64 = base64.b64encode(body.context.encode()).decode() if body.context else None
        result = _client().transit_encrypt(
            body.key_name,
            plaintext_b64,
            context_b64=context_b64,
            key_version=body.key_version,
        )
        return {"status": "encrypted", "key_name": body.key_name, **result}
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/crypto/decrypt")
def transit_decrypt(body: TransitDecryptRequest, _: Annotated[None, Depends(verify_api_key)]):
    try:
        context_b64 = base64.b64encode(body.context.encode()).decode() if body.context else None
        result = _client().transit_decrypt(body.key_name, body.ciphertext, context_b64=context_b64)
        plaintext_b64 = result.get("plaintext", "")
        plaintext = base64.b64decode(plaintext_b64).decode() if plaintext_b64 else ""
        return {"status": "decrypted", "key_name": body.key_name, "plaintext": plaintext, **result}
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/crypto/sign")
def transit_sign(body: TransitSignRequest, _: Annotated[None, Depends(verify_api_key)]):
    try:
        input_b64 = base64.b64encode(body.input.encode()).decode()
        result = _client().transit_sign(
            body.key_name,
            input_b64,
            hash_algorithm=body.hash_algorithm,
            key_version=body.key_version,
        )
        return {"status": "signed", "key_name": body.key_name, **result}
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/v1/keys/transit/{key_name}")
def read_transit_key(key_name: str, _: Annotated[None, Depends(verify_api_key)]):
    try:
        return _client().transit_key_read(key_name)
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/v1/keys/transit/{key_name}/rotate")
def rotate_transit_key(key_name: str, _: Annotated[None, Depends(verify_api_key)]):
    try:
        result = _client().transit_key_rotate(key_name)
        return {"status": "rotated", "key_name": key_name, **result}
    except OpenBaoError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
