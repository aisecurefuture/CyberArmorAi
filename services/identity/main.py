"""CyberArmor Identity Enrichment Service.

Pluggable identity provider integration for user context enrichment.
Supports: Microsoft Entra ID, Okta, Ping Identity, AWS IAM Identity Center.
Works with no provider configured (returns basic info only).
"""

import logging
import os
from datetime import datetime, timezone
from typing import Annotated, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from providers.base import IdentityProviderBase, UserInfo
from providers.entra import EntraIDProvider
from providers.okta import OktaProvider
from providers.ping import PingIdentityProvider
from providers.aws_iam import AWSIAMIdentityCenterProvider
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("identity_service")

IDENTITY_API_SECRET = os.getenv("IDENTITY_API_SECRET", "change-me-identity")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (IDENTITY_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: IDENTITY_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    verify_shared_secret(api_key, IDENTITY_API_SECRET, service_name="identity")


def discover_providers() -> Dict[str, IdentityProviderBase]:
    """Auto-detect configured identity providers from environment variables."""
    providers = {}
    if os.getenv("AZURE_TENANT_ID") and os.getenv("AZURE_CLIENT_ID"):
        try:
            providers["entra"] = EntraIDProvider()
            logger.info("Entra ID provider configured")
        except Exception as e:
            logger.warning("Entra ID provider init failed: %s", e)

    if os.getenv("OKTA_DOMAIN") and os.getenv("OKTA_API_TOKEN"):
        try:
            providers["okta"] = OktaProvider()
            logger.info("Okta provider configured")
        except Exception as e:
            logger.warning("Okta provider init failed: %s", e)

    if os.getenv("PING_ENV_ID") and os.getenv("PING_CLIENT_ID"):
        try:
            providers["ping"] = PingIdentityProvider()
            logger.info("Ping Identity provider configured")
        except Exception as e:
            logger.warning("Ping Identity provider init failed: %s", e)

    if os.getenv("AWS_SSO_INSTANCE_ARN"):
        try:
            providers["aws_iam"] = AWSIAMIdentityCenterProvider()
            logger.info("AWS IAM Identity Center provider configured")
        except Exception as e:
            logger.warning("AWS IAM provider init failed: %s", e)

    if not providers:
        logger.info("No identity providers configured; operating in standalone mode")
    return providers


# --- Pydantic Models ---

class EnrichRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    provider: Optional[str] = None

class UserInfoOut(BaseModel):
    id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    groups: List[str] = []
    roles: List[str] = []
    provider: str = "none"
    metadata: Dict = {}

class TokenValidateRequest(BaseModel):
    token: str
    provider: Optional[str] = None

class ProviderInfo(BaseModel):
    name: str
    type: str
    status: str


# --- Application ---

app = FastAPI(title="CyberArmor Identity Service", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
SERVICE_STARTED_AT = datetime.now(timezone.utc)

active_providers: Dict[str, IdentityProviderBase] = {}


@app.on_event("startup")
def on_startup():
    global active_providers
    active_providers = discover_providers()


@app.get("/health")
def health():
    return {"status": "ok", "providers": list(active_providers.keys()), "version": "0.2.0"}


@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "service": "identity",
        "providers": list(active_providers.keys()),
        "version": "0.2.0",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics")
def metrics():
    uptime = round((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds(), 3)
    return PlainTextResponse(
        "\n".join([
            "# HELP cyberarmor_identity_uptime_seconds Service uptime in seconds",
            "# TYPE cyberarmor_identity_uptime_seconds gauge",
            f"cyberarmor_identity_uptime_seconds{{service=\"identity\",version=\"0.2.0\"}} {uptime}",
            "# HELP cyberarmor_identity_providers_configured Count of configured identity providers",
            "# TYPE cyberarmor_identity_providers_configured gauge",
            f"cyberarmor_identity_providers_configured{{service=\"identity\"}} {len(active_providers)}",
        ]) + "\n",
        media_type="text/plain",
    )


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("identity")


@app.get("/providers", response_model=List[ProviderInfo])
def list_providers(_: Annotated[None, Depends(verify_api_key)]):
    result = []
    for name, provider in active_providers.items():
        result.append(ProviderInfo(name=name, type=provider.provider_type, status="active"))
    if not result:
        result.append(ProviderInfo(name="standalone", type="none", status="active"))
    return result


@app.post("/enrich", response_model=UserInfoOut)
async def enrich_user(body: EnrichRequest, _: Annotated[None, Depends(verify_api_key)]):
    """Enrich user context by looking up in configured identity provider."""
    identifier = body.email or body.user_id
    if not identifier:
        raise HTTPException(status_code=400, detail="Provide user_id or email")

    provider_name = body.provider
    if provider_name and provider_name in active_providers:
        providers_to_try = {provider_name: active_providers[provider_name]}
    elif provider_name and provider_name not in active_providers:
        raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' not configured")
    else:
        providers_to_try = active_providers

    for pname, provider in providers_to_try.items():
        try:
            user = await provider.get_user_info(identifier)
            if user:
                return UserInfoOut(
                    id=user.id, email=user.email, display_name=user.display_name,
                    department=user.department, job_title=user.metadata.get("job_title", ""),
                    groups=user.groups, roles=user.roles,
                    provider=pname, metadata=user.metadata,
                )
        except Exception as e:
            logger.warning("Provider %s lookup failed for %s: %s", pname, identifier, e)

    # No provider found or no match; return basic info
    return UserInfoOut(id=identifier, email=body.email, provider="standalone")


@app.get("/users/{identifier}", response_model=UserInfoOut)
async def get_user(identifier: str, provider: Optional[str] = None, _: Annotated[None, Depends(verify_api_key)] = None):
    """Get user info from identity provider."""
    for pname, prov in active_providers.items():
        if provider and pname != provider:
            continue
        try:
            user = await prov.get_user_info(identifier)
            if user:
                return UserInfoOut(
                    id=user.id, email=user.email, display_name=user.display_name,
                    department=user.department, job_title=user.metadata.get("job_title", ""),
                    groups=user.groups, roles=user.roles,
                    provider=pname, metadata=user.metadata,
                )
        except Exception as e:
            logger.warning("User lookup failed provider=%s id=%s err=%s", pname, identifier, e)

    raise HTTPException(status_code=404, detail="User not found")


@app.get("/users/{identifier}/groups", response_model=List[str])
async def get_user_groups(identifier: str, provider: Optional[str] = None, _: Annotated[None, Depends(verify_api_key)] = None):
    """Get user group membership."""
    for pname, prov in active_providers.items():
        if provider and pname != provider:
            continue
        try:
            groups = await prov.list_groups(identifier)
            if groups is not None:
                return groups
        except Exception as e:
            logger.warning("Group lookup failed provider=%s id=%s err=%s", pname, identifier, e)
    return []


@app.post("/validate-token")
async def validate_token(body: TokenValidateRequest, _: Annotated[None, Depends(verify_api_key)]):
    """Validate an identity provider token."""
    for pname, prov in active_providers.items():
        if body.provider and pname != body.provider:
            continue
        try:
            result = await prov.authenticate_user(body.token)
            if result.success:
                return {"valid": True, "provider": pname, "claims": result.token_claims}
        except Exception as e:
            logger.warning("Identity validation failed provider=%s error_type=%s", pname, type(e).__name__)
    return {"valid": False, "provider": None, "claims": {}}

