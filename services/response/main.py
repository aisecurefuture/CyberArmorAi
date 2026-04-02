import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret
from cyberarmor_core.crypto import build_auth_headers

logger = logging.getLogger("response_service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

PROXY_AGENT_URL = os.getenv("PROXY_AGENT_URL", "http://proxy-agent:8010")
WEBHOOK_URL = os.getenv("RESPONSE_WEBHOOK_URL", "")
RESPONSE_API_SECRET = os.getenv("RESPONSE_API_SECRET", "change-me-response")
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}

app = FastAPI(title="CyberArmor Response Orchestrator", version="0.1.1")
SERVICE_STARTED_AT = datetime.now(timezone.utc)


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (RESPONSE_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: RESPONSE_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ResponseAction(BaseModel):
    kind: str  # block|redirect|quarantine|notify|ticket|webhook
    target: Optional[str] = None
    message: Optional[str] = None


class Incident(BaseModel):
    tenant_id: str
    source: str
    severity: str
    description: str
    actions: List[ResponseAction] = []
    detected_at: datetime = datetime.now(timezone.utc)


def verify_api_key(api_key: str | None = Header(default=None, alias="x-api-key")) -> None:
    verify_shared_secret(api_key, RESPONSE_API_SECRET, service_name="response")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "service": "response",
        "version": "0.1.1",
    }


@app.get("/metrics")
def metrics():
    uptime = round((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds(), 3)
    return PlainTextResponse(
        "\n".join([
            "# HELP cyberarmor_response_uptime_seconds Service uptime in seconds",
            "# TYPE cyberarmor_response_uptime_seconds gauge",
            f"cyberarmor_response_uptime_seconds{{service=\"response\",version=\"0.1.1\"}} {uptime}",
        ]) + "\n",
        media_type="text/plain",
    )


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("response")


async def dispatch_actions(incident: Incident):
    async with httpx.AsyncClient(timeout=5.0) as client:
        for action in incident.actions:
            if action.kind == "block" and action.target:
                try:
                    headers = build_auth_headers(
                        PROXY_AGENT_URL,
                        os.getenv("PROXY_AGENT_API_SECRET", ""),
                        {"Content-Type": "application/json"},
                    )
                    await client.post(
                        f"{PROXY_AGENT_URL}/actions/block",
                        headers=headers,
                        json={"tenant_id": incident.tenant_id, "target": action.target},
                    )
                    logger.info("block dispatched tenant=%s target=%s", incident.tenant_id, action.target)
                except Exception as exc:
                    logger.error("block dispatch failed tenant=%s target=%s err=%s", incident.tenant_id, action.target, exc)
            if action.kind == "webhook" and WEBHOOK_URL:
                try:
                    await client.post(WEBHOOK_URL, json={"tenant_id": incident.tenant_id, "source": incident.source, "action": action.kind, "target": action.target, "message": action.message})
                except Exception as exc:
                    logger.error("webhook dispatch failed err=%s", exc)


@app.post("/respond")
async def respond(incident: Incident, _: None = Depends(verify_api_key)):
    logger.warning(
        "incident tenant=%s source=%s severity=%s actions=%s",
        incident.tenant_id,
        incident.source,
        incident.severity,
        [a.kind for a in incident.actions],
    )
    await dispatch_actions(incident)
    return {"status": "queued", "actions": incident.actions}
