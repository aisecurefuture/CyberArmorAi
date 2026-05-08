"""Evidence writer.

Each gate decision produces an evidence record that goes to the audit
service. Evidence is the proof layer: what the gate saw, why it decided,
and the full signal vector. The schema here is the contract — keep
additions backward-compatible.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from cyberarmor_core.crypto import build_auth_headers

logger = logging.getLogger("url_trust_gate.evidence")


@dataclass
class EvidenceRecord:
    request_id: str
    tenant_id: str
    source: str
    user_id: Optional[str]
    app_id: Optional[str]
    agent_id: Optional[str]
    canonical_url: str  # already redacted by the gate
    url_fingerprint: str
    redirect_chain: List[str]
    content_hash: Optional[str]
    screenshot_hash: Optional[str]
    scores: Dict[str, Any]
    iocs: List[Dict[str, Any]]
    decision: Dict[str, Any]
    crawled: bool
    detonated: bool
    recorded_at: str


class EvidenceWriter:
    def __init__(self, audit_url: str, audit_secret: str):
        self._audit_url = audit_url
        self._audit_secret = audit_secret

    async def write(self, record: EvidenceRecord) -> Optional[str]:
        evidence_id = uuid.uuid4().hex
        payload = {"evidence_id": evidence_id, **asdict(record)}

        # POST /events is the generic audit sink. The kind field routes the
        # record to the url-trust-gate view in SOC dashboards.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(
                    f"{self._audit_url}/events",
                    json={"kind": "url-trust-gate", "data": payload},
                    headers=build_auth_headers(self._audit_url, self._audit_secret),
                )
                if resp.status_code >= 400:
                    logger.warning(
                        "evidence_write_non_2xx status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return None
        except Exception as exc:
            # Evidence write failures must NOT block the gate decision.
            # Callers increment the evidence_write_errors Prometheus counter.
            logger.warning("evidence_write_failed err=%s", exc)
            return None

        return evidence_id
