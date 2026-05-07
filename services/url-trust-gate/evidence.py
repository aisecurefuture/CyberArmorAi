"""Evidence writer.

Each gate decision produces an evidence record that goes to the audit
service. Evidence is the proof layer (what the gate saw and why) AND the
training data layer (what the ML pipeline learns from). The schema here
is the contract — keep additions backward-compatible.
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

        # TODO: switch to a proper audit service endpoint name once the
        # audit service exposes a typed channel for url-trust-gate
        # evidence (e.g. POST /events/url-trust-gate). Until then, the
        # generic /events sink is the right target.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(
                    f"{self._audit_url}/events",
                    json={"kind": "url-trust-gate", "data": payload},
                    headers=build_auth_headers(self._audit_secret),
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
            # Log loudly; a separate reconciler should sweep up and
            # re-deliver. TODO: spool to local disk for retry.
            logger.warning("evidence_write_failed err=%s", exc)
            return None

        return evidence_id

    # TODO: training-data export hook. Once enough labelled records
    # accumulate, an offline job should pull from the audit store, join
    # with /feedback corrections, and emit a training shard for the
    # detection service's ML models.
