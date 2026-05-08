"""Evidence writer.

Each gate decision produces an evidence record that goes to the audit
service. Evidence is the proof layer: what the gate saw, why it decided,
and the full signal vector. The schema here is the contract — keep
additions backward-compatible.

Reliability model
-----------------
Evidence writes are synchronous with the gate response — every decision
that reaches the caller has already attempted to persist its record.
Transient audit-service failures are retried up to ``max_retries`` times
with exponential back-off (default: 3 attempts, initial delay 0.25 s,
capped at 2 s). On final failure the full payload is emitted as a
structured WARNING log at level ``evidence_write_dead_letter`` so that
any log-aggregation pipeline (Splunk, CloudWatch, Elastic, etc.) can
ingest and reconcile it independently of the audit service.

The gate decision is never blocked or delayed by evidence write failures
— if all retries are exhausted the gate still returns its verdict and the
caller sees ``evidence_id=None``. Callers increment the
``evidence_write_errors_total`` Prometheus counter on ``None`` so the
gap is visible in dashboards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from cyberarmor_core.crypto import build_auth_headers

logger = logging.getLogger("url_trust_gate.evidence")

# Retry defaults — operators can override via EvidenceWriter constructor.
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE_S = 0.25   # 0.25 s, 0.5 s, 1.0 s (capped at 2 s)
_DEFAULT_BACKOFF_CAP_S = 2.0


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
    def __init__(
        self,
        audit_url: str,
        audit_secret: str,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_base_s: float = _DEFAULT_BACKOFF_BASE_S,
        backoff_cap_s: float = _DEFAULT_BACKOFF_CAP_S,
    ):
        self._audit_url = audit_url
        self._audit_secret = audit_secret
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._backoff_cap_s = backoff_cap_s

    async def write(self, record: EvidenceRecord) -> Optional[str]:
        """Persist an evidence record to the audit service.

        Retries up to ``max_retries`` times with exponential back-off on
        transient failures (network errors and 5xx responses). Returns the
        ``evidence_id`` string on success, or ``None`` if all attempts fail.
        On final failure, emits a dead-letter log entry containing the full
        serialised payload so it can be recovered from log aggregation.
        """
        evidence_id = uuid.uuid4().hex
        payload = {"evidence_id": evidence_id, **asdict(record)}
        body = {"kind": "url-trust-gate", "data": payload}
        headers = build_auth_headers(self._audit_url, self._audit_secret)

        last_exc: Optional[Exception] = None

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.post(
                        f"{self._audit_url}/events",
                        json=body,
                        headers=headers,
                    )

                if resp.status_code < 400:
                    # Success — log only on retry so the happy path is quiet.
                    if attempt > 1:
                        logger.info(
                            "evidence_write_recovered attempt=%s evidence_id=%s",
                            attempt, evidence_id,
                        )
                    return evidence_id

                if resp.status_code < 500:
                    # 4xx — client error, retrying won't help.
                    logger.warning(
                        "evidence_write_client_error status=%s body=%s evidence_id=%s",
                        resp.status_code, resp.text[:200], evidence_id,
                    )
                    break

                # 5xx — transient server error, retry.
                logger.warning(
                    "evidence_write_server_error status=%s attempt=%s/%s evidence_id=%s",
                    resp.status_code, attempt, self._max_retries, evidence_id,
                )
                last_exc = RuntimeError(f"audit service {resp.status_code}")

            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "evidence_write_attempt_failed err=%s attempt=%s/%s evidence_id=%s",
                    exc, attempt, self._max_retries, evidence_id,
                )

            if attempt < self._max_retries:
                delay = min(
                    self._backoff_base_s * (2 ** (attempt - 1)),
                    self._backoff_cap_s,
                )
                await asyncio.sleep(delay)

        # All attempts exhausted — emit a dead-letter record so log
        # aggregation (Splunk, CloudWatch, Elastic, etc.) can recover it.
        # Callers must increment the evidence_write_errors_total counter.
        logger.warning(
            "evidence_write_dead_letter evidence_id=%s last_err=%s payload=%s",
            evidence_id,
            last_exc,
            json.dumps(payload, default=str),
        )
        return None
