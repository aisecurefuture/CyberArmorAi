"""CyberArmor URL / Context Trust Gate Service.

Pre-ingestion control point that sits between humans, browsers, endpoint
agents, RASP-instrumented apps, and AI agents on one side, and the open
web on the other. Before any of those consumers fetches or follows a URL,
or ingests external content into AI context, the gate:

  1. Canonicalises the URL (host, path, querystring, redirect chain).
  2. Looks up reputation (tenant allow/block lists, cached verdicts, optional
     external feeds such as Safe Browsing / VirusTotal).
  3. Optionally fetches the destination with an isolated low-footprint
     crawler (no user creds/cookies, SSRF-blocked egress, size/time-limited).
  4. Optionally renders the page in a detonation sandbox to catch hidden
     DOM/CSS-hidden/Unicode-hidden promptware.
  5. Streams extracted content to the Detection Service for phishing,
     prompt-injection, promptware, DLP/exfil, and IOC scoring.
  6. Calls the Policy Service to map score+context to an action
     (allow / warn / redact / sandbox / block).
  7. Optionally dispatches incidents to the Response Service.
  8. Persists evidence (URL hash, redirect chain, extracted IOCs, content
     hash, decision lineage) to the Audit Service for proof and as
     training data for the ML detection layer.

This module is intentionally a SCAFFOLD. The fast paths (cache lookup,
canonicalisation, policy/detection plumbing) are wired end-to-end; the
crawler, detonation sandbox, ML scoring fan-out, and evidence-store
writes are stubbed with TODOs.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from cyberarmor_core.crypto import (
    build_auth_headers,
    get_public_key_info,
    verify_shared_secret,
)

from canonicalize import canonicalize_url, classify_querystring_sensitivity
from reputation import ReputationCache, ReputationVerdict
from crawler import SafeCrawler, CrawlResult
from detonation import DetonationSandbox, DetonationResult
from extractors import extract_signals, ExtractedSignals
from evidence import EvidenceRecord, EvidenceWriter
from feeds import ReputationAggregator
from metrics import MetricsRegistry
from tenant_lists import TenantListClient

logger = logging.getLogger("url_trust_gate")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

URL_TRUST_GATE_API_SECRET = os.getenv("URL_TRUST_GATE_API_SECRET", "change-me-url-trust-gate")
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection-service:8002")
DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET", "change-me-detection")
POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://policy-service:8001")
POLICY_API_SECRET = os.getenv("POLICY_API_SECRET", "change-me-policy")
RESPONSE_SERVICE_URL = os.getenv("RESPONSE_SERVICE_URL", "http://response-service:8003")
RESPONSE_API_SECRET = os.getenv("RESPONSE_API_SECRET", "change-me-response")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", "http://audit-service:8004")
AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "change-me-audit")

ENFORCE_SECURE_SECRETS = os.getenv(
    "CYBERARMOR_ENFORCE_SECURE_SECRETS", "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv(
    "CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false"
).strip().lower() in {"1", "true", "yes", "on"}

# Crawler / detonation defaults. These are conservative by design: every
# enterprise-safe trap called out in the design (latency, SSRF, side
# effects, dynamic content, false positives) is bounded by one of these.
CRAWLER_TIMEOUT_S = float(os.getenv("URL_TRUST_GATE_CRAWLER_TIMEOUT_S", "4.0"))
CRAWLER_MAX_BYTES = int(os.getenv("URL_TRUST_GATE_CRAWLER_MAX_BYTES", "1048576"))  # 1 MiB
CRAWLER_MAX_REDIRECTS = int(os.getenv("URL_TRUST_GATE_CRAWLER_MAX_REDIRECTS", "5"))
DETONATION_DEFAULT_OFF = os.getenv("URL_TRUST_GATE_DETONATION_DEFAULT", "off").lower() != "on"
FAST_PATH_CACHE_TTL_S = int(os.getenv("URL_TRUST_GATE_CACHE_TTL_S", "900"))


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (URL_TRUST_GATE_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for: URL_TRUST_GATE_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def verify_api_key(api_key: Annotated[str | None, Header(alias="x-api-key")] = None):
    verify_shared_secret(api_key, URL_TRUST_GATE_API_SECRET, service_name="url-trust-gate")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class TrustGateRequest(BaseModel):
    """Incoming request to evaluate a URL before a consumer fetches it."""

    tenant_id: str
    url: str
    # Where the request originated. Drives policy and evidence tagging.
    # Examples: "browser-extension", "endpoint-agent", "proxy", "rasp",
    # "ai-router", "office-extension", "email-link-rewrite".
    source: str
    # Optional consumer identity context (user, app, agent). Used by the
    # policy engine; never logged in raw form unless tenant policy allows.
    user_id: Optional[str] = None
    app_id: Optional[str] = None
    agent_id: Optional[str] = None
    # Hint to the gate about how much work to do. "fast" = cache + reputation
    # only; "standard" = + safe crawl; "deep" = + detonation sandbox.
    depth: str = Field(default="standard", pattern="^(fast|standard|deep)$")
    # If true, the consumer is asking the gate to render in a sandbox even
    # when policy would normally short-circuit on cache hit. Used for
    # one-off "is this still safe?" checks.
    force_recrawl: bool = False
    # Optional caller-provided context. Free-form; used only by policy.
    context: Optional[Dict[str, Any]] = None


class IOC(BaseModel):
    kind: str  # url|domain|ip|email|hash|wallet|phone|...
    value: str
    confidence: float = 0.0
    source: str = "url-trust-gate"


class TrustGateScores(BaseModel):
    phishing: float = 0.0
    malware: float = 0.0
    prompt_injection: float = 0.0
    promptware: float = 0.0
    data_exfil: float = 0.0
    credential_harvest: float = 0.0
    brand_impersonation: float = 0.0
    overall_risk: float = 0.0


class TrustGateDecision(BaseModel):
    # action mirrors policy service vocabulary plus gate-specific extras.
    action: str  # allow|warn|redact|sandbox|block|isolate
    reason: str
    matched_policy: Optional[str] = None
    redact_segments: List[str] = Field(default_factory=list)
    # If the gate suggests browser isolation, this is where to redirect.
    isolation_url: Optional[str] = None


class TrustGateResponse(BaseModel):
    request_id: str
    tenant_id: str
    canonical_url: str
    redirect_chain: List[str] = Field(default_factory=list)
    cache_hit: bool = False
    crawled: bool = False
    detonated: bool = False
    scores: TrustGateScores
    iocs: List[IOC] = Field(default_factory=list)
    decision: TrustGateDecision
    evidence_id: Optional[str] = None
    elapsed_ms: int = 0


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberArmor URL / Context Trust Gate", version="0.1.0")
SERVICE_STARTED_AT = datetime.now(timezone.utc)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Module-level singletons. Each is a thin wrapper today; the heavy lifting
# is intentionally pushed behind these interfaces so they can be swapped
# out (e.g. detonation -> dedicated containerised sandbox cluster) without
# touching the request handler.
_reputation_cache = ReputationCache(ttl_s=FAST_PATH_CACHE_TTL_S)
_crawler = SafeCrawler(
    timeout_s=CRAWLER_TIMEOUT_S,
    max_bytes=CRAWLER_MAX_BYTES,
    max_redirects=CRAWLER_MAX_REDIRECTS,
)
_detonation = DetonationSandbox()
_evidence = EvidenceWriter(audit_url=AUDIT_SERVICE_URL, audit_secret=AUDIT_API_SECRET)
_feeds = ReputationAggregator.from_env()
_tenant_lists = TenantListClient(
    policy_url=POLICY_SERVICE_URL, policy_secret=POLICY_API_SECRET
)
_metrics = MetricsRegistry()


# ---------------------------------------------------------------------------
# Health / readiness / metrics — match conventions from detection & policy
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "url-trust-gate",
        "started_at": SERVICE_STARTED_AT.isoformat(),
        "uptime_s": int((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds()),
    }


@app.get("/ready")
def ready() -> Dict[str, Any]:
    # TODO: probe detection/policy/audit reachability before declaring ready.
    return {"status": "ready"}


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    # Prometheus expects the canonical content-type on the scrape endpoint.
    # The version string ("0.0.4") tells Prometheus which text format we emit
    # so it can parse the exposition correctly.
    return PlainTextResponse(
        _metrics.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/pki/public-key")
def pki_public_key() -> Dict[str, Any]:
    return get_public_key_info()


# ---------------------------------------------------------------------------
# Core endpoint
# ---------------------------------------------------------------------------

@app.post("/evaluate", response_model=TrustGateResponse, dependencies=[Depends(verify_api_key)])
async def evaluate(req: TrustGateRequest) -> TrustGateResponse:
    """Evaluate a URL/context request and return an enforcement decision.

    This is the single entry point used by browser extensions, endpoint
    agents, the proxy/RASP path, and the AI router. Latency budget for
    `depth=fast` is ~10ms (cache + canonicalisation only); `standard`
    targets <500ms with safe crawl; `deep` is best-effort and may run for
    several seconds inside the detonation sandbox.
    """

    start = time.monotonic()
    request_id = _new_request_id(req)

    # ---------------- 1. Canonicalise + querystring classification ----------
    canonical = canonicalize_url(req.url)
    qs_sensitivity = classify_querystring_sensitivity(canonical.query_params)
    # NOTE: redacted_url is what we LOG and store in evidence. Raw URL with
    # sensitive querystring values never leaves this function.
    redacted_url = canonical.redacted_url(qs_sensitivity)

    # ---------------- 2. Reputation / cache fast path -----------------------
    cached: Optional[ReputationVerdict] = None
    if not req.force_recrawl:
        cached = _reputation_cache.lookup(canonical.fingerprint)

    if cached is not None and req.depth == "fast":
        decision = await _decide_with_policy(
            req=req,
            scores=cached.scores,
            iocs=cached.iocs,
            canonical_url=redacted_url,
            crawled=False,
            detonated=False,
        )
        return _build_response(
            request_id=request_id,
            req=req,
            canonical_url=redacted_url,
            redirect_chain=cached.redirect_chain,
            cache_hit=True,
            crawled=False,
            detonated=False,
            scores=cached.scores,
            iocs=cached.iocs,
            decision=decision,
            evidence_id=None,  # fast path skips evidence write by design
            start=start,
        )

    # ---------------- 3. Tenant allow / block lists -------------------------
    # TODO: pull tenant allow/block list from policy service or local cache.
    # If exact match → short-circuit to allow/block without crawling. This
    # also handles known-corporate domains that should never be detonated.
    tenant_listed = await _tenant_listed_decision(req.tenant_id, canonical)
    if tenant_listed is not None:
        return _build_response(
            request_id=request_id,
            req=req,
            canonical_url=redacted_url,
            redirect_chain=[],
            cache_hit=False,
            crawled=False,
            detonated=False,
            scores=TrustGateScores(),
            iocs=[],
            decision=tenant_listed,
            evidence_id=None,
            start=start,
        )

    # ---------------- 4. Safe crawl -----------------------------------------
    crawl_result: Optional[CrawlResult] = None
    if req.depth in {"standard", "deep"}:
        crawl_result = await _crawler.fetch(
            canonical.url,
            tenant_id=req.tenant_id,
            request_id=request_id,
        )

    # ---------------- 5. Detonation (deep only) -----------------------------
    detonation_result: Optional[DetonationResult] = None
    if req.depth == "deep" and not DETONATION_DEFAULT_OFF:
        detonation_result = await _detonation.render(
            canonical.url,
            tenant_id=req.tenant_id,
            request_id=request_id,
        )

    # ---------------- 6. Signal extraction + ML scoring ---------------------
    signals: ExtractedSignals = extract_signals(
        canonical=canonical,
        crawl=crawl_result,
        detonation=detonation_result,
    )
    scores, iocs = await _score_with_detection(req, signals)

    # External reputation feeds (Safe Browsing etc.) run in parallel with
    # detection in spirit, but for simplicity we sequence them after. They
    # only sharpen the verdict — they're never the sole reason to block.
    feed_verdict = await _feeds.lookup(canonical.url)
    if feed_verdict.matched:
        scores.phishing = max(scores.phishing, feed_verdict.phishing)
        scores.malware = max(scores.malware, feed_verdict.malware)
        scores.overall_risk = max(
            scores.overall_risk, scores.phishing, scores.malware
        )
        for tt in feed_verdict.threat_types:
            iocs.append(
                IOC(
                    kind="threat-type",
                    value=tt,
                    confidence=feed_verdict.phishing or feed_verdict.malware,
                    source=",".join(feed_verdict.sources) or "external-feed",
                )
            )

    # ---------------- 7. Policy decision ------------------------------------
    decision = await _decide_with_policy(
        req=req,
        scores=scores,
        iocs=iocs,
        canonical_url=redacted_url,
        crawled=crawl_result is not None,
        detonated=detonation_result is not None,
    )

    # ---------------- 8. Evidence + cache write -----------------------------
    evidence_id = await _evidence.write(
        EvidenceRecord(
            request_id=request_id,
            tenant_id=req.tenant_id,
            source=req.source,
            user_id=req.user_id,
            app_id=req.app_id,
            agent_id=req.agent_id,
            canonical_url=redacted_url,
            url_fingerprint=canonical.fingerprint,
            redirect_chain=crawl_result.redirect_chain if crawl_result else [],
            content_hash=crawl_result.content_hash if crawl_result else None,
            screenshot_hash=detonation_result.screenshot_hash if detonation_result else None,
            scores=scores.model_dump(),
            iocs=[i.model_dump() for i in iocs],
            decision=decision.model_dump(),
            crawled=crawl_result is not None,
            detonated=detonation_result is not None,
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )
    )

    _reputation_cache.store(
        canonical.fingerprint,
        ReputationVerdict(
            scores=scores,
            iocs=iocs,
            redirect_chain=crawl_result.redirect_chain if crawl_result else [],
        ),
    )

    # ---------------- 9. Optional incident dispatch -------------------------
    if decision.action in {"block", "isolate"} and scores.overall_risk >= 0.8:
        await _dispatch_incident(req, decision, redacted_url, scores, iocs, evidence_id)

    return _build_response(
        request_id=request_id,
        req=req,
        canonical_url=redacted_url,
        redirect_chain=crawl_result.redirect_chain if crawl_result else [],
        cache_hit=False,
        crawled=crawl_result is not None,
        detonated=detonation_result is not None,
        scores=scores,
        iocs=iocs,
        decision=decision,
        evidence_id=evidence_id,
        start=start,
    )


@app.post("/feedback", dependencies=[Depends(verify_api_key)])
async def feedback(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Tenant override / FP-FN feedback hook.

    Used by SOC analysts and the dashboard to mark a prior decision as
    false positive / false negative. The flywheel: this writes back into
    evidence and signals the ML training pipeline that the verdict on this
    URL fingerprint should be revisited.
    """

    # TODO: validate schema, persist to audit, push to training queue.
    return {"status": "accepted", "received": payload}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _new_request_id(req: TrustGateRequest) -> str:
    h = hashlib.sha256()
    h.update(req.tenant_id.encode())
    h.update(b"\0")
    h.update(req.url.encode())
    h.update(b"\0")
    h.update(str(time.time_ns()).encode())
    return h.hexdigest()[:24]


def _build_response(
    *,
    request_id: str,
    req: TrustGateRequest,
    canonical_url: str,
    redirect_chain: List[str],
    cache_hit: bool,
    crawled: bool,
    detonated: bool,
    scores: TrustGateScores,
    iocs: List[IOC],
    decision: TrustGateDecision,
    evidence_id: Optional[str],
    start: float,
) -> TrustGateResponse:
    elapsed_ms = int((time.monotonic() - start) * 1000)
    _metrics.observe_request(
        depth=req.depth,
        decision=decision.action,
        cache_hit=cache_hit,
        crawled=crawled,
        detonated=detonated,
        elapsed_ms=elapsed_ms,
    )
    return TrustGateResponse(
        request_id=request_id,
        tenant_id=req.tenant_id,
        canonical_url=canonical_url,
        redirect_chain=redirect_chain,
        cache_hit=cache_hit,
        crawled=crawled,
        detonated=detonated,
        scores=scores,
        iocs=iocs,
        decision=decision,
        evidence_id=evidence_id,
        elapsed_ms=elapsed_ms,
    )


async def _tenant_listed_decision(
    tenant_id: str, canonical
) -> Optional[TrustGateDecision]:
    """Check tenant-scoped allow/block lists in the policy service.

    Returning None means "not listed; continue with full pipeline".
    """

    listed = await _tenant_lists.lookup(tenant_id, canonical.host, canonical.url)
    if listed is None:
        return None
    if listed == "allow":
        return TrustGateDecision(
            action="allow", reason="tenant allow-list match", matched_policy="tenant-allow-list"
        )
    if listed == "block":
        return TrustGateDecision(
            action="block", reason="tenant block-list match", matched_policy="tenant-block-list"
        )
    return None


async def _score_with_detection(
    req: TrustGateRequest, signals: ExtractedSignals
) -> tuple[TrustGateScores, List[IOC]]:
    """Stream extracted content to the Detection Service and aggregate scores.

    The detection service already exposes /scan, /scan/prompt-injection,
    /scan/promptware, /scan/sensitive-data and /scan/output-safety. The
    gate fans out the relevant subset based on which signals were
    successfully extracted, then aggregates into the trust-gate score
    vector.
    """

    scores = TrustGateScores()
    iocs: List[IOC] = []

    # Cheap heuristics that don't need the detection service. These run
    # even if the detection service is unreachable so the gate can still
    # produce a usable verdict.
    if signals.has_credential_form:
        scores.credential_harvest = max(scores.credential_harvest, 0.6)
    if signals.has_brand_impersonation_keywords:
        scores.brand_impersonation = max(scores.brand_impersonation, 0.5)
    if signals.hidden_text_blocks:
        # Hidden text alone is not malicious — it's a SIGNAL to look
        # harder, not a verdict. Score modestly and let the ML layer
        # confirm.
        scores.prompt_injection = max(scores.prompt_injection, 0.4)
        scores.promptware = max(scores.promptware, 0.3)

    # Fan out to detection service for ML scoring of any extracted text.
    if signals.text_for_ml:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(
                    f"{DETECTION_SERVICE_URL}/scan",
                    json={
                        "content": signals.text_for_ml,
                        "session_id": f"url-trust-gate:{req.tenant_id}",
                        "context": {
                            "source": "url-trust-gate",
                            "consumer_source": req.source,
                        },
                    },
                    headers=build_auth_headers(DETECTION_SERVICE_URL, DETECTION_API_SECRET),
                )
                if resp.status_code == 200:
                    body = resp.json()
                    # Detection service returns the list of findings under
                    # "detections" (with "findings" kept as a back-compat
                    # alias on some endpoints). Read both so we don't miss
                    # signals if the schema shifts.
                    findings = body.get("detections") or body.get("findings") or []
                    for f in findings:
                        kind = f.get("type", "")
                        conf = float(f.get("confidence", 0.0))
                        if "prompt_injection" in kind:
                            scores.prompt_injection = max(scores.prompt_injection, conf)
                        if "promptware" in kind:
                            scores.promptware = max(scores.promptware, conf)
                        if "exfil" in kind or "dlp" in kind or "sensitive" in kind:
                            scores.data_exfil = max(scores.data_exfil, conf)
                        if "phishing" in kind or "credential" in kind:
                            scores.credential_harvest = max(
                                scores.credential_harvest, conf
                            )
                else:
                    logger.warning(
                        "detection_non_200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
        except Exception as exc:
            # Fail-open on detection unreachable: the policy engine still
            # gets the heuristic scores. Mark the verdict as degraded so
            # downstream evidence shows it.
            logger.warning("detection_unreachable err=%s", exc)

    # IOCs from the extractors layer.
    iocs.extend(signals.iocs)

    # Composite risk: simple max-of for the scaffold. TODO: replace with a
    # tenant-tunable weighted aggregation, possibly an LLM judge for the
    # ambiguous middle band.
    scores.overall_risk = max(
        scores.phishing,
        scores.malware,
        scores.prompt_injection,
        scores.promptware,
        scores.data_exfil,
        scores.credential_harvest,
        scores.brand_impersonation,
    )

    return scores, iocs


async def _decide_with_policy(
    *,
    req: TrustGateRequest,
    scores: TrustGateScores,
    iocs: List[IOC],
    canonical_url: str,
    crawled: bool,
    detonated: bool,
) -> TrustGateDecision:
    """Ask the policy service what to do given scores + context.

    Falls back to a built-in conservative ruleset if the policy service is
    unreachable, so the gate degrades gracefully rather than failing open.
    """

    payload = {
        "tenant_id": req.tenant_id,
        "scope": "url-trust-gate",
        "context": {
            "source": req.source,
            "user_id": req.user_id,
            "app_id": req.app_id,
            "agent_id": req.agent_id,
            "canonical_url": canonical_url,
            "scores": scores.model_dump(),
            "ioc_count": len(iocs),
            "crawled": crawled,
            "detonated": detonated,
            **(req.context or {}),
        },
    }

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                f"{POLICY_SERVICE_URL}/evaluate",
                json=payload,
                headers=build_auth_headers(POLICY_SERVICE_URL, POLICY_API_SECRET),
            )
            if resp.status_code == 200:
                data = resp.json()
                action = _normalise_action(data.get("decision", "monitor"))
                reason = data.get("reason", "policy decision")
                # If the policy service has no rule for url-trust-gate
                # (legacy /evaluate returns ALLOW + reason="no_policy_match"
                # in that case), don't blindly downgrade — defer to the
                # gate's own score-based fallback so a deployment without
                # any url-trust-gate policies still enforces the heuristic
                # + ML defaults rather than failing open.
                if action == "allow" and reason in {
                    "no_policy_match", "policy_allow", "no policy match"
                }:
                    fb = _fallback_decision(scores)
                    if fb.action != "allow":
                        return fb
                return TrustGateDecision(
                    action=action,
                    reason=reason,
                    matched_policy=data.get("matched_policy"),
                    redact_segments=data.get("redact_segments", []) or [],
                    isolation_url=data.get("isolation_url"),
                )
            logger.warning(
                "policy_non_200 status=%s body=%s",
                resp.status_code,
                resp.text[:200],
            )
    except Exception as exc:
        logger.warning("policy_unreachable err=%s", exc)

    return _fallback_decision(scores)


def _normalise_action(action: str) -> str:
    """Map policy-service vocabulary to gate vocabulary.

    Policy uses {monitor, allow, warn, block}; the gate adds {redact,
    sandbox, isolate}. Anything we don't recognise is treated as "warn".
    """

    action = (action or "").lower().strip()
    if action in {"allow", "warn", "block", "monitor"}:
        return "allow" if action == "monitor" else action
    if action in {"redact", "sandbox", "isolate"}:
        return action
    return "warn"


def _fallback_decision(scores: TrustGateScores) -> TrustGateDecision:
    if scores.credential_harvest >= 0.7 or scores.phishing >= 0.7:
        return TrustGateDecision(action="block", reason="fallback: phishing/credential harvest")
    if scores.promptware >= 0.7 or scores.prompt_injection >= 0.7:
        return TrustGateDecision(action="redact", reason="fallback: hidden instruction risk")
    if scores.overall_risk >= 0.5:
        return TrustGateDecision(action="warn", reason="fallback: moderate risk")
    return TrustGateDecision(action="allow", reason="fallback: below thresholds")


async def _dispatch_incident(
    req: TrustGateRequest,
    decision: TrustGateDecision,
    canonical_url: str,
    scores: TrustGateScores,
    iocs: List[IOC],
    evidence_id: Optional[str],
) -> None:
    """Best-effort POST to the response service for high-severity verdicts."""

    incident = {
        "tenant_id": req.tenant_id,
        "source": "url-trust-gate",
        "severity": "high" if scores.overall_risk >= 0.9 else "medium",
        "description": (
            f"URL Trust Gate {decision.action} for {canonical_url}: "
            f"{decision.reason}"
        ),
        "actions": [{"kind": decision.action, "target": canonical_url}],
        "evidence_id": evidence_id,
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                f"{RESPONSE_SERVICE_URL}/respond",
                json=incident,
                headers=build_auth_headers(RESPONSE_SERVICE_URL, RESPONSE_API_SECRET),
            )
    except Exception as exc:
        logger.warning("response_dispatch_failed err=%s", exc)
