"""CyberArmor Detection Service – ML-based edition.

Detection pipeline (in priority order):
  1. Adversarial text normalisation (unicode, zero-width chars, homoglyphs, base64/hex decode)
  2. Prompt Injection – ML primary (protectai/deberta-v3-base-prompt-injection-v2)
                      + heuristic ensemble (secondary / tiebreaker)
                      + legacy regex (optional compat flag)
  3. Promptware session tracker (multi-turn attack chain correlation)
  4. Sensitive Data / DLP – NER model primary (dslim/bert-base-NER)
                           + regex fallback for structured patterns (SSN, CC, AWS keys …)
                           + semantic vector DLP (credential/PII concept prototypes)
  5. Output Safety – ML zero-shot classifier primary
                   + regex fallback for known dangerous patterns
  6. Toxicity – ML classifier (unitary/toxic-bert)
  7. Ollama LLM Judge – optional second-pass for high-ambiguity / high-risk inputs

All ML models run fully locally; no external API calls.
Model downloads happen on first use and are cached in TRANSFORMERS_CACHE.
Set TRANSFORMERS_OFFLINE=1 after initial download to prevent any HF network access.
"""

import base64
import binascii
import hashlib
import logging
import math
import os
import re
import time
import unicodedata
from collections import deque
from threading import Lock
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret

# ML detector singletons (lazy-loaded on first inference call)
from ml_models import (
    NER_PII_CONFIDENCE_THRESHOLD,
    OLLAMA_ENABLED,
    PROMPT_INJECTION_ML_THRESHOLD,
    ner_pii_detector,
    ollama_judge,
    prompt_injection_detector,
    toxicity_detector,
    zero_shot_detector,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("detection_service")

# ---------------------------------------------------------------------------
# Runtime secrets / configuration
# ---------------------------------------------------------------------------

DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET", "change-me-detection")
ENFORCE_SECURE_SECRETS = (
    os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
ALLOW_INSECURE_DEFAULTS = (
    os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (DETECTION_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for DETECTION_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()

# ---------------------------------------------------------------------------
# Detector thresholds / feature flags
# ---------------------------------------------------------------------------

# Prompt injection (ML primary)
_PI_ML_THRESHOLD = float(
    os.getenv("PROMPT_INJECTION_MODEL_THRESHOLD", str(PROMPT_INJECTION_ML_THRESHOLD))
)
_PI_ENSEMBLE_THRESHOLD = float(os.getenv("PROMPT_INJECTION_ENSEMBLE_THRESHOLD", "0.66"))
_LEGACY_PROMPT_REGEX_ENABLED = (
    os.getenv("CYBERARMOR_ENABLE_LEGACY_PROMPT_REGEX", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
_PI_RISK_BASE = float(os.getenv("PROMPT_INJECTION_RISK_BASE", "0.32"))
_PI_RISK_MULTIPLIER = float(os.getenv("PROMPT_INJECTION_RISK_MULTIPLIER", "0.85"))
_PI_RISK_CAP = float(os.getenv("PROMPT_INJECTION_RISK_CAP", "0.85"))

# DLP / semantic
_SEMANTIC_DLP_THRESHOLD = float(os.getenv("SEMANTIC_DLP_THRESHOLD", "0.62"))

# Promptware session
_PROMPTWARE_SESSION_ENABLED = (
    os.getenv("CYBERARMOR_PROMPTWARE_SESSION_ENABLED", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)
_PROMPTWARE_SESSION_WINDOW_SECONDS = int(
    os.getenv("PROMPTWARE_SESSION_WINDOW_SECONDS", "1800")
)
_PROMPTWARE_SESSION_MAX_EVENTS = int(os.getenv("PROMPTWARE_SESSION_MAX_EVENTS", "20"))
_PROMPTWARE_CHAIN_WARN_THRESHOLD = float(
    os.getenv("PROMPTWARE_CHAIN_WARN_THRESHOLD", "0.55")
)
_PROMPTWARE_CHAIN_BLOCK_THRESHOLD = float(
    os.getenv("PROMPTWARE_CHAIN_BLOCK_THRESHOLD", "0.85")
)

# Ollama second-pass judge: only invoked when combined risk >= this threshold
_OLLAMA_JUDGE_RISK_TRIGGER = float(os.getenv("OLLAMA_JUDGE_RISK_TRIGGER", "0.45"))

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenericScanRequest(BaseModel):
    content: str = ""
    direction: str = "request"
    content_type: str = "text/plain"
    source_url: Optional[str] = None
    tenant_id: str = "default"
    session_id: Optional[str] = None
    local_findings: List[Dict[str, Any]] = Field(default_factory=list)


class TextRequest(BaseModel):
    text: str
    session_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Adversarial text normalisation
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_B64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_HOMOGLYPH_MAP = str.maketrans(
    {
        # Greek → Latin lookalikes
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
        "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
        # Cyrillic → Latin lookalikes
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    }
)


def _normalize_adversarial_text(text: str) -> str:
    t = text or ""
    t = unicodedata.normalize("NFKC", t)
    t = _ZERO_WIDTH_RE.sub("", t)
    t = t.translate(_HOMOGLYPH_MAP)
    return t


def _decode_obfuscated_segments(text: str) -> str:
    """Append decoded base64 / hex segments to the original text."""
    out = [text or ""]
    for token in _B64_TOKEN_RE.findall(text or "")[:12]:
        try:
            decoded = base64.b64decode(
                token + ("=" * ((4 - len(token) % 4) % 4)), validate=False
            )
            decoded_txt = decoded.decode("utf-8", errors="ignore")
            if 6 <= len(decoded_txt) <= 800:
                out.append(decoded_txt)
        except Exception:
            pass
    for token in _HEX_TOKEN_RE.findall(text or "")[:12]:
        if len(token) % 2 != 0:
            continue
        try:
            decoded = binascii.unhexlify(token)
            decoded_txt = decoded.decode("utf-8", errors="ignore")
            if 6 <= len(decoded_txt) <= 800:
                out.append(decoded_txt)
        except Exception:
            pass
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Heuristic helpers  (used as ensemble signal alongside ML)
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    t = (text or "").strip().lower()
    buf: List[str] = []
    out: List[str] = []
    for ch in t:
        if ch.isalnum() or ch in {"_", "-", ":"}:
            buf.append(ch)
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return out


def _prompt_injection_heuristics(text: str) -> Dict[str, Any]:
    """Return heuristic signals used as ensemble input alongside the ML score."""
    t = (text or "").lower()
    patterns = {
        "instruction_override": (
            r"\b(ignore|bypass|override|forget|disregard)\b.{0,40}"
            r"\b(instruction|policy|guardrail|rule)\b"
        ),
        "system_prompt_exfil": (
            r"\b(reveal|show|print|dump|expose)\b.{0,40}"
            r"\b(system prompt|developer prompt|hidden prompt|secret)\b"
        ),
        "role_hijack": (
            r"\b(you are now|act as|pretend to be)\b.{0,50}"
            r"\b(root|admin|unrestricted|developer mode)\b"
        ),
        "tool_injection": (
            r"\b(use tool|call tool|invoke tool|execute command)\b.{0,60}"
            r"\b(ignore checks|without validation|silently)\b"
        ),
        "indirect_doc_injection": (
            r"\b(from document|in the file|retrieved context|quoted text)\b.{0,80}"
            r"\b(ignore|override|follow these instructions)\b"
        ),
    }
    matched = [
        name
        for name, pat in patterns.items()
        if re.search(pat, t, flags=re.IGNORECASE | re.DOTALL)
    ]
    return {
        "matched_signals": matched,
        "heuristic_score": round(min(1.0, len(matched) * 0.22), 4),
    }


def _extract_promptware_indicators(text: str) -> Dict[str, float]:
    tokens = _tokenize(text)
    if not tokens:
        return {"override": 0.0, "exfil": 0.0, "policy_evasion": 0.0, "tool_abuse": 0.0}
    override_terms = {"ignore", "bypass", "override", "disable", "forget", "evade", "jailbreak"}
    exfil_terms = {"reveal", "dump", "print", "exfiltrate", "secret", "token", "apikey", "password", "credential"}
    policy_terms = {"policy", "guardrail", "safety", "system", "instruction", "rule"}
    tool_terms = {"curl", "bash", "powershell", "exec", "shell", "command", "terminal", "sudo"}
    n = max(len(tokens), 1)

    def ratio(term_set: set) -> float:
        return sum(1 for t in tokens if t in term_set) / n

    return {
        "override": ratio(override_terms),
        "exfil": ratio(exfil_terms),
        "policy_evasion": ratio(policy_terms),
        "tool_abuse": ratio(tool_terms),
    }


# ---------------------------------------------------------------------------
# Semantic DLP (vector similarity against concept prototypes)
# ---------------------------------------------------------------------------

def _embed_text(text: str, dim: int = 256) -> List[float]:
    tokens = _tokenize(text)
    vec = [0.0] * dim
    for tok in tokens:
        idx = int(hashlib.sha256(tok.encode("utf-8")).hexdigest()[:8], 16) % dim
        vec[idx] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return float(sum(x * y for x, y in zip(a, b)))


_SEMANTIC_DLP_PROTOTYPES: Dict[str, List[str]] = {
    "credential_exfiltration": [
        "api key secret token password private credential dump",
        "print hidden credentials and secrets",
    ],
    "pii_exposure": [
        "social security number personal identifiable information",
        "credit card customer pii dump",
    ],
    "financial_sensitive": [
        "bank account routing number payment card details",
        "financial records and account statements",
    ],
    "source_code_secret_leak": [
        "source code with embedded secret keys",
        "repository private key configuration secret leak",
    ],
}
_SEMANTIC_DLP_EMBEDDINGS: Dict[str, List[List[float]]] = {
    k: [_embed_text(text) for text in vals]
    for k, vals in _SEMANTIC_DLP_PROTOTYPES.items()
}


def _scan_semantic_dlp(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not text or not text.strip():
        return findings
    emb = _embed_text(text)
    for concept, prototypes in _SEMANTIC_DLP_EMBEDDINGS.items():
        sims = [_cosine_similarity(emb, p) for p in prototypes]
        best = max(sims) if sims else 0.0
        if best >= _SEMANTIC_DLP_THRESHOLD:
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "semantic_dlp",
                    "concept": concept,
                    "similarity": round(best, 4),
                    "threshold": _SEMANTIC_DLP_THRESHOLD,
                    "severity": "high" if best >= 0.78 else "medium",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Regex fallback patterns (structured PII / dangerous output)
# ---------------------------------------------------------------------------

# These are kept as complementary signals when the NER model is unavailable
# or for patterns it doesn't reliably detect (e.g. exact AWS key format).
_SENSITIVE_REGEX_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "credit_card",
        re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?"
            r"\d{4}[- ]?\d{4}[- ]?\d{4}\b"
        ),
    ),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
]

_ENTITY_REGEX_PATTERNS = [
    ("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")),
    (
        "phone",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
    ),
    (
        "generic_api_key",
        re.compile(r"\b(?:sk|api|token)_[A-Za-z0-9]{12,}\b", re.IGNORECASE),
    ),
]

# Dangerous output patterns (command injection, XSS, browser data exfil).
# The zero-shot ML model is the primary detector; these patterns act as
# high-confidence supplementary signals.
_DANGEROUS_OUTPUT_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)", re.IGNORECASE),
    re.compile(r"powershell\s+-enc", re.IGNORECASE),
    re.compile(
        r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL
    ),
    re.compile(r"\bon\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*[^\s]+", re.IGNORECASE),
    re.compile(
        r"(?:document\.cookie|localStorage|sessionStorage|innerHTML\s*=)",
        re.IGNORECASE,
    ),
]

# Optional legacy prompt-injection regex (disabled by default)
_LEGACY_PROMPT_PATTERNS = [
    re.compile(r"ignore\\s+(all\\s+)?previous\\s+instructions", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"reveal\\s+(your|the)\\s+system\\s+prompt", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Promptware session tracker
# ---------------------------------------------------------------------------


class PromptwareSessionTracker:
    def __init__(self) -> None:
        self._sessions: Dict[str, deque] = {}
        self._lock = Lock()

    def _prune(self, q: deque, now_ts: float) -> None:
        while q and (now_ts - q[0]["ts"]) > _PROMPTWARE_SESSION_WINDOW_SECONDS:
            q.popleft()

    def _compute_chain_state(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        chain = 0.0
        weight = 1.0
        decay = 0.86
        combined: Dict[str, float] = {
            "override": 0.0, "exfil": 0.0, "policy_evasion": 0.0, "tool_abuse": 0.0
        }
        for ev in reversed(events):
            chain += ev["event_score"] * weight
            for k in combined:
                combined[k] += ev["indicators"][k] * weight
            weight *= decay
        chain = max(0.0, min(1.0, chain))
        for k in combined:
            combined[k] = round(max(0.0, min(1.0, combined[k])), 4)
        return {
            "event_count": len(events),
            "chain_confidence": round(chain, 4),
            "indicators": combined,
            "warn_threshold": _PROMPTWARE_CHAIN_WARN_THRESHOLD,
            "block_threshold": _PROMPTWARE_CHAIN_BLOCK_THRESHOLD,
        }

    def observe(
        self,
        session_key: str,
        text: str,
        pi_confidence: float,
    ) -> Optional[Dict[str, Any]]:
        if not session_key:
            return None
        indicators = _extract_promptware_indicators(text)
        now_ts = time.time()
        event_score = min(
            1.0,
            max(
                0.0,
                (0.62 * max(0.0, min(1.0, pi_confidence)))
                + (0.20 * indicators["override"])
                + (0.10 * indicators["exfil"])
                + (0.05 * indicators["policy_evasion"])
                + (0.03 * indicators["tool_abuse"]),
            ),
        )
        with self._lock:
            bucket = self._sessions.setdefault(
                session_key, deque(maxlen=_PROMPTWARE_SESSION_MAX_EVENTS)
            )
            bucket.append(
                {
                    "ts": now_ts,
                    "event_score": event_score,
                    "pi_confidence": max(0.0, min(1.0, pi_confidence)),
                    "indicators": indicators,
                }
            )
            self._prune(bucket, now_ts)
            events = list(bucket)
        if len(events) < 2:
            return None
        state = self._compute_chain_state(events)
        chain = float(state["chain_confidence"])
        if chain < _PROMPTWARE_CHAIN_WARN_THRESHOLD:
            return None
        return {
            "type": "promptware_attack_chain",
            "detector": "session_correlation",
            "session_id": session_key,
            "event_count": state["event_count"],
            "confidence": chain,
            "warn_threshold": state["warn_threshold"],
            "block_threshold": state["block_threshold"],
            "indicators": state["indicators"],
            "severity": "high" if chain >= _PROMPTWARE_CHAIN_BLOCK_THRESHOLD else "medium",
        }

    def snapshot(self, session_key: str) -> Dict[str, Any]:
        empty: Dict[str, Any] = {
            "session_id": session_key or "",
            "event_count": 0,
            "chain_confidence": 0.0,
            "indicators": {
                "override": 0.0, "exfil": 0.0,
                "policy_evasion": 0.0, "tool_abuse": 0.0,
            },
            "warn_threshold": _PROMPTWARE_CHAIN_WARN_THRESHOLD,
            "block_threshold": _PROMPTWARE_CHAIN_BLOCK_THRESHOLD,
        }
        if not session_key:
            return empty
        with self._lock:
            bucket = self._sessions.get(session_key)
            if not bucket:
                return empty
            self._prune(bucket, time.time())
            events = list(bucket)
        state = self._compute_chain_state(events)
        return {
            "session_id": session_key,
            "event_count": state["event_count"],
            "chain_confidence": state["chain_confidence"],
            "indicators": state["indicators"],
            "warn_threshold": state["warn_threshold"],
            "block_threshold": state["block_threshold"],
        }


_PROMPTWARE_TRACKER = PromptwareSessionTracker()


def _derive_session_key(
    tenant_id: str,
    direction: str,
    source_url: Optional[str],
    session_id: Optional[str],
) -> str:
    if session_id and session_id.strip():
        base = session_id.strip()
    elif source_url and source_url.strip():
        base = source_url.strip()
    else:
        base = "anonymous"
    return f"{tenant_id}:{direction}:{base}"


# ---------------------------------------------------------------------------
# Core detection functions
# ---------------------------------------------------------------------------


def _scan_prompt_injection(text: str) -> List[Dict[str, Any]]:
    """Detect prompt injection attacks.

    Pipeline:
      1. ML classifier (DeBERTa fine-tuned) → primary
      2. Heuristic ensemble (complements ML score)
      3. Legacy regex (optional, compat flag)
    """
    findings: List[Dict[str, Any]] = []
    normalized = _normalize_adversarial_text(text or "")
    expanded = _decode_obfuscated_segments(normalized)

    heur = _prompt_injection_heuristics(expanded)
    heur_score = float(heur.get("heuristic_score", 0.0))

    # --- ML primary ---
    ml_result = prompt_injection_detector.detect(expanded)
    if ml_result and ml_result.get("available"):
        prob = float(ml_result.get("confidence", 0.0))
        if ml_result.get("is_injection") and prob >= _PI_ML_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "ml_classifier",
                    "model": ml_result.get("model"),
                    "confidence": prob,
                    "threshold": _PI_ML_THRESHOLD,
                    "rationale": heur.get("matched_signals", []),
                    "severity": "high" if prob >= 0.82 else "medium",
                }
            )
        # Ensemble: blend ML confidence + heuristic signal
        ensemble_conf = max(
            0.0, min(1.0, (0.75 * prob) + (0.25 * heur_score))
        )
        if ensemble_conf >= _PI_ENSEMBLE_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "ensemble",
                    "model": ml_result.get("model"),
                    "confidence": round(ensemble_conf, 4),
                    "threshold": _PI_ENSEMBLE_THRESHOLD,
                    "signals": heur.get("matched_signals", []),
                    "severity": "high" if ensemble_conf >= 0.82 else "medium",
                }
            )
    else:
        # ML unavailable – fall back to heuristics alone
        if heur_score >= _PI_ENSEMBLE_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "heuristic_fallback",
                    "confidence": round(heur_score, 4),
                    "signals": heur.get("matched_signals", []),
                    "severity": "high" if heur_score >= 0.82 else "medium",
                }
            )

    # --- Legacy regex (optional compat flag) ---
    if _LEGACY_PROMPT_REGEX_ENABLED:
        for pattern in _LEGACY_PROMPT_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    {
                        "type": "prompt_injection",
                        "detector": "legacy_regex",
                        "pattern": pattern.pattern,
                        "match": match.group(0)[:120],
                        "severity": "medium",
                    }
                )
    return findings


def _scan_sensitive_data(text: str) -> List[Dict[str, Any]]:
    """Detect sensitive data / PII.

    Pipeline:
      1. NER model (primary) – dslim/bert-base-NER
      2. Regex fallback for structured patterns (SSN, CC, AWS key, private key)
      3. Semantic DLP vector similarity
      4. Entity regex (email, phone, IBAN, JWT, generic API keys)
      5. Exfiltration intent signals
    """
    findings: List[Dict[str, Any]] = []
    normalized = _normalize_adversarial_text(text or "")
    expanded = _decode_obfuscated_segments(normalized)

    # 1. NER-based PII (primary ML detector)
    findings.extend(ner_pii_detector.detect(expanded))

    # 2. Regex fallback for structured patterns that NER may miss
    for name, pattern in _SENSITIVE_REGEX_PATTERNS:
        for match in pattern.finditer(expanded):
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": name,
                    "match": match.group(0)[:120],
                    "severity": "high" if name in {"private_key", "aws_key"} else "medium",
                    "detector": "regex_fallback",
                }
            )

    # 3. Semantic DLP
    findings.extend(_scan_semantic_dlp(expanded))

    # 4. Entity-aware regex (email, phone, IBAN, JWT, API keys)
    for name, pat in _ENTITY_REGEX_PATTERNS:
        for m in pat.finditer(text):
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "entity_dlp",
                    "entity": name,
                    "match": m.group(0)[:120],
                    "severity": "medium" if name in {"email", "phone"} else "high",
                    "detector": "entity_regex",
                }
            )

    # 5. Exfiltration intent
    findings.extend(_scan_exfil_intent(expanded))
    return findings


def _scan_exfil_intent(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    t = (text or "").lower()
    intent_patterns = [
        r"\b(export|send|transmit|leak|exfiltrat\w*)\b.{0,40}\b(data|records|credentials|tokens|customer)\b",
        r"\b(upload|post|paste)\b.{0,40}\b(external|public|gist|pastebin|webhook)\b",
        r"\bcopy\b.{0,20}\b(all|entire)\b.{0,40}\b(database|table|customer|invoice|email)\b",
    ]
    hits = sum(
        1
        for pat in intent_patterns
        if re.search(pat, t, flags=re.IGNORECASE | re.DOTALL)
    )
    if hits > 0:
        findings.append(
            {
                "type": "sensitive_data",
                "subtype": "semantic_exfil_intent",
                "intent_score": round(min(1.0, hits * 0.38), 4),
                "severity": "high" if hits >= 2 else "medium",
            }
        )
    return findings


def _scan_output_safety(text: str) -> List[Dict[str, Any]]:
    """Detect dangerous output (command injection, XSS, browser data exfil).

    Pipeline:
      1. Zero-shot ML classifier (facebook/bart-large-mnli) – primary
      2. Regex patterns – supplementary high-confidence fallback
    """
    findings: List[Dict[str, Any]] = []

    # 1. Zero-shot ML (primary)
    zs_findings = zero_shot_detector.detect(text)
    # Filter to output-safety relevant labels
    _output_labels = {
        "harmful content generation request",
        "data exfiltration attempt",
    }
    for f in zs_findings:
        if f.get("label") in _output_labels:
            f["type"] = "dangerous_output"
            findings.append(f)

    # 2. Regex supplementary patterns
    for pattern in _DANGEROUS_OUTPUT_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                {
                    "type": "dangerous_output",
                    "pattern": pattern.pattern,
                    "match": match.group(0)[:120],
                    "severity": "high",
                    "detector": "regex_supplementary",
                }
            )
    return findings


def _scan_toxicity(text: str) -> List[Dict[str, Any]]:
    """Detect toxic / harmful content via ML classifier."""
    result = toxicity_detector.detect(text)
    return [result] if result else []


def _scan_ollama_judge(text: str, pre_score: float) -> List[Dict[str, Any]]:
    """Optional Ollama LLM second-pass judge.

    Only invoked when the pre-scan risk score exceeds OLLAMA_JUDGE_RISK_TRIGGER
    so that latency is not added to clearly benign requests.
    """
    if not OLLAMA_ENABLED or pre_score < _OLLAMA_JUDGE_RISK_TRIGGER:
        return []
    result = ollama_judge.analyze(text)
    return [result] if result else []


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


def _risk_score(findings: List[Dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    score = 0.0
    for f in findings:
        ftype = f.get("type", "")
        detector = f.get("detector", "")

        if ftype == "prompt_injection" and detector in {
            "ml_classifier", "ensemble", "heuristic_fallback",
        }:
            confidence = float(f.get("confidence", 0.0))
            threshold = float(f.get("threshold", _PI_ML_THRESHOLD))
            margin = max(0.0, confidence - threshold)
            score += min(_PI_RISK_BASE + (_PI_RISK_MULTIPLIER * margin), _PI_RISK_CAP)
            continue

        if ftype == "promptware_attack_chain":
            confidence = float(f.get("confidence", 0.0))
            score += min(0.45 + (0.45 * max(0.0, min(1.0, confidence))), 0.95)
            continue

        if ftype == "llm_threat_analysis":
            confidence = float(f.get("confidence", 0.0))
            sev = f.get("severity", "medium")
            base = {"high": 0.55, "medium": 0.35, "low": 0.15}.get(sev, 0.25)
            score += base + (0.3 * confidence)
            continue

        sev = f.get("severity", "low")
        if sev == "high":
            score += 0.35
        elif sev == "medium":
            score += 0.20
        else:
            score += 0.10

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _verify_api_key(api_key: Optional[str]) -> None:
    verify_shared_secret(api_key, DETECTION_API_SECRET, service_name="detection")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberArmor Detection Service", version="0.3.0")
SERVICE_STARTED_AT = time.time()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.3.0"}


@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "service": "detection",
        "version": "0.3.0",
        "ml_models": {
            "prompt_injection": "protectai/deberta-v3-base-prompt-injection-v2",
            "ner_pii": "dslim/bert-base-NER",
            "toxicity": "unitary/toxic-bert",
            "zero_shot": "facebook/bart-large-mnli",
        },
        "ollama_enabled": OLLAMA_ENABLED,
        "ollama_judge": ollama_judge.is_available(),
    }


@app.get("/metrics")
def metrics():
    uptime = round(time.time() - SERVICE_STARTED_AT, 3)
    return PlainTextResponse(
        "\n".join(
            [
                "# HELP cyberarmor_detection_uptime_seconds Service uptime in seconds",
                "# TYPE cyberarmor_detection_uptime_seconds gauge",
                f'cyberarmor_detection_uptime_seconds{{service="detection",version="0.3.0"}} {uptime}',
            ]
        )
        + "\n",
        media_type="text/plain",
    )


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("detection")


@app.post("/scan")
def scan(
    payload: GenericScanRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    text = payload.content or ""
    findings: List[Dict[str, Any]] = list(payload.local_findings)

    # Prompt injection + ensemble
    findings.extend(_scan_prompt_injection(text))

    # Promptware session correlation
    if _PROMPTWARE_SESSION_ENABLED:
        ml_conf = max(
            (
                float(f.get("confidence", 0.0))
                for f in findings
                if f.get("type") == "prompt_injection"
                and f.get("detector") == "ml_classifier"
            ),
            default=0.0,
        )
        session_key = _derive_session_key(
            payload.tenant_id, payload.direction, payload.source_url, payload.session_id
        )
        chain_finding = _PROMPTWARE_TRACKER.observe(
            session_key=session_key, text=text, pi_confidence=ml_conf
        )
        if chain_finding is not None:
            findings.append(chain_finding)

    # Sensitive data / DLP
    findings.extend(_scan_sensitive_data(text))

    # Output safety
    findings.extend(_scan_output_safety(text))

    # Toxicity
    findings.extend(_scan_toxicity(text))

    # Intermediate risk score (before Ollama second pass)
    pre_score = _risk_score(findings)

    # Optional Ollama LLM judge (high-risk second pass)
    findings.extend(_scan_ollama_judge(text, pre_score))

    score = _risk_score(findings)
    action = "allow"
    reason = ""
    if score >= 0.70:
        action = "block"
        reason = "high_risk_content_detected"
    elif score >= 0.35:
        action = "warn"
        reason = "medium_risk_content_detected"

    return {
        "action": action,
        "reason": reason,
        "risk_score": score,
        "detections": findings,
        "tenant_id": payload.tenant_id,
        "direction": payload.direction,
    }


@app.post("/scan/prompt-injection")
def scan_prompt(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_prompt_injection(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/promptware")
def scan_promptware(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_prompt_injection(payload.text)
    session_key = _derive_session_key("default", "request", None, payload.session_id)
    chain_finding = None
    if _PROMPTWARE_SESSION_ENABLED:
        ml_conf = max(
            (
                float(f.get("confidence", 0.0))
                for f in findings
                if f.get("type") == "prompt_injection"
                and f.get("detector") == "ml_classifier"
            ),
            default=0.0,
        )
        chain_finding = _PROMPTWARE_TRACKER.observe(
            session_key=session_key, text=payload.text, pi_confidence=ml_conf
        )
        if chain_finding is not None:
            findings.append(chain_finding)
    return {
        "risk_score": _risk_score(findings),
        "detections": findings,
        "session_state": _PROMPTWARE_TRACKER.snapshot(session_key),
        "session_tracking_enabled": _PROMPTWARE_SESSION_ENABLED,
        "chain_detection": chain_finding,
    }


@app.post("/scan/sensitive-data")
def scan_sensitive(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_sensitive_data(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/output-safety")
def scan_output(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_output_safety(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/toxicity")
def scan_toxicity(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_toxicity(payload.text)
    return {"risk_score": _risk_score(findings), "detections": findings}


@app.post("/scan/all")
def scan_all(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings: List[Dict[str, Any]] = []
    findings.extend(_scan_prompt_injection(payload.text))
    findings.extend(_scan_sensitive_data(payload.text))
    findings.extend(_scan_output_safety(payload.text))
    findings.extend(_scan_toxicity(payload.text))
    pre_score = _risk_score(findings)
    findings.extend(_scan_ollama_judge(payload.text, pre_score))
    return {"risk_score": _risk_score(findings), "detections": findings}
