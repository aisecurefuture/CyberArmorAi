"""Local redaction helpers for endpoint DLP workflows.

The endpoint agent keeps raw sensitive values out of telemetry. Classifiers can
still provide context before redaction, but emitted evidence uses placeholders,
counts, categories, and hashes instead of raw values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Pattern


@dataclass(frozen=True)
class RedactionPattern:
    label: str
    category: str
    placeholder: str
    pattern: Pattern[str]


@dataclass
class RedactionFinding:
    label: str
    category: str
    count: int


@dataclass
class RedactionResult:
    text: str
    action: str
    findings: List[RedactionFinding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(f.count for f in self.findings)

    @property
    def changed(self) -> bool:
        return self.count > 0


REDACTION_PATTERNS: List[RedactionPattern] = [
    RedactionPattern("SSN", "pii", "[REDACTED-SSN]", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    RedactionPattern("Email", "pii", "[REDACTED-EMAIL]", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    RedactionPattern("Phone", "pii", "[REDACTED-PHONE]", re.compile(r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")),
    RedactionPattern("Date of Birth", "pii", "[REDACTED-DOB]", re.compile(r"\b(?:dob|date of birth)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.I)),
    RedactionPattern("Credit Card", "pci", "[REDACTED-CARD]", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    RedactionPattern("Routing Number", "nacha", "[REDACTED-ROUTING]", re.compile(r"\b\d{9}\b")),
    RedactionPattern("Bank Account", "nacha", "[REDACTED-BANK-ACCOUNT]", re.compile(r"\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b", re.I)),
    RedactionPattern("IBAN", "nacha", "[REDACTED-IBAN]", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    RedactionPattern("NPI", "npi", "[REDACTED-NPI]", re.compile(r"\b(?:npi\s*[:#]?\s*)?\d{10}\b", re.I)),
    RedactionPattern("Private IP", "nonpublic", "[REDACTED-PRIVATE-IP]", re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
    RedactionPattern("AWS Access Key", "secrets", "[REDACTED-AWS-KEY]", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    RedactionPattern("OpenAI Key", "secrets", "[REDACTED-OPENAI-KEY]", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    RedactionPattern("Anthropic Key", "secrets", "[REDACTED-ANTHROPIC-KEY]", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    RedactionPattern("GitHub Token", "secrets", "[REDACTED-GITHUB-TOKEN]", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{36,}\b")),
    RedactionPattern("Slack Token", "secrets", "[REDACTED-SLACK-TOKEN]", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    RedactionPattern("Stripe Key", "secrets", "[REDACTED-STRIPE-KEY]", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    RedactionPattern("Bearer Token", "secrets", "[REDACTED-BEARER]", re.compile(r"\bBearer\s+[A-Za-z0-9_.-]{20,}\b")),
    RedactionPattern("JWT", "secrets", "[REDACTED-JWT]", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b")),
    RedactionPattern("Password", "secrets", "[REDACTED-PASSWORD]", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}", re.I)),
    RedactionPattern("API Key", "secrets", "[REDACTED-API-KEY]", re.compile(r"\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}", re.I)),
    RedactionPattern(
        "Private Key",
        "secrets",
        "[REDACTED-PRIVATE-KEY]",
        re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
    ),
]


REDACTION_CATEGORIES: Dict[str, List[str]] = {
    "redact": ["secrets", "pii", "pci", "nacha", "npi", "nonpublic"],
    "redact-secrets": ["secrets"],
    "redact-pii": ["pii"],
    "redact-pci": ["pci"],
    "redact-nacha": ["nacha"],
    "redact-npi": ["npi"],
    "redact-npii": ["npi"],
    "redact-nonpublic": ["nonpublic"],
}


def normalize_action(action: str) -> str:
    normalized = (action or "").strip().lower().replace("_", "-")
    if normalized == "redact-nachi":
        return "redact-nacha"
    return normalized


def is_redaction_action(action: str) -> bool:
    return normalize_action(action) in REDACTION_CATEGORIES


def categories_for_action(action: str) -> List[str]:
    return list(REDACTION_CATEGORIES.get(normalize_action(action), REDACTION_CATEGORIES["redact"]))


def patterns_for_action(action: str) -> Iterable[RedactionPattern]:
    categories = set(categories_for_action(action))
    return (pattern for pattern in REDACTION_PATTERNS if pattern.category in categories)


def redact_text(text: str, action: str = "redact") -> RedactionResult:
    redacted = str(text or "")
    findings: List[RedactionFinding] = []
    for redaction_pattern in patterns_for_action(action):
        redacted, count = redaction_pattern.pattern.subn(redaction_pattern.placeholder, redacted)
        if count:
            findings.append(
                RedactionFinding(
                    label=redaction_pattern.label,
                    category=redaction_pattern.category,
                    count=count,
                )
            )
    return RedactionResult(text=redacted, action=normalize_action(action) or "redact", findings=findings)
