"""CyberArmor RASP — Python Runtime Application Self-Protection.

Supports: WSGI, ASGI, requests, httpx, aiohttp monkey-patching.
Detects: AI/LLM API calls, prompt injection, sensitive data exfiltration.
"""

import functools
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("cyberarmor.rasp")


def _env(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value:
            return value
    return default


def _redeem_bootstrap_token(
    bootstrap_token: str,
    control_plane_url: str,
    *,
    package_key: str,
    subject_type: str,
    subject_name: str,
) -> Dict[str, Any]:
    payload = {
        "bootstrap_token": bootstrap_token,
        "package_key": package_key,
        "subject_type": subject_type,
        "subject_name": subject_name,
    }
    request = urllib.request.Request(
        f"{control_plane_url.rstrip('/')}/bootstrap/redeem",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.warning("CyberArmor RASP bootstrap redeem failed (%s): %s", exc.code, body[:300])
    except urllib.error.URLError as exc:
        logger.warning("CyberArmor RASP bootstrap redeem failed: %s", exc.reason)
    return {}

# ── Configuration ─────────────────────────────────────────
class RASPConfig:
    control_plane_url: str = _env("CYBERARMOR_URL", default="http://localhost:8000")
    api_key: str = _env("CYBERARMOR_API_KEY", default="")
    tenant_id: str = _env("CYBERARMOR_TENANT", default="default")
    bootstrap_token: str = _env("CYBERARMOR_BOOTSTRAP_TOKEN", default="")
    mode: str = _env("CYBERARMOR_MODE", default="monitor")  # monitor | warn | block | redact*
    dlp_enabled: bool = True
    prompt_injection_enabled: bool = True

    def __init__(self):
        if self.bootstrap_token and not self.api_key:
            redeemed = _redeem_bootstrap_token(
                self.bootstrap_token,
                self.control_plane_url,
                package_key="rasp-python",
                subject_type="rasp_runtime",
                subject_name=_env("CYBERARMOR_SUBJECT_NAME", default="python-rasp"),
            )
            runtime_env = redeemed.get("runtime_env", {})
            self.api_key = runtime_env.get("CYBERARMOR_API_KEY", self.api_key)
            self.tenant_id = runtime_env.get("CYBERARMOR_TENANT_ID", self.tenant_id)
            self.control_plane_url = redeemed.get("control_plane_url", self.control_plane_url)

config = RASPConfig()

# ── AI Endpoint Detection ─────────────────────────────────
AI_DOMAINS = {
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api-inference.huggingface.co",
    "api.together.xyz", "api.replicate.com", "api.groq.com",
}
AI_AZURE_PATTERN = re.compile(r"\.openai\.azure\.com|\.cognitiveservices\.azure\.com")

def is_ai_endpoint(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host in AI_DOMAINS or bool(AI_AZURE_PATTERN.search(host))
    except Exception:
        return False

# ── Prompt Injection Detection ────────────────────────────
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|in)", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),
    re.compile(r"<\s*(system|prompt|instruction)\s*>", re.I),
    re.compile(r"jailbreak|DAN\s+mode|bypass\s+filter", re.I),
    re.compile(r"forget\s+(everything|all|your)", re.I),
    re.compile(r"do\s+not\s+follow\s+(any|your)", re.I),
]

def detect_prompt_injection(text: str) -> Optional[str]:
    for p in PROMPT_INJECTION_PATTERNS:
        if p.search(text):
            return p.pattern
    return None

# ── DLP Patterns and Redaction ────────────────────────────
DLP_PATTERNS = [
    {"name": "ssn", "category": "pii", "placeholder": "[REDACTED-SSN]", "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b")},
    {"name": "email", "category": "pii", "placeholder": "[REDACTED-EMAIL]", "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")},
    {"name": "phone", "category": "pii", "placeholder": "[REDACTED-PHONE]", "pattern": re.compile(r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")},
    {"name": "credit_card", "category": "pci", "placeholder": "[REDACTED-CARD]", "pattern": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")},
    {"name": "routing_number", "category": "nacha", "placeholder": "[REDACTED-ROUTING]", "pattern": re.compile(r"\b\d{9}\b")},
    {"name": "bank_account", "category": "nacha", "placeholder": "[REDACTED-BANK-ACCOUNT]", "pattern": re.compile(r"\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b", re.I)},
    {"name": "npi", "category": "npi", "placeholder": "[REDACTED-NPI]", "pattern": re.compile(r"\b(?:npi\s*[:#]?\s*)?\d{10}\b", re.I)},
    {"name": "private_ip", "category": "nonpublic", "placeholder": "[REDACTED-PRIVATE-IP]", "pattern": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")},
    {"name": "aws_key", "category": "secrets", "placeholder": "[REDACTED-AWS-KEY]", "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b")},
    {"name": "openai_key", "category": "secrets", "placeholder": "[REDACTED-OPENAI-KEY]", "pattern": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")},
    {"name": "github_token", "category": "secrets", "placeholder": "[REDACTED-GITHUB-TOKEN]", "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b")},
    {"name": "bearer_token", "category": "secrets", "placeholder": "[REDACTED-BEARER]", "pattern": re.compile(r"\bBearer\s+[A-Za-z0-9_.-]{20,}\b")},
    {"name": "password", "category": "secrets", "placeholder": "[REDACTED-PASSWORD]", "pattern": re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}", re.I)},
    {"name": "private_key", "category": "secrets", "placeholder": "[REDACTED-PRIVATE-KEY]", "pattern": re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----")},
    {"name": "jwt", "category": "secrets", "placeholder": "[REDACTED-JWT]", "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b")},
    {"name": "api_key", "category": "secrets", "placeholder": "[REDACTED-API-KEY]", "pattern": re.compile(r"\b(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}", re.I)},
]

REDACTION_CATEGORIES = {
    "redact": {"secrets", "pii", "pci", "nacha", "npi", "nonpublic"},
    "redact-secrets": {"secrets"},
    "redact-pii": {"pii"},
    "redact-pci": {"pci"},
    "redact-nacha": {"nacha"},
    "redact-npi": {"npi"},
    "redact-nonpublic": {"nonpublic"},
}

def normalize_mode(mode: str) -> str:
    normalized = (mode or "").strip().lower().replace("_", "-")
    if normalized == "redact-nachi":
        return "redact-nacha"
    return normalized

def is_redaction_mode(mode: str) -> bool:
    return normalize_mode(mode) in REDACTION_CATEGORIES

def scan_dlp(text: str) -> List[str]:
    return [rule["name"] for rule in DLP_PATTERNS if rule["pattern"].search(text)]

def redact_text(text: str, mode: str = "redact") -> tuple[str, List[str]]:
    categories = REDACTION_CATEGORIES.get(normalize_mode(mode), REDACTION_CATEGORIES["redact"])
    redacted = text
    findings: List[str] = []
    for rule in DLP_PATTERNS:
        if rule["category"] not in categories:
            continue
        redacted, count = rule["pattern"].subn(rule["placeholder"], redacted)
        if count:
            findings.append(rule["name"])
    return redacted, findings

def _redact_json_value(value: Any, mode: str) -> Any:
    if isinstance(value, str):
        redacted, _ = redact_text(value, mode)
        return redacted
    if isinstance(value, list):
        return [_redact_json_value(item, mode) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json_value(item, mode) for key, item in value.items()}
    return value

def redact_provider_payload(body: str, mode: str) -> str:
    try:
        parsed = json.loads(body)
    except Exception:
        redacted, _ = redact_text(body, mode)
        return redacted
    redacted = _redact_json_value(parsed, mode)
    return json.dumps(redacted, separators=(",", ":"))

# ── Telemetry ─────────────────────────────────────────────
_event_buffer: List[Dict] = []
_buffer_lock = threading.Lock()

def _record_event(event_type: str, url: str, detail: str = ""):
    evt = {"ts": time.time(), "type": event_type, "url": url, "detail": detail[:200], "tenant": config.tenant_id}
    with _buffer_lock:
        _event_buffer.append(evt)
        if len(_event_buffer) >= 50:
            batch = list(_event_buffer)
            _event_buffer.clear()
            threading.Thread(target=_flush, args=(batch,), daemon=True).start()

def _flush(batch):
    try:
        import httpx
        httpx.post(f"{config.control_plane_url}/telemetry/ingest",
                    json=batch, headers={"x-api-key": config.api_key}, timeout=5)
    except Exception:
        pass

# ── Core Inspection ───────────────────────────────────────
class InspectionResult:
    def __init__(self, allowed=True, reason="", event_type="", redacted_body: str = ""):
        self.allowed = allowed
        self.reason = reason
        self.event_type = event_type
        self.redacted_body = redacted_body

def inspect_request(url: str, body: str = "") -> InspectionResult:
    """Inspect an outbound request to an AI service."""
    if not is_ai_endpoint(url):
        return InspectionResult()

    _record_event("ai_request", url)

    if config.prompt_injection_enabled and body:
        pattern = detect_prompt_injection(body)
        if pattern:
            _record_event("prompt_injection", url, pattern)
            if config.mode == "block":
                return InspectionResult(False, f"Prompt injection: {pattern}", "prompt_injection")

    if config.dlp_enabled and body:
        findings = scan_dlp(body)
        if findings:
            _record_event("sensitive_data", url, ",".join(findings))
            if config.mode == "block":
                return InspectionResult(False, f"Sensitive data: {','.join(findings)}", "dlp")
            if is_redaction_mode(config.mode):
                redacted_body = redact_provider_payload(body, config.mode)
                if redacted_body != body:
                    _record_event("sensitive_data_redacted", url, ",".join(findings))
                    return InspectionResult(True, "Sensitive data redacted", "dlp_redacted", redacted_body)

    return InspectionResult()

def inspect_response(url: str, body: str = "") -> InspectionResult:
    """Inspect and optionally redact response text from an AI service."""
    if not body or not is_ai_endpoint(url) or not is_redaction_mode(config.mode):
        return InspectionResult()
    findings = scan_dlp(body)
    if not findings:
        return InspectionResult()
    redacted_body = redact_provider_payload(body, config.mode)
    if redacted_body != body:
        _record_event("sensitive_response_redacted", url, ",".join(findings))
        return InspectionResult(True, "Sensitive response data redacted", "dlp_response_redacted", redacted_body)
    return InspectionResult()

# ── WSGI Middleware ────────────────────────────────────────
class CyberArmorWSGI:
    """WSGI middleware for AI traffic inspection."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        host = environ.get("HTTP_HOST", "")
        url = f"https://{host}{path}"

        if method == "POST" and is_ai_endpoint(url):
            body = environ["wsgi.input"].read()
            environ["wsgi.input"] = __import__("io").BytesIO(body)
            result = inspect_request(url, body.decode("utf-8", errors="ignore"))
            if not result.allowed:
                start_response("403 Forbidden", [("Content-Type", "application/json")])
                return [json.dumps({"error": result.reason, "policy": "cyberarmor-rasp"}).encode()]
            if result.redacted_body:
                redacted = result.redacted_body.encode("utf-8")
                environ["wsgi.input"] = __import__("io").BytesIO(redacted)
                environ["CONTENT_LENGTH"] = str(len(redacted))

        return self.app(environ, start_response)

# ── ASGI Middleware ────────────────────────────────────────
class CyberArmorASGI:
    """ASGI middleware for AI traffic inspection."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode()
        url = f"https://{host}{path}"

        if method == "POST" and is_ai_endpoint(url):
            body_parts = []
            async def receive_wrapper():
                msg = await receive()
                if msg["type"] == "http.request":
                    body_parts.append(msg.get("body", b""))
                return msg

            msg = await receive_wrapper()
            body = b"".join(body_parts).decode("utf-8", errors="ignore")
            result = inspect_request(url, body)
            if not result.allowed:
                await send({"type": "http.response.start", "status": 403, "headers": [[b"content-type", b"application/json"]]})
                await send({"type": "http.response.body", "body": json.dumps({"error": result.reason}).encode()})
                return
            if result.redacted_body:
                msg = {**msg, "body": result.redacted_body.encode("utf-8")}

            # Replay body
            async def replayed_receive():
                return msg
            await self.app(scope, replayed_receive, send)
        else:
            await self.app(scope, receive, send)

# ── Monkey-Patching (requests, httpx) ─────────────────────
_patched = False

def patch():
    """Monkey-patch popular HTTP libraries to intercept AI API calls."""
    global _patched
    if _patched:
        return
    _patched = True

    # Patch requests
    try:
        import requests
        _orig_request = requests.Session.request
        @functools.wraps(_orig_request)
        def patched_request(self, method, url, **kwargs):
            original_body_value = kwargs.get("json") if "json" in kwargs else kwargs.get("data")
            if method.upper() == "POST":
                body = original_body_value or ""
                if isinstance(body, dict):
                    body = json.dumps(body)
                elif isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                result = inspect_request(str(url), str(body))
                if not result.allowed:
                    raise PermissionError(f"CyberArmor RASP blocked: {result.reason}")
                if result.redacted_body:
                    if "json" in kwargs:
                        try:
                            kwargs["json"] = json.loads(result.redacted_body)
                        except Exception:
                            kwargs["data"] = result.redacted_body
                            kwargs.pop("json", None)
                    elif isinstance(original_body_value, bytes):
                        kwargs["data"] = result.redacted_body.encode("utf-8")
                    else:
                        kwargs["data"] = result.redacted_body
            response = _orig_request(self, method, url, **kwargs)
            try:
                content_type = response.headers.get("content-type", "")
                if "json" in content_type or "text" in content_type:
                    response_body = response.content.decode(response.encoding or "utf-8", errors="ignore")
                    response_result = inspect_response(str(url), response_body)
                    if response_result.redacted_body:
                        response._content = response_result.redacted_body.encode(response.encoding or "utf-8")  # type: ignore[attr-defined]
            except Exception:
                pass
            return response
        requests.Session.request = patched_request
        logger.info("CyberArmor RASP: patched requests.Session")
    except ImportError:
        pass

    # Patch httpx
    try:
        import httpx
        _orig_send = httpx.Client.send
        @functools.wraps(_orig_send)
        def patched_send(self, request, **kwargs):
            if request.method == "POST":
                body = request.content.decode("utf-8", errors="ignore") if request.content else ""
                result = inspect_request(str(request.url), body)
                if not result.allowed:
                    raise PermissionError(f"CyberArmor RASP blocked: {result.reason}")
                if result.redacted_body:
                    request.stream = httpx.ByteStream(result.redacted_body.encode("utf-8"))
                    request.headers["Content-Length"] = str(len(result.redacted_body.encode("utf-8")))
            response = _orig_send(self, request, **kwargs)
            try:
                response_body = response.content.decode(response.encoding or "utf-8", errors="ignore")
                response_result = inspect_response(str(request.url), response_body)
                if response_result.redacted_body:
                    response._content = response_result.redacted_body.encode(response.encoding or "utf-8")  # type: ignore[attr-defined]
                    response.headers["Content-Length"] = str(len(response._content))  # type: ignore[attr-defined]
            except Exception:
                pass
            return response
        httpx.Client.send = patched_send
        logger.info("CyberArmor RASP: patched httpx.Client")
    except ImportError:
        pass

# ── Decorator API ─────────────────────────────────────────
def protect(func):
    """Decorator to protect a function that makes AI API calls."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        patch()
        return func(*args, **kwargs)
    return wrapper

# ── Auto-init ─────────────────────────────────────────────
def init(**kwargs):
    """Initialize CyberArmor RASP with custom configuration."""
    for k, v in kwargs.items():
        if hasattr(config, k):
            setattr(config, k, v)
    patch()
    logger.info("CyberArmor RASP initialized (mode=%s)", config.mode)


# Canonical class aliases for CyberArmor naming.
CyberArmorWSGI = CyberArmorWSGI
CyberArmorASGI = CyberArmorASGI
