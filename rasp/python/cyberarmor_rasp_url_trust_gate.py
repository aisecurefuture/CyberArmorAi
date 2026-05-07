"""RASP outbound HTTP hook for the URL / Context Trust Gate.

Status: scaffold. Wraps the most common Python HTTP clients (requests,
httpx, urllib3) to consult the URL Trust Gate before any outbound
request reaches the network. The intent is to protect server-side AI
agents and tools that fetch external content into LLM context: those
fetches MUST go through the gate or hostile pages can land prompt
injection / promptware payloads inside the model.

Wire-up: call `enable(api_key=..., gate_url=..., tenant_id=...)` once at
process start (e.g. inside `cyberarmor_rasp.init`). Each hooked client
call then makes a synchronous `depth=fast` request to the gate. On
`block`/`isolate` the call raises `URLBlockedByTrustGate`; on `warn` /
`redact` the call proceeds but the verdict is recorded for the audit
layer.

This module is conservative on purpose:
  - Fail-open if the gate is unreachable (reachability is a separate
    monitoring concern; we do not want to break legitimate outbound
    traffic when the gate is down).
  - Never inspects request bodies. Only the URL is shipped to the gate.
  - Skips internal / loopback / link-local destinations so internal
    service-to-service calls are never round-tripped through the gate.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("cyberarmor_rasp.url_trust_gate")

DEFAULT_GATE_URL = os.getenv(
    "CYBERARMOR_URL_TRUST_GATE_URL", "http://url-trust-gate:8005/evaluate"
)
DEFAULT_TIMEOUT_S = float(os.getenv("CYBERARMOR_URL_TRUST_GATE_TIMEOUT_S", "1.5"))


class URLBlockedByTrustGate(Exception):
    """Raised when the gate returns a `block`/`isolate` verdict."""

    def __init__(self, url: str, reason: str, evidence_id: Optional[str] = None):
        super().__init__(f"blocked: {url} ({reason})")
        self.url = url
        self.reason = reason
        self.evidence_id = evidence_id


_state = {
    "enabled": False,
    "api_key": "",
    "gate_url": DEFAULT_GATE_URL,
    "tenant_id": "default",
    "timeout_s": DEFAULT_TIMEOUT_S,
    "patched": False,
}
_state_lock = threading.Lock()

# Local cache so a tight retry loop doesn't hammer the gate.
_RECENT: Dict[str, tuple[float, dict]] = {}
_RECENT_TTL_S = 60


def enable(
    *,
    api_key: str,
    gate_url: str = DEFAULT_GATE_URL,
    tenant_id: str = "default",
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> None:
    """Enable URL Trust Gate enforcement on outbound HTTP clients."""

    with _state_lock:
        _state.update(
            enabled=True,
            api_key=api_key,
            gate_url=gate_url,
            tenant_id=tenant_id,
            timeout_s=timeout_s,
        )
        if not _state["patched"]:
            _patch_clients()
            _state["patched"] = True


def disable() -> None:
    with _state_lock:
        _state["enabled"] = False


def _patch_clients() -> None:
    """Best-effort monkeypatch of the three common Python HTTP clients."""

    try:
        _patch_requests()
    except Exception as exc:
        logger.debug("requests patch skipped: %s", exc)
    try:
        _patch_httpx()
    except Exception as exc:
        logger.debug("httpx patch skipped: %s", exc)
    try:
        _patch_urllib3()
    except Exception as exc:
        logger.debug("urllib3 patch skipped: %s", exc)


def _patch_requests() -> None:
    import requests  # type: ignore

    original = requests.Session.send

    def wrapped(self, prepared, **kwargs):  # type: ignore[no-untyped-def]
        _check_or_raise(prepared.url, source="rasp:requests")
        return original(self, prepared, **kwargs)

    requests.Session.send = wrapped  # type: ignore[assignment]


def _patch_httpx() -> None:
    import httpx  # type: ignore

    original = httpx.Client.send
    original_async = httpx.AsyncClient.send

    def wrapped(self, request, **kwargs):  # type: ignore[no-untyped-def]
        _check_or_raise(str(request.url), source="rasp:httpx")
        return original(self, request, **kwargs)

    async def wrapped_async(self, request, **kwargs):  # type: ignore[no-untyped-def]
        _check_or_raise(str(request.url), source="rasp:httpx")
        return await original_async(self, request, **kwargs)

    httpx.Client.send = wrapped  # type: ignore[assignment]
    httpx.AsyncClient.send = wrapped_async  # type: ignore[assignment]


def _patch_urllib3() -> None:
    import urllib3  # type: ignore

    original = urllib3.connectionpool.HTTPConnectionPool.urlopen

    def wrapped(self, method, url, *args, **kwargs):  # type: ignore[no-untyped-def]
        scheme = "https" if self.scheme == "https" else "http"
        host = self.host
        full = f"{scheme}://{host}{url}" if url.startswith("/") else url
        _check_or_raise(full, source="rasp:urllib3")
        return original(self, method, url, *args, **kwargs)

    urllib3.connectionpool.HTTPConnectionPool.urlopen = wrapped  # type: ignore[assignment]


def _check_or_raise(url: str, *, source: str) -> None:
    if not _state["enabled"]:
        return
    if _is_internal(url):
        return

    cached = _recent_get(url)
    if cached is not None:
        _enforce(url, cached)
        return

    verdict = _consult_gate(url, source=source)
    if verdict is not None:
        _recent_put(url, verdict)
        _enforce(url, verdict)


def _enforce(url: str, verdict: dict) -> None:
    decision = verdict.get("decision") or {}
    action = (decision.get("action") or "allow").lower()
    if action in {"block", "isolate"}:
        raise URLBlockedByTrustGate(
            url=url,
            reason=decision.get("reason", "blocked by URL Trust Gate"),
            evidence_id=verdict.get("evidence_id"),
        )
    # warn / redact / sandbox — let the request proceed; the gate already
    # recorded evidence and the policy engine has the warn-channel
    # callbacks (toast / SOC notification) wired separately.


def _consult_gate(url: str, *, source: str) -> Optional[dict]:
    # Lazy-import requests so the patch doesn't fight itself: we use the
    # ORIGINAL unpatched bound method via the module reference.
    try:
        import requests  # type: ignore
    except Exception:
        return None

    payload = {
        "tenant_id": _state["tenant_id"],
        "url": url,
        "source": source,
        "depth": "fast",
    }
    try:
        # IMPORTANT: this call MUST not re-enter the patched send. We rely
        # on _is_internal() to short-circuit the gate's own host. If the
        # gate is deployed on an external/public host, this would loop —
        # operators should run the gate on an internal-only address.
        resp = requests.post(
            _state["gate_url"],
            json=payload,
            headers={"x-api-key": _state["api_key"]},
            timeout=_state["timeout_s"],
        )
        if resp.status_code != 200:
            logger.debug("url_trust_gate non-200 status=%s", resp.status_code)
            return None
        return resp.json()
    except Exception as exc:
        # Fail open. Outbound traffic should not break when the gate is
        # unreachable; reachability is monitored separately.
        logger.debug("url_trust_gate unreachable err=%s", exc)
        return None


def _is_internal(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except Exception:
        return False
    if not host:
        return True  # malformed; don't bother the gate
    if host == urlsplit(_state["gate_url"]).hostname:
        return True  # don't recurse into the gate
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_private
            or ip.is_reserved
        ):
            return True
    return False


def _recent_get(url: str) -> Optional[dict]:
    entry = _RECENT.get(url)
    if entry is None:
        return None
    ts, verdict = entry
    if time.monotonic() - ts > _RECENT_TTL_S:
        _RECENT.pop(url, None)
        return None
    return verdict


def _recent_put(url: str, verdict: dict) -> None:
    if len(_RECENT) > 5_000:
        # Cheap eviction.
        oldest = min(_RECENT.items(), key=lambda kv: kv[1][0])
        _RECENT.pop(oldest[0], None)
    _RECENT[url] = (time.monotonic(), verdict)


# TODO: extend with hooks for popular AI / agent frameworks once their
# tool-call plumbing is stable enough to monkeypatch:
#   - LangChain `BaseTool._run` (intercept URL-bearing tools).
#   - LlamaIndex `BaseReader` URL ingestion.
#   - OpenAI Assistants browse tool (gateway).
#   - Anthropic SDK tool_use blocks where input contains a URL.
# These are higher-value than the raw HTTP client patches because they
# operate on the URL the AGENT chose, not just the bytes on the wire.
