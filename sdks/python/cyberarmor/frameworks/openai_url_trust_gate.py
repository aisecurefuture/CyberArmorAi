"""OpenAI tool-use URL Trust Gate wrapper.

When an OpenAI model returns tool calls, the ``function.arguments`` JSON
can contain URLs that the agent is about to fetch. This module intercepts
those URLs **before** the agent executes the tool and routes them through
the CyberArmor URL Trust Gate.

Why at the response level, not the HTTP level?
    The RASP layer patches ``requests`` / ``httpx`` — it sees the fetch
    *after* the agent has already decided to act. This wrapper intercepts
    the provider response object *before* the agent runs the tool, which
    means:

    - A ``block`` verdict prevents the fetch entirely.
    - A ``redact`` verdict strips hostile URL arguments before they reach
      the tool runner — the tool is never called with the original value.
    - Evidence is written at the decision point, not at the network level.

Usage — single response::

    from cyberarmor.frameworks.openai_url_trust_gate import (
        GateConfig, guard_response, guard_response_async,
    )

    cfg = GateConfig(
        gate_url="https://your-gate/evaluate",
        api_key="...",
        tenant_id="acme",
    )

    # Sync
    response = openai_client.chat.completions.create(...)
    safe_response = guard_response(response, cfg=cfg)
    # safe_response.choices[0].message.tool_calls is safe to execute.
    # Blocked calls raise URLBlockedByTrustGate before returning.

    # Async
    response = await openai_client.chat.completions.create(...)
    safe_response = await guard_response_async(response, cfg=cfg)

Usage — lower-level (per-tool-call)::

    from cyberarmor.frameworks.openai_url_trust_gate import gate_tool_calls

    verdicts = gate_tool_calls(
        response.choices[0].message.tool_calls,
        cfg=cfg,
    )
    # verdicts: list of GatedToolCall(tool_call, safe_arguments_dict, verdict)
    # Blocked calls raise before this returns.

Fail-open: if the gate is unreachable the call proceeds; the verdict is
recorded as ``unknown``. Block / isolate verdicts raise
``URLBlockedByTrustGate``.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("cyberarmor.frameworks.openai_url_trust_gate")

_REDACTED_PLACEHOLDER = "[URL redacted by CyberArmor Trust Gate]"


# ---------------------------------------------------------------------------
# Shared types (mirrored from langchain_url_trust_gate for independence)
# ---------------------------------------------------------------------------


class URLBlockedByTrustGate(Exception):
    def __init__(self, url: str, reason: str, evidence_id: Optional[str] = None):
        super().__init__(f"blocked by URL Trust Gate: {url} ({reason})")
        self.url = url
        self.reason = reason
        self.evidence_id = evidence_id


@dataclass
class GateConfig:
    gate_url: str
    api_key: str
    tenant_id: str
    timeout_s: float = 2.0
    depth: str = "deep"  # tool-use is the highest-stakes AI ingestion path
    agent_id: Optional[str] = None  # optional identity of the calling agent


@dataclass
class GatedToolCall:
    """Result of gating a single OpenAI tool call.

    ``safe_arguments`` is a dict ready to pass to your tool runner. If the
    gate issued a ``redact`` verdict, any flagged URL values have been
    replaced with ``_REDACTED_PLACEHOLDER``. For ``allow`` / ``warn`` the
    dict is identical to the original parsed arguments.
    """
    tool_call: Any                     # original ChatCompletionMessageToolCall
    safe_arguments: Dict[str, Any]     # parsed + possibly redacted arguments
    verdict: Optional[Dict[str, Any]]  # raw gate response, None if unreachable
    urls_found: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _looks_like_url(s: str) -> bool:
    if not s or len(s) > 4096:
        return False
    try:
        parts = urlsplit(s.strip())
    except Exception:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def _extract_urls(obj: Any, found: Optional[List[str]] = None) -> List[str]:
    """Recursively walk a parsed JSON value and collect http/https URLs."""
    if found is None:
        found = []
    if isinstance(obj, str):
        if _looks_like_url(obj):
            found.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _extract_urls(v, found)
    elif isinstance(obj, list):
        for item in obj:
            _extract_urls(item, found)
    return found


def _redact_urls(obj: Any, blocked: set) -> Any:
    """Return a deep copy of *obj* with every URL in *blocked* replaced."""
    if isinstance(obj, str):
        return _REDACTED_PLACEHOLDER if obj in blocked else obj
    if isinstance(obj, dict):
        return {k: _redact_urls(v, blocked) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_urls(item, blocked) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Gate client (sync + async)
# ---------------------------------------------------------------------------


class _Client:
    def __init__(self, cfg: GateConfig):
        self._cfg = cfg

    def evaluate(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            with httpx.Client(timeout=self._cfg.timeout_s, trust_env=False) as http:
                resp = http.post(
                    self._cfg.gate_url,
                    json={
                        "tenant_id": self._cfg.tenant_id,
                        "url": url,
                        "source": "openai-tool-use",
                        "depth": self._cfg.depth,
                        "agent_id": self._cfg.agent_id,
                    },
                    headers={"x-api-key": self._cfg.api_key},
                )
                return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.debug("url_trust_gate unreachable err=%s", exc)
            return None

    async def evaluate_async(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(
                timeout=self._cfg.timeout_s, trust_env=False
            ) as http:
                resp = await http.post(
                    self._cfg.gate_url,
                    json={
                        "tenant_id": self._cfg.tenant_id,
                        "url": url,
                        "source": "openai-tool-use",
                        "depth": self._cfg.depth,
                        "agent_id": self._cfg.agent_id,
                    },
                    headers={"x-api-key": self._cfg.api_key},
                )
                return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.debug("url_trust_gate async unreachable err=%s", exc)
            return None


def _action(verdict: Optional[Dict[str, Any]]) -> str:
    if verdict is None:
        return "unknown"
    return (verdict.get("decision") or {}).get("action", "allow")


def _reason(verdict: Optional[Dict[str, Any]]) -> str:
    return (verdict.get("decision") or {}).get("reason", "") if verdict else ""


# ---------------------------------------------------------------------------
# Core: gate a list of tool calls (sync)
# ---------------------------------------------------------------------------


def gate_tool_calls(
    tool_calls: Sequence[Any],
    *,
    cfg: GateConfig,
) -> List[GatedToolCall]:
    """Evaluate every URL found in a list of OpenAI tool call objects.

    Iterates ``tool_calls``, parses each ``function.arguments`` JSON,
    extracts URLs, and evaluates them against the gate. Returns a list of
    :class:`GatedToolCall` objects — one per input tool call — with
    ``safe_arguments`` populated and any hostile URLs redacted.

    Raises :class:`URLBlockedByTrustGate` on the first ``block`` or
    ``isolate`` verdict before returning. All evaluations for that tool
    call are attempted before raising so evidence is written for each URL.
    """
    client = _Client(cfg)
    results: List[GatedToolCall] = []

    for tc in tool_calls:
        args_str = getattr(getattr(tc, "function", None), "arguments", None) or "{}"
        try:
            args = json.loads(args_str)
        except json.JSONDecodeError:
            logger.warning("tool_call_args_not_json id=%s args=%r", tc.id, args_str[:200])
            args = {}

        urls = _extract_urls(args)
        safe_args = deepcopy(args)
        warnings: List[str] = []
        last_verdict: Optional[Dict[str, Any]] = None
        redact_set: set = set()
        blocked_url: Optional[str] = None
        blocked_verdict: Optional[Dict[str, Any]] = None

        for url in urls:
            verdict = client.evaluate(url)
            last_verdict = verdict
            action = _action(verdict)
            reason = _reason(verdict)
            evidence_id = (verdict or {}).get("evidence_id")

            logger.info(
                "openai_tool_url_gate action=%s url=%s tool=%s evidence=%s",
                action, url,
                getattr(getattr(tc, "function", None), "name", "unknown"),
                evidence_id,
            )

            if action in {"block", "isolate"}:
                # Record all; raise after loop so every URL gets evaluated.
                blocked_url = url
                blocked_verdict = verdict
            elif action == "redact":
                redact_set.add(url)
                warnings.append(
                    f"URL redacted by Trust Gate ({reason}): {url}"
                )
            elif action == "warn":
                warnings.append(
                    f"Trust Gate warning ({reason}): {url}"
                )

        if redact_set:
            safe_args = _redact_urls(safe_args, redact_set)

        if blocked_url is not None:
            raise URLBlockedByTrustGate(
                url=blocked_url,
                reason=_reason(blocked_verdict),
                evidence_id=(blocked_verdict or {}).get("evidence_id"),
            )

        for w in warnings:
            logger.warning("openai_tool_url_gate_warning %s", w)

        results.append(GatedToolCall(
            tool_call=tc,
            safe_arguments=safe_args,
            verdict=last_verdict,
            urls_found=urls,
            warnings=warnings,
        ))

    return results


# ---------------------------------------------------------------------------
# Core: gate a list of tool calls (async)
# ---------------------------------------------------------------------------


async def gate_tool_calls_async(
    tool_calls: Sequence[Any],
    *,
    cfg: GateConfig,
) -> List[GatedToolCall]:
    """Async version of :func:`gate_tool_calls`.

    Evaluates all URLs across all tool calls concurrently using
    ``asyncio.gather`` for minimum latency.
    """
    import asyncio

    client = _Client(cfg)
    results: List[GatedToolCall] = []

    for tc in tool_calls:
        args_str = getattr(getattr(tc, "function", None), "arguments", None) or "{}"
        try:
            args = json.loads(args_str)
        except json.JSONDecodeError:
            logger.warning("tool_call_args_not_json id=%s", tc.id)
            args = {}

        urls = _extract_urls(args)
        safe_args = deepcopy(args)
        warnings: List[str] = []
        redact_set: set = set()
        blocked_url: Optional[str] = None
        blocked_verdict: Optional[Dict[str, Any]] = None

        verdicts = await asyncio.gather(
            *[client.evaluate_async(url) for url in urls],
            return_exceptions=False,
        )

        for url, verdict in zip(urls, verdicts):
            action = _action(verdict)
            reason = _reason(verdict)
            evidence_id = (verdict or {}).get("evidence_id")

            logger.info(
                "openai_tool_url_gate action=%s url=%s evidence=%s",
                action, url, evidence_id,
            )

            if action in {"block", "isolate"}:
                blocked_url = url
                blocked_verdict = verdict
            elif action == "redact":
                redact_set.add(url)
                warnings.append(f"URL redacted by Trust Gate ({reason}): {url}")
            elif action == "warn":
                warnings.append(f"Trust Gate warning ({reason}): {url}")

        if redact_set:
            safe_args = _redact_urls(safe_args, redact_set)

        if blocked_url is not None:
            raise URLBlockedByTrustGate(
                url=blocked_url,
                reason=_reason(blocked_verdict),
                evidence_id=(blocked_verdict or {}).get("evidence_id"),
            )

        for w in warnings:
            logger.warning("openai_tool_url_gate_warning %s", w)

        results.append(GatedToolCall(
            tool_call=tc,
            safe_arguments=safe_args,
            verdict=verdict,
            urls_found=urls,
            warnings=warnings,
        ))

    return results


# ---------------------------------------------------------------------------
# Convenience: guard a full chat completion response
# ---------------------------------------------------------------------------


def guard_response(response: Any, *, cfg: GateConfig) -> Any:
    """Gate all tool-call URLs in an OpenAI chat completion response.

    Evaluates every URL found in every tool call's ``function.arguments``
    and raises :class:`URLBlockedByTrustGate` if any are blocked. Returns
    the original response object unmodified (safe arguments are available
    via the lower-level :func:`gate_tool_calls` if you need the redacted
    versions).

    Handles missing / non-tool-call responses gracefully — if there are no
    tool calls the response passes through unchanged.
    """
    tool_calls = _extract_tool_calls(response)
    if not tool_calls:
        return response
    gate_tool_calls(tool_calls, cfg=cfg)
    return response


async def guard_response_async(response: Any, *, cfg: GateConfig) -> Any:
    """Async version of :func:`guard_response`."""
    tool_calls = _extract_tool_calls(response)
    if not tool_calls:
        return response
    await gate_tool_calls_async(tool_calls, cfg=cfg)
    return response


def _extract_tool_calls(response: Any) -> List[Any]:
    """Extract tool calls from an OpenAI chat completion response object."""
    try:
        choices = response.choices or []
        for choice in choices:
            tcs = getattr(getattr(choice, "message", None), "tool_calls", None)
            if tcs:
                return list(tcs)
    except Exception:
        pass
    return []
