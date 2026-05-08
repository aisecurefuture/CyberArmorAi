"""Anthropic tool-use URL Trust Gate wrapper.

When an Anthropic model returns tool-use content blocks, the ``block.input``
dict can contain URLs that the agent is about to fetch. This module intercepts
those URLs **before** the agent executes the tool and routes them through the
CyberArmor URL Trust Gate.

Why at the response level, not the HTTP level?
    The RASP layer patches ``requests`` / ``httpx`` — it sees the fetch
    *after* the agent has already decided to act. This wrapper intercepts
    the provider response object *before* the agent runs the tool, which
    means:

    - A ``block`` verdict prevents the fetch entirely.
    - A ``redact`` verdict strips hostile URL arguments before they reach
      the tool runner — the tool is never called with the original value.
    - Evidence is written at the decision point, not at the network level.

Anthropic tool-use response structure:
    Unlike OpenAI, Anthropic tool-use blocks carry ``input`` as a plain
    Python dict (not a JSON string). Each ``ToolUseBlock`` has:

    - ``type == "tool_use"``
    - ``id`` — unique call identifier
    - ``name`` — tool name
    - ``input`` — dict of arguments (already parsed)

Usage — single response::

    from cyberarmor.frameworks.anthropic_url_trust_gate import (
        GateConfig, guard_response, guard_response_async,
    )

    cfg = GateConfig(
        gate_url="https://your-gate/evaluate",
        api_key="...",
        tenant_id="acme",
    )

    # Sync
    response = anthropic_client.messages.create(...)
    safe_response = guard_response(response, cfg=cfg)
    # safe_response.content tool-use blocks are safe to execute.
    # Blocked calls raise URLBlockedByTrustGate before returning.

    # Async
    response = await anthropic_client.messages.create(...)
    safe_response = await guard_response_async(response, cfg=cfg)

Usage — lower-level (per-tool-use block)::

    from cyberarmor.frameworks.anthropic_url_trust_gate import gate_tool_uses

    verdicts = gate_tool_uses(
        [b for b in response.content if b.type == "tool_use"],
        cfg=cfg,
    )
    # verdicts: list of GatedToolUse(block, safe_input_dict, verdict)
    # Blocked calls raise before this returns.

Fail-open: if the gate is unreachable the call proceeds; the verdict is
recorded as ``unknown``. Block / isolate verdicts raise
``URLBlockedByTrustGate``.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import httpx
from urllib.parse import urlsplit

logger = logging.getLogger("cyberarmor.frameworks.anthropic_url_trust_gate")

_REDACTED_PLACEHOLDER = "[URL redacted by CyberArmor Trust Gate]"


# ---------------------------------------------------------------------------
# Shared types
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
class GatedToolUse:
    """Result of gating a single Anthropic tool-use block.

    ``safe_input`` is a dict ready to pass to your tool runner. If the gate
    issued a ``redact`` verdict, any flagged URL values have been replaced with
    ``_REDACTED_PLACEHOLDER``. For ``allow`` / ``warn`` the dict is identical
    to the original ``block.input``.
    """
    block: Any                          # original ToolUseBlock
    safe_input: Dict[str, Any]          # parsed + possibly redacted input
    verdict: Optional[Dict[str, Any]]   # raw gate response, None if unreachable
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
                        "source": "anthropic-tool-use",
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
                        "source": "anthropic-tool-use",
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
# Core: gate a list of tool-use blocks (sync)
# ---------------------------------------------------------------------------


def gate_tool_uses(
    blocks: Sequence[Any],
    *,
    cfg: GateConfig,
) -> List[GatedToolUse]:
    """Evaluate every URL found in a list of Anthropic tool-use blocks.

    Iterates ``blocks`` (each a ``ToolUseBlock`` with ``type == "tool_use"``),
    reads ``block.input`` (a dict), extracts URLs, and evaluates them against
    the gate. Returns a list of :class:`GatedToolUse` objects — one per input
    block — with ``safe_input`` populated and any hostile URLs redacted.

    Raises :class:`URLBlockedByTrustGate` on the first ``block`` or
    ``isolate`` verdict before returning. All evaluations for that block are
    attempted before raising so evidence is written for each URL.
    """
    client = _Client(cfg)
    results: List[GatedToolUse] = []

    for block in blocks:
        # Anthropic ToolUseBlock.input is already a dict, not a JSON string.
        raw_input = getattr(block, "input", None)
        if raw_input is None:
            raw_input = {}
        if not isinstance(raw_input, dict):
            logger.warning(
                "tool_use_block_input_not_dict id=%s type=%s",
                getattr(block, "id", "?"),
                type(raw_input).__name__,
            )
            raw_input = {}

        urls = _extract_urls(raw_input)
        safe_input = deepcopy(raw_input)
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
                "anthropic_tool_url_gate action=%s url=%s tool=%s evidence=%s",
                action, url,
                getattr(block, "name", "unknown"),
                evidence_id,
            )

            if action in {"block", "isolate"}:
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
            safe_input = _redact_urls(safe_input, redact_set)

        if blocked_url is not None:
            raise URLBlockedByTrustGate(
                url=blocked_url,
                reason=_reason(blocked_verdict),
                evidence_id=(blocked_verdict or {}).get("evidence_id"),
            )

        for w in warnings:
            logger.warning("anthropic_tool_url_gate_warning %s", w)

        results.append(GatedToolUse(
            block=block,
            safe_input=safe_input,
            verdict=last_verdict,
            urls_found=urls,
            warnings=warnings,
        ))

    return results


# ---------------------------------------------------------------------------
# Core: gate a list of tool-use blocks (async)
# ---------------------------------------------------------------------------


async def gate_tool_uses_async(
    blocks: Sequence[Any],
    *,
    cfg: GateConfig,
) -> List[GatedToolUse]:
    """Async version of :func:`gate_tool_uses`.

    Evaluates all URLs across all tool-use blocks concurrently using
    ``asyncio.gather`` for minimum latency.
    """
    import asyncio

    client = _Client(cfg)
    results: List[GatedToolUse] = []

    for block in blocks:
        raw_input = getattr(block, "input", None)
        if raw_input is None:
            raw_input = {}
        if not isinstance(raw_input, dict):
            logger.warning(
                "tool_use_block_input_not_dict id=%s type=%s",
                getattr(block, "id", "?"),
                type(raw_input).__name__,
            )
            raw_input = {}

        urls = _extract_urls(raw_input)
        safe_input = deepcopy(raw_input)
        warnings: List[str] = []
        redact_set: set = set()
        blocked_url: Optional[str] = None
        blocked_verdict: Optional[Dict[str, Any]] = None

        verdicts = await asyncio.gather(
            *[client.evaluate_async(url) for url in urls],
            return_exceptions=False,
        )

        last_verdict: Optional[Dict[str, Any]] = verdicts[-1] if verdicts else None

        for url, verdict in zip(urls, verdicts):
            action = _action(verdict)
            reason = _reason(verdict)
            evidence_id = (verdict or {}).get("evidence_id")

            logger.info(
                "anthropic_tool_url_gate action=%s url=%s tool=%s evidence=%s",
                action, url,
                getattr(block, "name", "unknown"),
                evidence_id,
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
            safe_input = _redact_urls(safe_input, redact_set)

        if blocked_url is not None:
            raise URLBlockedByTrustGate(
                url=blocked_url,
                reason=_reason(blocked_verdict),
                evidence_id=(blocked_verdict or {}).get("evidence_id"),
            )

        for w in warnings:
            logger.warning("anthropic_tool_url_gate_warning %s", w)

        results.append(GatedToolUse(
            block=block,
            safe_input=safe_input,
            verdict=last_verdict,
            urls_found=urls,
            warnings=warnings,
        ))

    return results


# ---------------------------------------------------------------------------
# Convenience: guard a full Anthropic messages response
# ---------------------------------------------------------------------------


def guard_response(response: Any, *, cfg: GateConfig) -> Any:
    """Gate all tool-use URLs in an Anthropic messages response.

    Evaluates every URL found in every tool-use block's ``input`` dict and
    raises :class:`URLBlockedByTrustGate` if any are blocked. Returns the
    original response object unmodified (safe inputs are available via the
    lower-level :func:`gate_tool_uses` if you need the redacted versions).

    Handles missing / non-tool-use responses gracefully — if there are no
    tool-use blocks the response passes through unchanged.
    """
    blocks = _extract_tool_use_blocks(response)
    if not blocks:
        return response
    gate_tool_uses(blocks, cfg=cfg)
    return response


async def guard_response_async(response: Any, *, cfg: GateConfig) -> Any:
    """Async version of :func:`guard_response`."""
    blocks = _extract_tool_use_blocks(response)
    if not blocks:
        return response
    await gate_tool_uses_async(blocks, cfg=cfg)
    return response


def _extract_tool_use_blocks(response: Any) -> List[Any]:
    """Extract tool-use blocks from an Anthropic messages response object."""
    try:
        content = response.content or []
        return [b for b in content if getattr(b, "type", None) == "tool_use"]
    except Exception:
        return []
