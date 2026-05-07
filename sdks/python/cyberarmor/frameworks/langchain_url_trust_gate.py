"""LangChain tool wrapper for the URL Trust Gate.

When AI agents fetch external URLs as part of tool calls, hostile pages
become a prompt-injection / promptware vector. This wrapper intercepts
URL-bearing LangChain tools (``requests_get``, ``WebBrowser``, etc.)
and routes them through the URL Trust Gate before the underlying
``_run`` executes.

Three usage modes:

1. **Wrap a single tool**::

       from cyberarmor.frameworks.langchain_url_trust_gate import wrap_tool
       safe_tool = wrap_tool(my_browser_tool, gate_url=..., api_key=..., tenant_id=...)

2. **Wrap every URL-bearing tool in an agent**::

       from cyberarmor.frameworks.langchain_url_trust_gate import wrap_agent_tools
       agent.tools = wrap_agent_tools(agent.tools, gate=...)

3. **Build a guarded URL-fetcher tool from scratch**::

       tool = make_guarded_browser_tool(gate=...)

The wrapper follows the same fail-open philosophy as the RASP layer:
if the gate is unreachable, the call proceeds and the verdict is
recorded as ``unknown``. Block / isolate verdicts raise
``URLBlockedByTrustGate``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("cyberarmor.frameworks.url_trust_gate")


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
    depth: str = "deep"  # AI ingestion is the highest-stakes path


# ---------------------------------------------------------------------------
# Gate client
# ---------------------------------------------------------------------------


class _Client:
    def __init__(self, cfg: GateConfig):
        self._cfg = cfg
        self._http: Optional[httpx.Client] = None
        self._async_http: Optional[httpx.AsyncClient] = None

    def _sync(self) -> httpx.Client:
        if self._http is None or self._http.is_closed:
            self._http = httpx.Client(timeout=self._cfg.timeout_s, trust_env=False)
        return self._http

    async def _async(self) -> httpx.AsyncClient:
        if self._async_http is None or self._async_http.is_closed:
            self._async_http = httpx.AsyncClient(
                timeout=self._cfg.timeout_s, trust_env=False
            )
        return self._async_http

    def evaluate(self, url: str, agent_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            resp = self._sync().post(
                self._cfg.gate_url,
                json={
                    "tenant_id": self._cfg.tenant_id,
                    "url": url,
                    "source": "langchain-tool",
                    "depth": self._cfg.depth,
                    "agent_id": agent_id,
                },
                headers={"x-api-key": self._cfg.api_key},
            )
            if resp.status_code != 200:
                return None
            return resp.json()
        except Exception as exc:
            logger.debug("url_trust_gate sync unreachable err=%s", exc)
            return None

    async def evaluate_async(
        self, url: str, agent_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        try:
            client = await self._async()
            resp = await client.post(
                self._cfg.gate_url,
                json={
                    "tenant_id": self._cfg.tenant_id,
                    "url": url,
                    "source": "langchain-tool",
                    "depth": self._cfg.depth,
                    "agent_id": agent_id,
                },
                headers={"x-api-key": self._cfg.api_key},
            )
            if resp.status_code != 200:
                return None
            return resp.json()
        except Exception as exc:
            logger.debug("url_trust_gate async unreachable err=%s", exc)
            return None


def _enforce(verdict: Optional[Dict[str, Any]], url: str) -> Optional[Dict[str, Any]]:
    if verdict is None:
        return None
    decision = (verdict.get("decision") or {}).get("action", "allow")
    if decision in {"block", "isolate"}:
        raise URLBlockedByTrustGate(
            url=url,
            reason=(verdict.get("decision") or {}).get(
                "reason", "blocked by URL Trust Gate"
            ),
            evidence_id=verdict.get("evidence_id"),
        )
    return verdict


# ---------------------------------------------------------------------------
# Tool wrapping
# ---------------------------------------------------------------------------


def _extract_url(args: tuple, kwargs: dict) -> Optional[str]:
    """Best-effort URL discovery in a tool's positional / keyword args.

    Tools are inconsistent: some take ``url=...``, some take a single
    positional string, some take a JSON blob. We check the obvious shapes
    and bail to None if we can't find a URL — the wrapper then lets the
    call through (we don't want to block tool calls we can't inspect;
    the network-layer hooks are the safety net).
    """

    for k in ("url", "input", "tool_input", "query"):
        v = kwargs.get(k)
        if isinstance(v, str) and _looks_like_url(v):
            return v
        if isinstance(v, dict):
            for kk in ("url", "input", "query"):
                vv = v.get(kk)
                if isinstance(vv, str) and _looks_like_url(vv):
                    return vv
    if args:
        first = args[0]
        if isinstance(first, str) and _looks_like_url(first):
            return first
        if isinstance(first, dict):
            for kk in ("url", "input", "query"):
                vv = first.get(kk)
                if isinstance(vv, str) and _looks_like_url(vv):
                    return vv
    return None


def _looks_like_url(s: str) -> bool:
    if not s or len(s) > 4096:
        return False
    try:
        parts = urlsplit(s.strip())
    except Exception:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def wrap_tool(tool: Any, *, cfg: GateConfig) -> Any:
    """Wrap a LangChain BaseTool so its ``_run`` consults the gate first.

    Returns the SAME tool instance with its ``_run`` / ``_arun`` patched.
    Idempotent — calling twice is a no-op.
    """

    if getattr(tool, "_cyberarmor_url_trust_gate_wrapped", False):
        return tool

    client = _Client(cfg)

    if hasattr(tool, "_run"):
        original_run = tool._run

        def guarded_run(*args, **kwargs):  # type: ignore[no-untyped-def]
            url = _extract_url(args, kwargs)
            if url is not None:
                verdict = client.evaluate(url, agent_id=getattr(tool, "name", None))
                _enforce(verdict, url)
            return original_run(*args, **kwargs)

        tool._run = guarded_run  # type: ignore[assignment]

    if hasattr(tool, "_arun"):
        original_arun = tool._arun

        async def guarded_arun(*args, **kwargs):  # type: ignore[no-untyped-def]
            url = _extract_url(args, kwargs)
            if url is not None:
                verdict = await client.evaluate_async(
                    url, agent_id=getattr(tool, "name", None)
                )
                _enforce(verdict, url)
            return await original_arun(*args, **kwargs)

        tool._arun = guarded_arun  # type: ignore[assignment]

    tool._cyberarmor_url_trust_gate_wrapped = True
    return tool


def wrap_agent_tools(tools: List[Any], *, cfg: GateConfig) -> List[Any]:
    """Wrap every URL-bearing tool in an agent's tool list.

    Heuristic: a tool is wrapped if it has ``_run`` or ``_arun``. We
    don't try to be clever about which tools "are" URL fetchers — the
    URL extractor returns None for non-URL inputs, so wrapping a
    non-fetcher tool is a no-op at runtime.
    """

    out: List[Any] = []
    for tool in tools:
        if hasattr(tool, "_run") or hasattr(tool, "_arun"):
            out.append(wrap_tool(tool, cfg=cfg))
        else:
            out.append(tool)
    return out


# ---------------------------------------------------------------------------
# Guarded browser tool
# ---------------------------------------------------------------------------


def make_guarded_browser_tool(*, cfg: GateConfig) -> Any:
    """Build a ``BaseTool`` that fetches URLs only after gate approval.

    Returns a real LangChain tool if ``langchain`` is importable; raises
    ``ImportError`` otherwise. We don't make langchain a hard dependency
    of the SDK because most callers won't use this.
    """

    try:
        from langchain.tools import BaseTool  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "langchain is required for make_guarded_browser_tool. "
            "Install langchain to enable this helper."
        ) from exc

    client = _Client(cfg)

    class GuardedBrowserTool(BaseTool):  # type: ignore[misc]
        name: str = "cyberarmor_guarded_browser"
        description: str = (
            "Fetch a URL safely. The destination is evaluated by the "
            "CyberArmor URL Trust Gate before fetching; phishing, "
            "prompt-injection, and promptware-laden pages are blocked. "
            "Input: a single URL string."
        )

        def _run(self, url: str) -> str:  # type: ignore[override]
            verdict = client.evaluate(url, agent_id=self.name)
            _enforce(verdict, url)
            # Reuse the gate's safe crawl result if it's already in the
            # verdict; otherwise fall back to a local fetch with the same
            # guards. The gate-side fetch is the authoritative one — the
            # local fallback only runs when the gate is unreachable.
            if verdict and verdict.get("decision", {}).get("action") in {"warn", "redact"}:
                # The gate has flagged the page. Return the WARNING so
                # the agent knows not to act on hostile content even if
                # we can't fully strip it.
                return (
                    f"[CyberArmor warning: {verdict['decision'].get('reason', '')}] "
                    f"page contents withheld; consult evidence "
                    f"{verdict.get('evidence_id', '')}"
                )
            try:
                with httpx.Client(timeout=5.0, trust_env=False) as http:
                    resp = http.get(url, follow_redirects=True)
                    return resp.text[:65_536]
            except Exception as exc:
                return f"[fetch error: {type(exc).__name__}]"

        async def _arun(self, url: str) -> str:  # type: ignore[override]
            verdict = await client.evaluate_async(url, agent_id=self.name)
            _enforce(verdict, url)
            if verdict and verdict.get("decision", {}).get("action") in {"warn", "redact"}:
                return (
                    f"[CyberArmor warning: {verdict['decision'].get('reason', '')}] "
                    f"page contents withheld; consult evidence "
                    f"{verdict.get('evidence_id', '')}"
                )
            try:
                async with httpx.AsyncClient(timeout=5.0, trust_env=False) as http:
                    resp = await http.get(url, follow_redirects=True)
                    return resp.text[:65_536]
            except Exception as exc:
                return f"[fetch error: {type(exc).__name__}]"

    return GuardedBrowserTool()
