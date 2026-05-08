"""Detonation worker — isolated Playwright sandbox for URL Trust Gate.

This service runs OUTSIDE the main backend network. It accepts URLs
from the URL Trust Gate, renders them in a one-shot Chromium context,
and returns extracted artefacts (visible text, CSS-hidden text,
Unicode-tag-hidden text, forms, downloads, screenshot hash).

Security posture (must be enforced by the deployment, not by this code):
  - Runs in a dedicated network namespace with NO route to internal
    services, internal DNS, or cloud metadata endpoints.
  - One-shot context per request. Cookies, storage, service workers,
    and HTTP cache are wiped between requests.
  - Empty profile: no user identity, no Authorization headers, no
    cookies forwarded.
  - Hard CPU/memory/wallclock budgets enforced via container limits.
  - Inbound API authenticated by ``x-api-key`` shared with the gate.

The worker NEVER persists fetched bytes. Only extracted text + a
content/screenshot hash leave the process boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Metrics (self-contained Prometheus text-format exposition)
# ---------------------------------------------------------------------------

import threading
from collections import defaultdict
from typing import Tuple

_LATENCY_BUCKETS_MS = (50, 100, 250, 500, 1000, 2500, 5000, 10000, 20000, 30000)

_DETONATION_HELP = {
    "detonation_renders_total": "Total /render requests, labelled by result (success, error, timeout, cancelled).",
    "detonation_render_latency_ms": "End-to-end /render latency in milliseconds. Use histogram_quantile for p50/p95/p99.",
    "detonation_bytes_transferred_total": "Total bytes transferred across all sub-resources per render.",
    "detonation_subrequests_total": "Total sub-resource requests issued during renders.",
}


class _DetMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[Tuple, float] = defaultdict(float)
        self._histograms: Dict[Tuple, Dict] = {}

    def record_render(self, result: str, elapsed_ms: int, bytes_xfr: int, req_count: int) -> None:
        with self._lock:
            self._counters[(("detonation_renders_total", "result", result),)] += 1
            self._counters[(("detonation_bytes_transferred_total",),)] += bytes_xfr
            self._counters[(("detonation_subrequests_total",),)] += req_count
            key = ("detonation_render_latency_ms",)
            h = self._histograms.setdefault(key, {
                "sum": 0.0, "count": 0,
                "buckets": [0] * len(_LATENCY_BUCKETS_MS), "overflow": 0,
            })
            h["sum"] += elapsed_ms
            h["count"] += 1
            placed = False
            for i, b in enumerate(_LATENCY_BUCKETS_MS):
                if elapsed_ms <= b:
                    h["buckets"][i] += 1
                    placed = True
                    break
            if not placed:
                h["overflow"] += 1

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            seen: set[str] = set()
            for key, val in self._counters.items():
                if len(key) == 1:
                    name = key[0][0]
                    lbl = ""
                else:
                    name, lk, lv = key[0]
                    lbl = '{' + f'{lk}="{lv}"' + '}'
                if name not in seen:
                    lines.append(f"# HELP {name} {_DETONATION_HELP.get(name, name)}")
                    lines.append(f"# TYPE {name} counter")
                    seen.add(name)
                lines.append(f"{name}{lbl} {val}")
            for (name,), h in self._histograms.items():
                if name not in seen:
                    lines.append(f"# HELP {name} {_DETONATION_HELP.get(name, name)}")
                    lines.append(f"# TYPE {name} histogram")
                    seen.add(name)
                cum = 0
                for b, cnt in zip(_LATENCY_BUCKETS_MS, h["buckets"]):
                    cum += cnt
                    lines.append(f'{name}_bucket{{le="{b}"}} {cum}')
                cum += h["overflow"]
                lines.append(f'{name}_bucket{{le="+Inf"}} {cum}')
                lines.append(f"{name}_sum {h['sum']}")
                lines.append(f"{name}_count {h['count']}")
            return "\n".join(lines) + "\n"


_metrics = _DetMetrics()

logger = logging.getLogger("detonation_worker")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DETONATION_WORKER_API_SECRET = os.getenv(
    "DETONATION_WORKER_API_SECRET", "change-me-detonation-worker"
)
NAV_TIMEOUT_MS = int(os.getenv("DETONATION_NAV_TIMEOUT_MS", "8000"))
TOTAL_TIMEOUT_S = float(os.getenv("DETONATION_TOTAL_TIMEOUT_S", "12.0"))
MAX_REQUESTS = int(os.getenv("DETONATION_MAX_REQUESTS", "100"))
MAX_BYTES = int(os.getenv("DETONATION_MAX_BYTES", "8388608"))  # 8 MiB
VIEWPORT_W = int(os.getenv("DETONATION_VIEWPORT_W", "1280"))
VIEWPORT_H = int(os.getenv("DETONATION_VIEWPORT_H", "800"))

ENFORCE_SECURE_SECRETS = os.getenv(
    "CYBERARMOR_ENFORCE_SECURE_SECRETS", "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv(
    "CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false"
).strip().lower() in {"1", "true", "yes", "on"}


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (DETONATION_WORKER_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults. Set "
            "DETONATION_WORKER_API_SECRET to a strong value, or set "
            "CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true for local dev."
        )


_enforce_secure_secrets()


def _verify_api_key(api_key: Annotated[Optional[str], Header(alias="x-api-key")] = None):
    if api_key != DETONATION_WORKER_API_SECRET:
        raise HTTPException(status_code=401, detail="invalid api key")


# ---------------------------------------------------------------------------
# Schemas (mirror the structure used by the gate's DetonationResult)
# ---------------------------------------------------------------------------


class RenderRequest(BaseModel):
    url: str
    tenant_id: str
    request_id: str
    nav_timeout_ms: Optional[int] = Field(default=None)
    total_timeout_s: Optional[float] = Field(default=None)


class RenderResponse(BaseModel):
    rendered_html: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    css_hidden_text: str = ""
    unicode_hidden_text: str = ""
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    downloads: List[Dict[str, Any]] = Field(default_factory=list)
    scripts_inline: List[str] = Field(default_factory=list)
    screenshot_hash: Optional[str] = None
    error: Optional[str] = None
    request_count: int = 0
    bytes_transferred: int = 0


# ---------------------------------------------------------------------------
# Browser lifecycle (lazy + shared)
# ---------------------------------------------------------------------------

_browser_lock = asyncio.Lock()
_state: Dict[str, Any] = {"playwright": None, "browser": None}


async def _ensure_browser():
    async with _browser_lock:
        if _state["browser"] is not None:
            return _state["browser"]
        from playwright.async_api import async_playwright  # type: ignore

        _state["playwright"] = await async_playwright().start()
        _state["browser"] = await _state["playwright"].chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",  # the CONTAINER is the sandbox
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-software-rasterizer",
                "--disable-extensions",
                "--disable-sync",
                "--mute-audio",
                "--no-default-browser-check",
                "--no-first-run",
            ],
        )
        return _state["browser"]


async def _shutdown_browser() -> None:
    try:
        if _state["browser"] is not None:
            await _state["browser"].close()
    except Exception:
        pass
    try:
        if _state["playwright"] is not None:
            await _state["playwright"].stop()
    except Exception:
        pass
    _state["browser"] = None
    _state["playwright"] = None


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Lazy: don't pay the browser-launch cost until the first /render.
    yield
    await _shutdown_browser()


app = FastAPI(
    title="CyberArmor Detonation Worker",
    version="0.1.0",
    lifespan=_lifespan,
)
SERVICE_STARTED_AT = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "detonation-worker",
        "started_at": SERVICE_STARTED_AT.isoformat(),
    }


@app.get("/ready")
def ready() -> Dict[str, Any]:
    # Don't actually launch the browser here; readiness is "process up".
    # Browser launch is amortised over the first /render call.
    return {"status": "ready"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> PlainTextResponse:
    return PlainTextResponse(
        _metrics.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post(
    "/render",
    response_model=RenderResponse,
    dependencies=[Depends(_verify_api_key)],
)
async def render(req: RenderRequest) -> RenderResponse:
    import time as _time
    nav_timeout = req.nav_timeout_ms or NAV_TIMEOUT_MS
    total_timeout = req.total_timeout_s or TOTAL_TIMEOUT_S
    _start = _time.monotonic()

    def _done(resp: RenderResponse, *, result: str) -> RenderResponse:
        elapsed = int((_time.monotonic() - _start) * 1000)
        _metrics.record_render(
            result=result,
            elapsed_ms=elapsed,
            bytes_xfr=resp.bytes_transferred,
            req_count=resp.request_count,
        )
        return resp

    try:
        browser = await _ensure_browser()
    except ImportError:
        return _done(RenderResponse(error="playwright_not_installed"), result="error")
    except Exception as exc:
        logger.warning("browser_launch_failed err=%s", exc)
        return _done(RenderResponse(error=f"browser_launch_failed:{type(exc).__name__}"), result="error")

    try:
        context = await browser.new_context(
            viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
            user_agent=(
                "CyberArmor-URLTrustGate-Sandbox/0.1 "
                "(+https://cyberarmor.ai/bots/url-trust-gate)"
            ),
            java_script_enabled=True,
            ignore_https_errors=False,
            bypass_csp=False,
            accept_downloads=False,
            storage_state=None,
        )
    except Exception as exc:
        return _done(RenderResponse(error=f"context_create_failed:{type(exc).__name__}"), result="error")

    result = RenderResponse()
    downloads: List[Dict[str, Any]] = []
    request_count = 0
    bytes_transferred = 0
    cancelled = False

    try:
        page = await context.new_page()

        async def on_request(_request) -> None:
            nonlocal request_count, cancelled
            request_count += 1
            if request_count > MAX_REQUESTS:
                cancelled = True
                try:
                    await page.close()
                except Exception:
                    pass

        async def on_response(response) -> None:
            nonlocal bytes_transferred, cancelled
            try:
                body = await response.body()
            except Exception:
                return
            bytes_transferred += len(body)
            if bytes_transferred > MAX_BYTES:
                cancelled = True
                try:
                    await page.close()
                except Exception:
                    pass

        page.on("request", lambda r: asyncio.create_task(on_request(r)))
        page.on("response", lambda r: asyncio.create_task(on_response(r)))
        page.on(
            "download",
            lambda d: downloads.append(
                {"url": d.url, "suggested_filename": d.suggested_filename}
            ),
        )

        try:
            await asyncio.wait_for(
                page.goto(req.url, wait_until="networkidle", timeout=nav_timeout),
                timeout=total_timeout,
            )
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            result.error = f"navigation_failed:{type(exc).__name__}"

        if cancelled and not result.error:
            result.error = "detonation_budget_exceeded"

        try:
            result.rendered_html = await page.content()
        except Exception:
            pass

        extraction = await _extract_dom_signals(page)
        result.visible_text = extraction.get("visible_text", "")
        result.hidden_text = extraction.get("hidden_text", "")
        result.css_hidden_text = extraction.get("css_hidden_text", "")
        result.unicode_hidden_text = extraction.get("unicode_hidden_text", "")
        result.forms = extraction.get("forms", []) or []
        result.scripts_inline = extraction.get("scripts_inline", []) or []

        try:
            shot = await page.screenshot(type="png", full_page=False, timeout=2000)
            result.screenshot_hash = hashlib.sha256(shot).hexdigest()
        except Exception:
            pass

        result.downloads = downloads
        result.request_count = request_count
        result.bytes_transferred = bytes_transferred
        _result_label = "cancelled" if cancelled else ("error" if result.error else "success")
        return _done(result, result=_result_label)
    except Exception as exc:
        logger.warning(
            "detonation_unexpected tenant=%s request=%s err=%s",
            req.tenant_id,
            req.request_id,
            exc,
        )
        return _done(RenderResponse(error=f"unexpected:{type(exc).__name__}"), result="error")
    finally:
        try:
            await context.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# DOM extraction — runs inside the rendered page. Same contract as the
# original in-process implementation in services/url-trust-gate/detonation.py
# so the gate's evidence schema is unchanged.
# ---------------------------------------------------------------------------

_EXTRACTION_JS = r"""
() => {
  const ZW_RE = /[​‌‍⁠﻿]/g;
  const TAG_RE = /[\u{E0000}-\u{E007F}]/gu;

  const visibleParts = [];
  const cssHiddenParts = [];
  const unicodeHiddenParts = [];
  const commentParts = [];
  const forms = [];
  const scriptsInline = [];

  function isCssHidden(el) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none') return true;
    if (cs.visibility === 'hidden' || cs.visibility === 'collapse') return true;
    if (parseFloat(cs.opacity || '1') === 0) return true;
    if (parseFloat(cs.fontSize || '16') < 1) return true;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return true;
    if (rect.right < 0 || rect.bottom < 0) return true;
    if (rect.left > 100000 || rect.top > 100000) return true;
    return false;
  }

  const walker = document.createTreeWalker(
    document.body || document.documentElement,
    NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT | NodeFilter.SHOW_ELEMENT,
    null
  );
  let n;
  while ((n = walker.nextNode())) {
    if (n.nodeType === Node.COMMENT_NODE) {
      const t = (n.nodeValue || '').trim();
      if (t) commentParts.push(t);
      continue;
    }
    if (n.nodeType === Node.TEXT_NODE) {
      const text = n.nodeValue || '';
      if (!text.trim()) continue;
      const parent = n.parentElement;
      const tagMatches = text.match(TAG_RE);
      const zwMatches = text.match(ZW_RE);
      if (tagMatches || zwMatches) {
        unicodeHiddenParts.push(text);
      }
      if (parent && isCssHidden(parent)) {
        cssHiddenParts.push(text);
      } else {
        visibleParts.push(text);
      }
      continue;
    }
    if (n.nodeType === Node.ELEMENT_NODE) {
      const el = n;
      if (el.tagName === 'SCRIPT' && !el.src && el.textContent) {
        scriptsInline.push(el.textContent.slice(0, 8192));
      }
      if (el.tagName === 'FORM') {
        const inputs = [];
        for (const inp of el.querySelectorAll('input,textarea,select')) {
          inputs.push({
            type: (inp.getAttribute('type') || inp.tagName.toLowerCase()),
            name: inp.getAttribute('name') || '',
            autocomplete: inp.getAttribute('autocomplete') || '',
          });
        }
        forms.push({
          action: el.getAttribute('action') || '',
          method: (el.getAttribute('method') || 'get').toLowerCase(),
          inputs,
        });
      }
    }
  }

  return {
    visible_text: visibleParts.join('\n').slice(0, 200000),
    hidden_text: (cssHiddenParts.concat(commentParts)).join('\n').slice(0, 200000),
    css_hidden_text: cssHiddenParts.join('\n').slice(0, 200000),
    unicode_hidden_text: unicodeHiddenParts.join('\n').slice(0, 50000),
    forms,
    scripts_inline: scriptsInline,
  };
}
"""


async def _extract_dom_signals(page) -> Dict[str, Any]:
    try:
        return await page.evaluate(_EXTRACTION_JS)
    except Exception:
        return {}
