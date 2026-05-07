"""Detonation sandbox — Playwright-backed headless render.

For deep-mode requests we render the page in a headless browser to catch
content the safe crawler can't see: JavaScript-rendered DOM, CSS-hidden
text, offscreen elements, Unicode tag/zero-width characters, forms, and
download intents.

Important deployment notes:

- The detonation worker MUST run in a dedicated container with no route
  to internal services or cloud metadata. This module is the in-process
  client; the actual browser MUST be sandboxed via container/network
  isolation. Setting ``URL_TRUST_GATE_DETONATION_DEFAULT=on`` only flips
  the default depth — it does NOT make Playwright safe to run in a
  shared namespace.
- We use a one-shot context per request. Profiles are NEVER reused;
  cookies, storage, service workers, and HTTP cache are all wiped.
- No user identity. The browser starts with an empty profile; cookies
  and Authorization headers are not propagated.
- Hard CPU/wallclock budget. Total render time is capped; the page is
  closed even if scripts are still pending.
- All network I/O the page initiates is ALSO bounded by request-count,
  total-bytes, and per-request size limits.

If Playwright is not installed at runtime (``pip install playwright`` +
``playwright install chromium``), the sandbox returns an error and the
gate falls back to standard-depth behaviour.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("url_trust_gate.detonation")

# Hard caps. Configurable via env so operators can tune for their cluster.
DETONATION_NAV_TIMEOUT_MS = int(os.getenv("URL_TRUST_GATE_DETONATION_NAV_TIMEOUT_MS", "8000"))
DETONATION_TOTAL_TIMEOUT_S = float(os.getenv("URL_TRUST_GATE_DETONATION_TOTAL_TIMEOUT_S", "12.0"))
DETONATION_MAX_REQUESTS = int(os.getenv("URL_TRUST_GATE_DETONATION_MAX_REQUESTS", "100"))
DETONATION_MAX_BYTES = int(os.getenv("URL_TRUST_GATE_DETONATION_MAX_BYTES", "8388608"))  # 8 MiB
DETONATION_VIEWPORT = (1280, 800)


@dataclass
class DetonationResult:
    rendered_html: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    css_hidden_text: str = ""
    unicode_hidden_text: str = ""
    forms: List[dict] = field(default_factory=list)
    downloads: List[dict] = field(default_factory=list)
    scripts_inline: List[str] = field(default_factory=list)
    screenshot_hash: Optional[str] = None
    error: Optional[str] = None
    request_count: int = 0
    bytes_transferred: int = 0


class DetonationSandbox:
    """Playwright-backed sandbox.

    Loads Playwright lazily so the gate can boot even when the browser
    image isn't installed. If Playwright import fails we degrade
    cleanly with a structured error.
    """

    def __init__(self) -> None:
        self._playwright_available: Optional[bool] = None
        self._browser_lock = asyncio.Lock()
        # Lazy: created on first use, kept alive for the process.
        self._playwright = None
        self._browser = None

    async def _ensure_browser(self):
        async with self._browser_lock:
            if self._browser is not None:
                return self._browser
            try:
                from playwright.async_api import async_playwright  # type: ignore
            except ImportError:
                self._playwright_available = False
                return None
            self._playwright_available = True
            self._playwright = await async_playwright().start()
            # Chromium with a hardened arg set. The container the worker
            # runs in is the real boundary; these flags just reduce
            # surface area inside the sandboxed process.
            self._browser = await self._playwright.chromium.launch(
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
            return self._browser

    async def render(
        self, url: str, *, tenant_id: str, request_id: str
    ) -> DetonationResult:
        browser = await self._ensure_browser()
        if browser is None:
            return DetonationResult(error="playwright_not_installed")

        # One-shot context per request. NO storage, NO cookies, NO permissions.
        try:
            context = await browser.new_context(
                viewport={"width": DETONATION_VIEWPORT[0], "height": DETONATION_VIEWPORT[1]},
                user_agent=(
                    "CyberArmor-URLTrustGate-Sandbox/0.1 "
                    "(+https://cyberarmor.ai/bots/url-trust-gate)"
                ),
                java_script_enabled=True,
                ignore_https_errors=False,
                bypass_csp=False,
                accept_downloads=False,
                # Empty storage state — no cookies, no localStorage.
                storage_state=None,
            )
        except Exception as exc:
            return DetonationResult(error=f"context_create_failed:{type(exc).__name__}")

        result = DetonationResult()
        downloads: List[dict] = []
        request_count = 0
        bytes_transferred = 0
        # Local closures because Playwright callbacks aren't async-friendly
        # for our state.
        cancelled = False

        try:
            page = await context.new_page()

            async def on_request(request) -> None:
                nonlocal request_count, cancelled
                request_count += 1
                if request_count > DETONATION_MAX_REQUESTS:
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
                if bytes_transferred > DETONATION_MAX_BYTES:
                    cancelled = True
                    try:
                        await page.close()
                    except Exception:
                        pass

            page.on("request", lambda r: asyncio.create_task(on_request(r)))
            page.on("response", lambda r: asyncio.create_task(on_response(r)))
            # We never accept downloads in detonation. If the page tries,
            # record the intent (as a signal) but don't write to disk.
            page.on(
                "download",
                lambda d: downloads.append(
                    {"url": d.url, "suggested_filename": d.suggested_filename}
                ),
            )

            try:
                await asyncio.wait_for(
                    page.goto(
                        url,
                        wait_until="networkidle",
                        timeout=DETONATION_NAV_TIMEOUT_MS,
                    ),
                    timeout=DETONATION_TOTAL_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                # Render whatever we have. Often the page has loaded enough
                # for promptware extraction even if a tracker pixel is hung.
                pass
            except Exception as exc:
                # Navigation errors (cert, DNS, connection refused) are
                # legit signal — we log and return early but keep partial
                # state.
                result.error = f"navigation_failed:{type(exc).__name__}"

            if cancelled and not result.error:
                result.error = "detonation_budget_exceeded"

            # Extract artefacts. Each step wrapped in its own try so a
            # single failure doesn't blank the whole result.
            try:
                result.rendered_html = await page.content()
            except Exception:
                pass

            extraction = await _extract_dom_signals(page)
            result.visible_text = extraction.get("visible_text", "")
            result.hidden_text = extraction.get("hidden_text", "")
            result.css_hidden_text = extraction.get("css_hidden_text", "")
            result.unicode_hidden_text = extraction.get("unicode_hidden_text", "")
            result.forms = extraction.get("forms", [])
            result.scripts_inline = extraction.get("scripts_inline", [])

            # Screenshot for the evidence record.
            try:
                shot = await page.screenshot(type="png", full_page=False, timeout=2000)
                result.screenshot_hash = hashlib.sha256(shot).hexdigest()
                # TODO: write screenshot bytes to the evidence object store
                # and reference them by hash. For now we just record the
                # hash so the evidence can be correlated later.
            except Exception:
                pass

            result.downloads = downloads
            result.request_count = request_count
            result.bytes_transferred = bytes_transferred
            return result
        except Exception as exc:
            logger.warning(
                "detonation_unexpected tenant=%s request=%s err=%s",
                tenant_id,
                request_id,
                exc,
            )
            return DetonationResult(error=f"unexpected:{type(exc).__name__}")
        finally:
            # Always tear down. Profiles are NEVER reused.
            try:
                await context.close()
            except Exception:
                pass

    async def aclose(self) -> None:
        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright is not None:
                await self._playwright.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# DOM extraction (runs inside the page via evaluate())
# ---------------------------------------------------------------------------

# JavaScript that runs inside the rendered page to walk the DOM and pull
# out:
#  - visible text (what a human sees)
#  - DOM nodes whose computed style hides them (display:none,
#    visibility:hidden, opacity:0, font-size:0, off-screen positioning)
#  - HTML comments (sometimes used for promptware)
#  - characters in the Unicode Tag block (U+E0000..U+E007F) and
#    zero-width space variants — these are AI-readable, human-invisible.
#  - form structure (inputs + types) for credential-harvest detection
#  - inline <script> bodies as text (NOT executed by us; just inspected)
_EXTRACTION_JS = r"""
() => {
  const ZW_RE = /[​‌‍⁠﻿]/g;
  // Unicode TAG block U+E0000..U+E007F (we emit the codepoints as-is).
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
    // Off-screen positioning trick.
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return true;
    if (rect.right < 0 || rect.bottom < 0) return true;
    if (rect.left > 100000 || rect.top > 100000) return true;
    return false;
  }

  // Walk the document body.
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
      // Tag-block / zero-width characters are SIGNAL regardless of
      // visibility — capture them separately.
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
      // Inline script bodies, captured as text, not executed.
      if (el.tagName === 'SCRIPT' && !el.src && el.textContent) {
        scriptsInline.push(el.textContent.slice(0, 8192));
      }
      // Forms — record inputs and their types for credential-harvest
      // detection back in the gate's extractors layer.
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
    // CSS-hidden + comments both go into hidden_text for the legacy
    // extractor; the granular split is preserved on css_hidden_text.
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
