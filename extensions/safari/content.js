/**
 * CyberArmor Protect — Safari Content Script
 * PII detection, AI chat monitoring (same core logic as Chromium/Firefox).
 */

(() => {
  const PII_PATTERNS = [
    { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
    { name: 'Credit Card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g },
    { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g },
  ];

  const AI_CHAT_SELECTORS = [
    'textarea[data-id="root"]', '#prompt-textarea', 'div[contenteditable="true"]',
    '.ProseMirror', 'textarea.w-full',
  ];

  function monitorInputs() {
    AI_CHAT_SELECTORS.forEach(sel => {
      document.querySelectorAll(sel).forEach(el => {
        if (el._cyberarmorMonitored) return;
        el._cyberarmorMonitored = true;
        el.addEventListener('paste', (e) => {
          const text = e.clipboardData?.getData('text') || '';
          const found = PII_PATTERNS.filter(p => p.pattern.test(text));
          if (found.length) {
            const banner = document.createElement('div');
            banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;padding:12px;background:#991b1b;color:#fff;text-align:center;font-family:system-ui;font-size:14px;';
            banner.textContent = `CyberArmor: PII detected (${found.map(f => f.name).join(', ')})`;
            document.body.prepend(banner);
            setTimeout(() => banner.remove(), 6000);
          }
        });
      });
    });

    // Notify background of AI domain visits
    const host = location.hostname;
    if (['chatgpt.com', 'claude.ai', 'gemini.google.com', 'copilot.microsoft.com', 'poe.com'].includes(host)) {
      browser.runtime.sendMessage({ type: 'aiActivity', domain: host });
    }
  }

  const cyberArmorObserver = new MutationObserver(monitorInputs);
  cyberArmorObserver.observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener('DOMContentLoaded', monitorInputs);

  // --- Upload interception bridge ---
  //
  // upload_interceptor.js runs in the page's MAIN world and wraps fetch /
  // XHR. It can't talk to the extension directly, so it posts a message
  // here; we forward to the background's evaluator and post the decision
  // back. Service-worker-initiated uploads (ChatGPT etc.) bypass the
  // page's fetch and won't reach this bridge — Safari has no DNR or
  // blocking webRequest, so that's a known gap on this browser.

  function _showUploadBlockedBanner(url, policy) {
    let host = '';
    try { host = new URL(url || '').hostname; } catch { /* ignore */ }
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;padding:12px;background:#991b1b;color:#fff;text-align:center;font-family:system-ui;font-size:14px;';
    banner.textContent = `CyberArmor: File upload to ${host || 'this service'} blocked by policy "${policy || 'policy'}".`;
    document.body.prepend(banner);
    setTimeout(() => banner.remove(), 8000);
  }

  // Coalesce per URL so retry loops don't stack banners.
  const _recentBanners = new Map();
  function _shouldShowBanner(url) {
    const now = Date.now();
    const prev = _recentBanners.get(url);
    if (prev && now - prev < 4000) return false;
    _recentBanners.set(url, now);
    return true;
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.type !== 'cyberarmor:upload_request') return;
    if (typeof browser === 'undefined' || !browser.runtime) {
      window.postMessage({ type: 'cyberarmor:upload_decision', id: msg.id, action: 'allow' }, '*');
      return;
    }
    const files = Array.isArray(msg.files) ? msg.files : [];
    const url = String(msg.url || '');
    let parsedHost = '';
    try { parsedHost = new URL(url).hostname; } catch { /* ignore */ }

    browser.runtime.sendMessage({
      type: 'evaluate_policy',
      context: {
        request: { url, hostname: parsedHost, type: 'upload', method: 'post' },
        content: {
          has_pii: false,
          pii_classes: [],
          has_file_upload: true,
          file_count: files.length,
          file_names: files.map((f) => String(f.name || '')),
          file_types: [...new Set(files.map((f) => String(f.type || '')).filter(Boolean))],
        },
      },
    }).then((resp) => {
      const result = resp && resp.result;
      const action = (result && result.matched && result.action) || 'allow';
      const policy = (result && result.policy) || '';
      const inCatalog = !!(resp && resp.inCatalog);
      const isAIService = !!(resp && resp.isAIService);
      window.postMessage({ type: 'cyberarmor:upload_decision', id: msg.id, action, policy }, '*');
      if (action === 'block_upload' && _shouldShowBanner(url)) {
        _showUploadBlockedBanner(url, policy);
        // Telemetry routed through background via the regular message bus
        // so the Incidents view still sees Safari blocks.
        browser.runtime.sendMessage({
          type: 'safari_upload_blocked',
          url, policy, file_count: files.length,
          file_names: files.map((f) => String(f.name || '')),
        }).catch(() => {});
      } else if (!inCatalog && isAIService) {
        // Discovery: upload passed through to an AI-service host we don't
        // cover yet. Throttle per (host,path) for 1h so heavy sessions
        // don't flood the server — mirrors the chromium bridge.
        let pathKey = url;
        let hostname = '';
        let pathname = '';
        try {
          const u = new URL(url);
          hostname = u.hostname; pathname = u.pathname;
          pathKey = hostname + pathname;
        } catch { /* ignore */ }
        window._cyberarmorDiscSeen = window._cyberarmorDiscSeen || new Map();
        const now = Date.now();
        const prev = window._cyberarmorDiscSeen.get(pathKey);
        if (!prev || now - prev > 60 * 60 * 1000) {
          window._cyberarmorDiscSeen.set(pathKey, now);
          const totalBytes = files.reduce((acc, f) => acc + (Number(f.size) || 0), 0);
          browser.runtime.sendMessage({
            type: 'safari_upload_discovered',
            url,
            hostname,
            path: pathname,
            file_count: files.length,
            file_types: [...new Set(files.map((f) => String(f.type || '')).filter(Boolean))],
            total_bytes: totalBytes,
            suggested_pattern: pathKey,
          }).catch(() => {});
        }
      }
    }).catch(() => {
      // Failed eval → fail open so the page still works.
      window.postMessage({ type: 'cyberarmor:upload_decision', id: msg.id, action: 'allow' }, '*');
    });
  });
})();
