// URL Trust Gate hook for the Chromium extension.
//
// Status: scaffold. Wires webNavigation.onBeforeNavigate to the
// CyberArmor URL Trust Gate service. The fast path (depth=fast) returns
// in ~10ms on cache hit; on miss, we let the navigation proceed and
// kick off a depth=standard evaluation in the background so the next
// click on the same URL is fast and protected.
//
// To enable, import this module from background.js after PQC auth
// bootstrap, and call attachUrlTrustGate({ getApiKey, gateUrl, tenantId }).

const DEFAULT_GATE_URL = "https://url-trust-gate.cyberarmor.local/evaluate";
const FAST_PATH_TIMEOUT_MS = 250; // hard ceiling so we never stall a click
const RECENT_VERDICTS = new Map(); // url -> { verdict, ts }
const RECENT_TTL_MS = 60_000;

export function attachUrlTrustGate({ getApiKey, gateUrl, tenantId, onBlock, onWarn }) {
  const url = gateUrl || DEFAULT_GATE_URL;

  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // ignore subframes
    if (!/^https?:/i.test(details.url)) return;

    const cached = recentLookup(details.url);
    if (cached && cached.action === "allow") return; // common case: nothing to do
    if (cached && (cached.action === "block" || cached.action === "warn")) {
      handleVerdict(cached, details, { onBlock, onWarn });
      return;
    }

    // Fast path: race the gate against a tight timeout. If the gate
    // wins and says block/warn, we redirect / interstitial. If the
    // timeout wins, we let the navigation proceed and fire-and-forget a
    // standard-depth evaluation so the next visit is protected.
    let verdict = null;
    try {
      verdict = await Promise.race([
        callGate(url, await getApiKey(), {
          tenant_id: tenantId,
          url: details.url,
          source: "browser-extension",
          depth: "fast",
        }),
        new Promise((resolve) => setTimeout(() => resolve(null), FAST_PATH_TIMEOUT_MS)),
      ]);
    } catch (err) {
      // Fail open on extension-side errors. The gate is a defence in
      // depth, not the only line — the proxy/RASP path catches what we
      // miss here.
      console.warn("[cyberarmor] url-trust-gate fast-path error", err);
    }

    if (verdict) {
      cacheVerdict(details.url, verdict);
      handleVerdict(verdict, details, { onBlock, onWarn });
    }

    // Standard-depth backfill so a cache miss only happens once.
    callGate(url, await getApiKey(), {
      tenant_id: tenantId,
      url: details.url,
      source: "browser-extension",
      depth: "standard",
    })
      .then((v) => v && cacheVerdict(details.url, v))
      .catch(() => {});
  });
}

async function callGate(gateUrl, apiKey, body) {
  const resp = await fetch(gateUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify(body),
    // Never send cookies. The gate runs without user identity by design.
    credentials: "omit",
  });
  if (!resp.ok) return null;
  return resp.json();
}

function handleVerdict(verdict, details, { onBlock, onWarn }) {
  const action = verdict?.decision?.action || "allow";
  if (action === "block" || action === "isolate") {
    // Redirect to the existing phishing warning interstitial. The
    // interstitial already exists in this extension; we just point it
    // at the verdict's reason + evidence id.
    const warningUrl = chrome.runtime.getURL("phishing_warning.html") +
      `?url=${encodeURIComponent(details.url)}` +
      `&reason=${encodeURIComponent(verdict.decision.reason || "blocked by URL Trust Gate")}` +
      `&evidence=${encodeURIComponent(verdict.evidence_id || "")}`;
    chrome.tabs.update(details.tabId, { url: warningUrl });
    onBlock?.(verdict, details);
    return;
  }
  if (action === "warn" || action === "redact" || action === "sandbox") {
    // TODO: render a non-blocking toast via content script. For now we
    // surface to the popup via storage so the user sees the warning on
    // the next icon click.
    chrome.storage.session?.set?.({
      cyberarmorLastWarning: {
        url: details.url,
        action,
        reason: verdict.decision.reason,
        ts: Date.now(),
      },
    });
    onWarn?.(verdict, details);
  }
}

function recentLookup(url) {
  const entry = RECENT_VERDICTS.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > RECENT_TTL_MS) {
    RECENT_VERDICTS.delete(url);
    return null;
  }
  return entry.verdict.decision || null;
}

function cacheVerdict(url, verdict) {
  RECENT_VERDICTS.set(url, { verdict, ts: Date.now() });
  if (RECENT_VERDICTS.size > 500) {
    // Cheap eviction.
    const oldest = [...RECENT_VERDICTS.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
    if (oldest) RECENT_VERDICTS.delete(oldest[0]);
  }
}
