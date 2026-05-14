/**
 * CyberArmor Protect — Firefox Background Script
 * Uses browser.* APIs (WebExtension standard) for policy sync, AI monitoring, phishing protection.
 */

importScripts("pqc_auth.js");

const AI_DOMAINS = new Set([
  'api.openai.com','api.anthropic.com','generativelanguage.googleapis.com',
  'api.cohere.ai','api.mistral.ai','api-inference.huggingface.co',
  'api.together.xyz','api.replicate.com','api.groq.com',
  'chatgpt.com','chat.openai.com','claude.ai','gemini.google.com',
  'copilot.microsoft.com','poe.com','perplexity.ai','huggingface.co',
]);

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|in)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*(system|prompt|instruction)\s*>/i,
  /jailbreak|DAN\s+mode|bypass\s+filter/i,
  /forget\s+(everything|all|your)/i,
];

let policies = [];
let config = {
  controlPlaneUrl: 'http://localhost:8000',
  apiKey: '',
  bootstrapToken: '',
  tenantId: 'default',
  syncInterval: 60000,
  actionMode: 'monitor',
  pqcAuthEnabled: true,
  pqcAuthStrict: false
};
let lastAuthStatus = { mode: "unknown", algorithm: "unknown", updatedAt: 0 };
let extIdentity = { agent_id: "", hostname: "", user_id: "" };

function _browserHostname() {
  try {
    const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
    const m = ua.match(/\(([^;)]+)/);
    const os = m ? m[1].trim() : "";
    return os ? `Firefox — ${os}` : "Firefox";
  } catch { return "Browser Extension"; }
}

async function _ensureExtIdentity() {
  const stored = await browser.storage.local.get(["extAgentId", "extHostname", "extUserId"]);
  let agent_id = stored.extAgentId;
  if (!agent_id) {
    agent_id = (typeof crypto !== "undefined" && crypto.randomUUID)
      ? crypto.randomUUID()
      : "ext-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
    await browser.storage.local.set({ extAgentId: agent_id });
  }
  const hostname = stored.extHostname || _browserHostname();
  if (!stored.extHostname) browser.storage.local.set({ extHostname: hostname });
  extIdentity = { agent_id, hostname, user_id: stored.extUserId || "" };
}

function recordAuthStatus(authInfo, context) {
  if (!authInfo) return;
  lastAuthStatus = {
    mode: authInfo.mode || "unknown",
    algorithm: authInfo.algorithm || "unknown",
    error: authInfo.error || "",
    context: context || "",
    updatedAt: Date.now(),
  };
  browser.storage.local.set({ cyberarmor_last_auth_status: lastAuthStatus });
  console.log(`[CyberArmor] Auth mode=${lastAuthStatus.mode} algorithm=${lastAuthStatus.algorithm} context=${lastAuthStatus.context}`);
}

// Load config
browser.storage.sync.get(['cyberarmor_config', 'cyberarmor_policies']).then(data => {
  if (data.cyberarmor_config) config = { ...config, ...data.cyberarmor_config };
  if (data.cyberarmor_policies) policies = data.cyberarmor_policies;
  browser.storage.local.get(['cyberarmor_last_auth_status', 'tenantUploadPatterns']).then((localData) => {
    if (localData.cyberarmor_last_auth_status) lastAuthStatus = localData.cyberarmor_last_auth_status;
    if (Array.isArray(localData.tenantUploadPatterns)) tenantUploadPatterns = localData.tenantUploadPatterns;
    _ensureExtIdentity().finally(() => ensureBootstrapRedeemed().finally(() => startPolicySync()));
  });
});

async function ensureBootstrapRedeemed() {
  if (!config.bootstrapToken || config.apiKey) return;
  const response = await fetch(`${config.controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bootstrap_token: config.bootstrapToken,
      package_key: 'firefox-extension',
      subject_type: 'browser_extension',
      subject_name: 'firefox-extension',
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Bootstrap redeem failed (${response.status})`);
  }
  config = {
    ...config,
    controlPlaneUrl: data.control_plane_url || config.controlPlaneUrl,
    apiKey: data.service_api_key || config.apiKey,
    tenantId: data.tenant_id || config.tenantId,
    bootstrapToken: '',
  };
  await browser.storage.sync.set({ cyberarmor_config: config });
}

function startPolicySync() {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  setInterval(syncPolicies, config.syncInterval);
  syncPolicies();
}

async function syncPolicies() {
  if (!config.controlPlaneUrl || !config.apiKey) {
    return { ok: false, count: 0, error: "missing controlPlaneUrl or apiKey" };
  }
  const url = `${config.controlPlaneUrl.replace(/\/$/, '')}/policies/${config.tenantId || 'default'}/export`;
  try {
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: config.controlPlaneUrl,
      apiKey: config.apiKey,
      pqcEnabled: config.pqcAuthEnabled !== false,
      strict: config.pqcAuthStrict === true,
      headers: { "x-tenant-id": config.tenantId || "" },
    });
    recordAuthStatus(auth.authInfo, "policy_sync");
    const resp = await fetch(url, { headers: auth.headers });
    if (resp.ok) {
      policies = await resp.json();
      browser.storage.local.set({ cyberarmor_policies: policies });
      console.log(`[CyberArmor] Synced ${policies.length} policies`);
      // Refresh tenant-promoted upload patterns on the same cadence as
      // policies so block_upload + discovery stays in lockstep with what
      // the portal shows.
      try { await syncTenantUploadPatterns(); } catch {}
      return { ok: true, count: policies.length };
    }
    const body = await resp.text().catch(() => '');
    const error = `HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`;
    console.warn(`[CyberArmor] Policy sync failed: ${error} (${url})`);
    return { ok: false, count: policies.length, error };
  } catch (e) {
    console.warn('[CyberArmor] Policy sync failed:', e.message);
    return { ok: false, count: policies.length, error: e.message };
  }
}

// --- Telemetry ---

async function sendTelemetry(event) {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  try {
    const url = `${config.controlPlaneUrl.replace(/\/$/, '')}/telemetry/ingest`;
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: config.controlPlaneUrl,
      apiKey: config.apiKey,
      pqcEnabled: config.pqcAuthEnabled !== false,
      strict: config.pqcAuthStrict === true,
      headers: {
        "Content-Type": "application/json",
        "x-tenant-id": config.tenantId || "",
      },
    });
    recordAuthStatus(auth.authInfo, "telemetry");
    const resp = await fetch(url, {
      method: 'POST',
      headers: auth.headers,
      keepalive: true,
      body: JSON.stringify({
        tenant_id: config.tenantId,
        agent_id: extIdentity.agent_id || undefined,
        hostname: extIdentity.hostname || undefined,
        user_id: extIdentity.user_id || undefined,
        event_type: event.type,
        payload: event.payload,
        source: 'browser_extension',
        occurred_at: new Date().toISOString(),
      }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      console.warn(`[CyberArmor] Telemetry rejected: HTTP ${resp.status} ${resp.statusText} ${body.slice(0, 160)}`);
    } else {
      console.log(`[CyberArmor] Telemetry sent: ${event.type}`);
    }
  } catch (err) {
    console.warn('[CyberArmor] Telemetry send failed:', err.message);
  }
}

// --- Policy evaluation ---
//
// Mirrors the chromium-shared evaluator so tenant policies behave identically
// in Firefox. Returns { matched, policy, action } on first match.
function evaluatePolicy(context) {
  // First-match wins on action; redact_classes union across matching redact
  // policies so layered policies stack. Mirrors chromium-shared.
  let winner = null;
  const redactUnion = new Set();
  const stacked = [];
  for (const policy of policies) {
    if (!policy || !policy.enabled) continue;
    if (!policy.conditions || !evaluateConditions(policy.conditions, context)) continue;
    if (!winner) {
      winner = {
        matched: true,
        policy: policy.name,
        action: policy.action,
        redact_classes: Array.isArray(policy.redact_classes) ? policy.redact_classes : [],
      };
    }
    if (policy.action === 'redact') {
      stacked.push(policy.name);
      for (const c of (policy.redact_classes || [])) redactUnion.add(c);
    }
  }
  if (!winner) return { matched: false };
  if (winner.action === 'redact') {
    winner.redact_classes = [...redactUnion];
    if (stacked.length > 1) winner.policy = stacked.join('+');
  }
  return winner;
}

function evaluateConditions(conditions, context) {
  const op = (conditions.operator || 'AND').toUpperCase();
  const rules = conditions.rules || [];
  if (!rules.length) return true;
  const results = rules.map((rule) => (rule.rules ? evaluateConditions(rule, context) : evaluateLeafRule(rule, context)));
  return op === 'OR' ? results.some(Boolean) : results.every(Boolean);
}

function equalsLoose(actual, expected) {
  if (actual === expected) return true;
  if (actual == null || expected == null) return false;
  return String(actual) === String(expected);
}

function evaluateLeafRule(rule, context) {
  const actual = (rule.field || '').split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), context);
  const expected = rule.value;
  switch (rule.operator) {
    case 'equals':       return equalsLoose(actual, expected);
    case 'not_equals':   return !equalsLoose(actual, expected);
    case 'contains':     return String(actual || '').includes(String(expected));
    case 'not_contains': return !String(actual || '').includes(String(expected));
    case 'matches':      return new RegExp(String(expected).replace(/\*/g, '.*')).test(String(actual || ''));
    case 'in':           return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
    case 'starts_with':  return String(actual || '').startsWith(String(expected));
    case 'ends_with':    return String(actual || '').endsWith(String(expected));
    case 'exists':       return actual != null;
    case 'not_exists':   return actual == null;
    default: return false;
  }
}

// Catalog of AI / collaboration upload endpoints. Kept in lock-step with
// chromium-shared/background.js AI_UPLOAD_PATTERNS — when one changes the
// other should too. Substring/wildcard format (no DNR-specific syntax).
const AI_UPLOAD_PATTERNS = [
  "chatgpt.com/backend-api/files",
  "chat.openai.com/backend-api/files",
  "claude.ai/api/*/upload_file",
  "claude.ai/api/organizations/",
  "claude.ai/api/convert_document",
  "gemini.google.com/_/upload",
  "gemini.google.com/_/uploads",
  "copilot.microsoft.com/c/api/files",
  "perplexity.ai/rest/uploads",
  "/upload/files",
  "/api/files/upload",
];

// Tenant-promoted patterns from /customer/upload-patterns/extras. Synced
// at policy-sync cadence; persisted in browser.storage.local so a worker
// idle/wake doesn't drop runtime coverage.
let tenantUploadPatterns = [];

async function syncTenantUploadPatterns() {
  if (!config.controlPlaneUrl || !config.apiKey) return tenantUploadPatterns;
  const url = `${config.controlPlaneUrl.replace(/\/$/, '')}/customer/upload-patterns/extras`;
  try {
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: config.controlPlaneUrl,
      apiKey: config.apiKey,
      pqcEnabled: config.pqcAuthEnabled !== false,
      strict: config.pqcAuthStrict === true,
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': config.tenantId || '' },
    });
    const resp = await fetch(url, { headers: auth.headers });
    if (!resp.ok) return tenantUploadPatterns;
    const data = await resp.json().catch(() => ({}));
    const next = Array.isArray(data.patterns)
      ? data.patterns.filter((p) => typeof p === 'string' && p.trim().length > 0)
      : [];
    tenantUploadPatterns = next;
    browser.storage.local.set({ tenantUploadPatterns: next });
    return next;
  } catch {
    return tenantUploadPatterns;
  }
}

function effectiveUploadPatternList() {
  // Tenant patterns are plain strings (no DNR syntax). Concat preserves
  // built-in precedence — built-ins live in AI_UPLOAD_PATTERNS top of
  // file, extras append. urlMatchesUploadPattern doesn't care about
  // order since it returns true on first match, but keep deterministic.
  return AI_UPLOAD_PATTERNS.concat(tenantUploadPatterns || []);
}

function urlMatchesUploadPattern(url) {
  if (!url) return false;
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  const hostPath = parsed.hostname + parsed.pathname;
  for (const raw of effectiveUploadPatternList()) {
    // Ordered-segment match: each * is a wildcard, every other segment
    // must appear in hostPath in order. No regex compilation needed.
    const segments = raw.split('*');
    let cursor = 0;
    let ok = true;
    for (const seg of segments) {
      if (!seg) continue;
      const idx = hostPath.indexOf(seg, cursor);
      if (idx < 0) { ok = false; break; }
      cursor = idx + seg.length;
    }
    if (ok) return true;
  }
  return false;
}

// Coalesce per (tabId, url) so a retry loop doesn't stack banners.
const _recentUploadBlocks = new Map();
function _shouldShowBlockBanner(tabId, url) {
  const key = `${tabId}:${url}`;
  const now = Date.now();
  const prev = _recentUploadBlocks.get(key);
  if (prev && now - prev < 4000) return false;
  _recentUploadBlocks.set(key, now);
  return true;
}

// Per-(host,path) throttle for discovery emits — same 1h window the
// chromium bridge uses, so a heavy session doesn't flood the server.
const _recentDiscoveryEmits = new Map();
function _shouldEmitDiscovery(hostpath) {
  const now = Date.now();
  const prev = _recentDiscoveryEmits.get(hostpath);
  if (prev && now - prev < 60 * 60 * 1000) return false;
  _recentDiscoveryEmits.set(hostpath, now);
  return true;
}

// Heuristic: did this request carry multipart/form-data with at least one
// file part? Firefox's requestBody.formData is a {key: [values]} dict;
// file fields appear with empty string values, and the raw bytes live in
// requestBody.raw. We don't decode raw, so the signal is: there's a
// non-empty formData object AND at least one value is empty (file field).
// Imperfect (text-only forms with empty inputs match too), but the
// server-side aggregator is what an admin reviews — false positives are
// triaged before promotion.
function _looksLikeFileUpload(details) {
  const body = details.requestBody;
  if (!body) return false;
  if (body.formData && typeof body.formData === 'object') {
    for (const vals of Object.values(body.formData)) {
      if (Array.isArray(vals)) {
        for (const v of vals) {
          if (typeof v === 'string' && v === '') return true;
        }
      }
    }
  }
  if (Array.isArray(body.raw) && body.raw.length && body.raw.some((r) => r && r.bytes && r.bytes.byteLength > 256)) {
    return true;
  }
  return false;
}

// Intercept every outgoing request:
//   1. If the URL is a known AI upload endpoint and a tenant policy with
//      action=block_upload matches the request context, cancel it +
//      banner. Firefox's blocking webRequest catches service-worker
//      fetches too — no separate DNR path needed.
//   2. If a tenant policy with action=block matches the URL, cancel the
//      request at the network layer.
//   3. If the URL is in AI_DOMAINS and the body matches a prompt-injection
//      pattern, cancel it (legacy behaviour preserved).
// Telemetry is emitted on every block so the dashboard sees Firefox events.
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    let parsedUrl;
    try { parsedUrl = new URL(details.url); } catch { return {}; }
    if (parsedUrl.protocol === 'chrome-extension:' || parsedUrl.protocol === 'moz-extension:') return {};

    // --- block_upload: catalog-targeted policy enforcement ---
    // Run before the generic block check so a single policy that covers
    // both intents (block_upload, with a URL filter) takes the upload-
    // specific code path and the matching banner copy.
    if (urlMatchesUploadPattern(details.url)) {
      try {
        const uploadResult = evaluatePolicy({
          request: {
            url: details.url,
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname,
            method: details.method,
            type: 'upload',
          },
          content: {
            has_file_upload: true,
            has_pii: false,
            pii_classes: [],
          },
        });
        if (uploadResult.matched && uploadResult.action === 'block_upload') {
          console.warn(`[CyberArmor] policy_block_upload "${uploadResult.policy}" → ${details.url}`);
          sendTelemetry({
            type: 'policy_block_upload_dnr',
            payload: {
              url: details.url,
              tabId: details.tabId,
              policy: uploadResult.policy,
              method: details.method,
              type: details.type,
            },
          });
          if (typeof details.tabId === 'number' && details.tabId >= 0
              && _shouldShowBlockBanner(details.tabId, details.url)) {
            browser.tabs.sendMessage(details.tabId, {
              type: 'cyberarmor:upload_blocked_dnr',
              url: details.url,
              policy: uploadResult.policy,
            }).catch(() => { /* tab may have closed */ });
          }
          return { cancel: true };
        }
      } catch (e) { console.debug('[CyberArmor] block_upload evaluation error:', e); }
    } else if (
      AI_DOMAINS.has(parsedUrl.hostname)
      && (details.method === 'POST' || details.method === 'PUT' || details.method === 'PATCH')
      && _looksLikeFileUpload(details)
    ) {
      // Discovery: an upload to an AI-service host that the catalog
      // doesn't know about. Surface it so the admin can promote.
      const hostpath = parsedUrl.hostname + parsedUrl.pathname;
      if (_shouldEmitDiscovery(hostpath)) {
        let totalBytes = 0;
        try {
          if (Array.isArray(details.requestBody && details.requestBody.raw)) {
            for (const r of details.requestBody.raw) {
              if (r && r.bytes && r.bytes.byteLength) totalBytes += r.bytes.byteLength;
            }
          }
        } catch { /* best-effort */ }
        sendTelemetry({
          type: 'upload_endpoint_discovered',
          payload: {
            url: details.url,
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname,
            method: details.method,
            total_bytes: totalBytes,
            suggested_pattern: hostpath,
          },
        });
      }
    }

    // --- General tenant policy evaluation ---
    try {
      const policyResult = evaluatePolicy({
        request: {
          url: details.url,
          hostname: parsedUrl.hostname,
          path: parsedUrl.pathname,
          method: details.method,
          type: AI_DOMAINS.has(parsedUrl.hostname) ? 'ai_service_access' : 'navigation',
        },
        content: {},
      });
      if (policyResult.matched && policyResult.action === 'block') {
        console.warn(`[CyberArmor] policy_block "${policyResult.policy}" → ${details.url}`);
        // Fire-and-forget; keepalive lets the POST survive the event-page idle.
        sendTelemetry({
          type: 'policy_block',
          payload: { url: details.url, tabId: details.tabId, policy: policyResult.policy },
        });
        return { cancel: true };
      }
    } catch (e) { console.debug('[CyberArmor] Policy evaluation error:', e); }

    // --- AI-domain prompt injection (legacy path, AI domains only) ---
    if (!AI_DOMAINS.has(parsedUrl.hostname)) return {};
    console.log(`[CyberArmor] AI request: ${details.method} ${parsedUrl.hostname}${parsedUrl.pathname}`);
    try {
      if (details.requestBody && details.requestBody.raw) {
        const decoder = new TextDecoder();
        const bodyText = details.requestBody.raw.map(r => decoder.decode(r.bytes)).join('');
        for (const pat of PROMPT_INJECTION_PATTERNS) {
          if (pat.test(bodyText)) {
            console.warn('[CyberArmor] Prompt injection detected in request to', parsedUrl.hostname);
            sendTelemetry({
              type: 'prompt_injection_blocked',
              payload: { url: details.url, hostname: parsedUrl.hostname, pattern: pat.source },
            });
            const blockPolicy = policies.find(p => p.action === 'block' && p.enabled);
            if (blockPolicy) return { cancel: true };
            break;
          }
        }
      }
    } catch (e) { console.debug('[CyberArmor] Inspection error:', e); }
    return {};
  },
  { urls: ['<all_urls>'] },
  ['blocking', 'requestBody']
);

// Message handling from content script / popup
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStatus') {
    sendResponse({ active: true, policies: policies.length, config, lastAuthStatus });
    return false;
  }
  if (msg.type === 'getPolicies') {
    sendResponse({ policies });
    return false;
  }
  if (msg.type === 'force_policy_sync' || msg.type === 'forcePolicySync') {
    syncPolicies().then((result) => sendResponse({ ...result, policies }));
    return true; // keep the message channel open for the async response
  }
  return false;
});

console.log('[CyberArmor Protect] Firefox extension loaded');
