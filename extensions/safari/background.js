/**
 * CyberArmor Protect — Safari Background (Service Worker)
 *
 * Safari Web Extension. Current manifest grants only "storage" + "activeTab"
 * so this background script CANNOT block requests (no webRequest /
 * declarativeNetRequest permissions). It pulls policies and emits telemetry
 * so the dashboard sees Safari sessions; true enforcement requires expanding
 * permissions in the manifest and rebuilding the Safari app target in Xcode.
 */

const AI_DOMAINS = new Set([
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
  'chatgpt.com', 'claude.ai', 'gemini.google.com', 'copilot.microsoft.com',
]);

const SYNC_INTERVAL_MS = 60000;

let policies = [];
let config = {
  controlPlaneUrl: 'http://localhost:8000',
  apiKey: '',
  bootstrapToken: '',
  tenantId: 'default',
  pqcAuthEnabled: true,
  pqcAuthStrict: false,
};
let lastAuthStatus = { mode: 'unknown', algorithm: 'unknown', updatedAt: 0 };
let extIdentity = { agent_id: '', hostname: '', user_id: '' };

function _browserHostname() {
  try {
    const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
    const m = ua.match(/\(([^;)]+)/);
    const os = m ? m[1].trim() : '';
    return os ? `Safari — ${os}` : 'Safari';
  } catch { return 'Browser Extension'; }
}

async function _ensureExtIdentity() {
  const stored = await browser.storage.local.get(['extAgentId', 'extHostname', 'extUserId']);
  let agent_id = stored.extAgentId;
  if (!agent_id) {
    agent_id = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : 'ext-' + Math.random().toString(36).slice(2) + Date.now().toString(36);
    await browser.storage.local.set({ extAgentId: agent_id });
  }
  const hostname = stored.extHostname || _browserHostname();
  if (!stored.extHostname) browser.storage.local.set({ extHostname: hostname });
  extIdentity = { agent_id, hostname, user_id: stored.extUserId || '' };
}

function recordAuthStatus(authInfo, context) {
  if (!authInfo) return;
  lastAuthStatus = {
    mode: authInfo.mode || 'unknown',
    algorithm: authInfo.algorithm || 'unknown',
    error: authInfo.error || '',
    context: context || '',
    updatedAt: Date.now(),
  };
  browser.storage.local.set({ cyberarmor_last_auth_status: lastAuthStatus });
}

// configReady — load config + cached policies on every worker boot. Safari
// service workers idle out like Chrome MV3, so this can't be a one-shot
// onInstalled/onStartup hook.
const configReady = (async () => {
  const synced = await browser.storage.sync.get(['cyberarmor_config', 'cyberarmor_policies']);
  if (synced.cyberarmor_config) config = { ...config, ...synced.cyberarmor_config };
  if (synced.cyberarmor_policies) policies = synced.cyberarmor_policies;
  const local = await browser.storage.local.get(['cyberarmor_last_auth_status']);
  if (local.cyberarmor_last_auth_status) lastAuthStatus = local.cyberarmor_last_auth_status;
  await _ensureExtIdentity();
  try { await ensureBootstrapRedeemed(); } catch (err) { console.warn('[CyberArmor] Safari bootstrap redeem failed:', err.message); }
  startPolicySync();
})();

async function ensureBootstrapRedeemed() {
  if (!config.bootstrapToken || config.apiKey) return;
  const response = await fetch(`${config.controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bootstrap_token: config.bootstrapToken,
      package_key: 'safari-extension',
      subject_type: 'browser_extension',
      subject_name: 'safari-extension',
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Bootstrap redeem failed (${response.status})`);
  config = {
    ...config,
    controlPlaneUrl: data.control_plane_url || config.controlPlaneUrl,
    apiKey: data.service_api_key || config.apiKey,
    tenantId: data.tenant_id || config.tenantId,
    bootstrapToken: '',
  };
  await browser.storage.sync.set({ cyberarmor_config: config });
}

// Safari extension has no pqc_auth.js shim, so fall back to plain API key
// header. The control-plane accepts both — see verify_api_key().
async function authHeaders(extra = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'x-tenant-id': config.tenantId || '',
    ...extra,
  };
  if (config.apiKey) headers['x-api-key'] = config.apiKey;
  recordAuthStatus({ mode: 'plaintext_api_key', algorithm: 'none' }, 'safari');
  return headers;
}

async function syncPolicies() {
  if (!config.controlPlaneUrl || !config.apiKey) {
    return { ok: false, count: 0, error: 'missing controlPlaneUrl or apiKey' };
  }
  const url = `${config.controlPlaneUrl.replace(/\/$/, '')}/policies/${config.tenantId || 'default'}/export`;
  try {
    const resp = await fetch(url, { headers: await authHeaders() });
    if (resp.ok) {
      policies = await resp.json();
      await browser.storage.local.set({ cyberarmor_policies: policies });
      console.log(`[CyberArmor] Synced ${policies.length} policies`);
      return { ok: true, count: policies.length };
    }
    const body = await resp.text().catch(() => '');
    const error = `HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`;
    console.warn(`[CyberArmor] Policy sync failed: ${error} (${url})`);
    return { ok: false, count: policies.length, error };
  } catch (err) {
    console.warn('[CyberArmor] Policy sync failed:', err.message);
    return { ok: false, count: policies.length, error: err.message };
  }
}

function startPolicySync() {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  syncPolicies();
  setInterval(syncPolicies, SYNC_INTERVAL_MS);
}

async function sendTelemetry(event) {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  try {
    const url = `${config.controlPlaneUrl.replace(/\/$/, '')}/telemetry/ingest`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: await authHeaders(),
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

// --- Policy evaluation (port of chromium-shared/background.js) ------
//
// Safari has no declarativeNetRequest or blocking webRequest, so policy
// enforcement is best-effort from the page side: a MAIN-world content
// script (upload_interceptor.js) wraps window.fetch / XHR, asks this
// evaluator via the runtime message channel, and aborts the request
// when the action is block_upload. Service-worker-initiated uploads
// (ChatGPT, etc.) bypass page fetch and will *not* be caught on Safari
// — accept the gap and document it.

const AI_UPLOAD_PATTERNS = [
  'chatgpt.com/backend-api/files',
  'chat.openai.com/backend-api/files',
  'claude.ai/api/*/upload_file',
  'claude.ai/api/organizations/',
  'claude.ai/api/convert_document',
  'gemini.google.com/_/upload',
  'gemini.google.com/_/uploads',
  'copilot.microsoft.com/c/api/files',
  'perplexity.ai/rest/uploads',
  '/upload/files',
  '/api/files/upload',
];

function urlMatchesUploadPattern(url) {
  if (!url) return false;
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  const hostPath = parsed.hostname + parsed.pathname;
  for (const raw of AI_UPLOAD_PATTERNS) {
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

function _equalsLoose(actual, expected) {
  if (actual === expected) return true;
  if (actual == null || expected == null) return false;
  return String(actual) === String(expected);
}

function _evalLeaf(rule, context) {
  const actual = (rule.field || '').split('.').reduce(
    (o, k) => (o && typeof o === 'object' ? o[k] : undefined), context,
  );
  const expected = rule.value;
  switch ((rule.operator || '').toLowerCase()) {
    case 'equals':       return _equalsLoose(actual, expected);
    case 'not_equals':   return !_equalsLoose(actual, expected);
    case 'contains':     return String(actual || '').includes(String(expected));
    case 'not_contains': return !String(actual || '').includes(String(expected));
    case 'starts_with':  return String(actual || '').startsWith(String(expected));
    case 'ends_with':    return String(actual || '').endsWith(String(expected));
    case 'exists':       return actual != null;
    case 'not_exists':   return actual == null;
    case 'in':           return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
    case 'has_any':      return Array.isArray(actual) && (Array.isArray(expected) ? expected : [expected]).some((v) => actual.includes(v));
    default: return false;
  }
}

function _evalConditions(conds, context) {
  if (!conds) return true;
  const op = (conds.operator || 'AND').toUpperCase();
  const rules = conds.rules || [];
  if (!rules.length) return true;
  const results = rules.map((r) => (r.rules ? _evalConditions(r, context) : _evalLeaf(r, context)));
  return op === 'OR' ? results.some(Boolean) : results.every(Boolean);
}

function evaluatePolicy(context) {
  let winner = null;
  for (const p of policies || []) {
    if (!p || p.enabled === false) continue;
    if (!_evalConditions(p.conditions, context)) continue;
    if (!winner) {
      winner = { matched: true, policy: p.name || p.id || '', action: p.action || 'monitor' };
    }
  }
  return winner || { matched: false };
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStatus') {
    sendResponse({ active: true, policies: policies.length, config, lastAuthStatus });
    return false;
  }
  if (msg.type === 'getPolicies') {
    sendResponse({ policies });
    return false;
  }
  if (msg.type === 'aiActivity') {
    // Content script reports activity on AI domains — surface as telemetry so
    // the dashboard sees Safari AI-tool sessions even without enforcement.
    if (msg.domain && AI_DOMAINS.has(msg.domain)) {
      sendTelemetry({
        type: 'ai_service_detected',
        payload: { hostname: msg.domain, tabId: sender.tab && sender.tab.id },
      });
    }
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === 'force_policy_sync' || msg.type === 'forcePolicySync') {
    configReady.then(() => syncPolicies()).then((result) => sendResponse({ ...result, policies }));
    return true;
  }
  if (msg.type === 'evaluate_policy') {
    sendResponse({ result: evaluatePolicy(msg.context) });
    return false;
  }
  if (msg.type === 'safari_upload_blocked') {
    // Mirror the chromium policy_block_upload_dnr event so the Incidents
    // view sees Safari blocks under the same event_type. tabId is read
    // from sender so the dashboard can attribute the block to the page
    // it happened on.
    sendTelemetry({
      type: 'policy_block_upload_dnr',
      payload: {
        url: msg.url,
        policy: msg.policy,
        file_count: msg.file_count,
        file_names: msg.file_names,
        tabId: sender.tab && sender.tab.id,
        browser: 'safari',
      },
    });
    sendResponse({ ok: true });
    return false;
  }
  return false;
});

console.log('[CyberArmor Protect] Safari extension loaded');
