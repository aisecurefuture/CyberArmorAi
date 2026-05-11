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
  return false;
});

console.log('[CyberArmor Protect] Safari extension loaded');
