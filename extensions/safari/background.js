/**
 * CyberArmor Protect — Safari Background (Service Worker)
 * Safari Web Extension using browser.* APIs (limited DNR support).
 */

const AI_DOMAINS = new Set([
  'api.openai.com','api.anthropic.com','generativelanguage.googleapis.com',
  'chatgpt.com','claude.ai','gemini.google.com','copilot.microsoft.com',
]);

let policies = [];
let config = { controlPlaneUrl: 'http://localhost:8000', apiKey: '', bootstrapToken: '', tenantId: 'default' };

// Load stored config
browser.storage.sync.get(['cyberarmor_config', 'cyberarmor_policies']).then(data => {
  if (data.cyberarmor_config) config = { ...config, ...data.cyberarmor_config };
  if (data.cyberarmor_policies) policies = data.cyberarmor_policies;
  ensureBootstrapRedeemed().catch((err) => console.warn('[CyberArmor] Safari bootstrap redeem failed:', err.message));
});

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

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStatus') {
    sendResponse({ active: true, policies: policies.length });
  } else if (msg.type === 'aiActivity') {
    console.log('[CyberArmor] AI activity:', msg.domain);
  }
  return true;
});

console.log('[CyberArmor Protect] Safari extension loaded');
