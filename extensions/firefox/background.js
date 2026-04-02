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
let config = { controlPlaneUrl: 'http://localhost:8000', apiKey: '', syncInterval: 60000, pqcAuthEnabled: true, pqcAuthStrict: false };
let lastAuthStatus = { mode: "unknown", algorithm: "unknown", updatedAt: 0 };

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
  browser.storage.local.get(['cyberarmor_last_auth_status']).then((localData) => {
    if (localData.cyberarmor_last_auth_status) lastAuthStatus = localData.cyberarmor_last_auth_status;
    startPolicySync();
  });
});

function startPolicySync() {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  setInterval(syncPolicies, config.syncInterval);
  syncPolicies();
}

async function syncPolicies() {
  try {
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: config.controlPlaneUrl,
      apiKey: config.apiKey,
      pqcEnabled: config.pqcAuthEnabled !== false,
      strict: config.pqcAuthStrict === true,
    });
    recordAuthStatus(auth.authInfo, "policy_sync");
    const resp = await fetch(`${config.controlPlaneUrl}/policies/default`, {
      headers: auth.headers
    });
    if (resp.ok) {
      policies = await resp.json();
      browser.storage.local.set({ cyberarmor_policies: policies });
    }
  } catch (e) { console.debug('[CyberArmor] Policy sync failed:', e.message); }
}

// Intercept AI API requests
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      const url = new URL(details.url);
      if (!AI_DOMAINS.has(url.hostname)) return {};

      // Log AI request
      console.log(`[CyberArmor] AI request: ${details.method} ${url.hostname}${url.pathname}`);

      // Check request body for prompt injection
      if (details.requestBody && details.requestBody.raw) {
        const decoder = new TextDecoder();
        const bodyText = details.requestBody.raw.map(r => decoder.decode(r.bytes)).join('');
        for (const pat of PROMPT_INJECTION_PATTERNS) {
          if (pat.test(bodyText)) {
            console.warn('[CyberArmor] Prompt injection detected in request to', url.hostname);
            // In block mode, cancel the request
            const blockPolicy = policies.find(p => p.action === 'block' && p.enabled);
            if (blockPolicy) {
              return { cancel: true };
            }
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
  } else if (msg.type === 'getPolicies') {
    sendResponse({ policies });
  }
  return true;
});

console.log('[CyberArmor Protect] Firefox extension loaded');
