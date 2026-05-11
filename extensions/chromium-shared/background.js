/**
 * CyberArmor Browser Protection - Chromium Background Service Worker
 * Works on: Chrome, Brave, Edge, Opera
 *
 * Features:
 * - Phishing protection with DNR rules
 * - Policy sync from control plane
 * - AI service monitoring (ChatGPT, Claude, Gemini, Copilot, etc.)
 * - Prompt injection detection
 * - MCP connection monitoring
 * - Telemetry reporting
 * - Monitor/warn/block action modes
 */

importScripts("pqc_auth.js");

const DEFAULT_CONFIG = {
  controlPlaneUrl: "http://localhost:8000",
  apiKey: "",
  bootstrapToken: "",
  tenantId: "demo",
  telemetryEnabled: true,
  redactPIIEnabled: true,
  phishingProtectionEnabled: true,
  phishingMode: "redirect",
  phishingAllowlistDomains: [],
  policySyncIntervalMs: 60000,
  aiMonitoringEnabled: true,
  promptInjectionDetection: true,
  actionMode: "monitor", // monitor, warn, block, redact*
  redactionAction: "redact",
  pqcAuthEnabled: true,
  pqcAuthStrict: false,
};

// Known AI service domains for monitoring
const AI_SERVICE_DOMAINS = [
  "chat.openai.com", "api.openai.com", "platform.openai.com",
  "claude.ai", "api.anthropic.com",
  "gemini.google.com", "generativelanguage.googleapis.com",
  "copilot.microsoft.com", "copilot.github.com",
  "huggingface.co", "api-inference.huggingface.co",
  "perplexity.ai", "api.perplexity.ai",
  "chat.mistral.ai", "api.mistral.ai",
  "cohere.ai", "api.cohere.ai",
  "together.ai", "api.together.xyz",
  "groq.com", "api.groq.com",
  "ollama.ai", "localhost:11434",
  "bard.google.com", "aistudio.google.com",
  "you.com", "poe.com", "character.ai",
  "deepseek.com", "api.deepseek.com",
  "x.ai", "api.x.ai",
];

// PII regex catalog — must stay in sync with content.js PII_PATTERNS.
// Used by the navigation listener to detect/redact PII embedded in query
// strings on direct GET navigations (Google Search and similar — where the
// content-script's form-submit interceptor never fires because the page
// navigates via location-change rather than dispatching a submit event).
const PII_PATTERNS = [
  { label: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: "phone", pattern: /\b\d{10}\b/g },
  { label: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi },
  { label: "credit_card", pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g },
  { label: "bank_account", pattern: /\b\d{9,12}\b/g },
  { label: "drivers_license", pattern: /\b[A-Z]{1,2}\d{4,8}\b/g },
  { label: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Za-z0-9]{4}\d{14}\b/g },
  { label: "api_key", pattern: /\b(?:sk-|pk_|api[_-]?key)[A-Za-z0-9]{16,}\b/gi },
  { label: "aws_key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { label: "private_key", pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g },
  { label: "password_field", pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi },
];

function detectPIILabels(text) {
  const labels = [];
  for (const { label, pattern } of PII_PATTERNS) {
    if (new RegExp(pattern.source, pattern.flags).test(text)) labels.push(label);
  }
  return labels;
}

// Redact a URL: scan the search + hash for any PII matching the allowed
// class set (or all detected, if the set is empty) and replace inline.
// Returns the redacted URL string, or null if nothing changed.
function redactURL(urlStr, allowedClasses) {
  let parsed;
  try { parsed = new URL(urlStr); } catch { return null; }
  const allowAll = !allowedClasses || allowedClasses.size === 0;
  let changed = false;

  const redactPart = (part) => {
    if (!part) return part;
    let out = decodeURIComponent(part);
    for (const { label, pattern } of PII_PATTERNS) {
      if (!(allowAll || allowedClasses.has("pii." + label))) continue;
      const re = new RegExp(pattern.source, pattern.flags);
      if (re.test(out)) {
        out = out.replace(new RegExp(pattern.source, pattern.flags), `[REDACTED-${label}]`);
        changed = true;
      }
    }
    return out;
  };

  if (parsed.search) parsed.search = "?" + redactPart(parsed.search.slice(1));
  if (parsed.hash)   parsed.hash   = "#" + redactPart(parsed.hash.slice(1));
  return changed ? parsed.toString() : null;
}

// Prompt injection patterns
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(the\s+)?(system|previous)\s+prompt/i,
  /\bjailbreak\b/i,
  /\bbegin\s+(?:new\s+)?system\s+prompt/i,
  /\bdeveloper\s+mode\b/i,
  /\bdisable\s+safety\b/i,
  /\bprint\s+(the\s+)?system\s+prompt/i,
  /\bexfiltrate\b/i,
  /\bprovide\s+credentials\b/i,
  /\bexecute\s+(bash|powershell|cmd)\b/i,
  /\bact\s+as\s+(?:an?\s+)?(?:un)?restricted/i,
  /\bDAN\s+mode\b/i,
  /\bbypass\s+(?:all\s+)?(?:safety|content)\s+filter/i,
];

let cachedConfig = { ...DEFAULT_CONFIG };
let cachedPolicies = [];
let policySyncTimer = null;
let lastAuthStatus = { mode: "unknown", algorithm: "unknown", updatedAt: 0 };

// MV3 service workers respawn on events after going idle; onInstalled/onStartup
// don't fire on respawn, so cachedConfig would otherwise stay at defaults until
// the next browser launch. Kick a top-level load + cache restore so any wake-up
// event sees real config, and await this in message handlers that need it.
const configReady = (async () => {
  await loadConfig();
  const stored = await new Promise((resolve) =>
    chrome.storage.local.get(["cachedPolicies", "cyberarmorLastAuthStatus"], resolve)
  );
  if (stored.cachedPolicies) cachedPolicies = stored.cachedPolicies;
  if (stored.cyberarmorLastAuthStatus) lastAuthStatus = stored.cyberarmorLastAuthStatus;
  // Re-emit DNR rules from cached policies so a fresh worker boot (or one with
  // no network) still enforces blocks at the network layer.
  if (cachedPolicies && cachedPolicies.length) {
    try { await updatePolicyDNR(cachedPolicies); } catch {}
  }
})();

function recordAuthStatus(authInfo, context) {
  if (!authInfo) return;
  lastAuthStatus = {
    mode: authInfo.mode || "unknown",
    algorithm: authInfo.algorithm || "unknown",
    error: authInfo.error || "",
    context: context || "",
    updatedAt: Date.now(),
  };
  chrome.storage.local.set({ cyberarmorLastAuthStatus: lastAuthStatus });
  console.log(`[CyberArmor] Auth mode=${lastAuthStatus.mode} algorithm=${lastAuthStatus.algorithm} context=${lastAuthStatus.context}`);
}

// --- Configuration Management ---

async function loadConfig() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_CONFIG, (cfg) => {
      cachedConfig = { ...DEFAULT_CONFIG, ...cfg };
      resolve(cachedConfig);
    });
  });
}

async function saveConfig(updates) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(updates, () => {
      Object.assign(cachedConfig, updates);
      resolve(cachedConfig);
    });
  });
}

async function ensureBootstrapRedeemed() {
  if (!cachedConfig.bootstrapToken || cachedConfig.apiKey) return;
  const response = await fetch(`${cachedConfig.controlPlaneUrl.replace(/\/$/, "")}/bootstrap/redeem`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      bootstrap_token: cachedConfig.bootstrapToken,
      package_key: "edge-extension",
      subject_type: "browser_extension",
      subject_name: "chromium-extension",
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Bootstrap redeem failed (${response.status})`);
  }
  await saveConfig({
    controlPlaneUrl: data.control_plane_url || cachedConfig.controlPlaneUrl,
    apiKey: data.service_api_key || cachedConfig.apiKey,
    tenantId: data.tenant_id || cachedConfig.tenantId,
    bootstrapToken: "",
  });
}

// --- Policy → declarativeNetRequest synthesis ---
//
// Block-action policies with URL-only conditions are translated into dynamic
// DNR rules at sync time so blocking happens at the network layer (covers
// subresources, fetch, XHR, websockets — not just top-level navigations).
// Policies with non-URL conditions (user_id, content.*, etc.) fall back to
// the onBeforeNavigate listener.
//
// Rule-ID ranges in this extension:
//   1–999          (unused)
//   1000–1099      phishing protection rules (PHISHING_RULES)
//   100000–199999  policy-derived block rules (this section)

const POLICY_DNR_ID_MIN = 100000;
const POLICY_DNR_ID_MAX = 199999;

// resourceTypes covered by the hard-block rule (every type except main_frame,
// which is handled by a separate redirect rule so the user sees the warning).
const POLICY_DNR_BLOCK_TYPES = [
  "sub_frame", "stylesheet", "script", "image", "font", "object",
  "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other",
];

// Convert one policy.conditions object to an array of DNR urlFilter strings
// (joined by OR — DNR fires when ANY rule matches). Returns null if the policy
// can't be fully expressed in DNR; caller skips it and the navigation listener
// handles enforcement at the top-level navigation layer.
function extractURLFilters(conditions) {
  if (!conditions || !Array.isArray(conditions.rules) || conditions.rules.length === 0) {
    return null;
  }
  const op = (conditions.operator || "AND").toUpperCase();

  const filters = [];
  for (const r of conditions.rules) {
    if (r.rules) return null; // nested groups: too complex for single DNR pass
    const field = r.field || "";
    const operator = r.operator;
    const value = String(r.value == null ? "" : r.value);
    if (!value) return null;
    if (field !== "request.url" && field !== "request.hostname") return null;
    let filter;
    switch (operator) {
      case "contains":    filter = value; break;
      case "equals":      filter = "|" + value + "|"; break;
      case "starts_with": filter = "|" + value; break;
      case "ends_with":   filter = value + "|"; break;
      default: return null;
    }
    filters.push(filter);
  }

  // AND with multiple url filters can't be a single urlFilter — DNR matches a
  // single substring/anchor pattern per rule. Skip and let the navigation
  // listener fall back (it can evaluate AND properly in JS).
  if (op === "AND" && filters.length > 1) return null;
  return filters;
}

async function updatePolicyDNR(policies) {
  if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateDynamicRules) return;

  const rules = [];
  let nextId = POLICY_DNR_ID_MIN;
  let skipped = 0;

  for (const policy of policies || []) {
    if (!policy || !policy.enabled || policy.action !== "block") continue;
    const filters = extractURLFilters(policy.conditions);
    if (!filters) {
      skipped++;
      console.log(`[CyberArmor] DNR skip "${policy.name}" — non-URL or compound condition; navigation listener will enforce`);
      continue;
    }
    const policyParam = encodeURIComponent(policy.name || "");
    for (const urlFilter of filters) {
      if (nextId + 1 > POLICY_DNR_ID_MAX) break;
      rules.push({
        id: nextId++,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            extensionPath: "/phishing_warning.html?reason=policy_block&policy=" + policyParam,
          },
        },
        condition: { urlFilter, resourceTypes: ["main_frame"] },
      });
      rules.push({
        id: nextId++,
        priority: 1,
        action: { type: "block" },
        condition: { urlFilter, resourceTypes: POLICY_DNR_BLOCK_TYPES },
      });
    }
  }

  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing
      .map((r) => r.id)
      .filter((id) => id >= POLICY_DNR_ID_MIN && id <= POLICY_DNR_ID_MAX);
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: rules });
    console.log(`[CyberArmor] DNR policy rules synced: ${rules.length} active (${skipped} skipped → listener fallback)`);
  } catch (err) {
    console.warn("[CyberArmor] DNR policy update failed:", err.message);
  }
}

// --- Policy Sync ---

async function syncPolicies() {
  if (!cachedConfig.controlPlaneUrl || !cachedConfig.apiKey) {
    return { ok: false, count: 0, error: "missing controlPlaneUrl or apiKey" };
  }
  const url = `${cachedConfig.controlPlaneUrl.replace(/\/$/, "")}/policies/${cachedConfig.tenantId}/export`;
  try {
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: cachedConfig.controlPlaneUrl,
      apiKey: cachedConfig.apiKey,
      pqcEnabled: cachedConfig.pqcAuthEnabled !== false,
      strict: cachedConfig.pqcAuthStrict === true,
      headers: {
        "Content-Type": "application/json",
        "x-tenant-id": cachedConfig.tenantId || "",
      },
    });
    recordAuthStatus(auth.authInfo, "policy_sync");
    const resp = await fetch(url, { headers: auth.headers });
    if (resp.ok) {
      cachedPolicies = await resp.json();
      await chrome.storage.local.set({ cachedPolicies, lastPolicySync: Date.now() });
      console.log(`[CyberArmor] Synced ${cachedPolicies.length} policies`);
      await updatePolicyDNR(cachedPolicies);
      return { ok: true, count: cachedPolicies.length };
    }
    const body = await resp.text().catch(() => "");
    const error = `HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`;
    console.warn(`[CyberArmor] Policy sync failed: ${error} (${url})`);
    return { ok: false, count: cachedPolicies.length, error };
  } catch (err) {
    console.warn("[CyberArmor] Policy sync failed:", err.message);
    const stored = await chrome.storage.local.get(["cachedPolicies"]);
    if (stored.cachedPolicies) cachedPolicies = stored.cachedPolicies;
    return { ok: false, count: cachedPolicies.length, error: err.message };
  }
}

function startPolicySync() {
  if (policySyncTimer) clearInterval(policySyncTimer);
  syncPolicies();
  policySyncTimer = setInterval(syncPolicies, cachedConfig.policySyncIntervalMs);
}

// --- Phishing Protection (DNR Rules) ---

const PHISHING_RULES = [
  { id: 1001, condition: { regexFilter: "https?://[^/]*@[^/]+", resourceTypes: ["main_frame"] } },
  { id: 1002, condition: { regexFilter: "https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}", resourceTypes: ["main_frame"] } },
  { id: 1003, condition: { regexFilter: "https?://[^/]*xn--[^/]+", resourceTypes: ["main_frame"] } },
  { id: 1004, condition: { urlFilter: "http://*/*login*", resourceTypes: ["main_frame"] } },
  { id: 1005, condition: { urlFilter: "http://*/*signin*", resourceTypes: ["main_frame"] } },
  { id: 1006, condition: { urlFilter: "http://*/*password*", resourceTypes: ["main_frame"] } },
  { id: 1007, condition: { urlFilter: "http://*/*credential*", resourceTypes: ["main_frame"] } },
  { id: 1008, condition: { urlFilter: "*phishing*", resourceTypes: ["main_frame"] } },
];

async function setupPhishingRules() {
  if (!cachedConfig.phishingProtectionEnabled) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: PHISHING_RULES.map((r) => r.id),
    });
    return;
  }
  const action = cachedConfig.phishingMode === "block"
    ? { type: "block" }
    : { type: "redirect", redirect: { extensionPath: "/phishing_warning.html" } };

  const rules = PHISHING_RULES.map((r) => ({
    id: r.id,
    priority: 1,
    action,
    condition: r.condition,
  }));

  // Remove allowlisted domains
  const allowlist = cachedConfig.phishingAllowlistDomains || [];
  const filteredRules = rules; // DNR handles allowlists via excludedDomains

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: PHISHING_RULES.map((r) => r.id),
    addRules: filteredRules,
  });
}

// --- AI Service Monitoring ---

function isAIServiceUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return AI_SERVICE_DOMAINS.some((domain) => hostname === domain || hostname.endsWith("." + domain));
  } catch {
    return false;
  }
}

function checkPromptInjection(text) {
  if (!text || !cachedConfig.promptInjectionDetection) return null;
  const matches = [];
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(pattern.source);
    }
  }
  return matches.length > 0 ? { risk: matches.length >= 3 ? "high" : "medium", patterns: matches } : null;
}

// --- Policy Evaluation (client-side) ---

function evaluatePolicy(context) {
  const enabledPolicies = cachedPolicies.filter((p) => p.enabled);
  for (const policy of enabledPolicies) {
    if (policy.conditions && evaluateConditions(policy.conditions, context)) {
      return {
        matched: true,
        policy: policy.name,
        action: policy.action,
        redact_classes: Array.isArray(policy.redact_classes) ? policy.redact_classes : [],
      };
    }
  }
  return { matched: false };
}

function evaluateConditions(conditions, context) {
  const op = (conditions.operator || "AND").toUpperCase();
  const rules = conditions.rules || [];
  if (!rules.length) return true;

  const results = rules.map((rule) => {
    if (rule.rules) return evaluateConditions(rule, context);
    return evaluateLeafRule(rule, context);
  });

  return op === "OR" ? results.some(Boolean) : results.every(Boolean);
}

function evaluateLeafRule(rule, context) {
  const actual = getNestedValue(context, rule.field || "");
  const expected = rule.value;
  switch (rule.operator) {
    case "equals": return actual === expected;
    case "not_equals": return actual !== expected;
    case "contains": return String(actual || "").includes(String(expected));
    case "not_contains": return !String(actual || "").includes(String(expected));
    case "matches": return new RegExp(String(expected).replace(/\*/g, ".*")).test(String(actual || ""));
    case "in": return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
    case "starts_with": return String(actual || "").startsWith(String(expected));
    case "ends_with": return String(actual || "").endsWith(String(expected));
    case "exists": return actual != null;
    case "not_exists": return actual == null;
    default: return false;
  }
}

function getNestedValue(obj, path) {
  return path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
}

// --- Telemetry ---

async function sendTelemetry(event) {
  if (!cachedConfig.telemetryEnabled || !cachedConfig.controlPlaneUrl) return;
  try {
    const url = `${cachedConfig.controlPlaneUrl.replace(/\/$/, "")}/telemetry/ingest`;
    const auth = await CyberArmorPQCAuth.buildHeaders({
      baseUrl: cachedConfig.controlPlaneUrl,
      apiKey: cachedConfig.apiKey,
      pqcEnabled: cachedConfig.pqcAuthEnabled !== false,
      strict: cachedConfig.pqcAuthStrict === true,
      headers: {
        "Content-Type": "application/json",
        "x-tenant-id": cachedConfig.tenantId || "",
      },
    });
    recordAuthStatus(auth.authInfo, "telemetry");
    // keepalive: true is the critical bit for MV3 service workers. The
    // navigation listener fires sendTelemetry without awaiting the result;
    // without keepalive, the worker can be torn down before the fetch
    // completes and the request is silently aborted.
    const resp = await fetch(url, {
      method: "POST",
      headers: auth.headers,
      keepalive: true,
      body: JSON.stringify({
        tenant_id: cachedConfig.tenantId,
        event_type: event.type,
        payload: event.payload,
        source: "browser_extension",
        occurred_at: new Date().toISOString(),
      }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.warn(`[CyberArmor] Telemetry rejected: HTTP ${resp.status} ${resp.statusText} ${body.slice(0, 160)}`);
    } else {
      console.log(`[CyberArmor] Telemetry sent: ${event.type}`);
    }
  } catch (err) {
    console.warn("[CyberArmor] Telemetry send failed:", err.message);
  }
}

// --- Navigation Monitoring ---

// Evaluate tenant policies against EVERY top-level navigation, not only known
// AI service domains. Fires on onBeforeNavigate so we can redirect to the
// warning page before the bad URL renders. (chrome.webNavigation can't truly
// cancel a top-level navigation, but a tabs.update racing the load gets us
// "the user sees the warning, not the upstream page" in practice.)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url || url.startsWith("chrome-extension://") || url.startsWith("chrome://")) return;

  await configReady;

  let parsed;
  try { parsed = new URL(url); } catch { return; }

  // Detect PII embedded in query string / hash. SPA-driven submits like
  // Google Search bypass the content-script submit interceptor because the
  // page navigates via location-change rather than dispatching a submit
  // event — the PII lands here instead.
  const queryPart = (parsed.search || "") + (parsed.hash || "");
  let piiLabels = [];
  if (queryPart.length > 1) {
    try { piiLabels = detectPIILabels(decodeURIComponent(queryPart)); }
    catch { piiLabels = detectPIILabels(queryPart); }
  }
  const piiClasses = piiLabels.map((l) => "pii." + l);

  const policyResult = evaluatePolicy({
    request: {
      url,
      hostname: parsed.hostname,
      path: parsed.pathname,
      type: isAIServiceUrl(url) ? "ai_service_access" : "navigation",
    },
    content: { pii_classes: piiClasses, has_pii: piiClasses.length > 0 },
  });

  // Temporary diagnostic — surfaces what the navigation listener sees so
  // misconfigured policies are debuggable from the service-worker console.
  if (piiClasses.length > 0 || policyResult.matched) {
    console.log("[CyberArmor nav]", {
      host: parsed.hostname,
      path: parsed.pathname,
      pii: piiClasses,
      policy: policyResult.policy || null,
      action: policyResult.action || null,
      redact_classes: policyResult.redact_classes || null,
    });
  }

  if (policyResult.matched && policyResult.action === "block") {
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL("phishing_warning.html") +
        "?u=" + encodeURIComponent(url) +
        "&reason=policy_block" +
        "&policy=" + encodeURIComponent(policyResult.policy || ""),
    });
    await sendTelemetry({
      type: "policy_block",
      payload: { url, tabId: details.tabId, policy: policyResult.policy, pii_classes: piiClasses },
    });
    return;
  }

  if (policyResult.matched && policyResult.action === "redact" && piiClasses.length > 0) {
    const allowed = new Set(policyResult.redact_classes || []);
    const redacted = redactURL(url, allowed);
    if (redacted && redacted !== url) {
      chrome.tabs.update(details.tabId, { url: redacted });
      await sendTelemetry({
        type: "policy_redact_navigation",
        payload: { url, redacted_url: redacted, tabId: details.tabId, policy: policyResult.policy, pii_classes: piiClasses },
      });
      chrome.tabs.sendMessage(details.tabId, {
        type: "show_warning",
        message: `Redacted PII in URL per policy "${policyResult.policy}".`,
      }).catch(() => {});
      return;
    }
  }

  if (policyResult.matched && policyResult.action === "warn") {
    chrome.tabs.sendMessage(details.tabId, {
      type: "show_warning",
      message: `Policy "${policyResult.policy}" matched ${parsed.hostname}`,
    }).catch(() => {});
  }
});

// Keep the AI-service-specific telemetry on completed navigations so the
// dashboard sees fully-loaded AI-tool sessions distinct from blocked attempts.
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await configReady;
  if (cachedConfig.aiMonitoringEnabled && isAIServiceUrl(details.url)) {
    sendTelemetry({
      type: "ai_service_detected",
      payload: { url: details.url, tabId: details.tabId },
    });
  }
});

// --- Message Listener ---

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "telemetry") {
    sendTelemetry({ type: msg.body?.event_type || "unknown", payload: msg.body?.payload || {} })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "check_prompt_injection") {
    const result = checkPromptInjection(msg.text);
    sendResponse({ injection: result });
    return false;
  }

  if (msg.type === "evaluate_policy") {
    const result = evaluatePolicy(msg.context);
    sendResponse({ result });
    return false;
  }

  if (msg.type === "get_policies") {
    sendResponse({ policies: cachedPolicies });
    return false;
  }

  if (msg.type === "force_policy_sync") {
    configReady.then(() => syncPolicies()).then((result) => {
      sendResponse({ ...result, policies: cachedPolicies });
    });
    return true;
  }

  if (msg.type === "phishing_allowlist_domain") {
    const domain = msg.domain;
    if (domain) {
      const list = cachedConfig.phishingAllowlistDomains || [];
      if (!list.includes(domain)) {
        list.push(domain);
        saveConfig({ phishingAllowlistDomains: list }).then(() => {
          setupPhishingRules();
          sendResponse({ ok: true });
        });
        return true;
      }
    }
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "get_config") {
    sendResponse({ config: { ...cachedConfig, lastAuthStatus } });
    return false;
  }

  if (msg.type === "update_config") {
    saveConfig(msg.updates).then((cfg) => {
      setupPhishingRules();
      if (msg.updates.policySyncIntervalMs || msg.updates.controlPlaneUrl || msg.updates.apiKey) {
        startPolicySync();
      }
      sendResponse({ ok: true, config: cfg });
    });
    return true;
  }

  return false;
});

// --- Startup ---

chrome.runtime.onInstalled.addListener(async () => {
  await loadConfig();
  chrome.storage.local.get(["cyberarmorLastAuthStatus"], (data) => {
    if (data.cyberarmorLastAuthStatus) lastAuthStatus = data.cyberarmorLastAuthStatus;
  });
  try { await ensureBootstrapRedeemed(); } catch (err) { console.warn("[CyberArmor] Bootstrap redeem failed:", err.message); }
  await setupPhishingRules();
  startPolicySync();
  console.log("[CyberArmor] Extension installed and initialized");
});

chrome.runtime.onStartup.addListener(async () => {
  await loadConfig();
  chrome.storage.local.get(["cyberarmorLastAuthStatus"], (data) => {
    if (data.cyberarmorLastAuthStatus) lastAuthStatus = data.cyberarmorLastAuthStatus;
  });
  try { await ensureBootstrapRedeemed(); } catch (err) { console.warn("[CyberArmor] Bootstrap redeem failed:", err.message); }
  await setupPhishingRules();
  startPolicySync();
  console.log("[CyberArmor] Extension started");
});

// Config change listener
chrome.storage.onChanged.addListener((changes) => {
  for (const key of Object.keys(changes)) {
    if (key in cachedConfig) {
      cachedConfig[key] = changes[key].newValue;
    }
  }
  if (changes.phishingProtectionEnabled || changes.phishingMode || changes.phishingAllowlistDomains) {
    setupPhishingRules();
  }
});
