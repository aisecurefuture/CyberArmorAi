/**
 * CyberArmor RASP — Node.js Runtime Application Self-Protection
 * Supports: Express/Koa/Fastify middleware, http/https monkey-patching
 */

'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

function pickEnv(...keys) {
  for (const key of keys) {
    const value = process.env[key];
    if (value && value.length > 0) return value;
  }
  return '';
}

// ── Config ───────────────────────────────────────────────
const config = {
  controlPlaneUrl: pickEnv('CYBERARMOR_CONTROL_PLANE_URL', 'CYBERARMOR_URL') || 'http://localhost:8000',
  apiKey: pickEnv('CYBERARMOR_API_KEY') || '',
  bootstrapToken: pickEnv('CYBERARMOR_BOOTSTRAP_TOKEN') || '',
  tenantId: pickEnv('CYBERARMOR_TENANT_ID', 'CYBERARMOR_TENANT') || 'default',
  mode: pickEnv('CYBERARMOR_MODE') || 'monitor', // monitor | warn | block | redact*
  dlpEnabled: true,
  promptInjectionEnabled: true,
};

let bootstrapPromise = null;

function getRuntimeSubjectName() {
  return pickEnv('CYBERARMOR_RASP_SUBJECT_NAME', 'HOSTNAME') || 'nodejs-rasp';
}

async function redeemBootstrapToken() {
  if (!config.bootstrapToken || config.apiKey || !config.controlPlaneUrl) return null;
  const payload = JSON.stringify({
    bootstrap_token: config.bootstrapToken,
    package_key: 'rasp-nodejs',
    subject_type: 'rasp_runtime',
    subject_name: getRuntimeSubjectName(),
  });

  const u = new URL('/bootstrap/redeem', config.controlPlaneUrl);
  const mod = u.protocol === 'https:' ? https : http;

  const responseText = await new Promise((resolve, reject) => {
    const req = mod.request(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`Bootstrap redeem failed with status ${res.statusCode}: ${body}`));
          return;
        }
        resolve(body);
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });

  const data = JSON.parse(responseText || '{}');
  if (data.api_key) {
    config.apiKey = data.api_key;
  }
  if (data.tenant_id) {
    config.tenantId = data.tenant_id;
  }
  return data;
}

async function ensureBootstrapRedeemed() {
  if (!config.bootstrapToken || config.apiKey) return;
  if (!bootstrapPromise) {
    bootstrapPromise = redeemBootstrapToken().catch((err) => {
      bootstrapPromise = null;
      throw err;
    });
  }
  await bootstrapPromise;
}

// ── AI Endpoints ─────────────────────────────────────────
const AI_DOMAINS = new Set([
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
  'api.cohere.ai', 'api.mistral.ai', 'api-inference.huggingface.co',
  'api.together.xyz', 'api.replicate.com', 'api.groq.com',
]);

function isAiEndpoint(hostname) {
  return AI_DOMAINS.has(hostname) ||
    /\.openai\.azure\.com$/.test(hostname) ||
    /\.cognitiveservices\.azure\.com$/.test(hostname);
}

// ── Detection ────────────────────────────────────────────
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|in)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*(system|prompt|instruction)\s*>/i,
  /jailbreak|DAN\s+mode|bypass\s+filter/i,
  /forget\s+(everything|all|your)/i,
];

const DLP_PATTERNS = [
  { name: 'ssn', category: 'pii', placeholder: '[REDACTED-SSN]', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'email', category: 'pii', placeholder: '[REDACTED-EMAIL]', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { name: 'phone', category: 'pii', placeholder: '[REDACTED-PHONE]', pattern: /\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g },
  { name: 'credit_card', category: 'pci', placeholder: '[REDACTED-CARD]', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
  { name: 'routing_number', category: 'nacha', placeholder: '[REDACTED-ROUTING]', pattern: /\b\d{9}\b/g },
  { name: 'bank_account', category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]', pattern: /\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b/gi },
  { name: 'npi', category: 'npi', placeholder: '[REDACTED-NPI]', pattern: /\b(?:npi\s*[:#]?\s*)?\d{10}\b/gi },
  { name: 'private_ip', category: 'nonpublic', placeholder: '[REDACTED-PRIVATE-IP]', pattern: /\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g },
  { name: 'aws_key', category: 'secrets', placeholder: '[REDACTED-AWS-KEY]', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'openai_key', category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'github_token', category: 'secrets', placeholder: '[REDACTED-GITHUB-TOKEN]', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/g },
  { name: 'bearer_token', category: 'secrets', placeholder: '[REDACTED-BEARER]', pattern: /\bBearer\s+[A-Za-z0-9_.-]{20,}\b/g },
  { name: 'password', category: 'secrets', placeholder: '[REDACTED-PASSWORD]', pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*['"]?[^'"\s]{6,}/gi },
  { name: 'jwt', category: 'secrets', placeholder: '[REDACTED-JWT]', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b/g },
  { name: 'api_key', category: 'secrets', placeholder: '[REDACTED-API-KEY]', pattern: /\b(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{12,}/gi },
  { name: 'private_key', category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]', pattern: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g },
];

const REDACTION_CATEGORIES = {
  redact: ['secrets', 'pii', 'pci', 'nacha', 'npi', 'nonpublic'],
  'redact-secrets': ['secrets'],
  'redact-pii': ['pii'],
  'redact-pci': ['pci'],
  'redact-nacha': ['nacha'],
  'redact-npi': ['npi'],
  'redact-nonpublic': ['nonpublic'],
};

function normalizeMode(mode) {
  const normalized = String(mode || '').trim().toLowerCase().replace(/_/g, '-');
  return normalized === 'redact-nachi' ? 'redact-nacha' : normalized;
}

function isRedactionMode(mode) {
  return Object.prototype.hasOwnProperty.call(REDACTION_CATEGORIES, normalizeMode(mode));
}

function detectPromptInjection(text) {
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(text)) return p.source;
  }
  return null;
}

function scanDlp(text) {
  return DLP_PATTERNS.filter(d => new RegExp(d.pattern.source, d.pattern.flags).test(text)).map(d => d.name);
}

function redactText(text, mode = 'redact') {
  const categories = REDACTION_CATEGORIES[normalizeMode(mode)] || REDACTION_CATEGORIES.redact;
  let redacted = String(text || '');
  const findings = [];
  for (const rule of DLP_PATTERNS) {
    if (!categories.includes(rule.category)) continue;
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let matched = false;
    redacted = redacted.replace(pattern, () => {
      matched = true;
      return rule.placeholder;
    });
    if (matched) findings.push(rule.name);
  }
  return { text: redacted, findings };
}

function redactJsonValue(value, mode) {
  if (typeof value === 'string') return redactText(value, mode).text;
  if (Array.isArray(value)) return value.map(item => redactJsonValue(item, mode));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactJsonValue(item, mode)]));
  }
  return value;
}

function redactProviderPayload(body, mode = 'redact') {
  try {
    return JSON.stringify(redactJsonValue(JSON.parse(body), mode));
  } catch {
    return redactText(body, mode).text;
  }
}

// ── Telemetry ────────────────────────────────────────────
const eventBuffer = [];
function recordEvent(type, url, detail = '') {
  eventBuffer.push({ ts: Date.now(), type, url, detail: detail.slice(0, 200), tenant: config.tenantId });
  if (eventBuffer.length >= 50) {
    const batch = eventBuffer.splice(0);
    flushTelemetry(batch).catch(() => {});
  }
}

async function flushTelemetry(batch) {
  if (!config.controlPlaneUrl) return;
  try {
    await ensureBootstrapRedeemed();
    const body = JSON.stringify(batch);
    const u = new URL('/telemetry/ingest', config.controlPlaneUrl);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey } });
    req.write(body);
    req.end();
  } catch {}
}

// ── Core Inspection ──────────────────────────────────────
function inspect(url, body = '') {
  const hostname = typeof url === 'string' ? new URL(url).hostname : (url.hostname || '');
  if (!isAiEndpoint(hostname)) return { allowed: true };

  recordEvent('ai_request', String(url));

  if (config.promptInjectionEnabled && body) {
    const pattern = detectPromptInjection(body);
    if (pattern) {
      recordEvent('prompt_injection', String(url), pattern);
      if (config.mode === 'block') return { allowed: false, reason: `Prompt injection: ${pattern}` };
    }
  }

  if (config.dlpEnabled && body) {
    const findings = scanDlp(body);
    if (findings.length) {
      recordEvent('sensitive_data', String(url), findings.join(','));
      if (config.mode === 'block') return { allowed: false, reason: `Sensitive data: ${findings.join(',')}` };
      if (isRedactionMode(config.mode)) {
        const redactedBody = redactProviderPayload(body, config.mode);
        if (redactedBody !== body) {
          recordEvent('sensitive_data_redacted', String(url), findings.join(','));
          return { allowed: true, reason: 'Sensitive data redacted', redactedBody };
        }
      }
    }
  }

  return { allowed: true };
}

// ── Express Middleware ────────────────────────────────────
function expressMiddleware() {
  return async (req, res, next) => {
    if (req.method !== 'POST') return next();
    const host = req.headers['x-forwarded-host'] || req.headers.host || '';
    if (!isAiEndpoint(host)) return next();
    try {
      await ensureBootstrapRedeemed();
    } catch (err) {
      return next(err);
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const result = inspect(`https://${host}${req.path}`, body);
      if (!result.allowed) {
        return res.status(403).json({ error: result.reason, policy: 'cyberarmor-rasp' });
      }
      if (result.redactedBody) {
        req.cyberarmorRedactedBody = result.redactedBody;
        if (req.body && typeof req.body === 'object') {
          try { req.body = JSON.parse(result.redactedBody); } catch {}
        } else if (typeof req.body === 'string') {
          req.body = result.redactedBody;
        }
        req.headers['content-length'] = String(Buffer.byteLength(result.redactedBody));
      }
      next();
    });
  };
}

// ── Koa Middleware ────────────────────────────────────────
function koaMiddleware() {
  return async (ctx, next) => {
    if (ctx.method === 'POST') {
      const host = ctx.headers['x-forwarded-host'] || ctx.host || '';
      if (isAiEndpoint(host)) {
        await ensureBootstrapRedeemed();
        const body = typeof ctx.request.body === 'string' ? ctx.request.body : JSON.stringify(ctx.request.body || '');
        const result = inspect(`https://${host}${ctx.path}`, body);
        if (!result.allowed) {
          ctx.status = 403;
          ctx.body = { error: result.reason, policy: 'cyberarmor-rasp' };
          return;
        }
        if (result.redactedBody) {
          ctx.request.cyberarmorRedactedBody = result.redactedBody;
          try {
            ctx.request.body = JSON.parse(result.redactedBody);
          } catch {
            ctx.request.body = result.redactedBody;
          }
        }
      }
    }
    await next();
  };
}

// ── HTTP Monkey-Patch ────────────────────────────────────
let patched = false;
function patch() {
  if (patched) return;
  patched = true;

  [http, https].forEach(mod => {
    const origRequest = mod.request;
    mod.request = function(urlOrOpts, optsOrCb, cb) {
      const opts = typeof urlOrOpts === 'string' ? new URL(urlOrOpts) : urlOrOpts;
      const hostname = opts.hostname || opts.host || '';
      if (isAiEndpoint(hostname)) {
        recordEvent('ai_request_outbound', `${hostname}${opts.path || ''}`);
      }
      const req = origRequest.call(mod, urlOrOpts, optsOrCb, cb);
      if (!isAiEndpoint(hostname)) return req;

      const originalWrite = req.write.bind(req);
      const originalEnd = req.end.bind(req);
      const chunks = [];

      req.write = function(chunk, encoding, callback) {
        if (typeof encoding === 'function') {
          callback = encoding;
          encoding = undefined;
        }
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding));
        if (typeof callback === 'function') process.nextTick(callback);
        return true;
      };

      req.end = function(chunk, encoding, callback) {
        if (typeof chunk === 'function') {
          callback = chunk;
          chunk = undefined;
          encoding = undefined;
        } else if (typeof encoding === 'function') {
          callback = encoding;
          encoding = undefined;
        }
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding));
        }
        const body = Buffer.concat(chunks).toString('utf8');
        const targetUrl = `${opts.protocol || 'https:'}//${hostname}${opts.path || ''}`;
        const result = inspect(targetUrl, body);
        if (!result.allowed) {
          req.destroy(new Error(`CyberArmor RASP blocked: ${result.reason}`));
          if (typeof callback === 'function') process.nextTick(callback);
          return req;
        }
        const outboundBody = result.redactedBody || body;
        if (outboundBody) {
          req.setHeader('Content-Length', Buffer.byteLength(outboundBody));
          originalWrite(outboundBody);
        }
        return originalEnd(callback);
      };
      return req;
    };
  });

  console.log('[CyberArmor RASP] HTTP modules patched');
}

// ── Init ─────────────────────────────────────────────────
async function init(opts = {}) {
  Object.assign(config, opts);
  await ensureBootstrapRedeemed();
  patch();
  console.log(`[CyberArmor RASP] Initialized (mode=${config.mode})`);
}

module.exports = {
  init,
  config,
  inspect,
  expressMiddleware,
  koaMiddleware,
  patch,
  isAiEndpoint,
  detectPromptInjection,
  scanDlp,
  redactText,
  redactProviderPayload,
  isRedactionMode,
  ensureBootstrapRedeemed,
};
