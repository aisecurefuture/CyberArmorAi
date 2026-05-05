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
  mode: pickEnv('CYBERARMOR_MODE') || 'monitor', // monitor | block
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
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'credit_card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/ },
  { name: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'github_token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/ },
  { name: 'private_key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/ },
];

function detectPromptInjection(text) {
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(text)) return p.source;
  }
  return null;
}

function scanDlp(text) {
  return DLP_PATTERNS.filter(d => d.pattern.test(text)).map(d => d.name);
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
      return origRequest.call(mod, urlOrOpts, optsOrCb, cb);
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

module.exports = { init, config, inspect, expressMiddleware, koaMiddleware, patch, isAiEndpoint, detectPromptInjection, scanDlp, ensureBootstrapRedeemed };
