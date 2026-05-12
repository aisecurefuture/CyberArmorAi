/**
 * CyberArmor Protect — Firefox Content Script
 * PII detection, XSS prevention, AI chat monitoring, prompt injection scanning.
 */

const PII_PATTERNS = [
  { name: 'SSN', category: 'pii', placeholder: '[REDACTED-SSN]', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'Credit Card', category: 'pci', placeholder: '[REDACTED-CARD]', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g },
  { name: 'Routing Number', category: 'nacha', placeholder: '[REDACTED-ROUTING]', pattern: /\b\d{9}\b/g },
  { name: 'Bank Account', category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]', pattern: /\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b/gi },
  { name: 'NPI', category: 'npi', placeholder: '[REDACTED-NPI]', pattern: /\b(?:npi\s*[:#]?\s*)?\d{10}\b/gi },
  { name: 'Email', category: 'pii', placeholder: '[REDACTED-EMAIL]', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: 'Private IP', category: 'nonpublic', placeholder: '[REDACTED-PRIVATE-IP]', pattern: /\b(?:(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b/g },
  { name: 'AWS Key', category: 'secrets', placeholder: '[REDACTED-AWS-KEY]', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'OpenAI Key', category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]', pattern: /sk-[A-Za-z0-9_-]{20,}/g },
  { name: 'GitHub Token', category: 'secrets', placeholder: '[REDACTED-GITHUB-TOKEN]', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g },
  { name: 'Private Key', category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g },
];

const REDACTION_CATEGORIES = {
  redact: ['secrets', 'pii', 'pci', 'nacha', 'npi'],
  'redact-secrets': ['secrets'],
  'redact-pii': ['pii'],
  'redact-pci': ['pci'],
  'redact-nacha': ['nacha'],
  'redact-npi': ['npi'],
  'redact-nonpublic': ['nonpublic'],
};

let config = { actionMode: 'warn' };

browser.storage.sync.get('cyberarmor_config').then(data => {
  config = { ...config, ...(data.cyberarmor_config || {}) };
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && changes.cyberarmor_config) {
    config = { ...config, ...(changes.cyberarmor_config.newValue || {}) };
  }
});

const XSS_PATTERNS = [
  /<script[\s>]/i, /javascript:/i, /on(error|load|click|mouseover)\s*=/i,
  /eval\s*\(/i, /document\.cookie/i, /innerHTML\s*=/i,
];

const AI_CHAT_SELECTORS = [
  'textarea[data-id="root"]', '#prompt-textarea', 'div[contenteditable="true"]',
  '.ProseMirror', 'textarea.w-full', 'textarea[placeholder*="message"]',
];

// Monitor AI chat inputs
function monitorAIChatInputs() {
  const inputs = [];
  AI_CHAT_SELECTORS.forEach(sel => {
    document.querySelectorAll(sel).forEach(el => inputs.push(el));
  });

  inputs.forEach(input => {
    if (input._cyberarmorMonitored) return;
    input._cyberarmorMonitored = true;

    input.addEventListener('paste', (e) => {
      const text = e.clipboardData?.getData('text') || '';
      const piiFound = scanFindings(text);
      if (piiFound.length > 0) {
        if (isRedactionMode(config.actionMode)) {
          e.preventDefault();
          insertText(input, redactText(text, config.actionMode));
          showWarning(`Sensitive data redacted in paste: ${piiFound.map(p => p.name).join(', ')}`);
        } else {
          showWarning(`PII detected in paste: ${piiFound.map(p => p.name).join(', ')}`);
        }
      }
    });

    input.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' || e.shiftKey || !isRedactionMode(config.actionMode)) return;
      const text = getInputText(input);
      const redacted = redactText(text, config.actionMode);
      if (redacted !== text) {
        setInputText(input, redacted);
        showWarning('Sensitive data redacted before AI submission.');
      }
    }, true);
  });
}

function normalizeMode(mode) {
  const normalized = String(mode || '').trim().toLowerCase().replace(/_/g, '-');
  return normalized === 'redact-nachi' ? 'redact-nacha' : normalized;
}

function isRedactionMode(mode) {
  return Object.prototype.hasOwnProperty.call(REDACTION_CATEGORIES, normalizeMode(mode));
}

function redactText(text, mode = 'redact') {
  const categories = REDACTION_CATEGORIES[normalizeMode(mode)] || REDACTION_CATEGORIES.redact;
  let redacted = String(text || '');
  for (const rule of PII_PATTERNS) {
    if (!categories.includes(rule.category)) continue;
    redacted = redacted.replace(new RegExp(rule.pattern.source, rule.pattern.flags), rule.placeholder);
  }
  return redacted;
}

function scanFindings(text) {
  return PII_PATTERNS.filter((rule) => {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    return pattern.test(text);
  });
}

function getInputText(input) {
  if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') return input.value || '';
  return input.innerText || input.textContent || '';
}

function setInputText(input, text) {
  if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
    input.value = text;
  } else {
    input.textContent = text;
  }
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function insertText(input, text) {
  if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? input.value.length;
    input.value = `${input.value.slice(0, start)}${text}${input.value.slice(end)}`;
  } else {
    document.execCommand('insertText', false, text);
  }
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

function showWarning(message) {
  const banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;padding:12px 20px;background:#991b1b;color:#fff;font-family:system-ui;font-size:14px;text-align:center;';
  banner.textContent = `⚠ CyberArmor: ${message}`;
  const close = document.createElement('button');
  close.textContent = '✕';
  close.style.cssText = 'margin-left:16px;background:none;border:none;color:#fff;cursor:pointer;font-size:16px;';
  close.onclick = () => banner.remove();
  banner.appendChild(close);
  document.body.prepend(banner);
  setTimeout(() => banner.remove(), 8000);
}

// Background script fires this when a blocking webRequest cancels an
// AI upload — surface it with the same banner copy the chromium build
// uses so the demo looks identical across browsers.
if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.onMessage) {
  browser.runtime.onMessage.addListener((msg) => {
    if (!msg || typeof msg !== 'object') return;
    if (msg.type !== 'cyberarmor:upload_blocked_dnr') return;
    let host = '';
    try { host = new URL(msg.url || '').hostname; } catch { /* ignore */ }
    showWarning(`File upload to ${host || 'this service'} blocked by policy "${msg.policy || 'policy'}".`);
  });
}

// Observe DOM for new chat inputs
const observer = new MutationObserver(() => monitorAIChatInputs());
observer.observe(document.documentElement, { childList: true, subtree: true });

// Initial scan
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', monitorAIChatInputs);
} else {
  monitorAIChatInputs();
}

console.log('[CyberArmor Protect] Firefox content script loaded');
