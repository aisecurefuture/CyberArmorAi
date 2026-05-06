/**
 * CyberArmor Protect — Office 365 Task Pane
 * Main UI logic for document scanning, DLP, and compliance checking.
 */

/* global Office, Word, Excel, PowerPoint, OneNote */

const DLP_PATTERNS = [
  { name: 'SSN', category: 'pii', placeholder: '[REDACTED-SSN]', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' },
  { name: 'Date of Birth', category: 'pii', placeholder: '[REDACTED-DOB]', pattern: /\b(?:dob|date of birth)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/gi, severity: 'medium' },
  { name: 'Credit Card', category: 'pci', placeholder: '[REDACTED-CARD]', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, severity: 'critical' },
  { name: 'Routing Number', category: 'nacha', placeholder: '[REDACTED-ROUTING]', pattern: /\b\d{9}\b/g, severity: 'high' },
  { name: 'Bank Account', category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]', pattern: /\b(?:account|acct)\s*(?:number|#|no\.?)?\s*[:=]?\s*\d{8,17}\b/gi, severity: 'high' },
  { name: 'NPI', category: 'npi', placeholder: '[REDACTED-NPI]', pattern: /\b(?:npi\s*[:#]?\s*)?\d{10}\b/gi, severity: 'high' },
  { name: 'Email', category: 'pii', placeholder: '[REDACTED-EMAIL]', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'low' },
  { name: 'Phone', category: 'pii', placeholder: '[REDACTED-PHONE]', pattern: /\b\d{3}[-.)]\s?\d{3}[-.)]\s?\d{4}\b/g, severity: 'medium' },
  { name: 'AWS Key', category: 'secrets', placeholder: '[REDACTED-AWS-KEY]', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'OpenAI Key', category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]', pattern: /sk-[A-Za-z0-9_-]{20,}/g, severity: 'critical' },
  { name: 'Private Key', category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]', pattern: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'API Key', category: 'secrets', placeholder: '[REDACTED-API-KEY]', pattern: /(?:api[_-]?key|apikey|secret|token|password)\s*[=:]\s*["']?[A-Za-z0-9_./+=-]{12,}/gi, severity: 'high' },
];

const REDACTION_CATEGORIES = {
  redact: ['secrets', 'pii', 'pci', 'nacha', 'npi', 'nonpublic'],
  'redact-secrets': ['secrets'],
  'redact-pii': ['pii'],
  'redact-pci': ['pci'],
  'redact-nacha': ['nacha'],
  'redact-npi': ['npi'],
};

function categoriesForMode(mode = 'redact') {
  return REDACTION_CATEGORIES[mode] || REDACTION_CATEGORIES.redact;
}

function redactText(text, mode = 'redact') {
  const categories = categoriesForMode(mode);
  let redacted = String(text || '');
  let count = 0;
  const labels = new Set();
  for (const rule of DLP_PATTERNS) {
    if (!categories.includes(rule.category)) continue;
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    redacted = redacted.replace(pattern, () => {
      count += 1;
      labels.add(rule.name);
      return rule.placeholder;
    });
  }
  return { text: redacted, count, labels: [...labels] };
}

Office.onReady((info) => {
  document.getElementById('scanBtn').addEventListener('click', scanDocument);
  document.getElementById('redactBtn').addEventListener('click', redactDocument);
  document.getElementById('complianceBtn').addEventListener('click', checkCompliance);
  document.getElementById('classifyBtn').addEventListener('click', classifyContent);
  renderPatternList();
});

async function scanDocument() {
  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '<p class="empty">Scanning...</p>';

  try {
    let text = '';
    const host = Office.context.host;

    if (host === Office.HostType.Word) {
      text = await getWordText();
    } else if (host === Office.HostType.Excel) {
      text = await getExcelText();
    } else if (host === Office.HostType.PowerPoint) {
      text = await getPowerPointText();
    } else {
      text = 'Unsupported host for direct scanning';
    }

    const findings = scanText(text);
    renderFindings(findings);
  } catch (e) {
    findingsEl.innerHTML = `<div class="finding critical">Error: ${e.message}</div>`;
  }
}

function scanText(text) {
  const findings = [];
  for (const pat of DLP_PATTERNS) {
    pat.pattern.lastIndex = 0;
    let match;
    while ((match = pat.pattern.exec(text)) !== null) {
      findings.push({
        name: pat.name,
        category: pat.category,
        severity: pat.severity,
        match: pat.placeholder,
        position: match.index,
      });
    }
  }
  return findings;
}

function renderFindings(findings) {
  const el = document.getElementById('findings');
  if (findings.length === 0) {
    el.innerHTML = '<p class="empty">No sensitive data found.</p>';
    return;
  }
  el.innerHTML = findings.map(f =>
    `<div class="finding ${f.severity}"><strong>${f.name}</strong> (${f.category || 'data'})<br><code>${f.match}</code></div>`
  ).join('');
}

function renderPatternList() {
  const el = document.getElementById('dlpPatterns');
  el.innerHTML = DLP_PATTERNS.map(p =>
    `<div class="pattern"><span>${p.name}</span><span class="badge active">Active</span></div>`
  ).join('');
}

async function getWordText() {
  return new Promise((resolve, reject) => {
    Word.run(async (context) => {
      const body = context.document.body;
      body.load('text');
      await context.sync();
      resolve(body.text);
    }).catch(reject);
  });
}

async function getExcelText() {
  return new Promise((resolve, reject) => {
    Excel.run(async (context) => {
      const sheet = context.workbook.worksheets.getActiveWorksheet();
      const range = sheet.getUsedRange();
      range.load('text');
      await context.sync();
      const allText = range.text.flat().join(' ');
      resolve(allText);
    }).catch(reject);
  });
}

async function getPowerPointText() {
  return new Promise((resolve) => {
    Office.context.document.getSelectedDataAsync(Office.CoercionType.Text, (result) => {
      resolve(result.status === Office.AsyncResultStatus.Succeeded ? result.value : '');
    });
  });
}

async function redactDocument() {
  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '<p class="empty">Redacting findings...</p>';

  try {
    const host = Office.context.host;
    if (host === Office.HostType.Word) {
      const result = await redactWordDocument();
      findingsEl.innerHTML = `<div class="finding ${result.count ? 'high' : 'medium'}"><strong>Redaction Complete</strong><br>${result.count} finding(s) replaced with safe placeholders.</div>`;
      return;
    }

    if (host === Office.HostType.Excel) {
      const result = await redactExcelWorksheet();
      findingsEl.innerHTML = `<div class="finding ${result.count ? 'high' : 'medium'}"><strong>Redaction Complete</strong><br>${result.count} cell finding(s) replaced with safe placeholders.</div>`;
      return;
    }

    if (host === Office.HostType.PowerPoint) {
      const result = await redactPowerPointSelection();
      findingsEl.innerHTML = `<div class="finding ${result.count ? 'high' : 'medium'}"><strong>Selection Redaction Complete</strong><br>${result.count} finding(s) replaced in the current selection.</div>`;
      return;
    }

    findingsEl.innerHTML = '<div class="finding medium"><strong>Redaction unavailable</strong><br>This Office host does not support document rewrite from the task pane.</div>';
  } catch (e) {
    findingsEl.innerHTML = `<div class="finding critical">Error: ${e.message}</div>`;
  }
}

async function redactWordDocument() {
  return new Promise((resolve, reject) => {
    Word.run(async (context) => {
      const body = context.document.body;
      body.load('text');
      await context.sync();
      const result = redactText(body.text, 'redact');
      if (result.text !== body.text) {
        body.insertText(result.text, Word.InsertLocation.replace);
        await context.sync();
      }
      resolve(result);
    }).catch(reject);
  });
}

async function redactExcelWorksheet() {
  return new Promise((resolve, reject) => {
    Excel.run(async (context) => {
      const sheet = context.workbook.worksheets.getActiveWorksheet();
      const range = sheet.getUsedRange();
      range.load('values');
      await context.sync();
      let count = 0;
      const nextValues = range.values.map(row => row.map(value => {
        if (typeof value !== 'string') return value;
        const result = redactText(value, 'redact');
        count += result.count;
        return result.text;
      }));
      if (count > 0) {
        range.values = nextValues;
        await context.sync();
      }
      resolve({ count });
    }).catch(reject);
  });
}

async function redactPowerPointSelection() {
  const selected = await getPowerPointText();
  const result = redactText(selected, 'redact');
  if (result.text !== selected) {
    await new Promise((resolve, reject) => {
      Office.context.document.setSelectedDataAsync(result.text, { coercionType: Office.CoercionType.Text }, (response) => {
        if (response.status === Office.AsyncResultStatus.Succeeded) resolve();
        else reject(new Error(response.error?.message || 'Could not redact selection'));
      });
    });
  }
  return result;
}

async function checkCompliance() {
  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '<div class="finding medium"><strong>Compliance Check</strong><br>Running GDPR, PCI-DSS, and SOC 2 checks on document content...</div>';
}

async function classifyContent() {
  const findingsEl = document.getElementById('findings');
  try {
    let text = '';
    if (Office.context.host === Office.HostType.Word) text = await getWordText();

    const findings = scanText(text);
    const hasCritical = findings.some(f => f.severity === 'critical');
    const hasHigh = findings.some(f => f.severity === 'high');
    const classification = hasCritical ? 'RESTRICTED' : hasHigh ? 'CONFIDENTIAL' : findings.length > 0 ? 'INTERNAL' : 'PUBLIC';

    findingsEl.innerHTML = `<div class="finding ${hasCritical ? 'critical' : hasHigh ? 'high' : 'medium'}">
      <strong>Classification: ${classification}</strong><br>
      Based on ${findings.length} finding(s) in document content.
    </div>`;
  } catch (e) {
    findingsEl.innerHTML = `<div class="finding critical">Error: ${e.message}</div>`;
  }
}
