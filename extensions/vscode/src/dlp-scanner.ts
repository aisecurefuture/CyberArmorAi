/**
 * DLP Scanner — Detect sensitive data in source files.
 */

import * as vscode from 'vscode';
import { PolicyClient } from './policy-client';

interface Finding { name: string; line: number; match: string; severity: string; category: string; }

const PATTERNS = [
  { name: 'AWS Access Key',   pattern: /AKIA[0-9A-Z]{16}/g,                        severity: 'critical', category: 'secrets', placeholder: '[REDACTED-AWS-KEY]' },
  { name: 'AWS Secret Key',   pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}/g, severity: 'critical', category: 'secrets', placeholder: '[REDACTED-AWS-SECRET]' },
  { name: 'GitHub Token',     pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical', category: 'secrets', placeholder: '[REDACTED-GITHUB-TOKEN]' },
  { name: 'OpenAI API Key',   pattern: /\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,})\b/g, severity: 'critical', category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]' },
  { name: 'Private Key',      pattern: /-----BEGIN\s+(RSA|EC|DSA|PRIVATE)\s+KEY-----/g, severity: 'critical', category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]' },
  { name: 'Generic API Key',  pattern: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}/gi, severity: 'high', category: 'secrets', placeholder: '[REDACTED-APIKEY]' },
  { name: 'JWT',              pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, severity: 'high', category: 'secrets', placeholder: '[REDACTED-JWT]' },
  { name: 'Password in Code', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, severity: 'high', category: 'secrets', placeholder: '[REDACTED-PASSWORD]' },
  { name: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi, severity: 'high', category: 'secrets', placeholder: '[REDACTED-CONNECTION-STRING]' },
  { name: 'SSN',              pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                   severity: 'critical', category: 'pii', placeholder: '[REDACTED-SSN]' },
  { name: 'Credit Card',      pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,             severity: 'critical', category: 'pci', placeholder: '[REDACTED-CARD]' },
  { name: 'Bank Account',     pattern: /\b(?:account\s*(?:number|no|#)?\s*[:=]?\s*)\d{8,17}\b/gi, severity: 'critical', category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]' },
  { name: 'Routing Number',   pattern: /\b(?:routing\s*(?:number|no|#)?\s*[:=]?\s*)\d{9}\b/gi, severity: 'critical', category: 'nacha', placeholder: '[REDACTED-ROUTING]' },
  { name: 'NPI',              pattern: /\bNPI\s*[:=]?\s*\d{10}\b/gi,              severity: 'critical', category: 'npi', placeholder: '[REDACTED-NPI]' },
  { name: 'Email Address',    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'low', category: 'pii', placeholder: '[REDACTED-EMAIL]' },
  { name: 'IP Address',       pattern: /\b(?:(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b/g, severity: 'low', category: 'nonpublic', placeholder: '[REDACTED-PRIVATE-IP]' },
];

const IGNORED_FILES = /\.(lock|min\.js|min\.css|map|svg|png|jpg|gif|ico|woff|ttf|eot)$/;

export class DLPScanner {
  private policyClient: PolicyClient;
  private diagnostics: vscode.DiagnosticCollection | null = null;
  private sessionFindings = 0;

  constructor(policyClient: PolicyClient) {
    this.policyClient = policyClient;
  }

  setDiagnostics(diag: vscode.DiagnosticCollection) { this.diagnostics = diag; }
  getSessionFindings(): number { return this.sessionFindings; }

  scanDocument(document: vscode.TextDocument): Finding[] {
    if (IGNORED_FILES.test(document.fileName)) return [];

    const text = document.getText();
    const findings: Finding[] = [];
    const diagList: vscode.Diagnostic[] = [];

    for (const pat of PATTERNS) {
      pat.pattern.lastIndex = 0;
      let match;
      while ((match = pat.pattern.exec(text)) !== null) {
        const pos = document.positionAt(match.index);
        findings.push({
          name: pat.name,
          line: pos.line + 1,
          match: pat.placeholder,
          severity: pat.severity,
          category: pat.category,
        });

        const range = new vscode.Range(pos, document.positionAt(match.index + match[0].length));
        const sev = pat.severity === 'critical' ? vscode.DiagnosticSeverity.Error :
                     pat.severity === 'high' ? vscode.DiagnosticSeverity.Warning :
                     vscode.DiagnosticSeverity.Information;
        diagList.push(new vscode.Diagnostic(range, `CyberArmor DLP: ${pat.name} detected`, sev));
      }
    }

    if (this.diagnostics) {
      this.diagnostics.set(document.uri, diagList);
    }

    this.sessionFindings += findings.length;
    return findings;
  }

  async redactDocument(document: vscode.TextDocument, mode = 'redact'): Promise<number> {
    const original = document.getText();
    const redacted = redactText(original, mode);
    if (redacted === original) return 0;
    const fullRange = new vscode.Range(
      document.positionAt(0),
      document.positionAt(original.length),
    );
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, fullRange, redacted);
    const ok = await vscode.workspace.applyEdit(edit);
    if (!ok) return 0;
    return countRedactions(original, mode);
  }
}

const REDACTION_CATEGORIES: Record<string, string[]> = {
  redact: ['secrets', 'pii', 'pci', 'nacha', 'npi', 'nonpublic'],
  'redact-sensitive': ['secrets', 'pii', 'pci', 'nacha', 'npi', 'nonpublic'],
  'redact-nonpublic': ['nonpublic'],
  'redact-secrets': ['secrets'],
  'redact-credentials': ['secrets'],
  'redact-pii': ['pii'],
  'redact-pci': ['pci'],
  'redact-nacha': ['nacha'],
  'redact-bank': ['nacha'],
  'redact-npi': ['npi'],
};

function categoriesForMode(mode: string): Set<string> {
  return new Set(REDACTION_CATEGORIES[String(mode || 'redact').toLowerCase()] || REDACTION_CATEGORIES.redact);
}

function redactText(text: string, mode: string): string {
  const categories = categoriesForMode(mode);
  let result = text;
  for (const pat of PATTERNS) {
    if (!categories.has(pat.category)) continue;
    pat.pattern.lastIndex = 0;
    result = result.replace(pat.pattern, pat.placeholder);
  }
  return result;
}

function countRedactions(text: string, mode: string): number {
  const categories = categoriesForMode(mode);
  let count = 0;
  for (const pat of PATTERNS) {
    if (!categories.has(pat.category)) continue;
    pat.pattern.lastIndex = 0;
    count += Array.from(text.matchAll(pat.pattern)).length;
  }
  return count;
}
