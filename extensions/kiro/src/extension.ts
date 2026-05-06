/**
 * CyberArmor Protect — Kiro IDE Extension
 * Kiro is an AWS-powered AI IDE. This extension monitors AI-generated code
 * from Kiro's spec-driven development for security issues and sensitive data.
 */

import * as vscode from 'vscode';

const DLP_PATTERNS = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, category: 'secrets', placeholder: '[REDACTED-AWS-KEY]' },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, category: 'secrets', placeholder: '[REDACTED-GITHUB-TOKEN]' },
  { name: 'OpenAI API Key', pattern: /\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,})\b/g, category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g, category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]' },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, category: 'secrets', placeholder: '[REDACTED-PASSWORD]' },
  { name: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi, category: 'secrets', placeholder: '[REDACTED-CONNECTION-STRING]' },
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, category: 'pii', placeholder: '[REDACTED-SSN]' },
  { name: 'Credit Card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, category: 'pci', placeholder: '[REDACTED-CARD]' },
  { name: 'Bank Account', pattern: /\b(?:account\s*(?:number|no|#)?\s*[:=]?\s*)\d{8,17}\b/gi, category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]' },
  { name: 'NPI', pattern: /\bNPI\s*[:=]?\s*\d{10}\b/gi, category: 'npi', placeholder: '[REDACTED-NPI]' },
  { name: 'Private IP', pattern: /\b(?:(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b/g, category: 'nonpublic', placeholder: '[REDACTED-PRIVATE-IP]' },
];

const REDACTION_CATEGORIES: Record<string, string[]> = {
  redact: ['secrets', 'pii', 'pci', 'nacha', 'npi'],
  'redact-secrets': ['secrets'],
  'redact-credentials': ['secrets'],
  'redact-pii': ['pii'],
  'redact-pci': ['pci'],
  'redact-nacha': ['nacha'],
  'redact-bank': ['nacha'],
  'redact-npi': ['npi'],
  'redact-nonpublic': ['nonpublic'],
};

const SUSPICIOUS_CODE = [
  { name: 'eval', pattern: /\beval\s*\(/g },
  { name: 'shell_exec', pattern: /\b(exec|execSync|child_process|os\.system|subprocess)\s*\(/g },
  { name: 'disable_ssl', pattern: /verify\s*[=:]\s*(?:false|False|0)|rejectUnauthorized\s*:\s*false/g },
];

let diagnostics: vscode.DiagnosticCollection;

async function redeemBootstrapToken(config: vscode.WorkspaceConfiguration): Promise<boolean> {
  const bootstrapToken = config.get<string>('bootstrapToken', '');
  const apiKey = config.get<string>('apiKey', '');
  const controlPlaneUrl = config.get<string>('controlPlaneUrl', 'http://localhost:8000');
  const tenantId = config.get<string>('tenantId', 'default');
  if (!bootstrapToken || apiKey) return false;
  const response = await fetch(`${controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bootstrap_token: bootstrapToken,
      package_key: 'kiro-extension',
      subject_type: 'extension',
      subject_name: vscode.env.machineId || 'kiro-extension',
    }),
  });
  if (!response.ok) {
    throw new Error(`Bootstrap redeem failed (${response.status}): ${await response.text()}`);
  }
  const redeemed = await response.json();
  await config.update('apiKey', redeemed.service_api_key || '', vscode.ConfigurationTarget.Global);
  await config.update('tenantId', redeemed.tenant_id || tenantId, vscode.ConfigurationTarget.Global);
  await config.update('controlPlaneUrl', redeemed.control_plane_url || controlPlaneUrl, vscode.ConfigurationTarget.Global);
  await config.update('bootstrapToken', '', vscode.ConfigurationTarget.Global);
  return true;
}

export async function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('cyberarmor');
  try {
    const redeemed = await redeemBootstrapToken(config);
    if (redeemed) {
      vscode.window.showInformationMessage('CyberArmor Protect for Kiro enrolled successfully.');
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
  }
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) CyberArmor';
  statusBar.tooltip = 'CyberArmor Protect for Kiro';
  statusBar.show();
  context.subscriptions.push(statusBar);

  diagnostics = vscode.languages.createDiagnosticCollection('cyberarmor-kiro');
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand('cyberarmor-kiro.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        const count = scanDocument(editor.document);
        vscode.window.showInformationMessage(`CyberArmor: ${count} finding(s)`);
      }
    }),
    vscode.commands.registerCommand('cyberarmor-kiro.redactFindings', redactCurrentFile),
    vscode.commands.registerCommand('cyberarmor-kiro.redeemBootstrapToken', async () => {
      try {
        const redeemed = await redeemBootstrapToken(vscode.workspace.getConfiguration('cyberarmor'));
        vscode.window.showInformationMessage(
          redeemed
            ? 'CyberArmor Protect for Kiro enrolled successfully.'
            : 'Bootstrap redeem skipped. Add a bootstrap token or clear the existing API key first.'
        );
      } catch (error: any) {
        vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
      }
    }),
  );

  // Monitor Kiro's AI spec-driven code generation
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      // Kiro generates code from specs — large insertions are likely AI-generated
      const hasLargeInsert = event.contentChanges.some(c => c.text.length > 100);
      if (hasLargeInsert) {
        scanDocument(event.document);
      }
    }),
    vscode.workspace.onWillSaveTextDocument(event => {
      scanDocument(event.document);
    })
  );

  vscode.window.showInformationMessage('CyberArmor Protect for Kiro activated');
}

export function deactivate() {}

function redactText(text: string, mode = 'redact'): string {
  const categories = new Set(REDACTION_CATEGORIES[mode] || REDACTION_CATEGORIES.redact);
  let redacted = text;
  for (const pat of DLP_PATTERNS) {
    if (!categories.has(pat.category)) continue;
    pat.pattern.lastIndex = 0;
    redacted = redacted.replace(pat.pattern, pat.placeholder);
  }
  return redacted;
}

function scanDocument(doc: vscode.TextDocument): number {
  const text = doc.getText();
  const diagList: vscode.Diagnostic[] = [];

  for (const pat of [...DLP_PATTERNS, ...SUSPICIOUS_CODE]) {
    pat.pattern.lastIndex = 0;
    let m;
    while ((m = pat.pattern.exec(text)) !== null) {
      const pos = doc.positionAt(m.index);
      const range = new vscode.Range(pos, doc.positionAt(m.index + m[0].length));
      diagList.push(new vscode.Diagnostic(range, `CyberArmor: ${pat.name}`, vscode.DiagnosticSeverity.Warning));
    }
  }

  diagnostics.set(doc.uri, diagList);
  return diagList.length;
}

async function redactCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const mode = vscode.workspace.getConfiguration('cyberarmor').get<string>('enforcementMode', 'redact');
  const original = editor.document.getText();
  const redacted = redactText(original, mode.startsWith('redact') ? mode : 'redact');
  if (redacted === original) {
    vscode.window.showInformationMessage('CyberArmor: no redactable findings in current file');
    return;
  }
  const edit = new vscode.WorkspaceEdit();
  edit.replace(editor.document.uri, new vscode.Range(editor.document.positionAt(0), editor.document.positionAt(original.length)), redacted);
  await vscode.workspace.applyEdit(edit);
  const remaining = scanDocument(editor.document);
  vscode.window.showInformationMessage(`CyberArmor: redacted sensitive findings in current file (${remaining} remaining)`);
}
