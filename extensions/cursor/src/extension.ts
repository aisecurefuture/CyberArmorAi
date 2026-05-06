/**
 * CyberArmor Protect — Cursor IDE Extension
 * Cursor uses VS Code extension format. This extension adds Cursor-specific
 * AI safety monitoring for Cursor's built-in AI features.
 */

import * as vscode from 'vscode';

const DLP_PATTERNS = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const, category: 'secrets', placeholder: '[REDACTED-AWS-KEY]' },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical' as const, category: 'secrets', placeholder: '[REDACTED-GITHUB-TOKEN]' },
  { name: 'OpenAI API Key', pattern: /\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,})\b/g, severity: 'critical' as const, category: 'secrets', placeholder: '[REDACTED-OPENAI-KEY]' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g, severity: 'critical' as const, category: 'secrets', placeholder: '[REDACTED-PRIVATE-KEY]' },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, severity: 'high' as const, category: 'secrets', placeholder: '[REDACTED-PASSWORD]' },
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' as const, category: 'pii', placeholder: '[REDACTED-SSN]' },
  { name: 'Credit Card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, severity: 'critical' as const, category: 'pci', placeholder: '[REDACTED-CARD]' },
  { name: 'Bank Account', pattern: /\b(?:account\s*(?:number|no|#)?\s*[:=]?\s*)\d{8,17}\b/gi, severity: 'critical' as const, category: 'nacha', placeholder: '[REDACTED-BANK-ACCOUNT]' },
  { name: 'NPI', pattern: /\bNPI\s*[:=]?\s*\d{10}\b/gi, severity: 'critical' as const, category: 'npi', placeholder: '[REDACTED-NPI]' },
  { name: 'Private IP', pattern: /\b(?:(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\b/g, severity: 'low' as const, category: 'nonpublic', placeholder: '[REDACTED-PRIVATE-IP]' },
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

let statusBar: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let findingsCount = 0;

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
      package_key: 'cursor-extension',
      subject_type: 'extension',
      subject_name: vscode.env.machineId || 'cursor-extension',
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
      vscode.window.showInformationMessage('CyberArmor Protect for Cursor enrolled successfully.');
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
  }
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) CyberArmor';
  statusBar.tooltip = 'CyberArmor Protect for Cursor — Active';
  statusBar.show();
  context.subscriptions.push(statusBar);

  diagnostics = vscode.languages.createDiagnosticCollection('cyberarmor-cursor');
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand('cyberarmor-cursor.scanFile', scanCurrentFile),
    vscode.commands.registerCommand('cyberarmor-cursor.redactFindings', redactCurrentFile),
    vscode.commands.registerCommand('cyberarmor-cursor.toggleMonitoring', toggleMonitoring),
    vscode.commands.registerCommand('cyberarmor-cursor.redeemBootstrapToken', async () => {
      try {
        const redeemed = await redeemBootstrapToken(vscode.workspace.getConfiguration('cyberarmor'));
        vscode.window.showInformationMessage(
          redeemed
            ? 'CyberArmor Protect for Cursor enrolled successfully.'
            : 'Bootstrap redeem skipped. Add a bootstrap token or clear the existing API key first.'
        );
      } catch (error: any) {
        vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
      }
    }),
  );

  // Monitor Cursor's AI-generated code via document change events
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.contentChanges.length > 0) {
        const largeChange = event.contentChanges.some(c => c.text.length > 50);
        if (largeChange) {
          // Large text insertion likely from AI — scan it
          scanDocument(event.document);
        }
      }
    })
  );

  // Save hook
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument(event => {
      const findings = scanDocument(event.document);
      if (findings > 0) {
        vscode.window.showWarningMessage(
          `CyberArmor: ${findings} sensitive data finding(s) detected before save`,
          'Redact Findings'
        ).then(choice => {
          if (choice === 'Redact Findings') redactDocument(event.document);
        });
      }
    })
  );

  vscode.window.showInformationMessage('CyberArmor Protect for Cursor activated');
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

function scanDocument(document: vscode.TextDocument): number {
  const text = document.getText();
  const diagList: vscode.Diagnostic[] = [];

  for (const pat of DLP_PATTERNS) {
    pat.pattern.lastIndex = 0;
    let match;
    while ((match = pat.pattern.exec(text)) !== null) {
      const pos = document.positionAt(match.index);
      const range = new vscode.Range(pos, document.positionAt(match.index + match[0].length));
      const sev = pat.severity === 'critical' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
      diagList.push(new vscode.Diagnostic(range, `CyberArmor: ${pat.name} detected`, sev));
    }
  }

  diagnostics.set(document.uri, diagList);
  findingsCount += diagList.length;
  return diagList.length;
}

function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const count = scanDocument(editor.document);
  vscode.window.showInformationMessage(`CyberArmor: ${count} finding(s)`);
}

async function redactDocument(document: vscode.TextDocument): Promise<number> {
  const mode = vscode.workspace.getConfiguration('cyberarmor').get<string>('enforcementMode', 'redact');
  const original = document.getText();
  const redacted = redactText(original, mode.startsWith('redact') ? mode : 'redact');
  if (redacted === original) return 0;
  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, new vscode.Range(document.positionAt(0), document.positionAt(original.length)), redacted);
  await vscode.workspace.applyEdit(edit);
  return scanDocument(document);
}

async function redactCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const remaining = await redactDocument(editor.document);
  vscode.window.showInformationMessage(`CyberArmor: redacted sensitive findings in current file (${remaining} remaining)`);
}

function toggleMonitoring() {
  const newState = statusBar.text.includes('OFF') ? '$(shield) CyberArmor' : '$(shield) CyberArmor (OFF)';
  statusBar.text = newState;
}
