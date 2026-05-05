/**
 * CyberArmor Protect — Cursor IDE Extension
 * Cursor uses VS Code extension format. This extension adds Cursor-specific
 * AI safety monitoring for Cursor's built-in AI features.
 */

import * as vscode from 'vscode';

const DLP_PATTERNS = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical' as const },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g, severity: 'critical' as const },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, severity: 'high' as const },
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' as const },
];

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
          `CyberArmor: ${findings} sensitive data finding(s) detected before save`
        );
      }
    })
  );

  vscode.window.showInformationMessage('CyberArmor Protect for Cursor activated');
}

export function deactivate() {}

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

function toggleMonitoring() {
  const newState = statusBar.text.includes('OFF') ? '$(shield) CyberArmor' : '$(shield) CyberArmor (OFF)';
  statusBar.text = newState;
}
