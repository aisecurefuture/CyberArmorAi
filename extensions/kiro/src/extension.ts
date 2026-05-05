/**
 * CyberArmor Protect — Kiro IDE Extension
 * Kiro is an AWS-powered AI IDE. This extension monitors AI-generated code
 * from Kiro's spec-driven development for security issues and sensitive data.
 */

import * as vscode from 'vscode';

const DLP_PATTERNS = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi },
  { name: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi },
];

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
