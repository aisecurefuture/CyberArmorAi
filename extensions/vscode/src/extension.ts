/**
 * CyberArmor — VS Code Extension
 * Monitors AI code suggestions, scans for secrets/PII, syncs with control plane.
 */

import * as vscode from 'vscode';
import { AIMonitor } from './ai-monitor';
import { DLPScanner } from './dlp-scanner';
import { PolicyClient } from './policy-client';
import { runWorkspaceSweep, startPeriodicSweep } from './abom-scanner';

let aiMonitor: AIMonitor;
let dlpScanner: DLPScanner;
let policyClient: PolicyClient;
let statusBarItem: vscode.StatusBarItem;
let authLogChannel: vscode.OutputChannel;
let abomSweepTimer: NodeJS.Timeout | undefined;
let abomLogChannel: vscode.OutputChannel | undefined;

function getCyberArmorConfig(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('cyberarmor');
}

async function redeemBootstrapToken(config: vscode.WorkspaceConfiguration): Promise<boolean> {
  const bootstrapToken = config.get<string>('bootstrapToken', '');
  const existingApiKey = config.get<string>('apiKey', '');
  const controlPlaneUrl = config.get<string>('controlPlaneUrl', 'http://localhost:8000');
  const tenantId = config.get<string>('tenantId', 'default');
  if (!bootstrapToken || existingApiKey) {
    return false;
  }
  const response = await fetch(`${controlPlaneUrl.replace(/\/$/, '')}/bootstrap/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bootstrap_token: bootstrapToken,
      package_key: 'vscode-extension',
      subject_type: 'extension',
      subject_name: vscode.env.machineId || 'vscode-extension',
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
  authLogChannel?.appendLine(`[${new Date().toISOString()}] bootstrap redeemed subject=${redeemed.subject_id || 'unknown'}`);
  return true;
}

export async function activate(context: vscode.ExtensionContext) {
  console.log('CyberArmor extension activating...');

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = '$(shield) CyberArmor';
  statusBarItem.tooltip = 'CyberArmor — Active';
  statusBarItem.command = 'cyberarmor.showStatus';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);
  authLogChannel = vscode.window.createOutputChannel('CyberArmor Auth');
  context.subscriptions.push(authLogChannel);

  // Init components
  const config = getCyberArmorConfig();
  try {
    const redeemed = await redeemBootstrapToken(config);
    if (redeemed) {
      vscode.window.showInformationMessage('CyberArmor bootstrap token redeemed successfully.');
    }
  } catch (error: any) {
    vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
  }
  policyClient = new PolicyClient(
    config.get('controlPlaneUrl', 'http://localhost:8000'),
    config.get('apiKey', ''),
    config.get('tenantId', 'default'),
  );
  aiMonitor = new AIMonitor(policyClient);
  dlpScanner = new DLPScanner(policyClient);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('cyberarmor.showStatus', () => showStatusPanel()),
    vscode.commands.registerCommand('cyberarmor.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('cyberarmor.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('cyberarmor.abomSweep', async () => {
      abomLogChannel = abomLogChannel || vscode.window.createOutputChannel('CyberArmor — A-BOM');
      abomLogChannel.show(true);
      abomLogChannel.appendLine(`[${new Date().toISOString()}] manual A-BOM sweep requested`);
      await runWorkspaceSweep(abomLogChannel);
      vscode.window.showInformationMessage('CyberArmor: workspace A-BOM sweep complete');
    }),
    vscode.commands.registerCommand('cyberarmor.redactFindings', () => redactCurrentFile()),
    vscode.commands.registerCommand('cyberarmor.toggleMonitoring', () => toggleMonitoring()),
    vscode.commands.registerCommand('cyberarmor.redeemBootstrapToken', async () => {
      try {
        const current = getCyberArmorConfig();
        const redeemed = await redeemBootstrapToken(current);
        if (redeemed) {
          vscode.window.showInformationMessage('CyberArmor bootstrap token redeemed successfully.');
        } else {
          vscode.window.showInformationMessage('CyberArmor bootstrap redeem skipped. Add a bootstrap token or clear the existing API key first.');
        }
      } catch (error: any) {
        vscode.window.showErrorMessage(`CyberArmor bootstrap redeem failed: ${error.message || error}`);
      }
    }),
  );

  // File save hook — scan for secrets
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument(event => {
      if (config.get('dlpOnSave', true)) {
        const mode = config.get<string>('enforcementMode', 'warn');
        if (mode.startsWith('redact')) {
          event.waitUntil(
            dlpScanner.redactDocument(event.document, mode).then((count) => {
              if (count > 0) {
                vscode.window.showInformationMessage(`CyberArmor: redacted ${count} sensitive finding(s) before save`);
              }
              return [];
            })
          );
          return;
        }
        const findings = dlpScanner.scanDocument(event.document);
        if (findings.length > 0) {
          vscode.window.showWarningMessage(
            `CyberArmor: ${findings.length} sensitive data finding(s) in ${event.document.fileName}`,
            'Show Details', 'Ignore'
          ).then(choice => {
            if (choice === 'Show Details') {
              showFindings(findings);
            }
          });
        }
      }
    })
  );

  // Watch for AI extension completions
  context.subscriptions.push(
    vscode.languages.registerInlineCompletionItemProvider(
      { pattern: '**' },
      aiMonitor.getCompletionProvider()
    )
  );

  // Diagnostics collection for DLP findings
  const diagnostics = vscode.languages.createDiagnosticCollection('cyberarmor');
  context.subscriptions.push(diagnostics);
  dlpScanner.setDiagnostics(diagnostics);

  // Active editor change — scan
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && config.get('dlpOnOpen', false)) {
        dlpScanner.scanDocument(editor.document);
      }
    })
  );

  // Policy sync
  policyClient.startSync(config.get('syncIntervalSeconds', 60));

  // A-BOM workspace sweep — sends installed manifests to the
  // control-plane so the BOM picks up "what dev is working on" with
  // source_kind=ide_workspace. Skipped when no apiKey is configured.
  if (config.get('abomEnabled', true)) {
    abomLogChannel = vscode.window.createOutputChannel('CyberArmor — A-BOM');
    abomSweepTimer = startPeriodicSweep(abomLogChannel);
  }

  vscode.window.showInformationMessage('CyberArmor activated');
}

export function deactivate() {
  policyClient?.stopSync();
  if (abomSweepTimer) {
    clearInterval(abomSweepTimer);
    abomSweepTimer = undefined;
  }
  console.log('CyberArmor deactivated');
}

function showStatusPanel() {
  const auth = policyClient.getLastAuthResult();
  const panel = vscode.window.createWebviewPanel('cyberarmorStatus', 'CyberArmor Status', vscode.ViewColumn.One, {});
  panel.webview.html = `<html><body style="font-family:system-ui;padding:20px;background:#1e1e1e;color:#ccc;">
    <h1>CyberArmor</h1>
    <p>Status: Active</p>
    <p>Policies loaded: ${policyClient.getPolicyCount()}</p>
    <p>Last auth mode: ${auth.mode} (${auth.algorithm})</p>
    <p>Last auth error: ${auth.error || 'none'}</p>
    <p>AI suggestions monitored: ${aiMonitor.getMonitoredCount()}</p>
    <p>DLP findings (session): ${dlpScanner.getSessionFindings()}</p>
  </body></html>`;
  authLogChannel.appendLine(`[${new Date().toISOString()}] auth mode=${auth.mode} algorithm=${auth.algorithm} error=${auth.error || 'none'}`);
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showWarningMessage('No active file'); return; }
  const findings = dlpScanner.scanDocument(editor.document);
  vscode.window.showInformationMessage(`CyberArmor: ${findings.length} finding(s) in current file`);
}

async function redactCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showWarningMessage('No active file'); return; }
  const config = getCyberArmorConfig();
  const mode = config.get<string>('enforcementMode', 'redact');
  const count = await dlpScanner.redactDocument(editor.document, mode.startsWith('redact') ? mode : 'redact');
  vscode.window.showInformationMessage(`CyberArmor: redacted ${count} sensitive finding(s)`);
}

async function scanWorkspace() {
  const files = await vscode.workspace.findFiles('**/*.{ts,js,py,java,cs,go,rs,rb,php,json,yaml,yml,env,cfg,ini}', '**/node_modules/**', 500);
  let totalFindings = 0;
  for (const file of files) {
    const doc = await vscode.workspace.openTextDocument(file);
    totalFindings += dlpScanner.scanDocument(doc).length;
  }
  vscode.window.showInformationMessage(`CyberArmor: Scanned ${files.length} files, ${totalFindings} total finding(s)`);
}

function toggleMonitoring() {
  const config = getCyberArmorConfig();
  const current = config.get('enabled', true);
  config.update('enabled', !current, vscode.ConfigurationTarget.Workspace);
  statusBarItem.text = !current ? '$(shield) CyberArmor' : '$(shield) CyberArmor (OFF)';
  vscode.window.showInformationMessage(`CyberArmor monitoring ${!current ? 'enabled' : 'disabled'}`);
}

function showFindings(findings: Array<{name: string, line: number, match: string, category?: string}>) {
  const channel = vscode.window.createOutputChannel('CyberArmor DLP');
  channel.show();
  findings.forEach(f => channel.appendLine(`[${f.name}] Line ${f.line}: ${f.match} (${f.category || 'sensitive'})`));
}
