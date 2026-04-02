/**
 * CyberArmor — VS Code Extension
 * Monitors AI code suggestions, scans for secrets/PII, syncs with control plane.
 */

import * as vscode from 'vscode';
import { AIMonitor } from './ai-monitor';
import { DLPScanner } from './dlp-scanner';
import { PolicyClient } from './policy-client';

let aiMonitor: AIMonitor;
let dlpScanner: DLPScanner;
let policyClient: PolicyClient;
let statusBarItem: vscode.StatusBarItem;
let authLogChannel: vscode.OutputChannel;

function getCyberArmorConfig(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('cyberarmor');
}

export function activate(context: vscode.ExtensionContext) {
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
    vscode.commands.registerCommand('cyberarmor.toggleMonitoring', () => toggleMonitoring()),
  );

  // File save hook — scan for secrets
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument(event => {
      if (config.get('dlpOnSave', true)) {
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

  vscode.window.showInformationMessage('CyberArmor activated');
}

export function deactivate() {
  policyClient?.stopSync();
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

function showFindings(findings: Array<{name: string, line: number, match: string}>) {
  const channel = vscode.window.createOutputChannel('CyberArmor DLP');
  channel.show();
  findings.forEach(f => channel.appendLine(`[${f.name}] Line ${f.line}: ${f.match}`));
}
