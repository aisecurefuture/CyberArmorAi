/**
 * CyberArmor VS Code — A-BOM workspace scanner.
 *
 * Walks every workspace folder, parses the manifest files we recognise
 * (package.json, requirements.txt, Cargo.toml, go.mod), and ships the
 * resulting CycloneDX 1.6 component list to the control-plane's
 * /rasp/abom/ingest endpoint with source_kind=ide_workspace.
 *
 * Same parser semantics as services/control-plane/repo_collector.py —
 * if the two ever diverge, fix that file first since the server is the
 * canonical reference.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

type Component = {
  type: string;
  name: string;
  version?: string;
  purl?: string;
  manufacturer?: string;
  properties?: Array<{ name: string; value: string }>;
  __path?: string;
};

const MANIFEST_BASENAMES = new Set([
  'package.json',
  'requirements.txt',
  'Cargo.toml',
  'go.mod',
]);

// Cap per-workspace so a node_modules-heavy monorepo can't pin the
// editor at activation time. We always include the workspace root's
// manifest; subdirectories are walked breadth-first.
const MANIFEST_BUDGET = 100;

function cleanNpmVersion(raw: unknown): string {
  if (raw === null || raw === undefined) return '';
  const s = String(raw).trim();
  if (!s) return '';
  if (/^(git\+|http|file:|link:|workspace:)/.test(s)) return s.slice(0, 64);
  return s.replace(/^[\^~=> <]+/, '').trim();
}

function parsePackageJson(text: string, repoLabel: string): Component[] {
  let data: any;
  try { data = JSON.parse(text); } catch { return []; }
  if (typeof data !== 'object' || data === null) return [];
  const rows: Component[] = [];
  const sections: Array<[string, string]> = [
    ['dependencies', 'runtime'],
    ['devDependencies', 'dev'],
    ['peerDependencies', 'peer'],
    ['optionalDependencies', 'optional'],
  ];
  for (const [section, scope] of sections) {
    const deps = data[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, versionSpec] of Object.entries(deps)) {
      const version = cleanNpmVersion(versionSpec);
      rows.push({
        type: 'library',
        name,
        version,
        purl: version ? `pkg:npm/${name}@${version}` : `pkg:npm/${name}`,
        properties: [
          { name: 'cyberarmor:package_manager', value: 'npm' },
          { name: 'cyberarmor:dep_scope', value: scope },
          { name: 'cyberarmor:source_repo', value: repoLabel },
        ],
      });
    }
  }
  return rows;
}

function parseRequirementsTxt(text: string, repoLabel: string): Component[] {
  const rows: Component[] = [];
  for (let line of (text || '').split(/\r?\n/)) {
    const hash = line.indexOf('#');
    if (hash >= 0) line = line.slice(0, hash);
    line = line.trim();
    if (!line) continue;
    if (line.startsWith('-r') || line.startsWith('--') || line.startsWith('-e ') || line.startsWith('-f')) continue;
    const semi = line.indexOf(';');
    if (semi >= 0) line = line.slice(0, semi).trim();
    // Strip extras: pkg[extra]==1.0 → pkg
    const m = line.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    const rest = (m[3] || '').trim();
    let version = '';
    const vm = rest.match(/^(?:==|~=|>=|<=|>|<|=)\s*([^\s,]+)/);
    if (vm) version = vm[1];
    rows.push({
      type: 'library',
      name,
      version,
      purl: version ? `pkg:pypi/${name}@${version}` : `pkg:pypi/${name}`,
      properties: [
        { name: 'cyberarmor:package_manager', value: 'pip' },
        { name: 'cyberarmor:source_repo', value: repoLabel },
      ],
    });
  }
  return rows;
}

function parseCargoToml(text: string, repoLabel: string): Component[] {
  // No TOML parser in core stdlib — use a line-based scanner. Handles
  // ``[dependencies]`` / ``[dev-dependencies]`` blocks and the two
  // common entry shapes (string or inline table). Not a full TOML
  // parser; tradeoff is good enough for IDE-side hints.
  const rows: Component[] = [];
  let section: string | null = null;
  let scope = '';
  for (const raw of (text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      section = sec[1].trim();
      scope = section === 'dependencies' ? 'runtime'
            : section === 'dev-dependencies' ? 'dev'
            : section === 'build-dependencies' ? 'build'
            : '';
      continue;
    }
    if (!scope) continue;
    const m = line.match(/^([A-Za-z0-9_\-]+)\s*=\s*(.+)$/);
    if (!m) continue;
    const name = m[1];
    let version = '';
    const value = m[2].trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      version = value.slice(1, -1);
    } else if (value.startsWith('{')) {
      const vm = value.match(/version\s*=\s*"([^"]+)"/);
      if (vm) version = vm[1];
    }
    version = version.replace(/^[\^~=> <]+/, '').trim();
    rows.push({
      type: 'library',
      name,
      version,
      purl: version ? `pkg:cargo/${name}@${version}` : `pkg:cargo/${name}`,
      properties: [
        { name: 'cyberarmor:package_manager', value: 'cargo' },
        { name: 'cyberarmor:dep_scope', value: scope },
        { name: 'cyberarmor:source_repo', value: repoLabel },
      ],
    });
  }
  return rows;
}

function parseGoMod(text: string, repoLabel: string): Component[] {
  const rows: Component[] = [];
  let inBlock = false;
  for (const raw of (text || '').split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('//')) continue;
    if (line.startsWith('require (')) { inBlock = true; continue; }
    if (line === ')') { inBlock = false; continue; }
    if (inBlock || line.startsWith('require ')) {
      let spec = line.replace(/^require\s+/, '');
      const indirect = spec.includes('indirect');
      const commentIdx = spec.indexOf('//');
      if (commentIdx >= 0) spec = spec.slice(0, commentIdx).trim();
      const parts = spec.split(/\s+/);
      if (parts.length < 2) continue;
      const [moduleName, version] = parts;
      rows.push({
        type: 'library',
        name: moduleName,
        version,
        purl: `pkg:golang/${moduleName}@${version}`,
        properties: [
          { name: 'cyberarmor:package_manager', value: 'gomod' },
          { name: 'cyberarmor:dep_scope', value: indirect ? 'indirect' : 'direct' },
          { name: 'cyberarmor:source_repo', value: repoLabel },
        ],
      });
    }
  }
  return rows;
}

const PARSERS: Record<string, (text: string, repoLabel: string) => Component[]> = {
  'package.json': parsePackageJson,
  'requirements.txt': parseRequirementsTxt,
  'Cargo.toml': parseCargoToml,
  'go.mod': parseGoMod,
};

// Directories we never walk. node_modules is the dominant size-cost
// avoidance, the others are best-effort to keep the budget for actual
// source manifests.
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'target', 'out',
  '.next', '.nuxt', '.venv', 'venv', '__pycache__', '.gradle',
  '.idea', '.vscode',
]);

async function walkManifests(root: string): Promise<string[]> {
  const found: string[] = [];
  const queue: string[] = [root];
  while (queue.length > 0 && found.length < MANIFEST_BUDGET) {
    const dir = queue.shift()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        queue.push(full);
      } else if (entry.isFile() && MANIFEST_BASENAMES.has(entry.name)) {
        found.push(full);
        if (found.length >= MANIFEST_BUDGET) break;
      }
    }
  }
  return found;
}

async function collectComponents(workspaceRoot: string, repoLabel: string): Promise<Component[]> {
  const manifests = await walkManifests(workspaceRoot);
  const out: Component[] = [];
  for (const manifest of manifests) {
    const basename = path.basename(manifest);
    const parser = PARSERS[basename];
    if (!parser) continue;
    let text: string;
    try { text = fs.readFileSync(manifest, 'utf-8'); }
    catch { continue; }
    let parsed: Component[] = [];
    try { parsed = parser(text, repoLabel) || []; }
    catch { continue; }
    const relPath = path.relative(workspaceRoot, manifest);
    for (const c of parsed) {
      c.__path = `${repoLabel}:${relPath}`;
      (c.properties = c.properties || []).push({
        name: 'cyberarmor:manifest_path',
        value: relPath,
      });
    }
    out.push(...parsed);
  }
  return out;
}

function workspaceSourceId(folder: vscode.WorkspaceFolder): string {
  // Hostname + workspace path keeps the ID stable across editor
  // restarts on the same machine while distinguishing the same repo
  // checked out by two different developers.
  const host = os.hostname() || 'unknown-host';
  return `ide:${host}:${folder.name}`;
}

async function postOne(controlPlaneUrl: string, apiKey: string, tenantId: string, folder: vscode.WorkspaceFolder): Promise<{ ingested: number; skipped: number } | null> {
  const sourceId = workspaceSourceId(folder);
  const components = await collectComponents(folder.uri.fsPath, sourceId);
  if (components.length === 0) return { ingested: 0, skipped: 0 };
  const body = {
    tenant_id: tenantId,
    collector: 'vscode',
    collector_version: '1.0',
    source_kind: 'ide_workspace',
    source_id: sourceId,
    hostname: os.hostname() || '',
    observed_at: new Date().toISOString(),
    components,
  };
  const url = `${controlPlaneUrl.replace(/\/$/, '')}/rasp/abom/ingest`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'x-tenant-id': tenantId,
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '');
    throw new Error(`abom ingest HTTP ${resp.status}: ${errBody.slice(0, 200)}`);
  }
  const data = await resp.json().catch(() => ({}));
  return {
    ingested: Number(data.components_ingested || 0),
    skipped: Number(data.skipped || 0),
  };
}

export async function runWorkspaceSweep(log?: vscode.OutputChannel): Promise<void> {
  const config = vscode.workspace.getConfiguration('cyberarmor');
  const apiKey = config.get<string>('apiKey', '');
  const tenantId = config.get<string>('tenantId', 'default');
  const controlPlaneUrl = config.get<string>('controlPlaneUrl', 'http://localhost:8000');
  if (!apiKey) {
    log?.appendLine('[abom] skipping sweep — no apiKey configured');
    return;
  }
  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length === 0) {
    log?.appendLine('[abom] skipping sweep — no workspace open');
    return;
  }
  for (const folder of folders) {
    try {
      const result = await postOne(controlPlaneUrl, apiKey, tenantId, folder);
      if (result) {
        log?.appendLine(`[abom] ${folder.name} → ingested=${result.ingested} skipped=${result.skipped}`);
      }
    } catch (err: any) {
      log?.appendLine(`[abom] ${folder.name} failed: ${err?.message || err}`);
    }
  }
}

/**
 * Spawn a periodic sweep timer. Returns the timer handle so the caller
 * can dispose it on extension deactivate.
 */
export function startPeriodicSweep(log?: vscode.OutputChannel): NodeJS.Timeout {
  const config = vscode.workspace.getConfiguration('cyberarmor');
  const intervalMs = Math.max(60_000, config.get<number>('abomSweepIntervalMs', 30 * 60 * 1000));
  // First sweep on a 10s delay so activation doesn't block the editor.
  setTimeout(() => { runWorkspaceSweep(log).catch(() => {}); }, 10_000);
  return setInterval(() => { runWorkspaceSweep(log).catch(() => {}); }, intervalMs);
}
