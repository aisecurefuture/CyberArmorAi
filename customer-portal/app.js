import { mountPolicyBuilder } from "/shared/policy-builder.js";
import { mountListView, openModal } from "/shared/list-view.js";
import {
  openPolicyDetailModal,
  openArtifactDetailModal,
  openReadOnlyModal,
} from "/shared/edit-modals.js";

const $ = (selector) => document.querySelector(selector);

const navItems = [
  { id: "overview", label: "Overview", hash: "#/overview" },
  { id: "policies", label: "Policies", hash: "#/policies" },
  { id: "policy-builder", label: "Policy Builder", hash: "#/policy-builder" },
  { id: "artifacts", label: "Artifacts", hash: "#/artifacts" },
  { id: "api-keys", label: "API Keys", hash: "#/api-keys" },
  { id: "proxy", label: "Proxy Controls", hash: "#/proxy" },
  { id: "scan", label: "Scan Tools", hash: "#/scan" },
  { id: "endpoints", label: "Endpoints", hash: "#/endpoints" },
  { id: "shadow-ai", label: "Shadow AI", hash: "#/shadow-ai" },
  { id: "compliance", label: "Compliance", hash: "#/compliance" },
  { id: "siem", label: "SIEM Config", hash: "#/siem" },
  { id: "identity", label: "Identity / SSO", hash: "#/identity" },
  { id: "dlp", label: "DLP & Data Class.", hash: "#/dlp" },
  { id: "reports", label: "Reports", hash: "#/reports" },
  { id: "agents", label: "Agent Directory", hash: "#/agents" },
  { id: "providers", label: "AI Providers", hash: "#/providers" },
  { id: "policy-studio", label: "Policy Studio", hash: "#/policy-studio" },
  { id: "graph", label: "Action Graph", hash: "#/graph" },
  { id: "risk", label: "AI Risk Dashboard", hash: "#/risk" },
  { id: "delegations", label: "Delegation Manager", hash: "#/delegations" },
  { id: "onboarding", label: "SDK & Onboarding", hash: "#/onboarding" },
  { id: "telemetry", label: "Telemetry", hash: "#/telemetry" },
  { id: "incidents", label: "Incidents", hash: "#/incidents" },
  { id: "audit", label: "Audit Logs", hash: "#/audit" },
  { id: "users", label: "Users", hash: "#/users" },
  { id: "settings", label: "Settings", hash: "#/settings" },
];

let session = null;

function esc(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function card(content) {
  return `<section class="rounded-3xl border border-slate-800 bg-slate-950/80 p-5 shadow-xl shadow-slate-950/40">${content}</section>`;
}

function metricCard(label, value, tone = "cyan", detail = "") {
  return card(`<div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(label)}</div><div class="mt-2 text-3xl font-semibold">${esc(value)}</div>${detail ? `<div class="mt-2 text-xs text-slate-400">${esc(detail)}</div>` : ""}`);
}

function emptyRow(message, colspan) {
  return `<tr><td class="px-3 py-8 text-center text-slate-500" colspan="${colspan}">${esc(message)}</td></tr>`;
}

function fmt(value) {
  if (!value) return "";
  try { return new Date(value).toLocaleString(); } catch { return String(value); }
}

function badge(text, tone = "cyan") {
  const colors = {
    cyan: "border-cyan-900 bg-cyan-950/50 text-cyan-100",
    green: "border-emerald-900 bg-emerald-950/50 text-emerald-100",
    amber: "border-amber-900 bg-amber-950/50 text-amber-100",
    red: "border-rose-900 bg-rose-950/50 text-rose-100",
    slate: "border-slate-800 bg-slate-900 text-slate-200",
  };
  return `<span class="inline-flex rounded-full border px-2.5 py-1 text-xs ${colors[tone] || colors.slate}">${esc(text)}</span>`;
}

function readCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return "";
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = readCookie("ca_customer_csrf");
    if (csrf) headers["x-csrf-token"] = csrf;
  }
  const { headers: _ignoredHeaders, ...rest } = options;
  const res = await fetch(path, {
    credentials: "same-origin",
    headers,
    ...rest,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

function renderNav() {
  $("#nav").innerHTML = navItems.map((item) => `
    <a class="nav-item block rounded-2xl px-4 py-3 text-sm text-slate-300 hover:bg-slate-900 hover:text-white" href="${item.hash}" data-nav="${item.id}">
      ${esc(item.label)}
    </a>
  `).join("");
}

function setActiveNav(route) {
  document.querySelectorAll("[data-nav]").forEach((el) => {
    const active = el.dataset.nav === route;
    el.classList.toggle("bg-cyan-500/10", active);
    el.classList.toggle("text-cyan-100", active);
    el.classList.toggle("border", active);
    el.classList.toggle("border-cyan-900/60", active);
  });
}

async function hydrateSession() {
  session = await api("/auth/me");
  $("#tenantName").textContent = session.tenant_id;
  $("#customerUser").textContent = session.email;
  $("#customerRole").innerHTML = badge(session.role, session.role === "tenant_admin" ? "green" : "cyan");
}

function requireAdminMarkup() {
  return card(`
    <div class="text-lg font-semibold">Tenant admin required</div>
    <p class="mt-2 text-sm text-slate-400">Your account can view tenant data, but this tenant configuration area is limited to tenant admins.</p>
  `);
}

function featureGrid(items) {
  return `<div class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">${items.map((item) => card(`
    <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(item.kicker || "Tenant scoped")}</div>
    <div class="mt-2 text-lg font-semibold">${esc(item.title)}</div>
    <p class="mt-2 text-sm text-slate-400">${esc(item.body)}</p>
    ${item.badge ? `<div class="mt-4">${badge(item.badge, item.tone || "cyan")}</div>` : ""}
  `)).join("")}</div>`;
}

function browserCoverageNote(pkg) {
  if (!pkg || pkg.package_key !== "edge-extension") return "";
  return `<div class="mt-2 text-xs text-cyan-300">Supports Chrome, Edge, Brave, Opera, and similar Chromium-based browsers.</div>`;
}

function bootstrapSetupCardHtml(tenantId = session?.tenant_id || "") {
  return card(`
    <div class="text-lg font-semibold">Bootstrap Setup</div>
    <p class="mt-2 text-sm text-slate-400">Use a one-time bootstrap token during installation, then redeem it into an install-scoped credential. Avoid embedding shared tenant secrets inside distributed agents, SDKs, browser extensions, and add-ins.</p>
    <div class="mt-4 grid gap-3 lg:grid-cols-2">
      <div>
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Recommended Flow</div>
        <ol class="mt-2 space-y-2 text-sm text-slate-300">
          <li>1. Download the package bundle.</li>
          <li>2. Issue a one-time bootstrap token for that package.</li>
          <li>3. Set <span class="font-mono text-cyan-200">CYBERARMOR_BOOTSTRAP_TOKEN</span> during setup.</li>
          <li>4. Let the package redeem it into an install-scoped credential.</li>
        </ol>
      </div>
      <div>
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Shared Env</div>
        <pre class="mt-2 overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-3 text-xs text-cyan-200">CYBERARMOR_CONTROL_PLANE_URL=https://control-plane.example
CYBERARMOR_TENANT_ID=${esc(tenantId)}
CYBERARMOR_BOOTSTRAP_TOKEN=cabt_...</pre>
      </div>
    </div>
    <div class="mt-3 text-xs text-slate-500">See shared docs: docs/architecture/client-bootstrap-setup.md</div>
  `);
}

function bindCustomerBootstrapButtons() {
  document.querySelectorAll(".customerBootstrapBtn").forEach((button) => {
    button.addEventListener("click", async () => {
      const panel = $("#customerBootstrapResult");
      if (panel) {
        panel.innerHTML = card(`<div class="text-sm text-slate-400">Issuing bootstrap token for ${esc(button.dataset.packageTitle || button.dataset.packageKey || "package")}...</div>`);
      }
      try {
        const issued = await api("/api/customer/bootstrap-tokens", {
          method: "POST",
          body: JSON.stringify({ package_key: button.dataset.packageKey, ttl_minutes: 30 }),
        });
        const envLines = Object.entries(issued.bootstrap_env || {}).map(([key, value]) => `${key}=${value}`).join("\n");
        const redeemExample = [
          "curl -X POST",
          `  ${issued.redeem_url}`,
          "  -H 'Content-Type: application/json'",
          `  -d '${JSON.stringify({ bootstrap_token: issued.bootstrap_token, package_key: button.dataset.packageKey }, null, 2)}'`,
        ].join("\n");
        if (panel) {
          panel.innerHTML = card(`
            <div class="text-lg font-semibold">Bootstrap Token Issued</div>
            <p class="mt-2 text-sm text-slate-400">This token is shown once. It expires at ${esc(fmt(issued.expires_at))}. Redeem it into an install-scoped credential instead of using it as a permanent API key.</p>
            <div class="mt-4 grid gap-3 lg:grid-cols-2">
              <div>
                <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Bootstrap Token</div>
                <div class="mt-2">${copyableSnippet(issued.bootstrap_token || "", { maxHeight: "max-h-24" })}</div>
              </div>
              <div>
                <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Suggested Env</div>
                <div class="mt-2">${copyableSnippet(envLines)}</div>
              </div>
            </div>
            <div class="mt-4">
              <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Redeem Example</div>
              <div class="mt-2">${copyableSnippet(redeemExample)}</div>
            </div>
            <div class="mt-3 text-xs text-slate-500">Package: ${esc(issued.package_key)} | Tenant: ${esc(issued.tenant_id)}</div>
          `);
          bindCopyButtons(panel);
        }
      } catch (error) {
        if (panel) panel.innerHTML = card(`<div class="text-sm text-rose-300">${esc(error.message)}</div>`);
      }
    });
  });
}

function bindCustomerBootstrapHelpButtons() {
  document.querySelectorAll(".customerBootstrapHelpBtn").forEach((button) => {
    button.addEventListener("click", () => {
      const panel = $("#customerBootstrapResult");
      if (panel) panel.innerHTML = bootstrapSetupCardHtml(button.dataset.tenantId || session?.tenant_id || "");
    });
  });
}

function simpleTable(headers, rows, emptyMessage) {
  return `<div class="overflow-x-auto rounded-2xl border border-slate-800">
    <table class="w-full text-left text-sm">
      <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
        <tr>${headers.map((header) => `<th class="px-3 py-2">${esc(header)}</th>`).join("")}</tr>
      </thead>
      <tbody>${rows.length ? rows.join("") : emptyRow(emptyMessage, headers.length)}</tbody>
    </table>
  </div>`;
}

function tabButton(id, label, active = false) {
  return `<button class="sectionTab rounded-2xl border px-4 py-2 text-sm ${active ? "border-cyan-900 bg-cyan-500/10 text-cyan-100" : "border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"}" data-tab="${esc(id)}" type="button">${esc(label)}</button>`;
}

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function readinessFromOverview(overview = {}) {
  const checks = [
    { key: "policies", label: "Create at least one policy", complete: Number(overview.policy_count || 0) > 0, href: "#/policy-builder" },
    { key: "endpoints", label: "Enroll an endpoint or agent", complete: Number(overview.agent_count || 0) > 0, href: "#/onboarding" },
    { key: "telemetry", label: "Receive tenant telemetry", complete: Number(overview.telemetry_count || 0) > 0, href: "#/telemetry" },
    { key: "evidence", label: "Generate audit or incident evidence", complete: Number(overview.audit_count || 0) + Number(overview.incident_count || 0) > 0, href: "#/reports" },
    { key: "providers", label: "Review provider posture", complete: Number(overview.provider_count || 0) > 0, href: "#/providers" },
  ];
  const complete = checks.filter((item) => item.complete).length;
  return { checks, complete, total: checks.length, score: Math.round((complete / checks.length) * 100) };
}

function readinessTone(score) {
  if (score >= 80) return "green";
  if (score >= 45) return "amber";
  return "red";
}

function progressBar(score, tone = "cyan") {
  const colors = { green: "bg-emerald-500", amber: "bg-amber-500", red: "bg-rose-500", cyan: "bg-cyan-500" };
  return `<div class="h-2 w-full rounded-full bg-slate-800"><div class="${colors[tone] || colors.cyan} h-2 rounded-full" style="width:${Math.max(0, Math.min(100, score))}%"></div></div>`;
}

// --- Mission Control activity widgets ---

// Inline SVG sparkline for the 24h telemetry series. No external chart lib,
// no extra dependency — just a 24-bar histogram with a subtle scale.
function sparklineSvg(series, { width = 280, height = 60, color = "#22d3ee" } = {}) {
  const data = Array.isArray(series) ? series : [];
  const len = data.length || 1;
  const max = Math.max(1, ...data);
  const gap = 2;
  const barW = Math.max(2, (width - gap * (len - 1)) / len);
  const bars = data.map((v, i) => {
    const h = max === 0 ? 0 : Math.max(1, (v / max) * (height - 4));
    const x = i * (barW + gap);
    const y = height - h;
    return `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barW.toFixed(2)}" height="${h.toFixed(2)}" fill="${color}" opacity="${v ? 0.85 : 0.18}" rx="1"></rect>`;
  }).join("");
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="w-full" style="height:${height}px">${bars}</svg>`;
}

const ACTION_BUCKETS = [
  { key: "block",   label: "Block",   color: "#f87171" },
  { key: "redact",  label: "Redact",  color: "#fbbf24" },
  { key: "warn",    label: "Warn",    color: "#fcd34d" },
  { key: "detect",  label: "Detect",  color: "#60a5fa" },
  { key: "monitor", label: "Monitor", color: "#94a3b8" },
  { key: "allow",   label: "Allow",   color: "#34d399" },
];

function actionBreakdownHtml(breakdown) {
  const counts = breakdown || {};
  const total = Object.values(counts).reduce((a, b) => a + (Number(b) || 0), 0);
  if (total === 0) {
    return `<div class="rounded-2xl border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
      No enforcement activity in the last 24h. Trigger an event from an enrolled endpoint to populate this panel.
    </div>`;
  }
  return `
    <div class="space-y-3">
      ${ACTION_BUCKETS.map((b) => {
        const v = Number(counts[b.key] || 0);
        const pct = total ? (v / total) * 100 : 0;
        return `
          <div>
            <div class="flex items-baseline justify-between text-xs">
              <span class="text-slate-300">${b.label}</span>
              <span class="font-mono text-slate-400">${v} · ${pct.toFixed(pct < 10 ? 1 : 0)}%</span>
            </div>
            <div class="mt-1 h-2 rounded-full bg-slate-900">
              <div class="h-2 rounded-full" style="width:${pct.toFixed(2)}%;background:${b.color}"></div>
            </div>
          </div>`;
      }).join("")}
    </div>`;
}

function severityClasses(s) {
  const sev = String(s || "").toLowerCase();
  if (sev === "critical" || sev === "high") return "bg-rose-500/15 text-rose-200 border border-rose-900/60";
  if (sev === "medium" || sev === "warn") return "bg-amber-500/15 text-amber-200 border border-amber-900/60";
  if (sev === "low" || sev === "info") return "bg-slate-700/40 text-slate-200 border border-slate-700";
  return "bg-cyan-500/15 text-cyan-200 border border-cyan-900/60";
}

function actionPillClasses(action) {
  const a = String(action || "").toLowerCase();
  if (a === "block")  return "bg-rose-500/20 text-rose-200";
  if (a === "redact") return "bg-amber-500/20 text-amber-200";
  if (a === "warn")   return "bg-amber-500/15 text-amber-200";
  if (a === "detect") return "bg-blue-500/20 text-blue-200";
  if (a === "allow")  return "bg-emerald-500/20 text-emerald-200";
  return "bg-slate-700/40 text-slate-200";
}

function recentActivityHtml(events) {
  const rows = Array.isArray(events) ? events : [];
  if (rows.length === 0) {
    return `<div class="rounded-2xl border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
      No telemetry yet for this tenant. Install an endpoint agent or browser extension and trigger any monitored event.
    </div>`;
  }
  return `
    <ul class="divide-y divide-slate-800">
      ${rows.map((e) => {
        const time = fmt(e.occurred_at);
        const host = e.hostname || e.agent_id || "—";
        const eventType = e.event_type || "event";
        const source = e.source || "";
        return `
          <li class="flex items-center gap-3 py-2.5 cursor-pointer hover:bg-slate-900/40 px-2 -mx-2 rounded-lg" data-recent-event='${esc(JSON.stringify(e))}'>
            <span class="inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${actionPillClasses(e.action_class)}">${esc(e.action_class || "event")}</span>
            <span class="min-w-0 flex-1">
              <span class="block truncate text-sm font-medium text-slate-100">${esc(eventType)}</span>
              <span class="block truncate text-xs text-slate-500">${esc(host)}${source ? ` · ${esc(source)}` : ""}</span>
            </span>
            ${e.severity ? `<span class="shrink-0 rounded-md px-2 py-0.5 text-[10px] uppercase tracking-wider ${severityClasses(e.severity)}">${esc(e.severity)}</span>` : ""}
            <span class="shrink-0 text-xs text-slate-500 tabular-nums">${esc(time)}</span>
          </li>`;
      }).join("")}
    </ul>`;
}

function topEventTypesHtml(rows) {
  const items = Array.isArray(rows) ? rows : [];
  if (items.length === 0) return "";
  const max = Math.max(1, ...items.map((r) => r.count || 0));
  return `
    <div class="space-y-2">
      ${items.map((r) => {
        const pct = (r.count / max) * 100;
        return `
          <div>
            <div class="flex items-baseline justify-between text-xs">
              <span class="truncate font-mono text-slate-300">${esc(r.event_type)}</span>
              <span class="ml-2 font-mono tabular-nums text-slate-400">${r.count}</span>
            </div>
            <div class="mt-1 h-1.5 rounded-full bg-slate-900">
              <div class="h-1.5 rounded-full bg-cyan-500/60" style="width:${pct.toFixed(2)}%"></div>
            </div>
          </div>`;
      }).join("")}
    </div>`;
}

function missionControlHtml(settings, overview) {
  const readiness = readinessFromOverview(overview);
  const tone = readinessTone(readiness.score);
  const nextActions = readiness.checks.filter((item) => !item.complete).slice(0, 3);
  const completedRows = readiness.checks.map((item) => `
    <a href="${item.href}" class="flex items-start gap-3 rounded-2xl border border-slate-800 bg-slate-900/50 px-4 py-3 hover:bg-slate-900">
      <span class="mt-0.5 inline-flex h-5 w-5 items-center justify-center rounded-full ${item.complete ? "bg-emerald-500/20 text-emerald-200" : "bg-slate-800 text-slate-400"}">${item.complete ? "✓" : "•"}</span>
      <span>
        <span class="block text-sm font-medium text-slate-100">${esc(item.label)}</span>
        <span class="mt-1 block text-xs text-slate-500">${item.complete ? "Complete" : "Recommended next step"}</span>
      </span>
    </a>
  `).join("");
  const series = overview.telemetry_series_24h || [];
  const series24hTotal = series.reduce((a, b) => a + b, 0);

  return `
    <div class="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
      ${metricCard("Policies", overview.policy_count ?? "0", "cyan", "active and archived")}
      ${metricCard("Endpoints", overview.agent_count ?? "0", "green", "registered or telemetry-only")}
      ${metricCard("Telemetry", overview.telemetry_count ?? "0", "cyan", "tenant events")}
      ${metricCard("Incidents", overview.incident_count ?? "0", "amber", "evidence candidates")}
      ${metricCard("AI Providers", overview.provider_count ?? "0", "green", "router visible")}
      ${metricCard("Audit Events", overview.audit_count ?? "0", "slate", "reviewable records")}
    </div>

    <div class="mt-5 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
      ${card(`
        <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Mission Control</div>
            <div class="mt-2 text-2xl font-semibold">Tenant readiness: ${readiness.score}%</div>
            <p class="mt-2 max-w-2xl text-sm text-slate-400">A practical readiness score based on policy, endpoint, telemetry, provider, and evidence signals for this tenant.</p>
          </div>
          <div class="min-w-44">${badge(`${readiness.complete}/${readiness.total} controls ready`, tone)}</div>
        </div>
        <div class="mt-5">${progressBar(readiness.score, tone)}</div>
        <div class="mt-5 grid gap-3 md:grid-cols-2">${completedRows}</div>
      `)}
      ${card(`
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Next Best Actions</div>
        <div class="mt-3 space-y-3">
          ${nextActions.length ? nextActions.map((item) => `
            <a href="${item.href}" class="block rounded-2xl border border-slate-800 bg-slate-900/60 p-4 hover:bg-slate-900">
              <div class="text-sm font-semibold">${esc(item.label)}</div>
              <div class="mt-1 text-xs text-cyan-200">Open workflow →</div>
            </a>
          `).join("") : `<div class="rounded-2xl border border-emerald-900 bg-emerald-950/30 p-4 text-sm text-emerald-100">Core pilot readiness is in place. Review Reports for evidence exports or tune policies.</div>`}
        </div>
        <div class="mt-4 grid grid-cols-2 gap-2 text-sm">
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/onboarding">Guided Onboarding</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/reports">Export Evidence</a>
        </div>
      `)}
    </div>

    <div class="mt-5 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
      ${card(`
        <div class="flex items-baseline justify-between">
          <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Telemetry — last 24h</div>
          <div class="text-sm font-mono tabular-nums text-slate-300">${series24hTotal} events</div>
        </div>
        <div class="mt-3">${sparklineSvg(series, { height: 56 })}</div>
        <div class="mt-2 flex justify-between text-[10px] text-slate-500"><span>24h ago</span><span>now</span></div>
        <div class="mt-5 text-xs uppercase tracking-[0.18em] text-slate-500">Top event types (24h)</div>
        <div class="mt-3">${topEventTypesHtml(overview.top_event_types_24h)}</div>
      `)}
      ${card(`
        <div class="font-semibold">Threat posture <span class="text-xs font-normal text-slate-500">— last 24h</span></div>
        <p class="mt-1 text-xs text-slate-500">How the policy engine responded to events seen in the last 24 hours.</p>
        <div class="mt-4">${actionBreakdownHtml(overview.action_breakdown_24h)}</div>
      `)}
    </div>

    <div class="mt-5">
      ${card(`
        <div class="flex items-baseline justify-between">
          <div class="font-semibold">Recent activity</div>
          <a class="text-xs text-cyan-200 hover:text-cyan-100" href="#/telemetry">View all telemetry →</a>
        </div>
        <p class="mt-1 text-xs text-slate-500">The 10 most recent events from this tenant. Click any row to inspect the full payload.</p>
        <div class="mt-3" id="missionRecentActivity">${recentActivityHtml(overview.recent_events)}</div>
      `)}
    </div>

    <div class="mt-5 grid gap-4 lg:grid-cols-2">
      ${card(`
        <div class="font-semibold">Quick Actions</div>
        <div class="mt-4 grid grid-cols-2 gap-2 text-sm">
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/policies">Policies</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/policy-builder">Policy Builder</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/endpoints">Endpoints</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/agents">Agent Directory</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/telemetry">Telemetry</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/users">Users</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/api-keys">API Keys</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/reports">Reports</a>
        </div>
      `)}
      ${card(`
        <div class="font-semibold">Tenant Scope</div>
        <div class="mt-4 space-y-3 text-sm text-slate-300">
          <div class="flex justify-between gap-4"><span class="text-slate-500">Tenant</span><span>${esc(settings.tenant.name)}</span></div>
          <div class="flex justify-between gap-4"><span class="text-slate-500">Tenant ID</span><span class="font-mono text-cyan-100">${esc(settings.tenant.id)}</span></div>
          <div class="flex justify-between gap-4"><span class="text-slate-500">Signed in</span><span>${esc(settings.user.email)}</span></div>
          <div class="flex justify-between gap-4"><span class="text-slate-500">Enforcement</span>${badge("server-side tenant session", "green")}</div>
        </div>
      `)}
    </div>
  `;
}

function buildShadowAiHtml({ agents = [], telemetry = [] }) {
  const explainSeverity = (event) => {
    const payload = event.payload || {};
    const severity = String(payload.severity || event.severity || "medium").toLowerCase();
    const eventType = String(event.event_type || "").toLowerCase();
    const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || payload.provider || "AI tool";
    if (eventType === "ai_tool_process_detected") return `${severity}: live AI process detected on the endpoint (${toolName})`;
    if (eventType === "ai_service_connection_detected") return `${severity}: active connection to AI service (${payload.domain || payload.remote_ip || "unknown destination"})`;
    if (eventType === "unauthorized_ai_tool_detected") return `${severity}: installed tool is marked unauthorized by policy`;
    if (eventType === "ai_tool_installed") return `${severity}: installed AI tool inventory finding`;
    if (eventType === "mcp_connection_detected") return `${severity}: possible MCP traffic on a known MCP port`;
    if (eventType === "suspicious_cmdline_detected") {
      const patterns = Array.isArray(payload.matched_patterns) ? payload.matched_patterns.join(", ") : "suspicious command-line match";
      return `${severity}: ${patterns}`;
    }
    return `${severity}: detector-assigned severity`;
  };
  const eventSummary = (event) => {
    const payload = event.payload || {};
    const parts = [];
    if (payload.process_name) parts.push(`process=${payload.process_name}`);
    if (payload.username || payload.user_id || event.user_id) parts.push(`user=${payload.username || payload.user_id || event.user_id}`);
    if (payload.domain) parts.push(`domain=${payload.domain}`);
    if (payload.remote_ip) parts.push(`remote_ip=${payload.remote_ip}`);
    if (payload.pid) parts.push(`pid=${payload.pid}`);
    if (payload.detection_method) parts.push(`method=${payload.detection_method}`);
    if (payload.detail) parts.push(`detail=${payload.detail}`);
    if (Array.isArray(payload.matched_patterns) && payload.matched_patterns.length) parts.push(`patterns=${payload.matched_patterns.join(", ")}`);
    return parts.join(" | ") || "No additional details";
  };
  const interesting = telemetry.filter((event) => {
    const eventType = String(event.event_type || "").toLowerCase();
    return eventType.includes("ai_") || eventType.includes("genai") || eventType.includes("shadow") || eventType.includes("mcp") || eventType.includes("suspicious_cmdline");
  });
  const agentById = new Map(agents.map((agent) => [agent.agent_id || agent.id, agent]));
  const appMap = new Map();
  interesting.forEach((event) => {
    const payload = event.payload || {};
    const agentId = event.agent_id || payload.agent_id || "unknown-agent";
    const agent = agentById.get(agentId) || {};
    const hostname = event.hostname || payload.hostname || agent.hostname || "unknown-host";
    const userId = event.user_id || payload.username || payload.user_id || "unknown-user";
    const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || payload.provider || "Unknown AI Tool";
    const severity = String(payload.severity || event.severity || "medium").toLowerCase();
    const key = `${hostname}:${toolName}:${userId}`;
    const ts = Date.parse(event.occurred_at || payload.timestamp || "") || 0;
    const current = appMap.get(key) || {
      hostname,
      toolName,
      userId,
      severity,
      count: 0,
      firstSeen: ts,
      lastSeen: ts,
      reasons: new Set(),
    };
    current.count += 1;
    current.firstSeen = current.firstSeen ? Math.min(current.firstSeen, ts) : ts;
    current.lastSeen = Math.max(current.lastSeen, ts);
    current.reasons.add(explainSeverity(event));
    if (["high", "critical"].includes(severity) || (severity === "medium" && !["high", "critical"].includes(current.severity))) current.severity = severity;
    appMap.set(key, current);
  });
  const severityTone = (value) => ["high", "critical"].includes(value) ? "red" : value === "medium" ? "amber" : "green";
  const fmtTs = (ts) => ts ? new Date(ts).toLocaleString() : "unknown";
  const detections = Array.from(appMap.values()).sort((a, b) => b.lastSeen - a.lastSeen);
  const detectionRows = detections.map((item) => `
    <tr class="border-t border-slate-800 hover:bg-slate-900/50">
      <td class="px-3 py-3 text-xs">${esc(item.hostname)}</td>
      <td class="px-3 py-3">
        <div class="font-medium">${esc(item.toolName)}</div>
        <div class="mt-2 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-[11px] text-slate-300"><span class="font-semibold text-slate-100">Severity basis:</span> ${esc(Array.from(item.reasons).join(" ; ") || "Detector-assigned severity")}</div>
      </td>
      <td class="px-3 py-3 text-xs">${esc(item.userId)}</td>
      <td class="px-3 py-3">${badge(item.severity, severityTone(item.severity))}</td>
      <td class="px-3 py-3 text-xs">${esc(String(item.count))}</td>
      <td class="px-3 py-3 text-xs">${esc(fmtTs(item.firstSeen))}</td>
      <td class="px-3 py-3 text-xs">${esc(fmtTs(item.lastSeen))}</td>
    </tr>
  `);
  const recentRows = interesting
    .sort((a, b) => (Date.parse(b.occurred_at || "") || 0) - (Date.parse(a.occurred_at || "") || 0))
    .slice(0, 50)
    .map((event) => {
      const payload = event.payload || {};
      const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || payload.provider || "Unknown AI Tool";
      const hostname = event.hostname || payload.hostname || "unknown-host";
      const severity = String(payload.severity || event.severity || "medium").toLowerCase();
      return `
        <tr class="border-t border-slate-800 hover:bg-slate-900/50">
          <td class="px-3 py-3 text-xs">${esc(fmt(event.occurred_at))}</td>
          <td class="px-3 py-3 text-xs">${esc(hostname)}</td>
          <td class="px-3 py-3">${esc(toolName)}</td>
          <td class="px-3 py-3">${badge(severity, severityTone(severity))}</td>
          <td class="px-3 py-3">${badge(event.event_type || "endpoint_event", "cyan")}</td>
          <td class="px-3 py-3 max-w-xs truncate text-xs">${esc(eventSummary(event))}</td>
          <td class="px-3 py-3 max-w-sm text-xs">${esc(explainSeverity(event))}</td>
        </tr>
      `;
    });
  const highRiskCount = detections.filter((item) => ["high", "critical"].includes(item.severity)).length;
  const hostCount = new Set(detections.map((item) => item.hostname)).size;
  return `
    <div class="grid gap-3 md:grid-cols-4">
      ${metricCard("Detected Apps", detections.length, "cyan", "unique host/tool/user combinations")}
      ${metricCard("Affected Hosts", hostCount, "green", "endpoints with detections")}
      ${metricCard("High Risk", highRiskCount, highRiskCount ? "red" : "green", "high or critical severity")}
      ${metricCard("Raw Events", interesting.length, "slate", "endpoint AI telemetry")}
    </div>
    <div class="mt-5">${card(`
      <div class="font-semibold">Severity Guide</div>
      <p class="mt-1 text-sm text-slate-400">How endpoint Shadow AI detections are classified for this tenant.</p>
      <div class="mt-4 grid gap-3 md:grid-cols-3">
        <div class="rounded-2xl border border-emerald-900 bg-emerald-950/30 p-4 text-sm text-slate-300">${badge("Info / Low", "green")}<p class="mt-3">Inventory or lifecycle signals with limited immediate risk.</p></div>
        <div class="rounded-2xl border border-amber-900 bg-amber-950/30 p-4 text-sm text-slate-300">${badge("Medium", "amber")}<p class="mt-3">Suspicious but indirect signals, including MCP-port traffic or suspicious command-line patterns.</p></div>
        <div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-4 text-sm text-slate-300">${badge("High / Critical", "red")}<p class="mt-3">Active AI usage, known AI-service connections, or unauthorized AI tooling.</p></div>
      </div>
    `)}</div>
    <div class="mt-5">${card(`
      <div class="font-semibold">Detected Shadow AI On Endpoints</div>
      <p class="mt-1 text-sm text-slate-400">Aggregated from tenant endpoint telemetry events such as AI process detection and AI service connections.</p>
      <div class="mt-4">${simpleTable(["Host", "Tool / Service", "User", "Severity", "Events", "First Seen", "Last Seen"], detectionRows, "No shadow AI detections yet. Endpoint agents need to post tenant telemetry.")}</div>
    `)}</div>
    <div class="mt-5">${card(`
      <div class="font-semibold">Recent Endpoint AI Events</div>
      <div class="mt-4">${simpleTable(["Time", "Host", "Tool / Service", "Severity", "Event Type", "Summary", "Why This Severity"], recentRows, "No recent endpoint AI events.")}</div>
    `)}</div>
  `;
}

function graphValue(event, keys, fallback = "") {
  const payload = event.payload || {};
  for (const key of keys) {
    const value = key.split(".").reduce((current, part) => current && current[part], { ...event, payload });
    if (value !== undefined && value !== null && String(value).trim() !== "") return String(value);
  }
  return fallback;
}

function buildActionGraphHtml({ agents = [], telemetry = [], providers = [] }) {
  const nodes = new Map();
  const edges = [];
  const addNode = (id, label, type, column) => {
    if (!id) return null;
    const key = `${type}:${id}`;
    if (!nodes.has(key)) nodes.set(key, { key, id, label, type, column });
    return key;
  };
  const addEdge = (from, to, label, tone = "cyan") => {
    if (from && to) edges.push({ from, to, label, tone });
  };

  const tenantKey = addNode(session.tenant_id, session.tenant_id, "tenant", 0);
  agents.forEach((agent) => {
    const agentKey = addNode(agent.agent_id || agent.hostname, agent.agent_id || agent.hostname || "agent", "agent", 1);
    addEdge(tenantKey, agentKey, agent.status || "registered", "green");
  });

  telemetry.slice(0, 30).forEach((event) => {
    const user = graphValue(event, ["user_id", "payload.user", "payload.user_id", "payload.actor", "payload.email"], "unknown-user");
    const agent = graphValue(event, ["agent_id", "payload.agent_id", "payload.agent", "hostname"], "");
    const provider = graphValue(event, ["payload.provider", "payload.ai_provider", "payload.vendor"], "");
    const model = graphValue(event, ["payload.model", "payload.model_id", "payload.deployment"], "");
    const action = graphValue(event, ["payload.action", "payload.operation", "event_type"], event.event_type || "event");
    const decision = graphValue(event, ["payload.decision", "payload.policy_decision", "payload.outcome"], "");
    const risk = graphValue(event, ["payload.risk_score", "payload.risk", "payload.score"], "");

    const userKey = addNode(user, user, "user", 1);
    const agentKey = addNode(agent || user, agent || event.hostname || "direct", agent ? "agent" : "user", 2);
    const providerKey = provider ? addNode(provider, provider, "provider", 3) : null;
    const modelKey = model ? addNode(model, model, "model", 4) : null;
    const actionKey = addNode(`${action}:${event.id || event.occurred_at || edges.length}`, action, "action", 5);
    const decisionKey = decision ? addNode(decision, risk ? `${decision} (${risk})` : decision, "decision", 6) : null;

    addEdge(tenantKey, userKey, "member", "slate");
    addEdge(userKey, agentKey, agent ? "uses" : "initiates", "cyan");
    addEdge(agentKey, providerKey || modelKey || actionKey, event.event_type || "event", "cyan");
    addEdge(providerKey, modelKey || actionKey, provider ? "routes" : "", "green");
    addEdge(modelKey, actionKey, model ? "executes" : "", "green");
    addEdge(actionKey, decisionKey, "policy", decision === "block" ? "amber" : "cyan");
  });

  providers.forEach((provider) => {
    addNode(provider.name || provider.id || provider.provider, provider.name || provider.id || provider.provider || "provider", "provider", 3);
  });

  const nodeList = [...nodes.values()];
  const columns = new Map();
  nodeList.forEach((node) => {
    if (!columns.has(node.column)) columns.set(node.column, []);
    columns.get(node.column).push(node);
  });
  const width = 1120;
  const height = Math.max(360, Math.max(...[...columns.values()].map((list) => list.length), 1) * 92 + 80);
  const xFor = (column) => 70 + column * 155;
  const yFor = (node) => {
    const list = columns.get(node.column) || [];
    const index = list.findIndex((item) => item.key === node.key);
    const gap = height / (list.length + 1);
    return Math.round(gap * (index + 1));
  };
  const colors = {
    tenant: ["#164e63", "#67e8f9"],
    user: ["#1e3a8a", "#93c5fd"],
    agent: ["#064e3b", "#6ee7b7"],
    provider: ["#713f12", "#fcd34d"],
    model: ["#4c1d95", "#c4b5fd"],
    action: ["#7f1d1d", "#fca5a5"],
    decision: ["#0f172a", "#cbd5e1"],
  };
  const edgeColor = { cyan: "#22d3ee", green: "#34d399", amber: "#f59e0b", slate: "#64748b" };
  const edgeRows = edges.slice(0, 20).map((edge) => {
    const from = nodes.get(edge.from);
    const to = nodes.get(edge.to);
    return `<tr class="border-t border-slate-800"><td class="px-3 py-3">${esc(from?.label || "")}</td><td class="px-3 py-3">${esc(edge.label || "")}</td><td class="px-3 py-3">${esc(to?.label || "")}</td></tr>`;
  });

  if (nodeList.length <= 1 || edges.length === 0) {
    return card(`
      <div class="font-semibold">Action Graph</div>
      <p class="mt-2 text-sm text-slate-400">No graph edges yet for this tenant. Send telemetry with fields such as <span class="font-mono text-cyan-100">agent_id</span>, <span class="font-mono text-cyan-100">payload.provider</span>, <span class="font-mono text-cyan-100">payload.model</span>, <span class="font-mono text-cyan-100">payload.action</span>, and <span class="font-mono text-cyan-100">payload.decision</span> to build the graph.</p>
    `);
  }

  return `
    ${card(`
      <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div class="font-semibold">Tenant Action Graph</div>
          <p class="mt-1 text-sm text-slate-400">Derived from recent tenant telemetry, registered agents, and provider visibility.</p>
        </div>
        ${badge(`${nodeList.length} nodes / ${edges.length} edges`, "cyan")}
      </div>
      <div class="mt-5 overflow-x-auto rounded-2xl border border-slate-800 bg-slate-950">
        <svg viewBox="0 0 ${width} ${height}" class="min-w-[980px] w-full" role="img" aria-label="Tenant action graph">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"></path>
            </marker>
          </defs>
          ${edges.map((edge) => {
            const from = nodes.get(edge.from);
            const to = nodes.get(edge.to);
            if (!from || !to) return "";
            const x1 = xFor(from.column) + 58;
            const y1 = yFor(from);
            const x2 = xFor(to.column) - 58;
            const y2 = yFor(to);
            const midX = Math.round((x1 + x2) / 2);
            const color = edgeColor[edge.tone] || edgeColor.slate;
            return `<path d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}" stroke="${color}" stroke-width="1.8" fill="none" opacity="0.8" marker-end="url(#arrow)"></path>`;
          }).join("")}
          ${nodeList.map((node) => {
            const [fill, stroke] = colors[node.type] || colors.decision;
            const x = xFor(node.column);
            const y = yFor(node);
            return `<g>
              <rect x="${x - 58}" y="${y - 24}" width="116" height="48" rx="16" fill="${fill}" stroke="${stroke}" stroke-width="1.5" opacity="0.95"></rect>
              <text x="${x}" y="${y - 3}" text-anchor="middle" fill="#f8fafc" font-size="11" font-weight="700">${esc(node.type.toUpperCase())}</text>
              <text x="${x}" y="${y + 13}" text-anchor="middle" fill="#cbd5e1" font-size="10">${esc(node.label).slice(0, 18)}</text>
            </g>`;
          }).join("")}
        </svg>
      </div>
    `)}
    <div class="mt-5">${simpleTable(["From", "Action", "To"], edgeRows, "No graph edges found.")}</div>
  `;
}

function tenantScopedPlaceholder(title, subtitle, items, adminOnly = false) {
  $("#pageTitle").textContent = title;
  $("#pageSubtitle").textContent = subtitle;
  if (adminOnly && session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  $("#app").innerHTML = featureGrid(items);
}

async function sectionLiveData(section, items) {
  const [overview, policies, agents, telemetry, audit, incidents, providers] = await Promise.all([
    api("/api/customer/overview").catch(() => ({})),
    api("/api/customer/policies").catch(() => []),
    api("/api/customer/agents?limit=50").catch(() => []),
    api("/api/customer/telemetry?limit=50").catch(() => []),
    api("/api/customer/audit?limit=50").catch(() => []),
    api("/api/customer/incidents?limit=50").catch(() => []),
    api("/api/customer/providers").catch(() => ({})),
  ]);
  const providerRows = Array.isArray(providers.providers) ? providers.providers : [];
  const metrics = {
    "policy-builder": [
      metricCard("Policy Rules", overview.policy_count ?? 0, "cyan"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
    ],
    "proxy": [
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
    ],
    "scan": [
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
      metricCard("Policy Rules", overview.policy_count ?? 0, "green"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
    ],
    "shadow-ai": [
      metricCard("Endpoints", overview.agent_count ?? 0, "green"),
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
      metricCard("AI Providers", overview.provider_count ?? 0, "slate"),
    ],
    "compliance": [
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
      metricCard("Policy Rules", overview.policy_count ?? 0, "cyan"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
    ],
    "siem": [
      metricCard("Forwardable Audit Events", overview.audit_count ?? 0, "slate"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
    ],
    "dlp": [
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
      metricCard("Policies", overview.policy_count ?? 0, "green"),
    ],
    "reports": [
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
    ],
    "policy-studio": [
      metricCard("Policy Rules", overview.policy_count ?? 0, "cyan"),
      metricCard("AI Providers", overview.provider_count ?? 0, "green"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
    ],
    "graph": [
      metricCard("Agents", overview.agent_count ?? 0, "green"),
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
    ],
    "risk": [
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
      metricCard("Shadow Signals", overview.telemetry_count ?? 0, "cyan"),
      metricCard("Policy Rules", overview.policy_count ?? 0, "green"),
    ],
    "delegations": [
      metricCard("Agents", overview.agent_count ?? 0, "green"),
      metricCard("Audit Events", overview.audit_count ?? 0, "slate"),
      metricCard("Incidents", overview.incident_count ?? 0, "amber"),
    ],
    "onboarding": [
      metricCard("Endpoints", overview.agent_count ?? 0, "green"),
      metricCard("API Events", overview.audit_count ?? 0, "slate"),
      metricCard("Telemetry Events", overview.telemetry_count ?? 0, "cyan"),
    ],
  };
  const policyRows = (Array.isArray(policies) ? policies : []).slice(0, 10).map((p) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3 font-mono text-xs">${esc(p.name || p.id || "")}</td><td class="px-3 py-3">${esc(p.action || "monitor")}</td><td class="px-3 py-3">${badge(p.enabled === false ? "disabled" : "enabled", p.enabled === false ? "slate" : "green")}</td></tr>
  `);
  const agentRows = agents.slice(0, 10).map((a) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3 font-mono text-xs">${esc(a.agent_id || "")}</td><td class="px-3 py-3">${esc(a.hostname || "")}</td><td class="px-3 py-3">${badge(a.status || "unknown", a.status === "running" ? "green" : "slate")}</td></tr>
  `);
  const telemetryRows = telemetry.slice(0, 10).map((event) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(event.occurred_at || event.created_at))}</td><td class="px-3 py-3">${esc(event.event_type || "")}</td><td class="px-3 py-3">${esc(event.hostname || event.agent_id || event.source || "")}</td></tr>
  `);
  const auditRows = audit.slice(0, 10).map((event) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(event.created_at))}</td><td class="px-3 py-3">${esc(event.method || "")} ${esc(event.path || "")}</td><td class="px-3 py-3">${badge(event.status || "", String(event.status || "").startsWith("2") ? "green" : "amber")}</td></tr>
  `);
  const incidentRows = incidents.slice(0, 10).map((incident) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3 font-mono text-xs">${esc(incident.request_id || "")}</td><td class="px-3 py-3">${esc(incident.event_type || "")}</td><td class="px-3 py-3">${badge(incident.decision || "unknown", incident.decision === "block" ? "amber" : "cyan")}</td></tr>
  `);
  const providerRowsHtml = providerRows.slice(0, 10).map((provider) => `
    <tr class="border-t border-slate-800"><td class="px-3 py-3">${esc(provider.name || provider.id || provider.provider || "")}</td><td class="px-3 py-3">${badge(provider.status || "available", provider.status === "configured" ? "green" : "slate")}</td><td class="px-3 py-3 text-xs text-slate-400">${esc(provider.description || "")}</td></tr>
  `);
  const tablesBySection = {
    "policy-builder": simpleTable(["Policy", "Action", "Status"], policyRows, "No tenant policies found."),
    "proxy": simpleTable(["Time", "Event", "Asset"], telemetryRows, "No proxy telemetry found."),
    "scan": simpleTable(["Time", "Event", "Asset"], telemetryRows, "No scan telemetry found."),
    "shadow-ai": buildShadowAiHtml({ agents, telemetry }),
    "compliance": simpleTable(["Time", "Action", "Status"], auditRows, "No compliance evidence events found."),
    "siem": simpleTable(["Time", "Action", "Status"], auditRows, "No audit events available for forwarding."),
    "dlp": simpleTable(["Time", "Event", "Asset"], telemetryRows, "No DLP telemetry found."),
    "reports": simpleTable(["Request", "Type", "Decision"], incidentRows, "No reportable incidents found."),
    "policy-studio": simpleTable(["Policy", "Action", "Status"], policyRows, "No tenant policies found."),
    "graph": buildActionGraphHtml({ agents, telemetry, providers: providerRows }),
    "risk": simpleTable(["Request", "Type", "Decision"], incidentRows, "No tenant risk incidents found."),
    "delegations": simpleTable(["Time", "Action", "Status"], auditRows, "No delegation audit events found."),
    "onboarding": simpleTable(["Agent", "Hostname", "Status"], agentRows, "No onboarded tenant agents found."),
    "providers": simpleTable(["Provider", "Status", "Details"], providerRowsHtml, "No tenant provider data found."),
  };
  return `
    <div class="grid gap-3 md:grid-cols-3">${(metrics[section] || []).join("")}</div>
    <div class="mt-5">${tablesBySection[section] || featureGrid(items)}</div>
    <div class="mt-5">${featureGrid(items)}</div>
  `;
}

async function tenantScopedConfigPage(section, title, subtitle, items, defaults = {}, adminOnly = false) {
  $("#pageTitle").textContent = title;
  $("#pageSubtitle").textContent = subtitle;
  if (adminOnly && session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  const saved = await api(`/api/customer/config/${encodeURIComponent(section)}`);
  const liveHtml = await sectionLiveData(section, items);
  const config = Object.keys(saved.config || {}).length ? saved.config : defaults;
  const canEdit = session.role === "tenant_admin";
  $("#app").innerHTML = `
    <div class="mb-4 flex flex-wrap gap-2">
      ${tabButton("live", "Live Data", true)}
      ${tabButton("config", "JSON Config")}
    </div>
    <div data-tab-panel="live">${liveHtml}</div>
    <div class="hidden" data-tab-panel="config">
    <div class="mt-5">
      ${card(`
        <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <div class="font-semibold">${esc(title)} Configuration</div>
            <p class="mt-1 text-sm text-slate-400">Stored server-side for tenant <span class="font-mono text-cyan-100">${esc(session.tenant_id)}</span>. ${canEdit ? "Changes here do not affect other tenants." : "Tenant admins can edit this configuration."}</p>
          </div>
          ${saved.updated_by ? `<div class="text-xs text-slate-500">Last updated by ${esc(saved.updated_by)}</div>` : badge("not customized", "slate")}
        </div>
        <form id="sectionConfigForm" class="mt-4">
          <textarea id="sectionConfigJson" class="min-h-72 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm text-slate-100 outline-none focus:border-cyan-400" ${canEdit ? "" : "readonly"}>${esc(JSON.stringify(config, null, 2))}</textarea>
          <div class="mt-3 flex flex-col gap-3 md:flex-row md:items-center">
            ${canEdit ? `<button class="rounded-2xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 hover:bg-cyan-400" type="submit">Save tenant config</button>` : ""}
            <div id="sectionConfigMessage" class="text-sm text-slate-400"></div>
          </div>
        </form>
      `)}
    </div>
    </div>
  `;
  document.querySelectorAll(".sectionTab").forEach((button) => {
    button.addEventListener("click", () => {
      const active = button.dataset.tab;
      document.querySelectorAll(".sectionTab").forEach((tab) => {
        const isActive = tab.dataset.tab === active;
        tab.className = `sectionTab rounded-2xl border px-4 py-2 text-sm ${isActive ? "border-cyan-900 bg-cyan-500/10 text-cyan-100" : "border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"}`;
      });
      document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
        panel.classList.toggle("hidden", panel.dataset.tabPanel !== active);
      });
    });
  });
  if (canEdit) {
    $("#sectionConfigForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      $("#sectionConfigMessage").className = "text-sm text-slate-400";
      $("#sectionConfigMessage").textContent = "Saving...";
      try {
        const parsed = JSON.parse($("#sectionConfigJson").value || "{}");
        await api(`/api/customer/config/${encodeURIComponent(section)}`, {
          method: "PUT",
          body: JSON.stringify({ config: parsed }),
        });
        $("#sectionConfigMessage").className = "text-sm text-emerald-300";
        $("#sectionConfigMessage").textContent = "Saved tenant configuration.";
      } catch (error) {
        $("#sectionConfigMessage").className = "text-sm text-rose-300";
        $("#sectionConfigMessage").textContent = error.message;
      }
    });
  }
}

async function viewOverview() {
  $("#pageTitle").textContent = "Mission Control";
  $("#pageSubtitle").textContent = "Tenant readiness, next actions, and live activity";
  const [settings, overview] = await Promise.all([
    api("/api/customer/settings"),
    api("/api/customer/overview"),
  ]);
  $("#app").innerHTML = missionControlHtml(settings, overview);
  // Wire Recent Activity row clicks → quick read-only modal. We don't have
  // the full payload on the overview endpoint by design (kept it lean), so
  // the modal just shows headers + a deep link into Telemetry.
  document.querySelectorAll("#missionRecentActivity [data-recent-event]").forEach((el) => {
    el.addEventListener("click", () => {
      let event = {};
      try { event = JSON.parse(el.dataset.recentEvent || "{}"); } catch { /* noop */ }
      openReadOnlyModal({
        title: `Telemetry Event — ${event.event_type || ""}`,
        record: event,
        // Match the Telemetry view's labeled rows exactly so the modal looks
        // identical regardless of which entry point opened it. The "View raw
        // JSON" details below shows the full record, including payload.
        fields: [
          { key: "occurred_at",  label: "Time",         render: (r) => esc(fmt(r.occurred_at || r.created_at)) },
          { key: "source",       label: "Source" },
          { key: "event_type",   label: "Event Type" },
          { key: "action_class", label: "Action class", render: (r) => r.action_class ? `<span class="inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase ${actionPillClasses(r.action_class)}">${esc(r.action_class)}</span>` : "" },
          { key: "hostname",     label: "Hostname" },
          { key: "agent_id",     label: "Agent" },
          { key: "user_id",      label: "User" },
          { key: "tenant_id",    label: "Tenant" },
        ],
      });
    });
  });
}

async function viewPolicyBuilder() {
  $("#pageTitle").textContent = "Policy Builder";
  $("#pageSubtitle").textContent = "Author tenant-scoped policies with grouped conditions and artifact references";
  const isAdmin = session.role === "tenant_admin";
  const container = $("#app");
  container.innerHTML = card(`<div class="text-slate-400">Loading policy builder...</div>`);
  mountPolicyBuilder({
    container,
    tenantId: session.tenant_id,
    fetchJson: (path, init) => api(path, init),
    paths: {
      artifacts: "/api/customer/artifacts",
      createPolicy: "/api/customer/policies",
    },
    readOnly: !isAdmin,
    notify: ({ message }) => {
      const el = container.querySelector("#cpb_message");
      if (el) el.textContent = message;
    },
    onSaved: () => { location.hash = "#/policies"; },
  });
}

const ARTIFACT_KIND_META = {
  user_list: { label: "User IDs", placeholder: "alice@corp.com\nbob@corp.com" },
  email_list: { label: "Emails", placeholder: "alice@corp.com" },
  group_list: { label: "Groups", placeholder: "engineering\nsecurity-admins" },
  domain_list: { label: "Domains", placeholder: "chat.openai.com\nclaude.ai" },
  host_list: { label: "Hostnames", placeholder: "dev-laptop-01\ndev-laptop-02" },
  ip_list: { label: "IP addresses", placeholder: "10.0.0.5" },
  cidr_list: { label: "CIDR ranges", placeholder: "10.0.0.0/24" },
  keyword_list: { label: "Keywords", placeholder: "password\napi_key" },
  regex: { label: "Regex patterns", placeholder: "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b" },
};

async function viewArtifacts() {
  $("#pageTitle").textContent = "Artifacts";
  $("#pageSubtitle").textContent = "Tenant-scoped reusable lists and regex patterns for policy rules";
  const isAdmin = session.role === "tenant_admin";
  let includeArchived = false;
  let editing = null;

  function kindOptions(selected) {
    return Object.keys(ARTIFACT_KIND_META).map((k) =>
      `<option value="${k}" ${selected === k ? "selected" : ""}>${esc(ARTIFACT_KIND_META[k].label)} (${k})</option>`
    ).join("");
  }

  async function refresh() {
    try {
      const qs = includeArchived ? "?include_archived=true" : "";
      const rows = await api(`/api/customer/artifacts${qs}`);
      render(Array.isArray(rows) ? rows : []);
    } catch (error) {
      $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
    }
  }

  function render(rows) {
    const tableRows = rows.map((r) => {
      const archived = !!r.archived_at;
      const enabled = r.enabled !== false;
      const count = Array.isArray(r.items) ? r.items.length : 0;
      const refName = `$artifact:${r.name}`;
      const status = archived
        ? badge("archived", "slate")
        : enabled ? badge("active", "green") : badge("disabled", "amber");
      const actions = !isAdmin ? "" : `
        <button class="artEdit rounded-xl border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs hover:bg-slate-800 mr-1" data-id="${esc(r.id)}">Edit</button>
        ${archived
          ? `<button class="artUnarchive rounded-xl border border-emerald-900 bg-emerald-950/40 px-2.5 py-1 text-xs text-emerald-100 mr-1" data-id="${esc(r.id)}">Unarchive</button>`
          : `<button class="artToggle rounded-xl border ${enabled ? "border-amber-900 bg-amber-950/40 text-amber-100" : "border-emerald-900 bg-emerald-950/40 text-emerald-100"} px-2.5 py-1 text-xs mr-1" data-id="${esc(r.id)}" data-enabled="${enabled}">${enabled ? "Disable" : "Enable"}</button>`}
        ${archived
          ? `<button class="artDelete rounded-xl border border-rose-900 bg-rose-950/40 px-2.5 py-1 text-xs text-rose-100" data-id="${esc(r.id)}">Delete</button>`
          : `<button class="artArchive rounded-xl border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs hover:bg-slate-800" data-id="${esc(r.id)}">Archive</button>`}
      `;
      return `<tr class="border-t border-slate-800">
        <td class="px-3 py-3 font-medium">${esc(r.name)}</td>
        <td class="px-3 py-3 text-xs text-slate-400">${esc(r.description || "")}</td>
        <td class="px-3 py-3">${badge(r.kind, "cyan")}</td>
        <td class="px-3 py-3 text-xs">${count} item${count === 1 ? "" : "s"}</td>
        <td class="px-3 py-3">${status}</td>
        <td class="px-3 py-3 font-mono text-xs text-slate-400">${esc(refName)}</td>
        <td class="px-3 py-3 text-right whitespace-nowrap">${actions}</td>
      </tr>`;
    }).join("");

    const isEditing = !!editing;
    const form = !isAdmin ? "" : card(`
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold">${isEditing ? `Edit artifact: ${esc(editing.name)}` : "New artifact"}</div>
        ${isEditing ? `<button id="artCancel" class="text-xs text-slate-400 hover:text-slate-200" type="button">Cancel</button>` : ""}
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Name (referenced in policy rules as <span class="font-mono">$artifact:name</span>)</label>
          <input id="artName" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="engineering_users" value="${esc(editing?.name || "")}" ${isEditing ? "disabled" : ""} />
        </div>
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Kind</label>
          <select id="artKind" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm">${kindOptions(editing?.kind)}</select>
        </div>
        <div class="md:col-span-2 space-y-1">
          <label class="text-xs text-slate-300">Description</label>
          <input id="artDesc" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="Optional description" value="${esc(editing?.description || "")}" />
        </div>
        <div class="md:col-span-2 space-y-1">
          <label class="text-xs text-slate-300">Items (one per line)</label>
          <textarea id="artItems" rows="8" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs" placeholder="${esc(ARTIFACT_KIND_META[editing?.kind || "user_list"].placeholder)}">${esc((editing?.items || []).join("\n"))}</textarea>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <button id="artSave" class="rounded-2xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" type="button">${isEditing ? "Save" : "Create"}</button>
        <div id="artMessage" class="text-sm text-slate-400"></div>
      </div>
    `);

    $("#app").innerHTML = `
      <div class="mb-4 flex items-center justify-between">
        <div class="text-sm text-slate-400">${isAdmin ? "Artifacts are tenant-scoped lists and regex patterns reused across policy rules." : "Tenant admins can create and edit artifacts. Analysts have read-only access."}</div>
        <label class="flex items-center gap-2 text-xs text-slate-300">
          <input id="artShowArchived" type="checkbox" ${includeArchived ? "checked" : ""} /> Show archived
        </label>
      </div>
      ${form}
      <div class="mt-4">${card(`
        <div class="overflow-x-auto rounded-2xl border border-slate-800">
          <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
              <tr>
                <th class="px-3 py-2">Name</th>
                <th class="px-3 py-2">Description</th>
                <th class="px-3 py-2">Kind</th>
                <th class="px-3 py-2">Items</th>
                <th class="px-3 py-2">Status</th>
                <th class="px-3 py-2">Reference</th>
                <th class="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>${tableRows || emptyRow("No artifacts yet.", 7)}</tbody>
          </table>
        </div>
      `)}</div>
    `;

    $("#artShowArchived").addEventListener("change", (event) => {
      includeArchived = event.target.checked;
      refresh();
    });

    if (!isAdmin) return;

    $("#artKind").addEventListener("change", (event) => {
      const meta = ARTIFACT_KIND_META[event.target.value];
      if (meta) $("#artItems").setAttribute("placeholder", meta.placeholder);
    });
    if (isEditing) {
      $("#artCancel").addEventListener("click", () => { editing = null; refresh(); });
    }
    $("#artSave").addEventListener("click", async () => {
      const name = ($("#artName").value || "").trim();
      const kind = $("#artKind").value;
      const description = ($("#artDesc").value || "").trim();
      const items = ($("#artItems").value || "").split("\n").map((s) => s.trim()).filter(Boolean);
      const message = $("#artMessage");
      message.className = "text-sm text-slate-400";
      if (!name) { message.className = "text-sm text-rose-300"; message.textContent = "Name required."; return; }
      if (!items.length) { message.className = "text-sm text-rose-300"; message.textContent = "At least one item required."; return; }
      message.textContent = isEditing ? "Saving..." : "Creating...";
      try {
        if (isEditing) {
          await api(`/api/customer/artifacts/id/${encodeURIComponent(editing.id)}`, {
            method: "PUT",
            body: JSON.stringify({ description, kind, items }),
          });
        } else {
          await api("/api/customer/artifacts", {
            method: "POST",
            body: JSON.stringify({ name, description, kind, items }),
          });
        }
        editing = null;
        refresh();
      } catch (error) {
        message.className = "text-sm text-rose-300";
        message.textContent = error.message;
      }
    });
    document.querySelectorAll(".artEdit").forEach((btn) => {
      btn.addEventListener("click", () => {
        editing = rows.find((r) => r.id === btn.dataset.id) || null;
        render(rows);
      });
    });
    document.querySelectorAll(".artToggle").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/customer/artifacts/id/${encodeURIComponent(btn.dataset.id)}/toggle`, {
            method: "PATCH",
            body: JSON.stringify({ enabled: btn.dataset.enabled !== "true" }),
          });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
    document.querySelectorAll(".artArchive").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!window.confirm("Archive this artifact? Policies that reference it will stop matching until unarchived or replaced.")) return;
        try {
          await api(`/api/customer/artifacts/id/${encodeURIComponent(btn.dataset.id)}/archive`, { method: "PATCH" });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
    document.querySelectorAll(".artUnarchive").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/customer/artifacts/id/${encodeURIComponent(btn.dataset.id)}/unarchive`, { method: "PATCH" });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
    document.querySelectorAll(".artDelete").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!window.confirm("Permanently delete this artifact? This cannot be undone.")) return;
        try {
          await api(`/api/customer/artifacts/id/${encodeURIComponent(btn.dataset.id)}`, { method: "DELETE" });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
  }

  await refresh();
}

function maskApiKey(key) {
  if (!key || key.length <= 7) return key || "";
  return "•".repeat(Math.max(8, key.length - 7)) + key.slice(-7);
}

async function viewApiKeys() {
  $("#pageTitle").textContent = "API Keys";
  $("#pageSubtitle").textContent = "Tenant-scoped API keys";
  if (session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  const keys = await api("/api/customer/api-keys");
  $("#app").innerHTML = `
    <div class="flex flex-col gap-4 lg:flex-row lg:items-start">
      <form id="apiKeyForm" class="min-w-80 rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        <div class="font-semibold">Create tenant API key</div>
        <p class="mt-1 text-xs text-slate-400">Keys created here are automatically scoped to <span class="font-mono text-cyan-100">${esc(session.tenant_id)}</span>.</p>
        <select id="apiKeyRole" class="mt-4 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400">
          <option value="analyst">Analyst</option>
          <option value="service">Service</option>
          <option value="admin">Admin</option>
        </select>
        <button class="mt-3 w-full rounded-2xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 hover:bg-cyan-400" type="submit">Create key</button>
        <div id="apiKeyMessage" class="mt-3 text-sm text-slate-400"></div>
      </form>
      <div id="apiKeysList" class="min-w-0 flex-1"></div>
    </div>
  `;

  const rows = Array.isArray(keys) ? keys : [];
  mountListView({
    container: $("#apiKeysList"),
    rows,
    filename: `api_keys_${session.tenant_id || "tenant"}`,
    columns: [
      { key: "key",    label: "Key (masked)", type: "text",
        value: (r) => maskApiKey(r.key),
        render: (r) => `<span class="font-mono text-xs">${esc(maskApiKey(r.key))}</span>`,
        csv: (r) => maskApiKey(r.key) },
      { key: "role",   label: "Role",   type: "enum",
        value: (r) => r.role || "analyst" },
      { key: "active", label: "Status", type: "enum",
        value: (r) => r.active ? "active" : "disabled",
        render: (r) => badge(r.active ? "active" : "disabled", r.active ? "green" : "slate") },
      { key: "created_at", label: "Created", type: "date",
        value: (r) => r.created_at || "",
        render: (r) => `<span class="text-xs text-slate-400">${esc(fmt(r.created_at))}</span>` },
      { key: "actions", label: "", type: "text", sortable: false, filterable: false,
        value: () => "",
        render: (r) => r.active ? `<button class="disableApiKey rounded-xl border border-amber-900 px-2.5 py-1 text-xs text-amber-100 hover:bg-amber-950" data-key="${esc(r.key)}" type="button" onclick="event.stopPropagation()">Disable</button>` : "",
        csv: () => "" },
    ],
    onRowClick: (apiKey) => openReadOnlyModal({
      title: `API Key — ${maskApiKey(apiKey.key)}`,
      record: { ...apiKey, key: maskApiKey(apiKey.key) },
      fields: [
        { key: "key",        label: "Key (masked)" },
        { key: "role",       label: "Role" },
        { key: "active",     label: "Status",  render: (r) => badge(r.active ? "active" : "disabled", r.active ? "green" : "slate") },
        { key: "tenant_id",  label: "Tenant" },
        { key: "created_at", label: "Created", render: (r) => esc(fmt(r.created_at)) },
      ],
    }),
    emptyMessage: "No tenant API keys yet.",
  });

  $("#apiKeyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#apiKeyMessage").className = "mt-3 text-sm text-slate-400";
    $("#apiKeyMessage").textContent = "Creating key...";
    try {
      const created = await api("/api/customer/api-keys", {
        method: "POST",
        body: JSON.stringify({ role: $("#apiKeyRole").value }),
      });
      $("#apiKeyMessage").className = "mt-3 text-sm text-emerald-300";
      $("#apiKeyMessage").textContent = `Created key ${created.key} — copy now, it will be masked on reload.`;
      // Don't refresh immediately — let user copy the unmasked value first.
    } catch (error) {
      $("#apiKeyMessage").className = "mt-3 text-sm text-rose-300";
      $("#apiKeyMessage").textContent = error.message;
    }
  });
  document.querySelectorAll(".disableApiKey").forEach((button) => {
    button.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      await api(`/api/customer/api-keys/${encodeURIComponent(button.dataset.key)}/disable`, { method: "PATCH" });
      await viewApiKeys();
    });
  });
}

const PROXY_POLICY_ACTIONS = ["allow", "monitor", "warn", "block"];

function flattenPolicyRules(node, out = []) {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node.rules)) {
    node.rules.forEach((rule) => flattenPolicyRules(rule, out));
    return out;
  }
  if (node.field) out.push(node);
  return out;
}

function parseProxyPolicyDraft(policy = {}) {
  const rules = flattenPolicyRules(policy.conditions || {});
  const draft = {
    name: policy.name || "",
    description: policy.description || "",
    action: String(policy.action || "monitor").toLowerCase(),
    priority: Number(policy.priority ?? 100),
    userId: "",
    hostname: "",
    domain: "",
    provider: "",
    pathContains: "",
  };
  rules.forEach((rule) => {
    const field = String(rule.field || "").toLowerCase();
    const value = rule.value == null ? "" : String(rule.value);
    if (!draft.userId && (field.includes("user") || field.includes("identity.subject"))) draft.userId = value;
    else if (!draft.hostname && field.includes("host")) draft.hostname = value;
    else if (!draft.domain && field.includes("domain")) draft.domain = value;
    else if (!draft.provider && field.includes("provider")) draft.provider = value;
    else if (!draft.pathContains && (field.includes("path") || field.includes("url"))) draft.pathContains = value;
  });
  return draft;
}

function proxyPolicyPayload(draft, existing = {}) {
  const rules = [];
  if (draft.userId) rules.push({ field: "identity.user_id", operator: "equals", value: draft.userId });
  if (draft.hostname) rules.push({ field: "request.hostname", operator: "equals", value: draft.hostname });
  if (draft.domain) rules.push({ field: "request.domain", operator: "equals", value: draft.domain });
  if (draft.provider) rules.push({ field: "provider", operator: "equals", value: draft.provider });
  if (draft.pathContains) rules.push({ field: "request.path", operator: "contains", value: draft.pathContains });
  const tags = new Set(Array.isArray(existing.tags) ? existing.tags : []);
  tags.add("proxy");
  return {
    name: draft.name,
    description: draft.description || null,
    enabled: existing.enabled !== false,
    action: draft.action,
    scope: "proxy",
    priority: Number.isFinite(Number(draft.priority)) ? Number(draft.priority) : 100,
    conditions: { operator: "and", rules },
    rules: {
      mode: "proxy",
      targets: {
        user_id: draft.userId || null,
        hostname: draft.hostname || null,
        domain: draft.domain || null,
        provider: draft.provider || null,
        path_contains: draft.pathContains || null,
      },
    },
    tags: Array.from(tags),
  };
}

function proxyPolicySummary(policy) {
  const draft = parseProxyPolicyDraft(policy);
  const parts = [];
  if (draft.userId) parts.push(`user=${draft.userId}`);
  if (draft.hostname) parts.push(`hostname=${draft.hostname}`);
  if (draft.domain) parts.push(`domain=${draft.domain}`);
  if (draft.provider) parts.push(`provider=${draft.provider}`);
  if (draft.pathContains) parts.push(`path~${draft.pathContains}`);
  return parts.join(" | ") || "No proxy selectors";
}

async function viewProxy() {
  $("#pageTitle").textContent = "Proxy Controls";
  $("#pageSubtitle").textContent = "Tenant-scoped proxy policy lifecycle";
  if (session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  let includeArchived = true;
  let editing = null;

  async function refresh() {
    try {
      const qs = new URLSearchParams({ scope: "proxy", include_archived: String(includeArchived) });
      const rows = await api(`/api/customer/policies?${qs.toString()}`);
      render(Array.isArray(rows) ? rows : []);
    } catch (error) {
      $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
    }
  }

  function render(rows) {
    const isEditing = !!editing;
    const draft = parseProxyPolicyDraft(editing || {});
    const tableRows = rows.map((policy) => {
      const archived = !!policy.archived_at;
      const enabled = policy.enabled !== false;
      return `<tr class="border-t border-slate-800">
        <td class="px-3 py-3 font-medium">${esc(policy.name || policy.id || "")}</td>
        <td class="px-3 py-3 text-xs text-slate-400">${esc(proxyPolicySummary(policy))}</td>
        <td class="px-3 py-3">${badge(policy.action || "monitor", policy.action === "block" ? "red" : policy.action === "warn" ? "amber" : policy.action === "allow" ? "green" : "cyan")}</td>
        <td class="px-3 py-3">${badge(String(policy.priority ?? 100), "slate")}</td>
        <td class="px-3 py-3">${archived ? badge("archived", "slate") : enabled ? badge("active", "green") : badge("disabled", "amber")}</td>
        <td class="px-3 py-3 text-right whitespace-nowrap">
          <button class="proxyEdit rounded-xl border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs hover:bg-slate-800 mr-1" data-id="${esc(policy.id)}">Edit</button>
          ${archived
            ? `<button class="proxyUnarchive rounded-xl border border-emerald-900 bg-emerald-950/40 px-2.5 py-1 text-xs text-emerald-100 mr-1" data-id="${esc(policy.id)}">Unarchive</button>`
            : `<button class="proxyToggle rounded-xl border ${enabled ? "border-amber-900 bg-amber-950/40 text-amber-100" : "border-emerald-900 bg-emerald-950/40 text-emerald-100"} px-2.5 py-1 text-xs mr-1" data-id="${esc(policy.id)}" data-enabled="${enabled}">${enabled ? "Disable" : "Enable"}</button>`}
          ${archived ? "" : `<button class="proxyArchive rounded-xl border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs hover:bg-slate-800" data-id="${esc(policy.id)}">Archive</button>`}
        </td>
      </tr>`;
    }).join("");

    $("#app").innerHTML = `
      <div class="mb-4 flex items-center justify-between">
        <div class="text-sm text-slate-400">Create tenant proxy controls for specific users, hosts, domains, providers, and request paths.</div>
        <label class="flex items-center gap-2 text-xs text-slate-300">
          <input id="proxyShowArchived" type="checkbox" ${includeArchived ? "checked" : ""} /> Show archived
        </label>
      </div>
      ${card(`
        <div class="flex items-center justify-between mb-3">
          <div class="font-semibold">${isEditing ? `Edit proxy policy: ${esc(editing.name)}` : "New proxy policy"}</div>
          ${isEditing ? `<button id="proxyCancel" class="text-xs text-slate-400 hover:text-slate-200" type="button">Cancel</button>` : ""}
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Policy name</label>
            <input id="proxyName" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="warn-shadow-openai-web" value="${esc(draft.name)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Action</label>
            <select id="proxyAction" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm">
              ${PROXY_POLICY_ACTIONS.map((action) => `<option value="${action}" ${draft.action === action ? "selected" : ""}>${esc(action)}</option>`).join("")}
            </select>
          </div>
          <div class="md:col-span-2 space-y-1">
            <label class="text-xs text-slate-300">Description</label>
            <input id="proxyDescription" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="Why this rule exists" value="${esc(draft.description)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">User ID / email</label>
            <input id="proxyUserId" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="alice@customer.com" value="${esc(draft.userId)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Hostname</label>
            <input id="proxyHostname" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="sales-laptop-01" value="${esc(draft.hostname)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Domain</label>
            <input id="proxyDomain" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="chat.openai.com" value="${esc(draft.domain)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Provider</label>
            <input id="proxyProvider" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="openai" value="${esc(draft.provider)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Path contains</label>
            <input id="proxyPath" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="/v1/chat/completions" value="${esc(draft.pathContains)}" />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Priority</label>
            <input id="proxyPriority" type="number" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" value="${esc(String(draft.priority || 100))}" />
          </div>
        </div>
        <div class="mt-3 flex items-center gap-3">
          <button id="proxySave" class="rounded-2xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" type="button">${isEditing ? "Save policy" : "Create policy"}</button>
          <div id="proxyMessage" class="text-sm text-slate-400"></div>
        </div>
      `)}
      <div class="mt-4">${card(`
        <div class="overflow-x-auto rounded-2xl border border-slate-800">
          <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
              <tr>
                <th class="px-3 py-2">Name</th>
                <th class="px-3 py-2">Selectors</th>
                <th class="px-3 py-2">Action</th>
                <th class="px-3 py-2">Priority</th>
                <th class="px-3 py-2">Status</th>
                <th class="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>${tableRows || emptyRow("No tenant proxy policies yet.", 6)}</tbody>
          </table>
        </div>
      `)}</div>
    `;

    $("#proxyShowArchived").addEventListener("change", (event) => {
      includeArchived = event.target.checked;
      refresh();
    });
    if (isEditing) {
      $("#proxyCancel").addEventListener("click", () => {
        editing = null;
        refresh();
      });
    }
    $("#proxySave").addEventListener("click", async () => {
      const message = $("#proxyMessage");
      const draftValues = {
        name: ($("#proxyName").value || "").trim(),
        description: ($("#proxyDescription").value || "").trim(),
        action: ($("#proxyAction").value || "monitor").trim().toLowerCase(),
        priority: Number($("#proxyPriority").value || 100),
        userId: ($("#proxyUserId").value || "").trim(),
        hostname: ($("#proxyHostname").value || "").trim(),
        domain: ($("#proxyDomain").value || "").trim(),
        provider: ($("#proxyProvider").value || "").trim(),
        pathContains: ($("#proxyPath").value || "").trim(),
      };
      message.className = "text-sm text-slate-400";
      if (!draftValues.name) {
        message.className = "text-sm text-rose-300";
        message.textContent = "Policy name required.";
        return;
      }
      if (!draftValues.userId && !draftValues.hostname && !draftValues.domain && !draftValues.provider && !draftValues.pathContains) {
        message.className = "text-sm text-rose-300";
        message.textContent = "Add at least one selector so the proxy rule can match traffic.";
        return;
      }
      message.textContent = isEditing ? "Saving..." : "Creating...";
      try {
        const payload = proxyPolicyPayload(draftValues, editing || {});
        if (isEditing) {
          await api(`/api/customer/policies/id/${encodeURIComponent(editing.id)}`, {
            method: "PUT",
            body: JSON.stringify(payload),
          });
        } else {
          await api("/api/customer/policies", {
            method: "POST",
            body: JSON.stringify(payload),
          });
        }
        editing = null;
        refresh();
      } catch (error) {
        message.className = "text-sm text-rose-300";
        message.textContent = error.message;
      }
    });

    document.querySelectorAll(".proxyEdit").forEach((button) => {
      button.addEventListener("click", () => {
        editing = rows.find((policy) => policy.id === button.dataset.id) || null;
        render(rows);
      });
    });
    document.querySelectorAll(".proxyToggle").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api(`/api/customer/policies/id/${encodeURIComponent(button.dataset.id)}/toggle`, {
            method: "PATCH",
            body: JSON.stringify({ enabled: button.dataset.enabled !== "true" }),
          });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
    document.querySelectorAll(".proxyArchive").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!window.confirm("Archive this proxy policy? It will stop enforcing until unarchived.")) return;
        try {
          await api(`/api/customer/policies/id/${encodeURIComponent(button.dataset.id)}/archive`, { method: "PATCH" });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
    document.querySelectorAll(".proxyUnarchive").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api(`/api/customer/policies/id/${encodeURIComponent(button.dataset.id)}/unarchive`, { method: "PATCH" });
          refresh();
        } catch (error) {
          $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
        }
      });
    });
  }

  await refresh();
}

async function viewScan() {
  await tenantScopedConfigPage("scan", "Scan Tools", "Tenant scanning utilities", [
    { title: "Prompt Injection Checks", body: "Run or review prompt-injection validation workflows against this tenant's integrations.", badge: "customer workspace", tone: "cyan" },
    { title: "Policy Drift", body: "Compare configured tenant policies against expected controls and onboarding baselines.", badge: "coming online", tone: "amber" },
    { title: "Provider Hygiene", body: "Validate tenant AI provider configuration and safe routing expectations.", badge: "tenant scoped", tone: "green" },
  ], { enabled_checks: ["prompt_injection", "policy_drift", "provider_hygiene"], schedule: "manual" });
}

async function viewPolicies() {
  $("#pageTitle").textContent = "Policies";
  $("#pageSubtitle").textContent = "Tenant-scoped policy rules";
  const policies = await api("/api/customer/policies");
  const rows = Array.isArray(policies) ? policies : [];
  $("#app").innerHTML = `<div id="policiesList"></div>`;
  const canEdit = session.role === "tenant_admin";
  mountListView({
    container: $("#policiesList"),
    rows,
    filename: `policies_${session.tenant_id || "tenant"}`,
    columns: [
      { key: "name",        label: "Name",        type: "text",
        value: (r) => r.name || r.id || "",
        render: (r) => `<span class="font-mono text-xs">${esc(r.name || r.id || "")}</span>` },
      { key: "description", label: "Description", type: "text",
        value: (r) => r.description || "" },
      { key: "action",      label: "Action",      type: "enum",
        enumValues: ["allow","warn","redact","sandbox","block","isolate","route","audit-only","monitor"],
        value: (r) => r.action || "monitor",
        render: (r) => badge(r.action || "monitor", r.action === "block" ? "amber" : "cyan") },
      { key: "priority",    label: "Priority",    type: "number",
        value: (r) => r.priority ?? 100 },
      { key: "status",      label: "Status",      type: "enum",
        enumValues: ["enabled","disabled"],
        value: (r) => r.enabled === false ? "disabled" : "enabled",
        render: (r) => badge(r.enabled === false ? "disabled" : "enabled", r.enabled === false ? "slate" : "green") },
      { key: "updated_at",  label: "Updated",     type: "date",
        value: (r) => r.updated_at || r.created_at || "",
        render: (r) => `<span class="text-xs text-slate-400">${esc(fmt(r.updated_at || r.created_at))}</span>` },
    ],
    onRowClick: (policy) => openPolicyDetailModal({
      policy,
      tenantId: session.tenant_id,
      fetchJson: api,
      paths: {
        artifacts: "/api/customer/artifacts",
        createPolicy: "/api/customer/policies",
        updatePolicy: "/api/customer/policies/id/{id}",
      },
      canEdit,
      onSaved: async () => { await viewPolicies(); },
    }),
    emptyMessage: "No policies found for this tenant.",
  });
}

// --- Endpoints helpers ---

const ENDPOINT_HEALTH_META = {
  healthy:        { label: "Healthy",   color: "bg-emerald-500/20 text-emerald-200", dot: "bg-emerald-400" },
  warn:           { label: "Warning",   color: "bg-amber-500/20 text-amber-200",     dot: "bg-amber-300" },
  stale:          { label: "Stale",     color: "bg-amber-500/15 text-amber-100",     dot: "bg-amber-500" },
  offline:        { label: "Offline",   color: "bg-rose-500/20 text-rose-200",       dot: "bg-rose-400" },
  never_reported: { label: "No telemetry", color: "bg-slate-700/40 text-slate-200",  dot: "bg-slate-500" },
  unknown:        { label: "Unknown",   color: "bg-slate-700/40 text-slate-300",     dot: "bg-slate-500" },
};

function endpointHealthBadge(h) {
  const meta = ENDPOINT_HEALTH_META[h] || ENDPOINT_HEALTH_META.unknown;
  return `<span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${meta.color}">
    <span class="h-1.5 w-1.5 rounded-full ${meta.dot}"></span>${esc(meta.label)}
  </span>`;
}

function relativeSince(mins) {
  if (mins == null) return "—";
  if (mins < 1)  return "just now";
  if (mins < 60) return `${Math.round(mins)}m ago`;
  if (mins < 24 * 60) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / (24 * 60))}d ago`;
}

function platformBadgeHtml(platform) {
  const p = String(platform || "").toLowerCase();
  // Recognise common values from the agents — Darwin/macOS, Windows, Linux.
  const isMac = p.includes("darwin") || p.includes("mac");
  const isWin = p.includes("win");
  const isLin = p.includes("linux");
  const cls = isMac ? "bg-slate-700/40 text-slate-200"
             : isWin ? "bg-cyan-500/20 text-cyan-200"
             : isLin ? "bg-amber-500/15 text-amber-200"
             : "bg-slate-700/40 text-slate-300";
  const label = isMac ? "macOS" : isWin ? "Windows" : isLin ? "Linux" : (platform || "—");
  return `<span class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold ${cls}">${esc(label)}</span>`;
}

async function viewEndpoints() {
  $("#pageTitle").textContent = "Endpoints";
  $("#pageSubtitle").textContent = "Endpoint and extension fleet — heartbeats, health, and event volume";
  const [agents, catalog] = await Promise.all([
    api("/api/customer/agents?limit=500"),
    api("/api/customer/downloads/catalog").catch(() => []),
  ]);
  const endpointPackages = (Array.isArray(catalog) ? catalog : []).filter((pkg) =>
    ["agent", "extension", "browser_extension"].includes(pkg.category)
  );
  const rows = Array.isArray(agents) ? agents : [];

  // Aggregate health and platform mix for the top summary strip. Health bucket
  // is computed server-side (see _classify_agent_health) so the badge meaning
  // is consistent across all surfaces.
  const healthCounts = { healthy: 0, warn: 0, stale: 0, offline: 0, never_reported: 0, unknown: 0 };
  const platformCounts = { macOS: 0, Windows: 0, Linux: 0, other: 0 };
  let totalEvents24h = 0;
  for (const r of rows) {
    const h = r.health || "unknown";
    healthCounts[h] = (healthCounts[h] || 0) + 1;
    const p = String(r.platform || r.os || "").toLowerCase();
    if (p.includes("darwin") || p.includes("mac"))      platformCounts.macOS++;
    else if (p.includes("win"))                         platformCounts.Windows++;
    else if (p.includes("linux"))                       platformCounts.Linux++;
    else                                                platformCounts.other++;
    if (typeof r.event_count_24h === "number") totalEvents24h += r.event_count_24h;
  }

  const summaryCard = card(`
    <div class="flex flex-wrap items-center gap-4">
      <div class="flex flex-col">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">Endpoints</span>
        <span class="text-2xl font-semibold tabular-nums text-slate-100">${rows.length}</span>
      </div>
      <div class="mx-2 h-10 w-px bg-slate-800"></div>
      ${["healthy", "warn", "stale", "offline", "never_reported"].filter((k) => healthCounts[k] > 0).map((k) => {
        const meta = ENDPOINT_HEALTH_META[k];
        return `<div class="flex items-center gap-2 rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2">
          <span class="h-2 w-2 rounded-full ${meta.dot}"></span>
          <div class="flex flex-col leading-tight">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">${esc(meta.label)}</span>
            <span class="font-mono text-sm tabular-nums text-slate-100">${healthCounts[k]}</span>
          </div>
        </div>`;
      }).join("")}
      <div class="mx-2 h-10 w-px bg-slate-800"></div>
      ${["macOS", "Windows", "Linux", "other"].filter((p) => platformCounts[p] > 0).map((p) =>
        `<div class="flex flex-col rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2 leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">${esc(p)}</span>
          <span class="font-mono text-sm tabular-nums text-slate-100">${platformCounts[p]}</span>
        </div>`
      ).join("")}
      <div class="ml-auto flex flex-col text-right">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">Fleet events 24h</span>
        <span class="font-mono text-sm tabular-nums text-slate-100">${totalEvents24h}</span>
      </div>
    </div>
  `);

  $("#app").innerHTML = `
    <div class="space-y-4">
      ${summaryCard}
      <div id="endpointsList"></div>
    </div>
    <div class="mt-4"></div>
    ${card(`
      <div class="flex items-center justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Agent & Extension Downloads</div>
          <p class="mt-1 text-sm text-slate-400">Download the bundle, issue a one-time bootstrap token, then redeem it into an install-scoped credential during setup instead of embedding a shared secret.</p>
        </div>
        ${session.role === "tenant_admin" ? `<div class="text-xs text-emerald-300">Tenant admins can issue bootstrap tokens</div>` : `<div class="text-xs text-slate-500">Bootstrap token issuance requires a tenant admin</div>`}
      </div>
      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        ${endpointPackages.map((pkg) => `
          <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
            <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(pkg.category.replaceAll("_", " "))}</div>
            <div class="mt-2 text-base font-semibold">${esc(pkg.title)}</div>
            <p class="mt-2 text-sm text-slate-400">${esc(pkg.description || "")}</p>
            ${browserCoverageNote(pkg)}
            <div class="mt-3 rounded-xl bg-slate-950 px-3 py-2 text-xs font-mono text-cyan-200">${esc(pkg.install_hint || "")}</div>
            <div class="mt-4 flex flex-wrap gap-2">
              <a class="rounded-xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" href="${esc(pkg.download_url)}">Download ZIP</a>
              ${session.role === "tenant_admin"
                ? `<button class="customerBootstrapBtn rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" data-package-key="${esc(pkg.package_key)}" data-package-title="${esc(pkg.title)}" type="button">Issue Bootstrap Token</button>`
                : ""}
              <button class="customerBootstrapHelpBtn rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800" data-tenant-id="${esc(session.tenant_id || "")}" type="button" title="Bootstrap Setup: download, issue a one-time token, and redeem it into an install-scoped credential during setup.">Bootstrap Setup</button>
            </div>
          </div>
        `).join("") || `<div class="text-sm text-slate-500">Package catalog unavailable.</div>`}
      </div>
      <div id="customerBootstrapResult" class="mt-4"></div>
    `)}
  `;
  bindCustomerBootstrapButtons();
  bindCustomerBootstrapHelpButtons();

  mountListView({
    container: $("#endpointsList"),
    rows,
    filename: `endpoints_${session.tenant_id || "tenant"}`,
    columns: [
      // Lead with the human-readable asset, not the UUID.
      { key: "hostname", label: "Endpoint", type: "text",
        value: (r) => r.hostname || r.agent_id || "",
        render: (r) => {
          const host = r.hostname || "";
          const aid = r.agent_id || "";
          return `<div class="leading-tight">
            <div class="text-sm font-medium text-slate-100">${esc(host || "(no hostname)")}</div>
            ${aid ? `<div class="font-mono text-[10px] text-slate-500">${esc(aid.slice(0, 12))}…</div>` : ""}
          </div>`;
        } },
      { key: "health", label: "Health", type: "enum",
        value: (r) => r.health || "unknown",
        render: (r) => endpointHealthBadge(r.health) },
      { key: "minutes_since_heartbeat", label: "Last seen", type: "number",
        value: (r) => r.minutes_since_heartbeat == null ? Number.POSITIVE_INFINITY : r.minutes_since_heartbeat,
        render: (r) => `<span class="text-xs text-slate-400 tabular-nums" title="${esc(fmt(r.last_seen))}">${esc(relativeSince(r.minutes_since_heartbeat))}</span>` },
      { key: "platform", label: "Platform", type: "enum",
        value: (r) => r.platform || r.os || "",
        render: (r) => platformBadgeHtml(r.platform || r.os) },
      { key: "username", label: "User", type: "text",
        value: (r) => r.username || "",
        render: (r) => r.username ? `<span class="text-xs text-slate-200">${esc(r.username)}</span>` : `<span class="text-slate-700">—</span>` },
      { key: "version", label: "Version", type: "text",
        value: (r) => r.version || "",
        render: (r) => r.version ? `<span class="font-mono text-[11px] text-slate-300">${esc(r.version)}</span>` : `<span class="text-slate-700">—</span>` },
      { key: "event_count_24h", label: "Events 24h", type: "number",
        value: (r) => Number(r.event_count_24h) || 0,
        render: (r) => {
          const n = Number(r.event_count_24h) || 0;
          const cls = n === 0 ? "text-slate-600" : n > 100 ? "text-cyan-200 font-semibold" : "text-slate-200";
          return `<span class="${cls} tabular-nums">${n}</span>`;
        } },
      { key: "active_monitor_count", label: "Monitors", type: "number", sortable: false,
        value: (r) => Number(r.active_monitor_count) || 0,
        render: (r) => r.active_monitor_count != null
          ? `<span class="text-xs text-slate-300 tabular-nums">${r.active_monitor_count}</span>`
          : `<span class="text-slate-700">—</span>` },
    ],
    onRowClick: (agent) => openReadOnlyModal({
      title: `Endpoint — ${agent.hostname || agent.agent_id || ""}`,
      record: agent,
      fields: [
        { key: "hostname",  label: "Hostname" },
        { key: "agent_id",  label: "Agent ID",       render: (r) => r.agent_id ? `<span class="font-mono text-xs">${esc(r.agent_id)}</span>` : "" },
        { key: "health",    label: "Health",         render: (r) => endpointHealthBadge(r.health) },
        { key: "last_seen", label: "Last heartbeat", render: (r) => `${esc(fmt(r.last_seen))}<div class="text-xs text-slate-500">${esc(relativeSince(r.minutes_since_heartbeat))}</div>` },
        { key: "username",  label: "User" },
        { key: "platform",  label: "Platform",       render: (r) => platformBadgeHtml(r.platform || r.os) },
        { key: "os",        label: "OS" },
        { key: "version",   label: "Agent Version" },
        { key: "status",    label: "Status",         render: (r) => badge(r.status || "unknown", r.status === "running" ? "green" : "slate") },
        { key: "event_count_24h",     label: "Events (24h)" },
        { key: "active_monitor_count", label: "Active monitors" },
        { key: "registered_at", label: "Registered", render: (r) => esc(fmt(r.registered_at)) },
        { key: "ip_address", label: "IP" },
        { key: "tenant_id",  label: "Tenant" },
      ],
    }),
    emptyMessage: "No endpoints found for this tenant. Install an endpoint agent or browser extension from the cards below to start populating this list.",
  });
}

async function viewShadowAi() {
  await tenantScopedConfigPage("shadow-ai", "Shadow AI", "AI services detected on tenant endpoints", [
    { title: "Endpoint Discovery", body: "Surface AI tools and model endpoints observed from tenant telemetry and endpoint-agent events.", badge: "telemetry driven", tone: "cyan" },
    { title: "Unapproved Usage", body: "Highlight provider usage that is outside tenant policy or onboarding expectations.", badge: "needs data", tone: "amber" },
    { title: "Remediation", body: "Route findings into tenant incidents, policy updates, or user education workflows.", badge: "tenant only", tone: "green" },
  ], { approved_tools: [], alert_on_unapproved: true, remediation: "create_incident" });
}

async function viewCompliance() {
  await tenantScopedConfigPage("compliance", "Compliance", "Tenant framework assessments and controls", [
    { title: "SOC 2", body: "Map tenant controls, evidence, and audit events to trust-service criteria.", badge: "mapped", tone: "green" },
    { title: "NIST CSF", body: "Track identify, protect, detect, respond, and recover posture for this tenant.", badge: "framework ready", tone: "cyan" },
    { title: "GDPR", body: "Review tenant data handling, DLP activity, and AI usage auditability.", badge: "evidence backed", tone: "slate" },
  ], { frameworks: ["SOC 2", "NIST CSF", "GDPR"], evidence_retention_days: 365 });
}

async function viewSiem() {
  await tenantScopedConfigPage("siem", "SIEM Config", "Tenant security event forwarding configuration", [
    { title: "Destinations", body: "Configure Splunk, Elastic, Sentinel, or webhook forwarding for this tenant's events.", badge: "tenant admin", tone: "green" },
    { title: "Event Types", body: "Choose whether audit logs, incidents, telemetry, or DLP findings are forwarded.", badge: "scoped filters", tone: "cyan" },
    { title: "Secret Handling", body: "SIEM credentials should be stored server-side and never echoed back to the browser.", badge: "write-only secrets", tone: "amber" },
  ], { destinations: [], event_types: ["audit", "incidents", "telemetry", "dlp"], enabled: false }, true);
}

async function viewIdentity() {
  await viewSettings();
}

async function viewDlp() {
  await tenantScopedConfigPage("dlp", "DLP & Data Class.", "Tenant data classification and loss prevention", [
    { title: "Classification Labels", body: "Define tenant labels such as Public, Internal, Confidential, and Restricted.", badge: "tenant taxonomy", tone: "cyan" },
    { title: "Detection Patterns", body: "Track PII, secrets, credentials, and regulated data classes for this tenant.", badge: "policy linked", tone: "green" },
    { title: "Credential Leak Prevention", body: "Use redaction-mode decisions for AI-bound prompts and responses that contain keys, tokens, passwords, or other secrets.", badge: "pre-breach control", tone: "amber" },
    { title: "Response Actions", body: "Connect DLP findings to redact, block, escalate, or audit-only policy outcomes.", badge: "enforcement ready", tone: "slate" },
  ], { labels: ["Public", "Internal", "Confidential", "Restricted"], patterns: ["pii", "secrets", "credentials"], default_action: "redact" }, true);
}

async function viewReports() {
  await tenantScopedConfigPage("reports", "Reports & Evidence Export", "Tenant security, compliance, and evidence export packages", [
    { title: "Compliance Report", body: "Generate a tenant-scoped summary of framework assessment results and evidence gaps.", badge: "SOC 2 / NIST / GDPR", tone: "green" },
    { title: "DLP Activity Report", body: "Summarize tenant data-classification hits, DLP detections, and response outcomes.", badge: "tenant data only", tone: "cyan" },
    { title: "AI Risk Report", body: "Package tenant AI providers, agents, policy decisions, incidents, and audit findings.", badge: "executive ready", tone: "amber" },
  ], { enabled_reports: ["compliance", "dlp", "ai_risk"], schedule: "manual", recipients: [] });
  $("#app").insertAdjacentHTML("beforeend", `
    <div class="mt-4"></div>
    ${card(`
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div class="text-lg font-semibold">Evidence Export</div>
          <p class="mt-2 max-w-2xl text-sm text-slate-400">Create tenant-scoped JSON evidence packs for audit review, incident triage, demo validation, or customer success handoff.</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button class="evidenceExport rounded-2xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" data-scope="summary" type="button">Export Summary</button>
          <button class="evidenceExport rounded-2xl border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 hover:bg-slate-800" data-scope="full" type="button">Export Full Pack</button>
        </div>
      </div>
      <div class="mt-4 grid gap-3 md:grid-cols-3">
        <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><div class="text-sm font-semibold">Audit logs</div><p class="mt-1 text-xs text-slate-400">Policy, portal, and API activity records.</p></div>
        <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><div class="text-sm font-semibold">Telemetry</div><p class="mt-1 text-xs text-slate-400">Endpoint and runtime events for the tenant.</p></div>
        <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"><div class="text-sm font-semibold">Incidents</div><p class="mt-1 text-xs text-slate-400">Runtime decisions, findings, and evidence candidates.</p></div>
      </div>
      <div id="evidenceExportMessage" class="mt-4 text-sm text-slate-400"></div>
    `)}
  `);
  document.querySelectorAll(".evidenceExport").forEach((button) => {
    button.addEventListener("click", async () => {
      const scope = button.dataset.scope || "summary";
      const message = $("#evidenceExportMessage");
      message.textContent = `Preparing ${scope} evidence export...`;
      message.className = "mt-4 text-sm text-slate-400";
      try {
        const pack = await api(`/api/customer/evidence/export?scope=${encodeURIComponent(scope)}`);
        downloadJson(`cyberarmor_${session.tenant_id}_${scope}_evidence_${new Date().toISOString().slice(0, 10)}.json`, pack);
        message.textContent = "Evidence export created.";
        message.className = "mt-4 text-sm text-emerald-300";
      } catch (error) {
        message.textContent = error.message;
        message.className = "mt-4 text-sm text-rose-300";
      }
    });
  });
}

// --- Telemetry helpers ---

function sourceBadgeHtml(source) {
  const s = String(source || "unknown");
  // Differentiated colors so it's obvious at a glance which subsystem
  // wrote the event. Matches the source values our agents actually emit.
  const map = {
    browser_extension:           "bg-cyan-500/20 text-cyan-200",
    endpoint:                    "bg-emerald-500/20 text-emerald-200",
    endpoint_clipboard_helper:   "bg-emerald-500/15 text-emerald-200",
    proxy_agent:                 "bg-amber-500/20 text-amber-200",
    runtime:                     "bg-amber-500/20 text-amber-200",
    rasp:                        "bg-violet-500/20 text-violet-200",
    sdk:                         "bg-violet-500/15 text-violet-200",
    phishing_warning:            "bg-rose-500/20 text-rose-200",
  };
  return `<span class="inline-flex max-w-[14ch] truncate items-center rounded px-1.5 py-0.5 font-mono text-[10px] ${map[s] || "bg-slate-700/40 text-slate-300"}" title="${esc(s)}">${esc(s)}</span>`;
}

function severityBadgeHtml(severity) {
  if (!severity) return `<span class="text-slate-700">—</span>`;
  const s = String(severity).toLowerCase();
  const cls = (s === "critical" || s === "high") ? "bg-rose-500/20 text-rose-200"
            : (s === "medium")                   ? "bg-amber-500/20 text-amber-200"
            : (s === "low")                      ? "bg-slate-700/40 text-slate-200"
            : (s === "info" || s === "informational") ? "bg-cyan-500/15 text-cyan-200"
            : "bg-slate-700/40 text-slate-300";
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${cls}">${esc(severity)}</span>`;
}

// Time-window options for the picker. Values are millisecond windows or
// null for "all time".
const TELEMETRY_WINDOWS = [
  { id: "1h",  label: "Last hour",   ms:    60 * 60 * 1000 },
  { id: "24h", label: "Last 24h",    ms: 24 * 60 * 60 * 1000 },
  { id: "7d",  label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All time",    ms: null },
];

async function viewTelemetry() {
  $("#pageTitle").textContent = "Telemetry";
  $("#pageSubtitle").textContent = "Tenant-scoped events — newest first";
  const PAGE_SIZE = 250;
  const initial = await api(`/api/customer/telemetry?limit=${PAGE_SIZE}`);
  const rows = Array.isArray(initial) ? [...initial] : [];

  const state = {
    sourceFilter: "all",       // "all" | <source value>
    actionFilter: "all",       // "all" | one of action class names
    severityFilter: "all",     // "all" | critical/high/medium/low/info
    windowId: "all",           // matches TELEMETRY_WINDOWS[].id
    loadingMore: false,
    exhausted: rows.length < PAGE_SIZE,
  };

  function rowTimestampMs(r) {
    const t = r.occurred_at || r.created_at;
    return t ? Date.parse(t) : 0;
  }

  function visibleRows() {
    const win = TELEMETRY_WINDOWS.find((w) => w.id === state.windowId);
    const cutoff = win && win.ms ? Date.now() - win.ms : 0;
    return rows.filter((r) => {
      if (cutoff && rowTimestampMs(r) < cutoff) return false;
      if (state.sourceFilter !== "all" && (r.source || "unknown") !== state.sourceFilter) return false;
      if (state.actionFilter !== "all" && (r.action_class || "monitor") !== state.actionFilter) return false;
      if (state.severityFilter !== "all" && String(r.severity || "").toLowerCase() !== state.severityFilter) return false;
      return true;
    });
  }

  function computeStats() {
    const action = { block: 0, redact: 0, warn: 0, detect: 0, monitor: 0, allow: 0 };
    const sources = {};
    const severities = {};
    for (const r of rows) {
      const a = r.action_class || "monitor";
      action[a] = (action[a] || 0) + 1;
      const src = r.source || "unknown";
      sources[src] = (sources[src] || 0) + 1;
      const sev = String(r.severity || "").toLowerCase();
      if (sev) severities[sev] = (severities[sev] || 0) + 1;
    }
    // Oldest loaded timestamp for "showing last X minutes" context
    const oldestTs = rows.length ? rowTimestampMs(rows[rows.length - 1]) : 0;
    const newestTs = rows.length ? rowTimestampMs(rows[0]) : 0;
    return { action, sources, severities, oldestTs, newestTs };
  }

  function chipCls(active) {
    return active
      ? "rounded-full bg-cyan-500/20 text-cyan-100 border border-cyan-400/40 px-3 py-1 text-xs"
      : "rounded-full bg-slate-900 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1 text-xs";
  }

  async function loadMore() {
    if (state.loadingMore || state.exhausted) return;
    const oldest = rows[rows.length - 1];
    const cursor = oldest && (oldest.occurred_at || oldest.created_at);
    if (!cursor) { state.exhausted = true; render(); return; }
    state.loadingMore = true;
    render();
    try {
      const next = await api(`/api/customer/telemetry?limit=${PAGE_SIZE}&before=${encodeURIComponent(cursor)}`);
      const batch = Array.isArray(next) ? next : [];
      if (batch.length === 0) {
        state.exhausted = true;
      } else {
        rows.push(...batch);
        if (batch.length < PAGE_SIZE) state.exhausted = true;
      }
    } finally {
      state.loadingMore = false;
      render();
    }
  }

  function render() {
    const filtered = visibleRows();
    const { action, sources, severities, oldestTs, newestTs } = computeStats();
    const sourceKeys = Object.keys(sources).sort((a, b) => sources[b] - sources[a]);
    const severityOrder = ["critical", "high", "medium", "low", "info"].filter((s) => severities[s]);
    const span = (oldestTs && newestTs && newestTs > oldestTs)
      ? `${fmt(new Date(oldestTs).toISOString())} → ${fmt(new Date(newestTs).toISOString())}`
      : "—";

    $("#app").innerHTML = `
      <div class="space-y-4">
        ${card(`
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Window</span>
            ${TELEMETRY_WINDOWS.map((w) =>
              `<button data-window="${w.id}" class="${chipCls(state.windowId === w.id)}">${esc(w.label)}</button>`
            ).join("")}
            <div class="ml-auto text-[11px] text-slate-500 tabular-nums">Loaded span: ${span}</div>
          </div>
        `)}
        ${card(`
          <div class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Action class</span>
              <button data-action-chip="all" class="${chipCls(state.actionFilter === "all")}">All <span class="text-slate-500">·${rows.length}</span></button>
              ${ACTION_BUCKETS.filter((b) => action[b.key]).map((b) => `
                <button data-action-chip="${b.key}" class="${chipCls(state.actionFilter === b.key)} flex items-center gap-1">
                  <span class="inline-block h-2 w-2 rounded-full" style="background:${b.color}"></span>
                  ${esc(b.label)} <span class="text-slate-500">·${action[b.key]}</span>
                </button>
              `).join("")}
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Source</span>
              <button data-source-chip="all" class="${chipCls(state.sourceFilter === "all")}">All</button>
              ${sourceKeys.map((src) => `
                <button data-source-chip="${esc(src)}" class="${chipCls(state.sourceFilter === src)}">
                  ${esc(src)} <span class="text-slate-500">·${sources[src]}</span>
                </button>
              `).join("")}
            </div>
            ${severityOrder.length ? `
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-[10px] uppercase tracking-wider text-slate-500">Severity</span>
                <button data-severity-chip="all" class="${chipCls(state.severityFilter === "all")}">All</button>
                ${severityOrder.map((s) => `
                  <button data-severity-chip="${s}" class="${chipCls(state.severityFilter === s)}">
                    ${esc(s)} <span class="text-slate-500">·${severities[s]}</span>
                  </button>
                `).join("")}
              </div>
            ` : ""}
          </div>
        `)}
        <div id="telemetryList"></div>
        <div id="telemetryPager" class="flex items-center justify-center gap-3 pt-2 pb-1 text-sm">
          ${state.exhausted
            ? `<span class="text-xs text-slate-500">All ${rows.length} telemetry events loaded.</span>`
            : `<button id="telemetryLoadMore" type="button" ${state.loadingMore ? "disabled" : ""} class="rounded-2xl border border-slate-700 bg-slate-900 px-5 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50">${state.loadingMore ? "Loading…" : `Load more (currently ${rows.length})`}</button>`}
        </div>
      </div>
    `;

    mountListView({
      container: $("#telemetryList"),
      rows: filtered,
      filename: `telemetry_${session.tenant_id || "tenant"}`,
      columns: [
        { key: "occurred_at", label: "Time", type: "date",
          value: (r) => r.occurred_at || r.created_at || "",
          render: (r) => `<span class="text-xs text-slate-400 tabular-nums">${esc(fmt(r.occurred_at || r.created_at))}</span>` },
        { key: "action_class", label: "Action", type: "enum",
          value: (r) => r.action_class || "monitor",
          render: (r) => `<span class="inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${actionPillClasses(r.action_class)}">${esc(r.action_class || "event")}</span>` },
        { key: "source", label: "Source", type: "enum",
          value: (r) => r.source || "unknown",
          render: (r) => sourceBadgeHtml(r.source) },
        { key: "event_type", label: "Event", type: "text",
          value: (r) => r.event_type || "",
          render: (r) => {
            const teaser = r.payload_teaser || "";
            return `<div class="leading-tight">
              <span class="font-mono text-xs text-slate-100">${esc(r.event_type || "")}</span>
              ${teaser ? `<div class="mt-0.5 truncate font-mono text-[10px] text-slate-500">${esc(teaser)}</div>` : ""}
            </div>`;
          } },
        { key: "severity", label: "Severity", type: "enum",
          value: (r) => String(r.severity || "").toLowerCase(),
          render: (r) => severityBadgeHtml(r.severity) },
        { key: "asset", label: "Asset", type: "text",
          value: (r) => r.hostname || r.agent_id || "",
          render: (r) => {
            const host = r.hostname || "";
            const aid = r.agent_id || "";
            return host
              ? `<div class="leading-tight">
                  <div class="text-xs text-slate-200">${esc(host)}</div>
                  ${aid ? `<div class="font-mono text-[10px] text-slate-500">${esc(aid.slice(0, 8))}…</div>` : ""}
                </div>`
              : aid ? `<span class="font-mono text-xs text-slate-300">${esc(aid)}</span>`
                    : `<span class="text-slate-700">—</span>`;
          } },
      ],
      onRowClick: (event) => openReadOnlyModal({
        title: `${event.event_type || "Telemetry"} — ${fmt(event.occurred_at || event.created_at)}`,
        record: event,
        fields: [
          { key: "occurred_at",  label: "Time",         render: (r) => esc(fmt(r.occurred_at || r.created_at)) },
          { key: "source",       label: "Source",       render: (r) => sourceBadgeHtml(r.source) },
          { key: "event_type",   label: "Event Type" },
          { key: "action_class", label: "Action class", render: (r) => r.action_class ? `<span class="inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase ${actionPillClasses(r.action_class)}">${esc(r.action_class)}</span>` : "" },
          { key: "severity",     label: "Severity",     render: (r) => severityBadgeHtml(r.severity) },
          { key: "hostname",     label: "Hostname" },
          { key: "agent_id",     label: "Agent" },
          { key: "user_id",      label: "User" },
          { key: "tenant_id",    label: "Tenant" },
        ],
      }),
      emptyMessage: filtered.length === 0 && rows.length > 0
        ? "No events match the current filters. Widen the time window or clear chips."
        : "No telemetry found for this tenant. Install an endpoint agent or browser extension to start collecting events.",
    });

    document.querySelectorAll("[data-window]").forEach((el) => {
      el.addEventListener("click", () => { state.windowId = el.dataset.window; render(); });
    });
    document.querySelectorAll("[data-action-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.actionFilter = el.dataset.actionChip; render(); });
    });
    document.querySelectorAll("[data-source-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.sourceFilter = el.dataset.sourceChip; render(); });
    });
    document.querySelectorAll("[data-severity-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.severityFilter = el.dataset.severityChip; render(); });
    });
    const btn = $("#telemetryLoadMore");
    if (btn) btn.addEventListener("click", loadMore);
  }

  render();
}

// --- Audit Log helpers ---

// Method → semantic color so a busy log scans visually. GET is the dominant
// noise; we mute it. Writes are the interesting events; we tint them.
function methodBadgeHtml(method) {
  const m = String(method || "").toUpperCase();
  const map = {
    GET:     "bg-slate-700/40 text-slate-300",
    HEAD:    "bg-slate-700/40 text-slate-300",
    OPTIONS: "bg-slate-700/40 text-slate-400",
    POST:    "bg-cyan-500/20 text-cyan-200",
    PUT:     "bg-amber-500/20 text-amber-200",
    PATCH:   "bg-amber-500/20 text-amber-200",
    DELETE:  "bg-rose-500/20 text-rose-200",
  };
  return `<span class="inline-flex w-14 justify-center rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wide ${map[m] || "bg-slate-700/40 text-slate-300"}">${esc(m || "—")}</span>`;
}

// Status → traffic light. 2xx green, 3xx cyan, 4xx amber, 5xx red.
function statusBadgeHtml(status) {
  const s = String(status || "");
  const first = s.charAt(0);
  const cls = first === "2" ? "bg-emerald-500/20 text-emerald-200"
            : first === "3" ? "bg-cyan-500/20 text-cyan-200"
            : first === "4" ? "bg-amber-500/20 text-amber-200"
            : first === "5" ? "bg-rose-500/20 text-rose-200"
            : "bg-slate-700/40 text-slate-300";
  return `<span class="inline-flex w-12 justify-center rounded-full px-2 py-0.5 text-[10px] font-mono font-semibold ${cls}">${esc(s || "—")}</span>`;
}

function principalLabelHtml(record) {
  const kind = record.principal_kind || "raw";
  const label = record.principal_label || record.principal || "anonymous";
  const kindClass = {
    anonymous:   "bg-slate-700/40 text-slate-300",
    api_key:     "bg-cyan-500/15 text-cyan-200",
    pqc_api_key: "bg-violet-500/15 text-violet-200",
    jwt:         "bg-emerald-500/15 text-emerald-200",
    raw:         "bg-slate-700/40 text-slate-300",
  }[kind] || "bg-slate-700/40 text-slate-300";
  return `<span class="inline-flex max-w-[20ch] truncate items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] ${kindClass}" title="${esc(label)}">${esc(label)}</span>`;
}

function durationLabel(ms) {
  if (ms == null || Number.isNaN(ms)) return "";
  if (ms < 1)    return `<span class="text-emerald-300">&lt;1ms</span>`;
  if (ms < 100)  return `<span class="text-emerald-300">${ms.toFixed(0)}ms</span>`;
  if (ms < 500)  return `<span class="text-amber-200">${ms.toFixed(0)}ms</span>`;
  if (ms < 2000) return `<span class="text-amber-300">${ms.toFixed(0)}ms</span>`;
  return `<span class="text-rose-300 font-semibold">${(ms / 1000).toFixed(2)}s</span>`;
}

// Routes the audit log is full of as side-effects of the portal session
// (auth polling, health checks, etc.). The "Hide noise" filter chip masks
// these so the operator can see real activity.
const AUDIT_NOISE_PATTERNS = [
  /^\/customer-auth\/session\b/,
  /^\/customer\/(settings|overview)\b/,
  /^\/health\b/, /^\/ready\b/, /^\/metrics\b/, /^\/favicon\.ico$/,
];
function isNoisePath(path) {
  return AUDIT_NOISE_PATTERNS.some((re) => re.test(path || ""));
}

async function viewAudit() {
  $("#pageTitle").textContent = "Audit Logs";
  $("#pageSubtitle").textContent = "Every API call against this tenant's control plane";
  const PAGE_SIZE = 250;
  const initial = await api(`/api/customer/audit?limit=${PAGE_SIZE}`);
  const rows = Array.isArray(initial) ? [...initial] : [];

  // UI state local to this view.
  const state = {
    statusClass: "all",   // "all" | "2xx" | "3xx" | "4xx" | "5xx"
    methodFilter: "all",  // "all" | "writes" | <single method>
    hideNoise: true,
    loadingMore: false,
    exhausted: rows.length < PAGE_SIZE,
  };

  // Recompute summary stats whenever `rows` changes (Load more appends).
  function computeStats() {
    const totals = { all: rows.length, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };
    const methodTotals = {};
    const durations = [];
    for (const r of rows) {
      const c = String(r.status || "").charAt(0);
      if (c === "2") totals["2xx"]++;
      else if (c === "3") totals["3xx"]++;
      else if (c === "4") totals["4xx"]++;
      else if (c === "5") totals["5xx"]++;
      const m = String(r.method || "").toUpperCase();
      methodTotals[m] = (methodTotals[m] || 0) + 1;
      if (typeof r.duration_ms === "number") durations.push(r.duration_ms);
    }
    let p95Ms = 0;
    if (durations.length) {
      durations.sort((a, b) => a - b);
      p95Ms = durations[Math.floor(durations.length * 0.95)] || durations.at(-1);
    }
    return { totals, methodTotals, p95Ms };
  }

  async function loadMore() {
    if (state.loadingMore || state.exhausted) return;
    const oldest = rows[rows.length - 1];
    if (!oldest || !oldest.created_at) { state.exhausted = true; render(); return; }
    state.loadingMore = true;
    render();
    try {
      const next = await api(`/api/customer/audit?limit=${PAGE_SIZE}&before=${encodeURIComponent(oldest.created_at)}`);
      const batch = Array.isArray(next) ? next : [];
      if (batch.length === 0) {
        state.exhausted = true;
      } else {
        rows.push(...batch);
        if (batch.length < PAGE_SIZE) state.exhausted = true;
      }
    } finally {
      state.loadingMore = false;
      render();
    }
  }

  function visibleRows() {
    return rows.filter((r) => {
      if (state.hideNoise && isNoisePath(r.path)) return false;
      const c = String(r.status || "").charAt(0);
      if (state.statusClass !== "all" && state.statusClass !== `${c}xx`) return false;
      const m = String(r.method || "").toUpperCase();
      if (state.methodFilter === "writes" && ["GET", "HEAD", "OPTIONS"].includes(m)) return false;
      if (state.methodFilter !== "all" && state.methodFilter !== "writes" && state.methodFilter !== m) return false;
      return true;
    });
  }

  function chipCls(active) {
    return active
      ? "rounded-full bg-cyan-500/20 text-cyan-100 border border-cyan-400/40 px-3 py-1 text-xs"
      : "rounded-full bg-slate-900 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1 text-xs";
  }
  function summaryCard(label, value, key, tone) {
    return `<button data-status-chip="${key}" class="${chipCls(state.statusClass === key)} flex items-center gap-2">
      <span class="text-[10px] uppercase tracking-wider text-slate-400">${esc(label)}</span>
      <span class="font-mono text-sm ${tone || "text-slate-100"}">${value}</span>
    </button>`;
  }

  function render() {
    const filtered = visibleRows();
    const { totals, methodTotals, p95Ms } = computeStats();
    $("#app").innerHTML = `
      <div class="space-y-4">
        ${card(`
          <div class="flex flex-wrap items-center gap-2">
            ${summaryCard("Total", totals.all, "all", "text-slate-100")}
            ${summaryCard("2xx", totals["2xx"], "2xx", "text-emerald-300")}
            ${summaryCard("3xx", totals["3xx"], "3xx", "text-cyan-300")}
            ${summaryCard("4xx", totals["4xx"], "4xx", "text-amber-300")}
            ${summaryCard("5xx", totals["5xx"], "5xx", "text-rose-300")}
            <div class="mx-2 h-5 w-px bg-slate-800"></div>
            <button data-method-chip="all" class="${chipCls(state.methodFilter === "all")}">All methods</button>
            <button data-method-chip="writes" class="${chipCls(state.methodFilter === "writes")}">Writes only</button>
            ${["POST","PUT","PATCH","DELETE","GET"].filter((m) => methodTotals[m]).map((m) =>
              `<button data-method-chip="${m}" class="${chipCls(state.methodFilter === m)}">${m} <span class="text-slate-500">·${methodTotals[m]}</span></button>`
            ).join("")}
            <div class="mx-2 h-5 w-px bg-slate-800"></div>
            <label class="flex items-center gap-2 text-xs text-slate-300">
              <input type="checkbox" id="auditHideNoise" ${state.hideNoise ? "checked" : ""}>
              <span>Hide session polling</span>
            </label>
            <div class="ml-auto text-xs text-slate-400">p95 latency: <span class="font-mono ${p95Ms >= 500 ? "text-amber-300" : "text-slate-200"}">${p95Ms.toFixed(0)}ms</span></div>
          </div>
        `)}
        <div id="auditList"></div>
        <div id="auditPager" class="flex items-center justify-center gap-3 pt-2 pb-1 text-sm">
          ${state.exhausted
            ? `<span class="text-xs text-slate-500">All ${rows.length} audit events loaded.</span>`
            : `<button id="auditLoadMore" type="button" ${state.loadingMore ? "disabled" : ""} class="rounded-2xl border border-slate-700 bg-slate-900 px-5 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50">${state.loadingMore ? "Loading…" : `Load more (currently ${rows.length})`}</button>`}
        </div>
      </div>
    `;

    mountListView({
      container: $("#auditList"),
      rows: filtered,
      filename: `audit_${session.tenant_id || "tenant"}`,
      columns: [
        { key: "created_at", label: "Time",    type: "date",
          value: (r) => r.created_at || "",
          render: (r) => `<span class="text-xs text-slate-400 tabular-nums">${esc(fmt(r.created_at))}</span>` },
        { key: "method",     label: "Method",  type: "enum",
          value: (r) => String(r.method || "").toUpperCase(),
          render: (r) => methodBadgeHtml(r.method) },
        { key: "path",       label: "Path",    type: "text",
          value: (r) => r.path || "",
          render: (r) => `<span class="font-mono text-xs text-slate-200">${esc(r.path || "")}</span>` },
        { key: "status",     label: "Status",  type: "enum",
          value: (r) => String(r.status || ""),
          render: (r) => statusBadgeHtml(r.status) },
        { key: "duration_ms", label: "Took",   type: "number",
          value: (r) => Number(r.duration_ms) || 0,
          render: (r) => `<span class="text-xs tabular-nums">${durationLabel(r.duration_ms)}</span>` },
        { key: "principal",  label: "Actor",   type: "text", sortable: false,
          value: (r) => r.principal_label || r.principal || "anonymous",
          render: (r) => principalLabelHtml(r) },
        { key: "client_ip",  label: "Client",  type: "text",
          value: (r) => r.client_ip || "",
          render: (r) => r.client_ip ? `<span class="font-mono text-[11px] text-slate-400">${esc(r.client_ip)}</span>` : `<span class="text-slate-700">—</span>` },
      ],
      onRowClick: (event) => openReadOnlyModal({
        title: `${event.method || ""} ${event.path || ""} → ${event.status || ""}`,
        record: event,
        fields: [
          { key: "created_at",  label: "Time",     render: (r) => esc(fmt(r.created_at)) },
          { key: "method",      label: "Method",   render: (r) => methodBadgeHtml(r.method) },
          { key: "path",        label: "Path",     render: (r) => `<span class="font-mono text-sm">${esc(r.path || "")}</span>` },
          { key: "status",      label: "Status",   render: (r) => statusBadgeHtml(r.status) },
          { key: "duration_ms", label: "Duration", render: (r) => `<span class="font-mono">${durationLabel(r.duration_ms)}</span>` },
          { key: "principal",   label: "Actor",    render: (r) => principalLabelHtml(r) + (r.principal_label !== r.principal ? `<div class="mt-1 break-all font-mono text-[10px] text-slate-500">${esc(r.principal || "")}</div>` : "") },
          { key: "tenant_id",   label: "Tenant" },
          { key: "client_ip",   label: "Client IP", render: (r) => r.client_ip ? `<span class="font-mono">${esc(r.client_ip)}</span>` : "" },
        ],
      }),
      emptyMessage: filtered.length === 0 && rows.length > 0
        ? "No matching audit events. Try widening the filters."
        : "No audit logs found for this tenant. Authenticated portal and agent activity show up here.",
    });

    // Wire chip handlers — re-render full view on each click.
    document.querySelectorAll("[data-status-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.statusClass = el.dataset.statusChip; render(); });
    });
    document.querySelectorAll("[data-method-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.methodFilter = el.dataset.methodChip; render(); });
    });
    const noiseToggle = $("#auditHideNoise");
    if (noiseToggle) noiseToggle.addEventListener("change", () => { state.hideNoise = noiseToggle.checked; render(); });
    const loadMoreBtn = $("#auditLoadMore");
    if (loadMoreBtn) loadMoreBtn.addEventListener("click", loadMore);
  }

  render();
}

async function viewIncidents() {
  $("#pageTitle").textContent = "Incidents";
  $("#pageSubtitle").textContent = "Tenant-scoped incidents";
  const incidents = await api("/api/customer/incidents?limit=250");
  $("#app").innerHTML = `<div id="incidentsList"></div>`;
  mountListView({
    container: $("#incidentsList"),
    rows: Array.isArray(incidents) ? incidents : [],
    filename: `incidents_${session.tenant_id || "tenant"}`,
    columns: [
      { key: "request_id",  label: "Request",  type: "text",
        value: (r) => r.request_id || "",
        render: (r) => `<span class="font-mono text-xs">${esc(r.request_id || "")}</span>` },
      { key: "event_type",  label: "Type",     type: "text",
        value: (r) => r.event_type || "" },
      { key: "decision",    label: "Decision", type: "enum",
        value: (r) => r.decision || "unknown",
        render: (r) => badge(r.decision || "unknown", r.decision === "block" ? "amber" : "cyan") },
      { key: "received_at", label: "Received", type: "date",
        value: (r) => r.received_at || "",
        render: (r) => `<span class="text-xs text-slate-400">${esc(fmt(r.received_at))}</span>` },
    ],
    onRowClick: (incident) => openReadOnlyModal({
      title: `Incident — ${incident.request_id || ""}`,
      record: incident,
      fields: [
        { key: "request_id", label: "Request ID" },
        { key: "event_type", label: "Type" },
        { key: "decision",   label: "Decision",  render: (r) => badge(r.decision || "unknown", r.decision === "block" ? "amber" : "cyan") },
        { key: "received_at",label: "Received",  render: (r) => esc(fmt(r.received_at)) },
        { key: "tenant_id",  label: "Tenant" },
        { key: "user_id",    label: "User" },
        { key: "agent_id",   label: "Agent" },
        { key: "source",     label: "Source" },
      ],
    }),
    emptyMessage: "No incidents found for this tenant.",
  });
}

async function viewProviders() {
  await tenantScopedConfigPage("providers", "AI Providers", "Tenant-scoped provider visibility", [
    { title: "Provider Inventory", body: "Monitor the providers visible to this tenant through the AI router.", badge: "live router data", tone: "green" },
    { title: "Approved Providers", body: "Persist tenant-specific provider approvals and routing preferences.", badge: "tenant config", tone: "cyan" },
    { title: "Credential Handling", body: "Keep provider credentials server-side and use this page for routing metadata only.", badge: "no browser secrets", tone: "amber" },
  ], { approved_providers: [], provider_routing: {}, credential_mode: "server_side" }, true);
}

async function viewAgents() {
  $("#pageTitle").textContent = "Agent Directory";
  $("#pageSubtitle").textContent = "Tenant AI agent identities and endpoint agents";
  await viewEndpoints();
  $("#pageTitle").textContent = "Agent Directory";
  $("#pageSubtitle").textContent = "Tenant AI agent identities and endpoint agents";
}

async function viewPolicyStudio() {
  $("#pageTitle").textContent = "Policy Studio";
  $("#pageSubtitle").textContent = "AI-aware tenant policy decisions and risk scoring";

  const DECISION_TYPES = ["ALLOW", "DENY", "ALLOW_WITH_REDACTION", "ALLOW_WITH_LIMITS", "REQUIRE_APPROVAL", "ALLOW_WITH_AUDIT_ONLY", "QUARANTINE"];
  const DECISION_COLORS = {
    ALLOW: "green",
    DENY: "red",
    ALLOW_WITH_REDACTION: "amber",
    ALLOW_WITH_LIMITS: "cyan",
    REQUIRE_APPROVAL: "cyan",
    ALLOW_WITH_AUDIT_ONLY: "slate",
    QUARANTINE: "red",
  };
  const legacyToDecision = (action) => ({ block: "DENY", warn: "ALLOW_WITH_AUDIT_ONLY", monitor: "ALLOW_WITH_AUDIT_ONLY", allow: "ALLOW" }[String(action || "").toLowerCase()] || "ALLOW");
  const policyToDecisionType = (policy) => {
    if (policy?.ai_decision_type) return policy.ai_decision_type;
    const action = String(policy?.action || "monitor").toLowerCase();
    if (action === "allow") {
      const tags = Array.isArray(policy?.tags) ? policy.tags.map((tag) => String(tag).toLowerCase()) : [];
      const desc = String(policy?.description || "").toLowerCase();
      if (tags.includes("redact") || tags.includes("redaction") || desc.includes("redact")) return "ALLOW_WITH_REDACTION";
    }
    return legacyToDecision(action);
  };
  const riskBar = (score) => {
    if (score === undefined || score === null) return "—";
    const pct = Math.round(Number(score) * 100);
    const tone = Number(score) > 0.7 ? "bg-rose-500" : Number(score) > 0.4 ? "bg-amber-500" : "bg-emerald-500";
    return `<div class="flex items-center gap-2"><div class="h-1.5 w-20 rounded-full bg-slate-800"><div class="${tone} h-1.5 rounded-full" style="width:${pct}%"></div></div><span class="text-xs">${esc(String(pct))}%</span></div>`;
  };

  try {
    const policies = await api("/api/customer/policies");
    const list = Array.isArray(policies) ? policies : [];
    const counts = {};
    DECISION_TYPES.forEach((type) => { counts[type] = 0; });
    list.forEach((policy) => {
      const type = policyToDecisionType(policy);
      counts[type] = (counts[type] || 0) + 1;
    });
    const rows = list.map((policy) => {
      const type = policyToDecisionType(policy);
      return `<tr class="border-t border-slate-800 hover:bg-slate-900/50">
        <td class="px-3 py-3 font-medium text-sm">${esc(policy.name || policy.id || "")}</td>
        <td class="px-3 py-3">${badge(type.replace(/_/g, " "), DECISION_COLORS[type] || "slate")}</td>
        <td class="px-3 py-3">${riskBar(policy.risk_score)}</td>
        <td class="px-3 py-3">${badge(String(policy.priority ?? 0), "slate")}</td>
        <td class="px-3 py-3">${(policy.ai_providers || []).map((provider) => badge(provider, "cyan")).join(" ") || badge("all", "slate")}</td>
        <td class="px-3 py-3">${policy.enabled !== false ? badge("enabled", "green") : badge("disabled", "slate")}</td>
        <td class="px-3 py-3"><button class="policyStudioTest rounded-xl border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs hover:bg-slate-800" data-policy="${esc(policy.name || policy.id || "")}">Test</button></td>
      </tr>`;
    }).join("");

    $("#app").innerHTML = `
      <div class="grid gap-3 md:grid-cols-4">
        ${["ALLOW", "DENY", "ALLOW_WITH_REDACTION", "REQUIRE_APPROVAL"].map((type) => metricCard(type.replace(/_/g, " "), counts[type] || 0, DECISION_COLORS[type] || "cyan")).join("")}
      </div>
      <div class="mt-5">${card(`
        <div class="mb-4 flex items-center justify-between">
          <div class="font-semibold">AI-aware tenant policies</div>
          <a href="#/policy-builder" class="rounded-2xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">+ New Policy</a>
        </div>
        <div class="overflow-x-auto rounded-2xl border border-slate-800">
          <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
              <tr>
                <th class="px-3 py-2">Name</th>
                <th class="px-3 py-2">Decision Type</th>
                <th class="px-3 py-2">Risk Score</th>
                <th class="px-3 py-2">Priority</th>
                <th class="px-3 py-2">AI Providers</th>
                <th class="px-3 py-2">Status</th>
                <th class="px-3 py-2">Test</th>
              </tr>
            </thead>
            <tbody>${rows || emptyRow("No tenant policies found.", 7)}</tbody>
          </table>
        </div>
      `)}</div>
      <div id="policyStudioPanel" class="mt-4"></div>
    `;
    document.querySelectorAll(".policyStudioTest").forEach((button) => {
      button.addEventListener("click", () => {
        const policyName = button.dataset.policy;
        const panel = $("#policyStudioPanel");
        panel.innerHTML = card(`
          <div class="font-semibold mb-4">Evaluate Policy: ${esc(policyName)}</div>
          <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div class="space-y-1">
              <label class="text-xs text-slate-300">Provider</label>
              <select id="policyStudioProvider" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm">
                <option>openai</option><option>anthropic</option><option>google</option><option>xai</option><option>perplexity</option>
              </select>
            </div>
            <div class="space-y-1">
              <label class="text-xs text-slate-300">Model</label>
              <input id="policyStudioModel" class="w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" value="gpt-4o" />
            </div>
            <div class="space-y-1 md:col-span-2">
              <label class="text-xs text-slate-300">Test Prompt</label>
              <textarea id="policyStudioPrompt" class="min-h-28 w-full rounded-2xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm" placeholder="Enter a prompt to evaluate against this tenant policy..."></textarea>
            </div>
          </div>
          <div class="mt-4 flex gap-2">
            <button id="policyStudioRun" class="rounded-2xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" type="button">Evaluate</button>
          </div>
          <div id="policyStudioResult" class="mt-4"></div>
        `);
        $("#policyStudioRun").addEventListener("click", async () => {
          try {
            const result = await api("/api/customer/policies/evaluate", {
              method: "POST",
              body: JSON.stringify({
                policy_name: policyName,
                context: {
                  provider: $("#policyStudioProvider").value,
                  model: $("#policyStudioModel").value,
                  prompt: $("#policyStudioPrompt").value,
                },
              }),
            });
            $("#policyStudioResult").innerHTML = `<div class="rounded-2xl border ${result.allowed !== false ? "border-emerald-900 bg-emerald-950/20" : "border-rose-900 bg-rose-950/20"} p-4">
              <div class="font-semibold mb-2">${result.allowed !== false ? "Allowed" : "Denied"}</div>
              <pre class="overflow-x-auto text-xs">${esc(JSON.stringify(result, null, 2))}</pre>
            </div>`;
          } catch (error) {
            $("#policyStudioResult").innerHTML = `<div class="text-sm text-rose-300">${esc(error.message)}</div>`;
          }
        });
      });
    });
  } catch (error) {
    $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
  }
}

async function viewGraph() {
  await tenantScopedConfigPage("graph", "Action Graph", "Visualize tenant agent-to-model action chains", [
    { title: "Agent Nodes", body: "Show tenant agents, delegated identities, and model interactions once audit graph events are present.", badge: "tenant graph", tone: "cyan" },
    { title: "Edges", body: "Trace requests, tool calls, provider hops, and policy decisions across the tenant boundary.", badge: "audit linked", tone: "green" },
    { title: "Gaps", body: "Use missing edges to spot SDK or onboarding gaps for this tenant.", badge: "needs telemetry", tone: "amber" },
  ], { include_events: ["audit", "telemetry", "policy_decision"], max_depth: 5 });
}

async function viewRisk() {
  await tenantScopedConfigPage("risk", "AI Risk Dashboard", "Tenant AI risk scores, threats, and recommendations", [
    { title: "Risk Signals", body: "Aggregate incidents, DLP findings, shadow AI, provider posture, and delegation risk for this tenant.", badge: "tenant rollup", tone: "cyan" },
    { title: "Recommendations", body: "Prioritize policy, onboarding, and provider hardening work for tenant admins.", badge: "actionable", tone: "green" },
    { title: "Trend View", body: "Track changes in tenant AI risk as telemetry and audit events accumulate.", badge: "time series ready", tone: "slate" },
  ], { weights: { incidents: 30, dlp: 25, shadow_ai: 20, provider_posture: 15, delegations: 10 }, recommendation_mode: "guided" });
}

async function viewDelegations() {
  await tenantScopedConfigPage("delegations", "Delegation Manager", "Create and manage tenant agent delegation chains", [
    { title: "Delegation Chains", body: "Review agent-to-agent or service-to-agent delegation chains for this tenant.", badge: "tenant admin", tone: "green" },
    { title: "Scopes", body: "Restrict delegation by provider, action, role, and expiration window.", badge: "least privilege", tone: "cyan" },
    { title: "Revocation", body: "Disable tenant delegation chains without affecting other tenants.", badge: "isolated", tone: "amber" },
  ], { chains: [], default_ttl_minutes: 60, require_approval: true }, true);
}

// --- Onboarding helpers ---

// Reusable "copy to clipboard" wrapper for any snippet. Renders the text in
// a mono pre with a corner button; bindCopyButtons() wires the click.
function copyableSnippet(content, { language = "", maxHeight = "max-h-48" } = {}) {
  const escaped = esc(content);
  const stamped = String(content).replace(/"/g, "&quot;");
  return `<div class="relative">
    <pre class="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 px-3 py-2.5 pr-16 text-xs text-cyan-200 ${maxHeight}">${escaped}</pre>
    ${language ? `<span class="absolute bottom-2 left-3 text-[10px] uppercase tracking-wider text-slate-600">${esc(language)}</span>` : ""}
    <button type="button" class="copySnippetBtn absolute top-2 right-2 rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-300 hover:bg-slate-800" data-copy="${stamped}">Copy</button>
  </div>`;
}

function bindCopyButtons(root = document) {
  root.querySelectorAll(".copySnippetBtn").forEach((btn) => {
    if (btn.dataset.bound === "1") return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", async () => {
      const text = btn.dataset.copy || "";
      try {
        await navigator.clipboard.writeText(text);
        const original = btn.textContent;
        btn.textContent = "Copied";
        btn.classList.add("text-emerald-200");
        setTimeout(() => { btn.textContent = original; btn.classList.remove("text-emerald-200"); }, 1200);
      } catch {
        // Fallback: select + execCommand is deprecated; just no-op on permission denial.
        btn.textContent = "Copy failed";
        setTimeout(() => { btn.textContent = "Copy"; }, 1500);
      }
    });
  });
}

function tenantSignalCard(overview) {
  const recent = (overview.recent_events || [])[0];
  const lastTs = recent && (recent.occurred_at || recent.created_at);
  let minutesAgo = null;
  if (lastTs) {
    const t = Date.parse(lastTs);
    if (!Number.isNaN(t)) minutesAgo = Math.max(0, (Date.now() - t) / 60000);
  }
  const series = overview.telemetry_series_24h || [];
  const lastHour = series.length ? series[series.length - 1] : 0;
  const total24h = series.reduce((a, b) => a + b, 0);

  let label, dot, summary;
  if (minutesAgo == null) {
    label = "Awaiting first event";
    dot = "bg-slate-500";
    summary = "Install a browser extension or endpoint agent below and trigger a monitored event — this card lights up the moment your tenant's first telemetry arrives.";
  } else if (minutesAgo < 5) {
    label = "Reporting now";
    dot = "bg-emerald-400";
    summary = `Last event ${relativeSince(minutesAgo)} · ${lastHour} in the last hour · ${total24h} in the last 24h.`;
  } else if (minutesAgo < 60) {
    label = "Recently active";
    dot = "bg-amber-300";
    summary = `Last event ${relativeSince(minutesAgo)} · ${lastHour} in the last hour · ${total24h} in the last 24h.`;
  } else {
    label = "Quiet";
    dot = "bg-slate-500";
    summary = `Last event ${relativeSince(minutesAgo)} · no events in the last hour · ${total24h} in the last 24h. If you expected activity, check the endpoint/extension logs.`;
  }
  return card(`
    <div class="flex flex-wrap items-center gap-4">
      <span class="inline-flex h-3 w-3 rounded-full ${dot} ring-2 ring-slate-900"></span>
      <div class="flex-1">
        <div class="text-base font-semibold">Tenant signal — ${esc(label)}</div>
        <div class="mt-1 text-sm text-slate-400">${esc(summary)}</div>
      </div>
      <a href="#/telemetry" class="rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Open Telemetry →</a>
    </div>
  `);
}

function tenantContextStrip(settings) {
  const tenant = settings.tenant || {};
  const user = settings.user || {};
  return card(`
    <div class="flex flex-wrap items-baseline gap-x-6 gap-y-2 text-sm">
      <div class="flex items-baseline gap-2">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">Tenant</span>
        <span class="font-semibold">${esc(tenant.name || "")}</span>
      </div>
      <div class="flex items-baseline gap-2">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">ID</span>
        <span class="font-mono text-xs text-cyan-100">${esc(tenant.id || "")}</span>
      </div>
      <div class="flex items-baseline gap-2">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">Control plane</span>
        <span class="font-mono text-xs text-slate-300">${esc(location.origin)}</span>
      </div>
      <div class="flex items-baseline gap-2">
        <span class="text-[10px] uppercase tracking-wider text-slate-500">Signed in as</span>
        <span>${esc(user.email || "")} ${badge(user.role || "user", user.role === "tenant_admin" ? "green" : "cyan")}</span>
      </div>
    </div>
  `);
}

function recommendedQuickstartCard(catalog) {
  // The browser extension is the fastest path from "blank tenant" to "first
  // event in dashboard". Surface it as the recommended starter so prospects
  // don't have to choose between five packages on their first visit.
  const ext = (Array.isArray(catalog) ? catalog : []).find((p) =>
    ["extension", "browser_extension"].includes(p.category)
  );
  if (!ext) return "";
  const adminCta = session.role === "tenant_admin"
    ? `<button class="customerBootstrapBtn rounded-xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" data-package-key="${esc(ext.package_key)}" data-package-title="${esc(ext.title)}" type="button">Issue Bootstrap Token</button>`
    : `<span class="text-xs text-slate-500">A tenant admin can issue the bootstrap token here.</span>`;
  return card(`
    <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <div class="inline-flex items-center gap-2 rounded-full bg-cyan-500/15 px-2 py-0.5 text-[10px] uppercase tracking-wider text-cyan-200">Recommended starter · ~3 min</div>
        <div class="mt-2 text-lg font-semibold">Browser extension (${esc(ext.title)})</div>
        <p class="mt-1 max-w-2xl text-sm text-slate-400">Fastest path from a blank tenant to a live event. No daemon install, no system permissions — just load the unpacked extension in Chrome, paste the bootstrap token, and you'll see your first event in Telemetry within seconds.</p>
      </div>
      <a class="shrink-0 rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" href="${esc(ext.download_url)}">Download ZIP →</a>
    </div>
    <ol class="mt-5 grid gap-3 text-sm md:grid-cols-2">
      <li class="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
        <div class="text-[10px] uppercase tracking-wider text-slate-500">Step 1 · Issue token</div>
        <p class="mt-1 text-slate-300">Click below to mint a one-time bootstrap token scoped to this tenant. Tokens are shown once and expire in 30 minutes.</p>
        <div class="mt-3">${adminCta}</div>
      </li>
      <li class="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
        <div class="text-[10px] uppercase tracking-wider text-slate-500">Step 2 · Load extension</div>
        <p class="mt-1 text-slate-300">Unzip the bundle, then in Chrome go to <span class="font-mono text-xs text-cyan-200">chrome://extensions</span>, toggle <em>Developer mode</em>, click <em>Load unpacked</em>, and select the unzipped folder.</p>
      </li>
      <li class="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
        <div class="text-[10px] uppercase tracking-wider text-slate-500">Step 3 · Paste token + URL</div>
        <p class="mt-1 text-slate-300">Open the extension's <em>Options</em> page. Set Control Plane URL and paste the bootstrap token; click Save. The extension redeems the token for an install-scoped API key automatically.</p>
        <div class="mt-3">${copyableSnippet(location.origin)}</div>
      </li>
      <li class="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
        <div class="text-[10px] uppercase tracking-wider text-slate-500">Step 4 · Trigger an event</div>
        <p class="mt-1 text-slate-300">Visit any site and the extension reports a <span class="font-mono text-cyan-200">page_visit</span> event. The Tenant Signal card above will light up green within 30 seconds.</p>
        <a class="mt-3 inline-block text-xs text-cyan-200 hover:text-cyan-100" href="#/telemetry">Watch the Telemetry view →</a>
      </li>
    </ol>
    <div id="customerBootstrapResult" class="mt-4"></div>
  `);
}

async function viewOnboarding() {
  const [overview, settings, catalog] = await Promise.all([
    api("/api/customer/overview").catch(() => ({})),
    api("/api/customer/settings").catch(() => ({})),
    api("/api/customer/downloads/catalog").catch(() => []),
  ]);
  const readiness = readinessFromOverview(overview);
  const sdkPackages = (Array.isArray(catalog) ? catalog : []).filter((pkg) =>
    ["sdk", "rasp"].includes(pkg.category)
  );

  // Keep the existing tenantScopedConfigPage render at the bottom so the
  // onboarding settings form (checklist + sdk_languages config) doesn't
  // disappear — we just insert richer content before and after it.
  const snippets = [
    { title: "Node.js",    body: "npm install @cyberarmor/sdk; configure with the tenant API key created from the API Keys tab.", badge: "npm",        tone: "green" },
    { title: "Python",     body: "pip install cyberarmor-sdk; set CYBERARMOR_API_KEY and CYBERARMOR_TENANT_ID env vars.",          badge: "pip",        tone: "cyan"  },
    { title: "Go / Java / .NET", body: "Server SDKs use the same tenant-scoped credentials; verify by inspecting Audit Logs.", badge: "server SDKs", tone: "slate" },
    { title: "RASP",       body: "Embed the RASP shim in the application process; policies match by host and path.",              badge: "in-process", tone: "violet" },
    { title: "Verification", body: "After install, generate one event from each integration and confirm both Telemetry and Audit show the row.", badge: "QA",     tone: "green" },
    { title: "SSO",        body: "Configure OIDC under Settings before inviting tenant users at scale.",                          badge: "tenant admin", tone: "cyan" },
  ];
  await tenantScopedConfigPage("onboarding", "SDK & Onboarding", "Quickstart, live tenant signal, and per-language install snippets", snippets, {
    checklist: ["create_api_key", "configure_sdk", "send_test_event", "verify_policy_decision", "confirm_audit_log"],
    sdk_languages: ["nodejs", "python", "go", "java", "dotnet"],
  });
  const app = $("#app");
  if (!app) return;

  // Prepend the dynamic, tenant-aware sections.
  app.insertAdjacentHTML("afterbegin", `
    ${tenantContextStrip(settings)}
    <div class="mt-4"></div>
    ${tenantSignalCard(overview)}
    <div class="mt-4"></div>
    ${recommendedQuickstartCard(catalog)}
    <div class="mt-4"></div>
    ${card(`
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div class="text-lg font-semibold">Guided Onboarding</div>
          <p class="mt-2 max-w-2xl text-sm text-slate-400">Follow this path to get from a blank tenant to a demo-ready, evidence-producing pilot environment.</p>
        </div>
        <div class="min-w-48">${badge(`${readiness.score}% ready`, readinessTone(readiness.score))}</div>
      </div>
      <div class="mt-4">${progressBar(readiness.score, readinessTone(readiness.score))}</div>
      <div class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        ${readiness.checks.map((item, index) => `
          <a href="${item.href}" class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 hover:bg-slate-900">
            <div class="flex items-center justify-between gap-2">
              <div class="text-xs uppercase tracking-[0.18em] text-slate-500">Step ${index + 1}</div>
              ${item.complete ? badge("done", "green") : badge("next", "amber")}
            </div>
            <div class="mt-3 text-sm font-semibold">${esc(item.label)}</div>
          </a>
        `).join("")}
      </div>
    `)}
    <div class="mt-4"></div>
  `);

  // Append the SDK/RASP/Add-in catalog at the bottom (unchanged grid).
  app.insertAdjacentHTML("beforeend", `
    <div class="mt-4"></div>
    ${card(`
      <div class="text-lg font-semibold">SDK, RASP, and Add-in Packages</div>
      <p class="mt-2 text-sm text-slate-400">Download the package, issue a one-time bootstrap token, then redeem it into an install-scoped credential during setup instead of embedding a shared secret.</p>
      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        ${sdkPackages.map((pkg) => `
          <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
            <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(pkg.category)}</div>
            <div class="mt-2 text-base font-semibold">${esc(pkg.title)}</div>
            <p class="mt-2 text-sm text-slate-400">${esc(pkg.description || "")}</p>
            ${browserCoverageNote(pkg)}
            ${pkg.install_hint ? `<div class="mt-3">${copyableSnippet(pkg.install_hint, { maxHeight: "max-h-24" })}</div>` : ""}
            <div class="mt-4 flex flex-wrap gap-2">
              <a class="rounded-xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" href="${esc(pkg.download_url)}">Download ZIP</a>
              ${session.role === "tenant_admin"
                ? `<button class="customerBootstrapBtn rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" data-package-key="${esc(pkg.package_key)}" data-package-title="${esc(pkg.title)}" type="button">Issue Bootstrap Token</button>`
                : ""}
              <button class="customerBootstrapHelpBtn rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800" data-tenant-id="${esc(session.tenant_id || "")}" type="button" title="Bootstrap Setup: download, issue a one-time token, and redeem it into an install-scoped credential during setup.">Bootstrap Setup</button>
            </div>
          </div>
        `).join("") || `<div class="text-sm text-slate-500">Package catalog unavailable.</div>`}
      </div>
    `)}
  `);
  bindCustomerBootstrapButtons();
  bindCustomerBootstrapHelpButtons();
  bindCopyButtons(app);
}

async function viewUsers() {
  $("#pageTitle").textContent = "Users";
  $("#pageSubtitle").textContent = "Manage users for your tenant";
  if (session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  const users = await api("/api/customer/users");
  const rows = users.map((user) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3">${esc(user.email)}</td>
      <td class="px-3 py-3">${badge(user.role, user.role === "tenant_admin" ? "green" : "cyan")}</td>
      <td class="px-3 py-3">${badge(user.status, user.status === "active" ? "green" : "amber")}</td>
      <td class="px-3 py-3 text-xs text-slate-400">${esc(user.last_login_at || "never")}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`
    <div class="flex flex-col gap-4 lg:flex-row lg:items-start">
      <form id="addUserForm" class="min-w-80 rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        <div class="font-semibold">Add tenant user</div>
        <p class="mt-1 text-xs text-slate-400">New users are automatically associated with tenant <span class="font-mono text-cyan-100">${esc(session.tenant_id)}</span>.</p>
        <input id="newUserEmail" class="mt-4 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" type="email" placeholder="user@company.com" required />
        <select id="newUserRole" class="mt-3 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400">
          <option value="tenant_viewer">Viewer</option>
          <option value="tenant_analyst">Analyst</option>
          <option value="tenant_admin">Tenant admin</option>
        </select>
        <button class="mt-3 w-full rounded-2xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 hover:bg-cyan-400" type="submit">Add user</button>
        <div id="userFormMessage" class="mt-3 text-sm text-slate-400"></div>
      </form>
      <div class="min-w-0 flex-1 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
            <tr><th class="px-3 py-2">Email</th><th class="px-3 py-2">Role</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Last login</th></tr>
          </thead>
          <tbody>${rows || `<tr><td class="px-3 py-8 text-slate-400" colspan="4">No tenant users yet.</td></tr>`}</tbody>
        </table>
      </div>
    </div>
  `);
  $("#addUserForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#userFormMessage").textContent = "Adding user...";
    try {
      await api("/api/customer/users", {
        method: "POST",
        body: JSON.stringify({
          email: $("#newUserEmail").value,
          role: $("#newUserRole").value,
          status: "active",
        }),
      });
      await viewUsers();
    } catch (error) {
      $("#userFormMessage").textContent = error.message;
      $("#userFormMessage").className = "mt-3 text-sm text-rose-300";
    }
  });
}

async function viewSettings() {
  $("#pageTitle").textContent = "Customer Settings";
  $("#pageSubtitle").textContent = "Tenant identity and portal configuration";
  const settings = await api("/api/customer/settings");
  const sso = session.role === "tenant_admin"
    ? await api("/api/customer/sso").catch((error) => ({ error: error.message }))
    : null;
  $("#app").innerHTML = card(`
    <div class="grid gap-4 md:grid-cols-2">
      <div class="rounded-2xl border border-slate-800 bg-slate-900/50 p-4">
        <div class="text-sm text-slate-400">Tenant ID</div>
        <div class="mt-2 font-mono text-cyan-100">${esc(settings.tenant.id)}</div>
        <p class="mt-3 text-xs text-slate-500">Tenant ID is assigned by CyberArmor platform admins and cannot be changed from the customer portal.</p>
      </div>
      <div class="rounded-2xl border border-slate-800 bg-slate-900/50 p-4">
        <div class="text-sm text-slate-400">Tenant Name</div>
        <div class="mt-2 text-lg font-semibold">${esc(settings.tenant.name)}</div>
        <p class="mt-3 text-xs text-slate-500">Editable customer settings can be added here without exposing cross-tenant controls.</p>
      </div>
      <div class="rounded-2xl border border-slate-800 bg-slate-900/50 p-4 md:col-span-2">
        <div class="flex items-center justify-between gap-3">
          <div>
            <div class="text-sm text-slate-400">Single Sign-On</div>
            <div class="mt-2 text-lg font-semibold">${sso && !sso.error ? esc(sso.provider_name || "OIDC") : "Not configured"}</div>
          </div>
          ${sso && !sso.error && sso.enabled ? badge("enabled", "green") : badge("not enabled", "amber")}
        </div>
        <p class="mt-3 text-xs text-slate-500">
          ${session.role === "tenant_admin"
            ? "Generic OIDC SSO is available beside email-code login. Configuration is stored tenant-scoped on the server; secret values are never returned by this API."
            : "Tenant admins can configure SSO for this tenant."}
        </p>
        ${sso && !sso.error ? `<div class="mt-3 text-xs text-slate-400">Issuer: <span class="font-mono text-slate-200">${esc(sso.issuer)}</span></div>` : ""}
        ${session.role === "tenant_admin" ? `
          <form id="ssoConfigForm" class="mt-5 grid gap-3 md:grid-cols-2">
            <label class="text-sm text-slate-300">Provider name
              <input id="ssoProvider" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" value="${esc((sso && !sso.error && sso.provider_name) || "oidc")}" />
            </label>
            <label class="text-sm text-slate-300">Scopes
              <input id="ssoScopes" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" value="${esc((sso && !sso.error && sso.scopes) || "openid email profile")}" />
            </label>
            <label class="text-sm text-slate-300 md:col-span-2">Issuer
              <input id="ssoIssuer" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="https://login.example.com/oauth2/default" value="${esc((sso && !sso.error && sso.issuer) || "")}" required />
            </label>
            <label class="text-sm text-slate-300">Client ID
              <input id="ssoClientId" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" value="${esc((sso && !sso.error && sso.client_id) || "")}" required />
            </label>
            <label class="text-sm text-slate-300">Client secret
              <input id="ssoClientSecret" type="password" autocomplete="new-password" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="${sso && !sso.error ? "Leave blank to keep existing secret" : "Required for first save"}" ${sso && !sso.error ? "" : "required"} />
            </label>
            <label class="text-sm text-slate-300 md:col-span-2">Authorization endpoint
              <input id="ssoAuthorizationEndpoint" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="https://login.example.com/oauth2/v1/authorize" value="${esc((sso && !sso.error && sso.authorization_endpoint) || "")}" required />
            </label>
            <label class="text-sm text-slate-300 md:col-span-2">Token endpoint
              <input id="ssoTokenEndpoint" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="https://login.example.com/oauth2/v1/token" value="${esc((sso && !sso.error && sso.token_endpoint) || "")}" required />
            </label>
            <label class="text-sm text-slate-300 md:col-span-2">JWKS URI
              <input id="ssoJwksUri" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="https://login.example.com/oauth2/v1/keys" value="${esc((sso && !sso.error && sso.jwks_uri) || "")}" required />
            </label>
            <label class="text-sm text-slate-300 md:col-span-2">Redirect URI override
              <input id="ssoRedirectUri" class="mt-1 w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-cyan-400" placeholder="Default: ${esc(location.origin)}/auth/sso/callback" value="${esc((sso && !sso.error && sso.redirect_uri) || "")}" />
            </label>
            <label class="flex items-center gap-3 text-sm text-slate-300">
              <input id="ssoEnabled" type="checkbox" class="h-4 w-4 rounded border-slate-700 bg-slate-950" ${sso && !sso.error && sso.enabled ? "checked" : ""} />
              Enable SSO for this tenant
            </label>
            <div class="md:col-span-2 flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-950/70 p-4 text-xs text-slate-400">
              <div>Configure your IdP redirect/callback URL as <span class="font-mono text-cyan-100">${esc(location.origin)}/auth/sso/callback</span> unless you set an override above.</div>
              <div>The client secret is write-only. CyberArmor stores it server-side and never returns it to this page.</div>
            </div>
            <button class="rounded-2xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 hover:bg-cyan-400" type="submit">Save SSO configuration</button>
            <div id="ssoFormMessage" class="self-center text-sm text-slate-400"></div>
          </form>
        ` : ""}
      </div>
    </div>
  `);
  if ($("#ssoConfigForm")) {
    $("#ssoConfigForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      $("#ssoFormMessage").className = "self-center text-sm text-slate-400";
      $("#ssoFormMessage").textContent = "Saving SSO configuration...";
      const body = {
        provider_name: $("#ssoProvider").value.trim() || "oidc",
        issuer: $("#ssoIssuer").value.trim(),
        client_id: $("#ssoClientId").value.trim(),
        authorization_endpoint: $("#ssoAuthorizationEndpoint").value.trim(),
        token_endpoint: $("#ssoTokenEndpoint").value.trim(),
        jwks_uri: $("#ssoJwksUri").value.trim(),
        redirect_uri: $("#ssoRedirectUri").value.trim() || null,
        scopes: $("#ssoScopes").value.trim() || "openid email profile",
        enabled: $("#ssoEnabled").checked,
      };
      const clientSecret = $("#ssoClientSecret").value;
      if (clientSecret) body.client_secret = clientSecret;
      try {
        await api("/api/customer/sso", { method: "PUT", body: JSON.stringify(body) });
        $("#ssoFormMessage").className = "self-center text-sm text-emerald-300";
        $("#ssoFormMessage").textContent = "SSO configuration saved.";
        $("#ssoClientSecret").value = "";
        await viewSettings();
      } catch (error) {
        $("#ssoFormMessage").className = "self-center text-sm text-rose-300";
        $("#ssoFormMessage").textContent = error.message;
      }
    });
  }
}

async function route() {
  const routeName = (location.hash || "#/overview").replace("#/", "");
  setActiveNav(routeName);
  try {
    if (routeName === "policies") return await viewPolicies();
    if (routeName === "policy-builder") return await viewPolicyBuilder();
    if (routeName === "artifacts") return await viewArtifacts();
    if (routeName === "api-keys") return await viewApiKeys();
    if (routeName === "proxy") return await viewProxy();
    if (routeName === "scan") return await viewScan();
    if (routeName === "endpoints") return await viewEndpoints();
    if (routeName === "shadow-ai") return await viewShadowAi();
    if (routeName === "compliance") return await viewCompliance();
    if (routeName === "siem") return await viewSiem();
    if (routeName === "identity") return await viewIdentity();
    if (routeName === "dlp") return await viewDlp();
    if (routeName === "reports") return await viewReports();
    if (routeName === "agents") return await viewAgents();
    if (routeName === "telemetry") return await viewTelemetry();
    if (routeName === "incidents") return await viewIncidents();
    if (routeName === "providers") return await viewProviders();
    if (routeName === "policy-studio") return await viewPolicyStudio();
    if (routeName === "graph") return await viewGraph();
    if (routeName === "risk") return await viewRisk();
    if (routeName === "delegations") return await viewDelegations();
    if (routeName === "onboarding") return await viewOnboarding();
    if (routeName === "audit") return await viewAudit();
    if (routeName === "users") return await viewUsers();
    if (routeName === "settings") return await viewSettings();
    return await viewOverview();
  } catch (error) {
    $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
  }
}

async function logout() {
  await api("/auth/logout", { method: "POST" }).catch(() => {});
  window.location.replace("/login.html");
}

// Mobile sidebar wiring — slide-in drawer on small screens, hidden on md+.
function setupMobileSidebar() {
  const sidebar = $("#sidebar");
  const backdrop = $("#sidebarBackdrop");
  const openBtn = $("#sidebarOpen");
  const closeBtn = $("#sidebarClose");
  if (!sidebar || !backdrop || !openBtn) return;

  function open() {
    sidebar.classList.remove("hidden");
    sidebar.classList.add("flex");
    backdrop.classList.remove("hidden");
    openBtn.setAttribute("aria-expanded", "true");
    document.body.style.overflow = "hidden";
  }
  function close() {
    // Only collapse on mobile widths — md+ keeps the sidebar persistent
    if (window.matchMedia("(min-width: 768px)").matches) return;
    sidebar.classList.add("hidden");
    sidebar.classList.remove("flex");
    backdrop.classList.add("hidden");
    openBtn.setAttribute("aria-expanded", "false");
    document.body.style.overflow = "";
  }

  openBtn.addEventListener("click", open);
  if (closeBtn) closeBtn.addEventListener("click", close);
  backdrop.addEventListener("click", close);

  // Close when a nav link is clicked (mobile UX — they navigated, dismiss the drawer)
  $("#nav").addEventListener("click", (event) => {
    if (event.target.closest("[data-nav]")) close();
  });

  // ESC closes
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !backdrop.classList.contains("hidden")) close();
  });

  // If the viewport grows past md, reset state so the sidebar shows as a fixed column
  window.addEventListener("resize", () => {
    if (window.matchMedia("(min-width: 768px)").matches) {
      backdrop.classList.add("hidden");
      sidebar.classList.remove("hidden");
      sidebar.classList.add("flex");
      document.body.style.overflow = "";
    }
  });
}

async function init() {
  renderNav();
  setupMobileSidebar();
  $("#logout").addEventListener("click", logout);
  await hydrateSession();
  window.addEventListener("hashchange", route);
  await route();
}

init().catch(() => {
  window.location.replace("/login.html");
});
