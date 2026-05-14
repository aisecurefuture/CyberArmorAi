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
  { id: "upload-discovery", label: "Upload Discovery", hash: "#/upload-discovery" },
  { id: "bom", label: "Bill of Materials", hash: "#/bom" },
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

// Lightweight pager for inline tables that don't go through mountListView.
// Caller owns state ({page, pageSize}) and re-renders on change.
//
//   const pager = simplePager({ total: 1234, state: tableState });
//   tbody.innerHTML = visible.map(rowHtml).join("");
//   container.insertAdjacentHTML("beforeend", pager.html);
//   pager.wire(rootEl, () => render());
const SIMPLE_PAGER_SIZES = [25, 50, 100, 250, "all"];

function simplePager({ total, state, idPrefix = "pg" }) {
  if (!state.pageSize) state.pageSize = 50;
  if (!state.page) state.page = 1;
  const pages = state.pageSize === "all" ? 1 : Math.max(1, Math.ceil(total / state.pageSize));
  if (state.page > pages) state.page = pages;

  const sliced = (rows) => {
    if (state.pageSize === "all") return rows;
    const start = (state.page - 1) * state.pageSize;
    return rows.slice(start, start + state.pageSize);
  };

  const first = total === 0 ? 0 : (state.pageSize === "all" ? 1 : (state.page - 1) * state.pageSize + 1);
  const last = state.pageSize === "all" ? total : Math.min(total, state.page * state.pageSize);
  const prevDisabled = state.page <= 1;
  const nextDisabled = state.page >= pages;

  const html = `
    <div class="flex flex-wrap items-center justify-between gap-3 px-1 py-2 text-xs text-slate-400">
      <div>
        Rows <span class="font-mono text-slate-200">${first}–${last}</span> of
        <span class="font-mono text-slate-200">${total}</span>
      </div>
      <div class="flex items-center gap-2">
        <label class="text-slate-500">Rows per page
          <select data-pager-act="size" data-pager-id="${idPrefix}" class="ml-1 rounded-lg border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-slate-200">
            ${SIMPLE_PAGER_SIZES.map((opt) =>
              `<option value="${opt}"${opt === state.pageSize ? " selected" : ""}>${opt === "all" ? "All" : opt}</option>`
            ).join("")}
          </select>
        </label>
        <button type="button" data-pager-act="first" data-pager-id="${idPrefix}" class="rounded-lg border border-slate-800 px-2 py-1 ${prevDisabled ? "opacity-40 pointer-events-none" : "hover:bg-slate-900"}">«</button>
        <button type="button" data-pager-act="prev"  data-pager-id="${idPrefix}" class="rounded-lg border border-slate-800 px-2 py-1 ${prevDisabled ? "opacity-40 pointer-events-none" : "hover:bg-slate-900"}">‹ Prev</button>
        <span class="px-1 text-slate-500">Page <span class="font-mono text-slate-200">${state.page}</span> of <span class="font-mono text-slate-200">${pages}</span></span>
        <button type="button" data-pager-act="next"  data-pager-id="${idPrefix}" class="rounded-lg border border-slate-800 px-2 py-1 ${nextDisabled ? "opacity-40 pointer-events-none" : "hover:bg-slate-900"}">Next ›</button>
        <button type="button" data-pager-act="last"  data-pager-id="${idPrefix}" class="rounded-lg border border-slate-800 px-2 py-1 ${nextDisabled ? "opacity-40 pointer-events-none" : "hover:bg-slate-900"}">»</button>
      </div>
    </div>
  `;

  function wire(rootEl, rerender) {
    rootEl.querySelectorAll(`[data-pager-id="${idPrefix}"]`).forEach((el) => {
      const act = el.dataset.pagerAct;
      if (act === "size") {
        el.addEventListener("change", () => {
          const v = el.value;
          state.pageSize = v === "all" ? "all" : Number(v);
          state.page = 1;
          rerender();
        });
      } else {
        el.addEventListener("click", () => {
          if (act === "first") state.page = 1;
          else if (act === "last") state.page = pages;
          else if (act === "prev") state.page = Math.max(1, state.page - 1);
          else if (act === "next") state.page = Math.min(pages, state.page + 1);
          rerender();
        });
      }
    });
  }

  return { html, wire, sliced, pages };
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
  if (a === "block")        return "bg-rose-500/20 text-rose-200";
  // block_upload renders in the same rose family as block, with slightly
  // less saturation so the two read as related but distinct at a glance.
  if (a === "block_upload") return "bg-rose-500/15 text-rose-100";
  if (a === "redact")       return "bg-amber-500/20 text-amber-200";
  if (a === "warn")         return "bg-amber-500/15 text-amber-200";
  if (a === "detect")       return "bg-blue-500/20 text-blue-200";
  if (a === "allow")        return "bg-emerald-500/20 text-emerald-200";
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

function missionControlHtml(settings, overview, abomStats) {
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
    <div class="grid gap-3 md:grid-cols-3 lg:grid-cols-6 xl:grid-cols-7">
      ${metricCard("Policies", overview.policy_count ?? "0", "cyan", "active and archived")}
      ${metricCard("Endpoints", overview.agent_count ?? "0", "green", "registered or telemetry-only")}
      ${metricCard("Telemetry", overview.telemetry_count ?? "0", "cyan", "tenant events")}
      ${metricCard("Incidents", overview.incident_count ?? "0", "amber", "evidence candidates")}
      ${metricCard("AI Providers", overview.provider_count ?? "0", "green", "router visible")}
      ${metricCard("Audit Events", overview.audit_count ?? "0", "slate", "reviewable records")}
      ${(() => {
        // BOM tile shows the rolled-up component count with a 24h delta
        // when the stats endpoint returns something. Falls back to "—"
        // when no collector has reported yet so the tile doesn't blink
        // in and out during demos.
        if (!abomStats || typeof abomStats.total !== "number") {
          return metricCard("BOM", "—", "slate", "no collectors reported yet");
        }
        const added = abomStats.added_24h || 0;
        const detail = added > 0
          ? `${added} added in last 24h`
          : `${abomStats.stale_7d || 0} stale >7d`;
        const tone = added > 0 ? "cyan" : (abomStats.stale_7d > 0 ? "amber" : "green");
        return `<a href="#/bom" class="block">${metricCard("BOM", abomStats.total, tone, detail)}</a>`;
      })()}
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
  const [settings, overview, abomStats] = await Promise.all([
    api("/api/customer/settings"),
    api("/api/customer/overview"),
    // A-BOM stats are optional — Mission Control should still render
    // before any collectors have reported, so swallow fetch failures.
    api("/api/customer/abom/stats").catch(() => null),
  ]);
  $("#app").innerHTML = missionControlHtml(settings, overview, abomStats);
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
    const msg = $("#apiKeyMessage");
    msg.className = "mt-3 text-sm text-slate-400";
    msg.textContent = "Creating key...";
    try {
      const created = await api("/api/customer/api-keys", {
        method: "POST",
        body: JSON.stringify({ role: $("#apiKeyRole").value }),
      });
      // Show the new key in a copy-able block — this is the only chance the
      // user gets to grab the unmasked value. We deliberately don't refresh
      // the list until they explicitly dismiss this banner.
      msg.className = "mt-3 space-y-2";
      msg.innerHTML = `
        <div class="rounded-2xl border border-emerald-900 bg-emerald-950/30 p-3">
          <div class="text-xs font-semibold text-emerald-200">New key — copy it now</div>
          <p class="mt-1 text-[11px] text-emerald-100/70">This is shown once. The list below will only ever show a masked version.</p>
          <div class="mt-2">${copyableSnippet(created.key || "", { maxHeight: "max-h-20" })}</div>
          <button id="apiKeyDismiss" type="button" class="mt-2 rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800">I've copied it — refresh list</button>
        </div>
      `;
      bindCopyButtons(msg);
      $("#apiKeyDismiss").addEventListener("click", () => viewApiKeys());
    } catch (error) {
      msg.className = "mt-3 text-sm text-rose-300";
      msg.textContent = error.message;
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
  $("#pageTitle").textContent = "Scan Tools";
  $("#pageSubtitle").textContent = "Run on-demand detection against arbitrary text for this tenant";

  function resultPanel(result, error) {
    if (error) {
      return `<div class="mt-3 rounded-xl border border-rose-900 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">${esc(error)}</div>`;
    }
    if (!result) return "";
    // Pull out a short summary from common detection-service response shapes
    // so the operator doesn't have to read raw JSON for the obvious answer.
    const flags = [];
    if (result.injection_detected || result.is_injection)             flags.push(`<span class="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-rose-200">prompt injection</span>`);
    if (Array.isArray(result.findings) && result.findings.length)     flags.push(`<span class="rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-amber-200">${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}</span>`);
    if (Array.isArray(result.pii_classes) && result.pii_classes.length) flags.push(...result.pii_classes.map((c) => `<span class="rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-amber-200">${esc(c)}</span>`));
    if (result.toxicity_score != null && result.toxicity_score > 0.5) flags.push(`<span class="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-rose-200">toxic ${(result.toxicity_score * 100).toFixed(0)}%</span>`);
    if (result.safe === true || (!flags.length && result.detected === false)) {
      flags.push(`<span class="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-emerald-200">clean</span>`);
    }
    const flagsHtml = flags.length ? `<div class="mt-3 flex flex-wrap gap-2">${flags.join("")}</div>` : "";
    return `
      ${flagsHtml}
      <details class="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <summary class="cursor-pointer text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Raw JSON</summary>
        <pre class="mt-2 max-h-64 overflow-auto text-xs text-slate-300">${esc(JSON.stringify(result, null, 2))}</pre>
      </details>`;
  }

  $("#app").innerHTML = `
    <div class="grid gap-4 lg:grid-cols-2">
      ${card(`
        <div class="font-semibold">Prompt Injection Scan</div>
        <p class="mt-1 text-xs text-slate-500">Test if a prompt contains jailbreak / ignore-instructions / system-prompt-leak patterns.</p>
        <textarea id="scanPrompt" rows="4" class="mt-3 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="Paste a prompt to inspect…"></textarea>
        <div class="mt-3 flex items-center gap-2">
          <button id="runPromptScan" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Scan</button>
          <span id="runPromptStatus" class="text-xs text-slate-500"></span>
        </div>
        <div id="promptResult"></div>
      `)}
      ${card(`
        <div class="font-semibold">Sensitive Data Scan</div>
        <p class="mt-1 text-xs text-slate-500">Detect PII and secrets (SSN, credit card, email, IBAN, API keys, etc.). Formatted SSNs like <span class="font-mono">123-45-6789</span> are detected directly; bare 9-digit values are only flagged when context suggests it.</p>
        <textarea id="scanData" rows="4" class="mt-3 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="Paste content to classify…"></textarea>
        <div class="mt-3 flex items-center gap-2">
          <button id="runDataScan" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Scan</button>
          <span id="runDataStatus" class="text-xs text-slate-500"></span>
        </div>
        <div id="dataResult"></div>
      `)}
      ${card(`
        <div class="font-semibold">Output Safety Scan</div>
        <p class="mt-1 text-xs text-slate-500">Check AI output for toxicity, unsafe content, or policy violations.</p>
        <textarea id="scanOutput" rows="4" class="mt-3 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="Paste AI response text…"></textarea>
        <div class="mt-3 flex items-center gap-2">
          <button id="runOutputScan" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Scan</button>
          <span id="runOutputStatus" class="text-xs text-slate-500"></span>
        </div>
        <div id="outputResult"></div>
      `)}
      ${card(`
        <div class="font-semibold">Full Pipeline Scan</div>
        <p class="mt-1 text-xs text-slate-500">Run all detectors at once — prompt injection, sensitive data, and output safety.</p>
        <textarea id="scanFull" rows="4" class="mt-3 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="Paste text for the full detection pipeline…"></textarea>
        <div class="mt-3 flex items-center gap-2">
          <button id="runFullScan" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Scan All</button>
          <span id="runFullStatus" class="text-xs text-slate-500"></span>
        </div>
        <div id="fullResult"></div>
      `)}
    </div>
  `;

  async function runScan(buttonId, statusId, inputId, resultId, endpoint) {
    const text = $(inputId).value.trim();
    if (!text) { $(statusId).textContent = "Enter text to scan."; return; }
    const btn = $(buttonId);
    btn.disabled = true;
    $(statusId).textContent = "Scanning…";
    $(resultId).innerHTML = "";
    try {
      const r = await api(`/api/customer${endpoint}`, {
        method: "POST",
        body: JSON.stringify({ text }),
      });
      $(statusId).textContent = "";
      $(resultId).innerHTML = resultPanel(r, null);
    } catch (err) {
      $(statusId).textContent = "";
      $(resultId).innerHTML = resultPanel(null, err.message);
    } finally {
      btn.disabled = false;
    }
  }

  $("#runPromptScan").addEventListener("click", () => runScan("#runPromptScan", "#runPromptStatus", "#scanPrompt", "#promptResult", "/scan/prompt-injection"));
  $("#runDataScan").addEventListener("click",   () => runScan("#runDataScan",   "#runDataStatus",   "#scanData",   "#dataResult",   "/scan/sensitive-data"));
  $("#runOutputScan").addEventListener("click", () => runScan("#runOutputScan", "#runOutputStatus", "#scanOutput", "#outputResult", "/scan/output-safety"));
  $("#runFullScan").addEventListener("click",   () => runScan("#runFullScan",   "#runFullStatus",   "#scanFull",   "#fullResult",   "/scan/all"));
}

// --- Policy helpers ---

function policyActionBadge(action) {
  const a = String(action || "monitor").toLowerCase();
  // Reuse the Mission Control / Telemetry pill colors so the same action
  // looks the same everywhere a customer sees it.
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${actionPillClasses(a)}">${esc(a)}</span>`;
}

async function viewPolicies() {
  $("#pageTitle").textContent = "Policies";
  $("#pageSubtitle").textContent = "Tenant-scoped policy rules — click any row to inspect or edit";
  const policies = await api("/api/customer/policies");
  const rows = Array.isArray(policies) ? policies : [];
  const canEdit = session.role === "tenant_admin";

  // Aggregate counts for the top summary strip.
  const enabled = rows.filter((p) => p.enabled !== false).length;
  const disabled = rows.length - enabled;
  const actionCounts = {};
  for (const p of rows) {
    const a = String(p.action || "monitor").toLowerCase();
    actionCounts[a] = (actionCounts[a] || 0) + 1;
  }
  const actionOrder = ["block", "block_upload", "redact", "warn", "monitor", "allow", "sandbox", "isolate", "audit-only", "route"]
    .filter((a) => actionCounts[a]);

  $("#app").innerHTML = `
    <div class="space-y-4">
      ${card(`
        <div class="flex flex-wrap items-center gap-4">
          <div class="flex flex-col leading-tight">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Policies</span>
            <span class="text-2xl font-semibold tabular-nums text-slate-100">${rows.length}</span>
          </div>
          <div class="mx-2 h-10 w-px bg-slate-800"></div>
          <div class="flex flex-col rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2 leading-tight">
            <span class="text-[10px] uppercase tracking-wider text-emerald-300">Enabled</span>
            <span class="font-mono text-sm tabular-nums text-emerald-200">${enabled}</span>
          </div>
          ${disabled ? `
            <div class="flex flex-col rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2 leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-400">Disabled</span>
              <span class="font-mono text-sm tabular-nums text-slate-200">${disabled}</span>
            </div>` : ""}
          <div class="mx-2 h-10 w-px bg-slate-800"></div>
          <div class="flex flex-wrap items-center gap-2">
            ${actionOrder.map((a) => `
              <span class="inline-flex items-center gap-2 rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs">
                ${policyActionBadge(a)}
                <span class="font-mono tabular-nums text-slate-300">${actionCounts[a]}</span>
              </span>`).join("")}
          </div>
          ${canEdit ? `<a href="#/policy-builder" class="ml-auto rounded-2xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">+ New policy</a>` : ""}
        </div>
      `)}
      <div id="policiesList"></div>
    </div>
  `;

  mountListView({
    container: $("#policiesList"),
    rows,
    filename: `policies_${session.tenant_id || "tenant"}`,
    columns: [
      { key: "name",        label: "Name",        type: "text",
        value: (r) => r.name || r.id || "",
        render: (r) => `<span class="font-medium text-slate-100">${esc(r.name || r.id || "")}</span>` },
      { key: "description", label: "Description", type: "text",
        value: (r) => r.description || "",
        render: (r) => r.description ? `<span class="text-xs text-slate-400">${esc(r.description)}</span>` : `<span class="text-slate-700">—</span>` },
      { key: "action",      label: "Action",      type: "enum",
        enumValues: ["allow","warn","redact","sandbox","block","isolate","route","audit-only","monitor"],
        value: (r) => r.action || "monitor",
        render: (r) => policyActionBadge(r.action) },
      { key: "priority",    label: "Priority",    type: "number",
        value: (r) => r.priority ?? 100,
        render: (r) => `<span class="font-mono text-xs tabular-nums text-slate-300">${r.priority ?? 100}</span>` },
      { key: "status",      label: "Status",      type: "enum",
        enumValues: ["enabled","disabled"],
        value: (r) => r.enabled === false ? "disabled" : "enabled",
        render: (r) => badge(r.enabled === false ? "disabled" : "enabled", r.enabled === false ? "slate" : "green") },
      { key: "updated_at",  label: "Updated",     type: "date",
        value: (r) => r.updated_at || r.created_at || "",
        render: (r) => `<span class="text-xs text-slate-400 tabular-nums" title="${esc(fmt(r.updated_at || r.created_at))}">${esc(relativeFromIso(r.updated_at || r.created_at))}</span>` },
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
    emptyMessage: "No policies found for this tenant. Use the Policy Builder to author your first rule.",
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

// --- Compliance helpers ---

// Categorisation matches the admin dashboard so visual parity holds. Falls
// back to "Framework" when the upstream framework id isn't recognised.
const COMPLIANCE_CATEGORY = {
  "nist-csf":      "Federal",
  "nist-800-53":   "Federal",
  "nist-ai-rmf":   "AI",
  "cmmc-l3":       "Defense",
  "pci-dss":       "Financial",
  "soc2":          "Trust",
  "gdpr":          "Privacy",
  "ccpa":          "Privacy",
  "iso27001":      "International",
  "cis-controls":  "Best Practice",
  "csa-ccm":       "Cloud",
  "owasp":         "AppSec",
  "sans-top25":    "Vulnerability",
  "nydfs":         "Financial",
};

function compliancePctBar(pct, tone) {
  const t = tone || (pct >= 80 ? "emerald" : pct >= 50 ? "amber" : "rose");
  const fill = t === "emerald" ? "bg-emerald-500" : t === "amber" ? "bg-amber-400" : t === "rose" ? "bg-rose-500" : "bg-indigo-500";
  return `<div class="flex items-center gap-2">
    <div class="flex-1 h-2 rounded-full bg-slate-800"><div class="${fill} h-2 rounded-full" style="width:${pct}%"></div></div>
    <span class="text-xs font-mono w-10 text-right tabular-nums text-slate-300">${pct.toFixed(0)}%</span>
  </div>`;
}

async function viewCompliance() {
  $("#pageTitle").textContent = "Compliance";
  $("#pageSubtitle").textContent = "Tenant-scoped framework assessments — run on demand, evidence merged from telemetry and audit";
  const isAdmin = session.role === "tenant_admin";

  // Tracks the latest assessment per framework id in this view's lifecycle.
  // Each entry is the result dict returned by the compliance service:
  // { framework_id, framework_name, controls_assessed, controls_passed,
  //   pass_rate, results: [...controls...], ... }.
  const lastAssessment = {};
  let frameworks = [];
  let loadError = null;
  // Window for evidence aggregation on the backend. "all" → no since/until,
  // backend treats applied policies as current state and aggregates telemetry
  // / audit / incidents over the full lifetime of the tenant.
  const COMPLIANCE_WINDOWS = [
    { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
    { id: "7d",  label: "Last 7d",  ms: 7  * 24 * 60 * 60 * 1000 },
    { id: "30d", label: "Last 30d", ms: 30 * 24 * 60 * 60 * 1000 },
    { id: "all", label: "All time", ms: null },
  ];
  let windowId = "7d";

  function currentWindowBody() {
    const w = COMPLIANCE_WINDOWS.find((x) => x.id === windowId);
    if (!w || w.ms == null) return {};
    const until = new Date();
    const since = new Date(until.getTime() - w.ms);
    return { since: since.toISOString(), until: until.toISOString() };
  }

  try {
    const resp = await api("/api/customer/compliance/frameworks");
    frameworks = Array.isArray(resp) ? resp : (resp && resp.frameworks) || [];
  } catch (err) {
    loadError = err.message || "compliance fetch failed";
  }

  // Backfill catalog from COMPLIANCE_CATEGORY if the upstream returned an
  // empty list (e.g. service degraded) so the demo still renders the grid.
  if (frameworks.length === 0 && !loadError) {
    frameworks = Object.keys(COMPLIANCE_CATEGORY).map((id) => ({
      id, name: id.toUpperCase(), category: COMPLIANCE_CATEGORY[id],
    }));
  }

  function frameworkCard(f) {
    const id = f.id;
    const name = f.name || id;
    const category = f.category || COMPLIANCE_CATEGORY[id] || "Framework";
    const result = lastAssessment[id];
    const pct = result ? (result.pass_rate != null ? result.pass_rate * 100 : (result.controls_passed / Math.max(result.controls_assessed, 1)) * 100) : null;
    const summary = result
      ? `${result.controls_passed || 0}/${result.controls_assessed || 0} controls passed`
      : "Not assessed yet";
    return `
      <div class="rounded-2xl border border-slate-800 bg-slate-950 p-4">
        <div class="flex items-baseline justify-between gap-2">
          <div class="font-semibold text-sm">${esc(name)}</div>
          ${badge(category, "cyan")}
        </div>
        <div class="mt-3">${pct == null
          ? `<div class="flex items-center gap-2"><div class="flex-1 h-2 rounded-full bg-slate-800"></div><span class="text-xs font-mono w-10 text-right text-slate-500">—%</span></div>`
          : compliancePctBar(pct)}</div>
        <div class="mt-2 text-[11px] text-slate-500">${esc(summary)}</div>
        <div class="mt-3 flex flex-wrap gap-2">
          ${isAdmin
            ? `<button class="runAssessmentBtn rounded-xl bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400" data-fw-id="${esc(id)}" data-fw-name="${esc(name)}" type="button">Run assessment</button>`
            : ""}
          ${result
            ? `<button class="viewAssessmentBtn rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800" data-fw-id="${esc(id)}" data-fw-name="${esc(name)}" type="button">View details</button>`
            : ""}
        </div>
      </div>`;
  }

  function render() {
    const totalAssessed = Object.keys(lastAssessment).length;
    const avgPct = totalAssessed
      ? Object.values(lastAssessment).reduce((s, r) => s + (r.pass_rate != null ? r.pass_rate * 100 : (r.controls_passed / Math.max(r.controls_assessed, 1)) * 100), 0) / totalAssessed
      : 0;

    $("#app").innerHTML = `
      <div class="space-y-4">
        ${loadError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load frameworks: ${esc(loadError)}.</div>` : ""}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Frameworks</span>
              <span class="text-2xl font-semibold tabular-nums">${frameworks.length}</span>
            </div>
            <div class="mx-2 h-10 w-px bg-slate-800"></div>
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Assessed this session</span>
              <span class="text-2xl font-semibold tabular-nums">${totalAssessed}</span>
            </div>
            <div class="mx-2 h-10 w-px bg-slate-800"></div>
            <div class="min-w-48 flex-1">
              <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Average pass rate</div>
              ${totalAssessed > 0 ? compliancePctBar(avgPct) : `<div class="text-xs text-slate-500">No assessments yet</div>`}
            </div>
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Evidence window</span>
              <div class="mt-1 flex flex-wrap gap-1" id="complianceWindowPicker">
                ${COMPLIANCE_WINDOWS.map((w) => `
                  <button type="button" data-window-id="${w.id}" class="rounded-full px-2 py-1 text-[11px] ${windowId === w.id ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(w.label)}</button>
                `).join("")}
              </div>
            </div>
            ${isAdmin ? `<button id="assessAllBtn" type="button" class="rounded-2xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Run all</button>` : `<span class="text-xs text-slate-500">View only — admins can run assessments.</span>`}
          </div>
        `)}
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">${frameworks.map(frameworkCard).join("")}</div>
        <div id="compliancePanel"></div>
      </div>
    `;

    document.querySelectorAll(".runAssessmentBtn").forEach((btn) => {
      btn.addEventListener("click", () => runAssessment(btn.dataset.fwId, btn.dataset.fwName));
    });
    document.querySelectorAll(".viewAssessmentBtn").forEach((btn) => {
      btn.addEventListener("click", () => showAssessmentDetails(btn.dataset.fwId, btn.dataset.fwName));
    });
    const allBtn = $("#assessAllBtn");
    if (allBtn) allBtn.addEventListener("click", runAll);
    document.querySelectorAll("#complianceWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", () => {
        windowId = btn.dataset.windowId;
        // Stale prior assessments — they were run against a different window.
        for (const k of Object.keys(lastAssessment)) delete lastAssessment[k];
        $("#compliancePanel").innerHTML = "";
        render();
      });
    });
  }

  async function runAssessment(fwId, fwName) {
    const panel = $("#compliancePanel");
    panel.innerHTML = card(`<div class="text-sm text-slate-400">Running ${esc(fwName)} assessment…</div>`);
    try {
      const result = await api("/api/customer/compliance/assess", {
        method: "POST",
        body: JSON.stringify({ framework: fwId, ...currentWindowBody() }),
      });
      lastAssessment[fwId] = result;
      panel.innerHTML = "";
      render();
      showAssessmentDetails(fwId, fwName);
    } catch (err) {
      panel.innerHTML = card(`<div class="text-sm text-rose-300">${esc(err.message)}</div>`);
    }
  }

  async function runAll() {
    const panel = $("#compliancePanel");
    panel.innerHTML = card(`<div class="text-sm text-slate-400">Running all assessments…</div>`);
    let succeeded = 0, failed = 0;
    for (const f of frameworks) {
      try {
        const result = await api("/api/customer/compliance/assess", {
          method: "POST",
          body: JSON.stringify({ framework: f.id, ...currentWindowBody() }),
        });
        lastAssessment[f.id] = result;
        succeeded++;
      } catch {
        failed++;
      }
    }
    panel.innerHTML = card(`
      <div class="text-sm">Assessed ${succeeded}/${frameworks.length} frameworks.
        ${failed > 0 ? `<span class="text-rose-300">${failed} failed.</span>` : ""}</div>
    `);
    render();
  }

  function showAssessmentDetails(fwId, fwName) {
    const result = lastAssessment[fwId];
    if (!result) return;
    const controls = Array.isArray(result.results) ? result.results : [];
    const passed = controls.filter((c) => c.passed === true);
    const failed = controls.filter((c) => c.passed === false);
    const pct = result.pass_rate != null ? result.pass_rate * 100 : (result.controls_passed / Math.max(result.controls_assessed, 1)) * 100;

    const controlRow = (c) => {
      const sev = String(c.severity || "").toLowerCase();
      const sevBadge = sev ? severityBadgeHtml(sev) : "";
      const status = c.passed === true
        ? `<span class="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-200">pass</span>`
        : c.passed === false
        ? `<span class="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase text-rose-200">fail</span>`
        : `<span class="rounded-full bg-slate-700/40 px-2 py-0.5 text-[10px] uppercase text-slate-300">n/a</span>`;
      const reason = c.reason || c.detail || "";
      return `<tr class="border-t border-slate-800">
        <td class="px-3 py-2 font-mono text-xs">${esc(c.id || c.control_id || "")}</td>
        <td class="px-3 py-2">${esc(c.name || c.title || "")}</td>
        <td class="px-3 py-2">${status}</td>
        <td class="px-3 py-2">${sevBadge}</td>
        <td class="px-3 py-2 text-xs text-slate-400">${esc(reason)}</td>
      </tr>`;
    };

    const panel = $("#compliancePanel");
    const win = result.window || {};
    const winLabel = win.since
      ? `${esc(String(win.since))} → ${esc(String(win.until || "now"))}`
      : "All time";
    const evidence = result.evidence_used && typeof result.evidence_used === "object" ? result.evidence_used : {};
    const evidenceKeys = Object.keys(evidence).sort();
    const evidenceChip = (k) => {
      const v = evidence[k];
      const truthy = v && (typeof v !== "number" || v > 0);
      const cls = truthy ? "bg-emerald-500/15 text-emerald-200" : "bg-slate-700/40 text-slate-400";
      const display = typeof v === "boolean" ? (v ? "true" : "false") : (typeof v === "number" ? String(v) : (v ? "set" : "unset"));
      return `<span class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] ${cls}"><span class="font-mono">${esc(k)}</span><span class="text-slate-400">=</span><span>${esc(display)}</span></span>`;
    };
    panel.innerHTML = card(`
      <div class="flex items-baseline justify-between gap-2">
        <div>
          <div class="text-lg font-semibold">${esc(fwName)} — Assessment results</div>
          <div class="mt-1 text-xs text-slate-500">${esc(result.timestamp || "")} · Window: ${winLabel}</div>
        </div>
        <button id="closeAssessment" type="button" class="text-xs text-slate-400 hover:text-slate-200">Close</button>
      </div>
      <div class="mt-3 grid grid-cols-2 gap-2 md:grid-cols-4">
        ${riskMetricCard("Pass rate", `${pct.toFixed(0)}%`, pct >= 80 ? "emerald" : pct >= 50 ? "amber" : "rose")}
        ${riskMetricCard("Total controls", controls.length, "slate")}
        ${riskMetricCard("Passing", passed.length, "emerald")}
        ${riskMetricCard("Failing", failed.length, failed.length > 0 ? "rose" : "emerald")}
      </div>
      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-[10px] uppercase tracking-wider text-slate-500">
            <tr><th class="px-3 py-2">Control</th><th class="px-3 py-2">Name</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Severity</th><th class="px-3 py-2">Reason</th></tr>
          </thead>
          <tbody>${controls.length === 0 ? `<tr><td colspan="5" class="px-3 py-6 text-center text-sm text-slate-500">No control results returned</td></tr>` : controls.map(controlRow).join("")}</tbody>
        </table>
      </div>
      ${evidenceKeys.length > 0 ? `
        <div class="mt-4">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Evidence used (derived from tenant state in window)</div>
          <div class="flex flex-wrap gap-1">${evidenceKeys.map(evidenceChip).join("")}</div>
        </div>
      ` : ""}
    `);
    $("#closeAssessment").addEventListener("click", () => { panel.innerHTML = ""; });
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  render();
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

// Catalog of detection patterns the detection-service ships with. Used for
// the Detection Patterns card so customers see what we can find on their
// behalf and whether any active policy actually references each class.
// Keep aligned with shared/policy-builder.js _BUILTIN_REDACT_CATALOG.
const DLP_PATTERN_CATALOG = [
  { id: "pii.ssn",                label: "SSN",                  group: "PII" },
  { id: "pii.ein",                label: "EIN",                  group: "PII" },
  { id: "pii.credit_card",        label: "Credit Card",          group: "PII" },
  { id: "pii.email",              label: "Email",                group: "PII" },
  { id: "pii.phone",              label: "Phone",                group: "PII" },
  { id: "pii.iban",               label: "IBAN",                 group: "PII" },
  { id: "pii.drivers_license",    label: "Driver's License",     group: "PII" },
  { id: "pii.passport",           label: "Passport",             group: "PII" },
  { id: "pii.bank_routing",       label: "ABA Routing",          group: "PII" },
  { id: "pii.date_of_birth",      label: "Date of Birth",        group: "PII" },
  { id: "pii.person_name",        label: "Person Name (NER)",    group: "PII" },
  { id: "pii.location",           label: "Location (NER)",       group: "PII" },
  { id: "pii.organization",       label: "Organization (NER)",   group: "PII" },
  { id: "pii.ip_address",         label: "IP Address",           group: "PII" },
  { id: "pii.url",                label: "URL",                  group: "PII" },
  { id: "pii.crypto_address",     label: "Crypto Address",       group: "PII" },
  { id: "secret.aws_access_key",  label: "AWS Access Key",       group: "Secrets" },
  { id: "secret.gcp_api_key",     label: "GCP API Key",          group: "Secrets" },
  { id: "secret.github_token",    label: "GitHub Token",         group: "Secrets" },
  { id: "secret.openai_key",      label: "OpenAI Key",           group: "Secrets" },
  { id: "secret.anthropic_key",   label: "Anthropic Key",        group: "Secrets" },
  { id: "secret.slack_token",     label: "Slack Token",          group: "Secrets" },
  { id: "secret.stripe_key",      label: "Stripe Key",           group: "Secrets" },
  { id: "secret.api_key",         label: "Generic API Key",      group: "Secrets" },
  { id: "secret.password",        label: "Password",             group: "Secrets" },
  { id: "secret.private_key",     label: "Private Key",          group: "Secrets" },
  { id: "secret.jwt",             label: "JWT",                  group: "Secrets" },
];

const DLP_DEFAULT_LABELS = [
  { label: "PUBLIC",        color: "emerald", desc: "No restrictions"                            },
  { label: "INTERNAL",      color: "slate",   desc: "Internal use only"                          },
  { label: "CONFIDENTIAL",  color: "amber",   desc: "Business sensitive"                         },
  { label: "RESTRICTED",    color: "rose",    desc: "Highly sensitive (PII, PHI, PCI, secrets)"  },
];

function dlpLabelPill(label, color, extra = "") {
  const tone = {
    emerald: "bg-emerald-500/20 text-emerald-200",
    slate:   "bg-slate-700/40  text-slate-200",
    amber:   "bg-amber-500/20  text-amber-200",
    rose:    "bg-rose-500/20   text-rose-200",
    cyan:    "bg-cyan-500/15   text-cyan-200",
  }[color] || "bg-slate-700/40 text-slate-200";
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${tone} ${extra}">${esc(label)}</span>`;
}

async function viewDlp() {
  $("#pageTitle").textContent = "DLP & Data Class.";
  $("#pageSubtitle").textContent = "Tenant data classification labels, custom rules, detection patterns, and live scan";
  const canEdit = session.role === "tenant_admin";

  let policies = [];
  let dlpConfig = {};
  let loadError = null;
  try {
    const [polRes, cfgRes] = await Promise.allSettled([
      api("/api/customer/policies"),
      api("/api/customer/config/dlp"),
    ]);
    if (polRes.status === "fulfilled") {
      policies = Array.isArray(polRes.value) ? polRes.value : [];
    }
    if (cfgRes.status === "fulfilled") {
      dlpConfig = (cfgRes.value && cfgRes.value.config) || {};
    }
  } catch (err) {
    loadError = err.message || "DLP fetch failed";
  }

  // Compute which detection classes are referenced by at least one active
  // (enabled, non-archived) tenant policy. We surface this on the patterns
  // card so the customer can tell at a glance which detections are wired up
  // to enforcement vs. just available in the catalog.
  const activeRedactClasses = new Set();
  for (const p of policies) {
    if (p.enabled === false) continue;
    if (p.archived === true) continue;
    const classes = Array.isArray(p.redact_classes) ? p.redact_classes : [];
    for (const c of classes) activeRedactClasses.add(String(c));
  }

  // Tenant-defined custom classification rules:
  //   dlpConfig.rules = [ { pattern: "...", label: "RESTRICTED" }, ... ]
  // We treat dlpConfig as the canonical store and merge a sane default
  // shape on first load.
  if (!Array.isArray(dlpConfig.rules)) dlpConfig.rules = [];
  if (!Array.isArray(dlpConfig.labels)) dlpConfig.labels = [];

  function labelsCard() {
    const customLabels = (dlpConfig.labels || []).filter((l) => l && l.label);
    return card(`
      <div class="font-semibold">Data Classification Labels</div>
      <p class="mt-1 text-xs text-slate-500">Default sensitivity levels for tenant <span class="font-mono text-cyan-100">${esc(session.tenant_id)}</span>. Custom labels (if any) layer on top.</p>
      <div class="mt-3 space-y-2">
        ${DLP_DEFAULT_LABELS.map((l) => `
          <div class="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
            <div class="flex items-center gap-2">${dlpLabelPill(l.label, l.color)}<span class="text-xs text-slate-400">${esc(l.desc)}</span></div>
          </div>
        `).join("")}
        ${customLabels.length === 0 ? "" : `
          <div class="pt-2 text-[10px] uppercase tracking-wider text-slate-500">Custom</div>
          ${customLabels.map((l) => `
            <div class="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
              <div class="flex items-center gap-2">${dlpLabelPill(String(l.label), l.color || "cyan")}<span class="text-xs text-slate-400">${esc(l.desc || "")}</span></div>
            </div>
          `).join("")}
        `}
      </div>
    `);
  }

  function rulesCard() {
    const rows = dlpConfig.rules || [];
    return card(`
      <div class="font-semibold">Custom Classification Rules</div>
      <p class="mt-1 text-xs text-slate-500">Override auto-classification for specific regex patterns or path globs. Rules are applied first-match-wins, top to bottom.</p>
      ${canEdit ? `
        <div class="mt-3 flex flex-wrap gap-2">
          <input id="dlpRulePattern" type="text" class="flex-1 min-w-[200px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm font-mono" placeholder="Pattern (regex or path glob)" />
          <select id="dlpRuleLabel" class="rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm">
            ${DLP_DEFAULT_LABELS.map((l) => `<option value="${esc(l.label)}"${l.label === "CONFIDENTIAL" ? " selected" : ""}>${esc(l.label)}</option>`).join("")}
          </select>
          <button id="dlpAddRule" type="button" class="rounded-xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Add</button>
        </div>
        <div id="dlpRuleMessage" class="mt-2 text-xs text-slate-500"></div>
      ` : `<div class="mt-3 text-xs text-slate-500">View only — tenant admins can manage rules.</div>`}
      <div class="mt-3 space-y-1">
        ${rows.length === 0
          ? `<div class="rounded-xl border border-dashed border-slate-800 px-3 py-4 text-center text-xs text-slate-500">No custom rules yet.</div>`
          : rows.map((r, idx) => `
            <div class="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-2">
              <div class="flex items-center gap-2 min-w-0">
                <span class="font-mono text-xs text-slate-200 truncate">${esc(r.pattern || "")}</span>
                <span class="text-slate-600">→</span>
                ${dlpLabelPill(String(r.label || "INTERNAL"), (DLP_DEFAULT_LABELS.find((d) => d.label === String(r.label).toUpperCase()) || {}).color || "cyan")}
              </div>
              ${canEdit ? `<button data-rule-idx="${idx}" class="dlpRemoveRule text-xs text-rose-300 hover:text-rose-200" type="button">Remove</button>` : ""}
            </div>
          `).join("")}
      </div>
    `);
  }

  function patternsCard() {
    const groups = ["PII", "Secrets"];
    return card(`
      <div class="flex items-baseline justify-between">
        <div class="font-semibold">DLP Detection Patterns</div>
        <div class="text-[10px] uppercase tracking-wider text-slate-500">${activeRedactClasses.size} of ${DLP_PATTERN_CATALOG.length} active in policy</div>
      </div>
      <p class="mt-1 text-xs text-slate-500">Catalog of structured detectors. <span class="text-emerald-300">Enforced</span> = referenced by an enabled tenant redact policy; <span class="text-slate-400">Available</span> = supported by the detector but not yet wired to enforcement.</p>
      ${groups.map((g) => `
        <div class="mt-3">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-1">${esc(g)}</div>
          <div class="space-y-1">
            ${DLP_PATTERN_CATALOG.filter((p) => p.group === g).map((p) => {
              const enforced = activeRedactClasses.has(p.id);
              return `<div class="flex items-center justify-between rounded-xl bg-slate-900 px-3 py-1.5">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="text-sm text-slate-200">${esc(p.label)}</span>
                  <span class="font-mono text-[10px] text-slate-500 truncate">${esc(p.id)}</span>
                </div>
                ${enforced
                  ? `<span class="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-200">enforced</span>`
                  : `<span class="rounded-full bg-slate-700/40 px-2 py-0.5 text-[10px] uppercase text-slate-300">available</span>`}
              </div>`;
            }).join("")}
          </div>
        </div>
      `).join("")}
    `);
  }

  function scanCard() {
    return card(`
      <div class="font-semibold">Scan &amp; Classify Content</div>
      <p class="mt-1 text-xs text-slate-500">Paste content to classify against tenant rules and DLP detection patterns. Calls <span class="font-mono">/api/customer/scan/sensitive-data</span>.</p>
      <textarea id="dlpScanInput" rows="4" class="mt-3 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="Paste content to classify..."></textarea>
      <div class="mt-3 flex items-center gap-2">
        <button id="dlpScanRun" type="button" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Classify</button>
        <span id="dlpScanStatus" class="text-xs text-slate-500"></span>
      </div>
      <div id="dlpScanResult" class="mt-3"></div>
    `);
  }

  function classifyResult(text, scanResult) {
    // Decide a single label for the snippet: any custom rule pattern match
    // wins first (in order), otherwise we derive from detection findings:
    // any secret / SSN / credit card / passport / DL → RESTRICTED,
    // any other PII → CONFIDENTIAL, otherwise INTERNAL. Empty input is PUBLIC.
    if (!text) return { label: "PUBLIC", reason: "no content" };
    for (const rule of dlpConfig.rules || []) {
      if (!rule || !rule.pattern) continue;
      let matched = false;
      try {
        const re = new RegExp(rule.pattern);
        matched = re.test(text);
      } catch {
        // Treat invalid regex as a substring match for resilience.
        matched = text.includes(rule.pattern);
      }
      if (matched) {
        return { label: String(rule.label || "CONFIDENTIAL").toUpperCase(), reason: `Custom rule matched: ${rule.pattern}` };
      }
    }
    const findings = Array.isArray(scanResult && scanResult.findings) ? scanResult.findings : [];
    if (findings.length === 0) return { label: "INTERNAL", reason: "No sensitive patterns detected" };
    const restrictedClasses = new Set(["ssn","ein","credit_card","passport","drivers_license","bank_routing","private_key","aws_access_key","gcp_api_key","github_token","openai_key","anthropic_key","slack_token","stripe_key","api_key","password","jwt"]);
    const hasRestricted = findings.some((f) => {
      const t = String(f.type || f.class || f.name || "").toLowerCase();
      return [...restrictedClasses].some((c) => t.includes(c));
    });
    if (hasRestricted) return { label: "RESTRICTED", reason: `${findings.length} sensitive finding${findings.length === 1 ? "" : "s"} (includes regulated data)` };
    return { label: "CONFIDENTIAL", reason: `${findings.length} PII finding${findings.length === 1 ? "" : "s"}` };
  }

  function render() {
    $("#app").innerHTML = `
      <div class="space-y-4">
        ${loadError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load DLP state: ${esc(loadError)}.</div>` : ""}
        <div class="grid gap-4 lg:grid-cols-2">
          ${labelsCard()}
          ${rulesCard()}
          ${patternsCard()}
          ${scanCard()}
        </div>
      </div>
    `;

    if (canEdit) {
      const addBtn = $("#dlpAddRule");
      if (addBtn) addBtn.addEventListener("click", addRule);
      document.querySelectorAll(".dlpRemoveRule").forEach((btn) => {
        btn.addEventListener("click", () => removeRule(Number(btn.dataset.ruleIdx)));
      });
    }
    const scanBtn = $("#dlpScanRun");
    if (scanBtn) scanBtn.addEventListener("click", runScan);
  }

  async function persistConfig() {
    await api("/api/customer/config/dlp", {
      method: "PUT",
      body: JSON.stringify({ config: dlpConfig }),
    });
  }

  async function addRule() {
    const pattern = ($("#dlpRulePattern").value || "").trim();
    const label = $("#dlpRuleLabel").value || "CONFIDENTIAL";
    const msg = $("#dlpRuleMessage");
    if (!pattern) { msg.textContent = "Enter a pattern."; msg.className = "mt-2 text-xs text-rose-300"; return; }
    dlpConfig.rules.push({ pattern, label });
    msg.textContent = "Saving...";
    msg.className = "mt-2 text-xs text-slate-400";
    try {
      await persistConfig();
      render();
    } catch (err) {
      dlpConfig.rules.pop();
      msg.textContent = err.message;
      msg.className = "mt-2 text-xs text-rose-300";
    }
  }

  async function removeRule(idx) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= dlpConfig.rules.length) return;
    const removed = dlpConfig.rules.splice(idx, 1)[0];
    try {
      await persistConfig();
      render();
    } catch (err) {
      dlpConfig.rules.splice(idx, 0, removed);
      render();
      alert(`Could not save: ${err.message}`);
    }
  }

  async function runScan() {
    const text = ($("#dlpScanInput").value || "").trim();
    const status = $("#dlpScanStatus");
    const out = $("#dlpScanResult");
    if (!text) { status.textContent = "Enter content to classify."; return; }
    status.textContent = "Scanning...";
    out.innerHTML = "";
    try {
      const result = await api("/api/customer/scan/sensitive-data", {
        method: "POST",
        body: JSON.stringify({ text }),
      });
      status.textContent = "";
      const cls = classifyResult(text, result);
      const color = (DLP_DEFAULT_LABELS.find((l) => l.label === cls.label) || { color: "slate" }).color;
      const findings = Array.isArray(result.findings) ? result.findings : [];
      out.innerHTML = `
        <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
          <div class="flex items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Classification</span>
            ${dlpLabelPill(cls.label, color)}
            <span class="text-xs text-slate-400">${esc(cls.reason)}</span>
          </div>
          ${findings.length > 0 ? `
            <div class="mt-3 flex flex-wrap gap-1">
              ${findings.map((f) => `<span class="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] text-amber-200">${esc(String(f.type || f.class || f.name || "match"))}${f.severity ? ` · ${esc(String(f.severity))}` : ""}</span>`).join("")}
            </div>
          ` : ""}
          <details class="mt-3 rounded-xl border border-slate-800 bg-slate-950 p-2">
            <summary class="cursor-pointer text-[10px] font-semibold uppercase tracking-wider text-slate-400">Raw scan JSON</summary>
            <pre class="mt-2 max-h-64 overflow-auto text-xs text-slate-300">${esc(JSON.stringify(result, null, 2))}</pre>
          </details>
        </div>`;
    } catch (err) {
      status.textContent = "";
      out.innerHTML = `<div class="rounded-xl border border-rose-900 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">${esc(err.message)}</div>`;
    }
  }

  render();
}

async function viewUploadDiscovery() {
  $("#pageTitle").textContent = "Upload Discovery";
  $("#pageSubtitle").textContent = "Browser-extension–observed upload endpoints that aren't yet in the catalog — promote to extend block_upload coverage";
  const isAdmin = session.role === "tenant_admin";

  let candidates = [];
  let promoted = [];
  let total = 0;
  let windowDays = 30;
  let loadError = null;
  let actionMessage = null; // {kind: "ok"|"err", text}

  async function load() {
    try {
      const resp = await api(`/api/customer/upload-discovery/candidates?days=${windowDays}&limit=200`);
      candidates = Array.isArray(resp && resp.candidates) ? resp.candidates : [];
      promoted = Array.isArray(resp && resp.promoted_patterns) ? resp.promoted_patterns : [];
      total = resp && resp.total || 0;
      loadError = null;
    } catch (err) {
      candidates = [];
      promoted = [];
      total = 0;
      loadError = err.message || "candidate fetch failed";
    }
  }

  function fmtBytes(n) {
    if (!n || n <= 0) return "—";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function candidateRow(c) {
    const types = (c.file_types || []).slice(0, 3).join(", ");
    const ts = c.last_seen ? new Date(c.last_seen).toLocaleString() : "—";
    return `<tr class="border-t border-slate-800">
      <td class="px-3 py-2 font-mono text-xs text-slate-200 break-all">${esc(c.suggested_pattern || "")}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(c.hostname || "—")}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${esc(String(c.count || 0))}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${esc(fmtBytes(c.total_bytes || 0))}</td>
      <td class="px-3 py-2 text-xs text-slate-300">${esc(types || "—")}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(ts)}</td>
      <td class="px-3 py-2 text-right">
        ${isAdmin
          ? `<button class="promotePatternBtn rounded-lg bg-cyan-500 px-2 py-1 text-[11px] font-semibold text-slate-950 hover:bg-cyan-400" data-pattern="${esc(c.suggested_pattern || "")}" type="button">Promote</button>`
          : `<span class="text-[10px] text-slate-500">admin only</span>`}
      </td>
    </tr>`;
  }

  function promotedRow(p) {
    return `<tr class="border-t border-slate-800">
      <td class="px-3 py-2 font-mono text-xs text-slate-200 break-all">${esc(p)}</td>
      <td class="px-3 py-2 text-right">
        ${isAdmin
          ? `<button class="removePatternBtn rounded-lg border border-rose-700 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 hover:bg-rose-500/20" data-pattern="${esc(p)}" type="button">Remove</button>`
          : ""}
      </td>
    </tr>`;
  }

  function render() {
    const totalUploads = candidates.reduce((s, c) => s + (c.count || 0), 0);
    const distinctHosts = new Set(candidates.map((c) => c.hostname)).size;

    $("#app").innerHTML = `
      <div class="space-y-4">
        ${loadError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load candidates: ${esc(loadError)}.</div>` : ""}
        ${actionMessage ? `<div class="rounded-2xl border ${actionMessage.kind === "ok" ? "border-emerald-900 bg-emerald-950/20 text-emerald-200" : "border-rose-900 bg-rose-950/30 text-rose-200"} p-3 text-sm">${esc(actionMessage.text)}</div>` : ""}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            ${riskMetricCard("Candidates", candidates.length, candidates.length > 0 ? "amber" : "slate")}
            ${riskMetricCard("Distinct hosts", distinctHosts, "slate")}
            ${riskMetricCard("Observed uploads", totalUploads, "slate")}
            ${riskMetricCard("Promoted patterns", promoted.length, "emerald")}
            <div class="ml-auto flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Window</span>
              <div class="mt-1 flex flex-wrap gap-1" id="udWindowPicker">
                ${[1, 7, 30, 90].map((d) => `
                  <button type="button" data-days="${d}" class="rounded-full px-2 py-1 text-[11px] ${windowDays === d ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${d}d</button>
                `).join("")}
              </div>
            </div>
          </div>
        `)}
        ${card(`
          <div class="font-semibold">Promotion candidates</div>
          <p class="mt-1 text-xs text-slate-500">Upload URLs the browser extension observed but that aren't covered by the built-in or promoted catalog. UUIDs and long hex/digit segments are collapsed to <span class="font-mono">*</span>. Promote a pattern to enforce <span class="font-mono">block_upload</span> policies on it.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th class="px-3 py-2">Suggested pattern</th>
                  <th class="px-3 py-2">Host</th>
                  <th class="px-3 py-2">Count</th>
                  <th class="px-3 py-2">Bytes</th>
                  <th class="px-3 py-2">File types</th>
                  <th class="px-3 py-2">Last seen</th>
                  <th class="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                ${candidates.length === 0
                  ? `<tr><td colspan="7" class="px-3 py-8 text-center text-sm text-slate-500">No unmatched uploads observed in the last ${windowDays} day${windowDays === 1 ? "" : "s"}. Trigger a file upload from any AI tool while the extension is running, or widen the window.</td></tr>`
                  : candidates.map(candidateRow).join("")}
              </tbody>
            </table>
          </div>
        `)}
        ${card(`
          <div class="font-semibold">Promoted patterns</div>
          <p class="mt-1 text-xs text-slate-500">Tenant-promoted upload patterns. Extensions pull these every minute and union them into the runtime catalog used by DNR and the fetch wrapper.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
                <th class="px-3 py-2">Pattern</th><th class="px-3 py-2"></th>
              </tr></thead>
              <tbody>
                ${promoted.length === 0
                  ? `<tr><td colspan="2" class="px-3 py-6 text-center text-xs text-slate-500">No patterns promoted yet.</td></tr>`
                  : promoted.map(promotedRow).join("")}
              </tbody>
            </table>
          </div>
        `)}
      </div>
    `;

    document.querySelectorAll("#udWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const d = Number(btn.dataset.days);
        if (!d || d === windowDays) return;
        windowDays = d;
        await load();
        render();
      });
    });
    document.querySelectorAll(".promotePatternBtn").forEach((btn) => {
      btn.addEventListener("click", () => promote(btn.dataset.pattern));
    });
    document.querySelectorAll(".removePatternBtn").forEach((btn) => {
      btn.addEventListener("click", () => removePattern(btn.dataset.pattern));
    });
  }

  async function promote(pattern) {
    if (!pattern) return;
    try {
      const resp = await api("/api/customer/upload-discovery/promote", {
        method: "POST",
        body: JSON.stringify({ pattern }),
      });
      promoted = Array.isArray(resp && resp.patterns) ? resp.patterns : promoted;
      actionMessage = { kind: "ok", text: `Promoted ${pattern}. Extensions pick this up on next policy sync (~60s).` };
      await load();
      render();
    } catch (err) {
      actionMessage = { kind: "err", text: err.message || "Promote failed." };
      render();
    }
  }

  async function removePattern(pattern) {
    if (!pattern) return;
    if (!confirm(`Remove pattern "${pattern}"?\nExtensions stop matching it on the next sync.`)) return;
    try {
      const resp = await api("/api/customer/upload-discovery/remove", {
        method: "POST",
        body: JSON.stringify({ pattern }),
      });
      promoted = Array.isArray(resp && resp.patterns) ? resp.patterns : promoted;
      actionMessage = { kind: "ok", text: `Removed ${pattern}.` };
      await load();
      render();
    } catch (err) {
      actionMessage = { kind: "err", text: err.message || "Remove failed." };
      render();
    }
  }

  await load();
  render();
}

// CycloneDX component.type → display badge tone. Hardware (device/firmware)
// gets emerald, software libraries amber, applications cyan, ML models
// violet, OS slate. Same palette the rest of the portal uses for cluster
// pills so the BOM view reads like the others at a glance.
const ABOM_TYPE_TONE = {
  "application":            { label: "App",       cls: "bg-cyan-500/20 text-cyan-200" },
  "library":                { label: "Library",   cls: "bg-amber-500/20 text-amber-200" },
  "framework":              { label: "Framework", cls: "bg-amber-500/20 text-amber-200" },
  "container":              { label: "Container", cls: "bg-cyan-500/15 text-cyan-200" },
  "platform":               { label: "Platform",  cls: "bg-slate-700/40 text-slate-200" },
  "operating-system":       { label: "OS",        cls: "bg-slate-700/40 text-slate-200" },
  "device":                 { label: "Device",    cls: "bg-emerald-500/20 text-emerald-200" },
  "device-driver":          { label: "Driver",    cls: "bg-emerald-500/15 text-emerald-200" },
  "firmware":               { label: "Firmware",  cls: "bg-emerald-500/15 text-emerald-200" },
  "file":                   { label: "File",      cls: "bg-slate-700/40 text-slate-200" },
  "machine-learning-model": { label: "ML model",  cls: "bg-violet-500/20 text-violet-200" },
  "data":                   { label: "Data",      cls: "bg-cyan-500/15 text-cyan-200" },
  "cryptographic-asset":    { label: "Crypto",    cls: "bg-violet-500/20 text-violet-200" },
};

function abomTypePill(type) {
  const t = String(type || "").toLowerCase();
  const meta = ABOM_TYPE_TONE[t] || { label: type || "—", cls: "bg-slate-700/40 text-slate-200" };
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${meta.cls}">${esc(meta.label)}</span>`;
}

async function viewBillOfMaterials() {
  $("#pageTitle").textContent = "Bill of Materials";
  $("#pageSubtitle").textContent = "Continuously-updated inventory of software, hardware, ML models, and crypto — collected from endpoint agents, RASP, IDE plugins, repos, and cloud (CycloneDX 1.6)";

  let tab = "components"; // "components" | "drift"
  let components = [];
  let total = 0;
  let coverage = [];
  let loadError = null;
  let typeFilter = "all";
  let search = "";
  let sourceFilter = "all";          // all | agent | repo | container | cloud_resource | ide_workspace
  let staleDays = 0;                 // 0 = no stale filter; otherwise only show last_seen_at older than N days
  let selected = null;               // component id for the inspector panel
  let selectedDetail = null;         // detail payload
  const tablePager = { page: 1, pageSize: 50 };
  // Drift sub-view state
  let driftDays = 7;
  let drift = null;
  let driftError = null;

  async function load() {
    try {
      const params = new URLSearchParams();
      params.set("limit", String(tablePager.pageSize === "all" ? 500 : tablePager.pageSize));
      params.set("offset", String(tablePager.pageSize === "all" ? 0 : (tablePager.page - 1) * tablePager.pageSize));
      if (typeFilter !== "all") params.set("type", typeFilter);
      if (search.trim()) params.set("q", search.trim());
      if (sourceFilter !== "all") params.set("source_kind", sourceFilter);
      if (staleDays > 0) params.set("stale_days", String(staleDays));
      const [resp, cov] = await Promise.allSettled([
        api(`/api/customer/abom/components?${params.toString()}`),
        api("/api/customer/abom/coverage"),
      ]);
      if (resp.status === "fulfilled") {
        components = Array.isArray(resp.value && resp.value.components) ? resp.value.components : [];
        total = resp.value && resp.value.total || 0;
        loadError = null;
      } else {
        components = [];
        total = 0;
        loadError = resp.reason?.message || "fetch failed";
      }
      coverage = cov.status === "fulfilled" && Array.isArray(cov.value && cov.value.collectors)
        ? cov.value.collectors
        : [];
    } catch (err) {
      loadError = err.message || "fetch failed";
    }
  }

  async function loadDetail(componentId) {
    try {
      selectedDetail = await api(`/api/customer/abom/components/${encodeURIComponent(componentId)}`);
    } catch (err) {
      selectedDetail = { error: err.message || "fetch failed" };
    }
  }

  async function loadDrift() {
    try {
      drift = await api(`/api/customer/abom/drift?days=${driftDays}`);
      driftError = null;
    } catch (err) {
      drift = null;
      driftError = err.message || "drift fetch failed";
    }
  }

  function exportCycloneDX(opts = {}) {
    // Use a regular <a download> link so the JSON streams straight from
    // the server to disk without going through the api() wrapper (which
    // would parse + re-serialize a 1MB document for no reason). signed=true
    // wraps the BOM in an HMAC envelope for evidence-grade exports.
    const signed = opts.signed === true;
    const a = document.createElement("a");
    a.href = `/api/customer/abom/export?format=cyclonedx${signed ? "&sign=true" : ""}`;
    const suffix = signed ? ".signed.cdx.json" : ".cdx.json";
    a.download = `cyberarmor_${session.tenant_id || "tenant"}_bom_${new Date().toISOString().slice(0, 10)}${suffix}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function detailPanel() {
    if (!selected) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
        <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Inspector</div>
        Click any row to see provenance — which collectors saw this component, on which hosts, when. Versions and PURLs are tracked strongest-wins across sources.
      </div>`;
    }
    if (!selectedDetail) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">Loading…</div>`;
    }
    if (selectedDetail.error) {
      return `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">${esc(selectedDetail.error)}</div>`;
    }
    const d = selectedDetail;
    const licenses = Array.isArray(d.licenses) ? d.licenses : [];
    const hashes = d.hashes && typeof d.hashes === "object" ? d.hashes : {};
    const observations = Array.isArray(d.observations) ? d.observations : [];
    return `
      <div class="rounded-2xl border border-slate-800 bg-slate-950 p-4">
        <div class="flex items-baseline justify-between gap-2">
          <div class="min-w-0">
            <div class="flex items-center gap-2">${abomTypePill(d.type)}<span class="text-[10px] uppercase tracking-wider text-slate-500">Component</span></div>
            <div class="mt-1 font-semibold text-slate-100 break-all">${esc(d.name)}${d.version ? `<span class="ml-2 text-xs text-slate-400 font-normal">${esc(d.version)}</span>` : ""}</div>
          </div>
          <button id="bomClearSelection" type="button" class="text-xs text-slate-400 hover:text-slate-200">Clear</button>
        </div>
        <div class="mt-3 grid grid-cols-2 gap-2">
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Observations</div><div class="text-lg font-semibold tabular-nums">${d.observation_count || 0}</div></div>
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">First seen</div><div class="text-xs text-slate-300">${d.first_seen_at ? esc(new Date(d.first_seen_at).toLocaleString()) : "—"}</div></div>
        </div>
        ${d.purl ? `<div class="mt-3 rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">PURL</div><div class="font-mono text-xs text-slate-200 break-all">${esc(d.purl)}</div></div>` : ""}
        ${d.cpe ? `<div class="mt-2 rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">CPE</div><div class="font-mono text-xs text-slate-200 break-all">${esc(d.cpe)}</div></div>` : ""}
        ${d.manufacturer ? `<div class="mt-2 rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Manufacturer</div><div class="text-xs text-slate-200">${esc(d.manufacturer)}</div></div>` : ""}
        ${licenses.length ? `<div class="mt-2 rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Licenses</div><div class="mt-1 flex flex-wrap gap-1">${licenses.map((l) => `<span class="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-200">${esc(String(l))}</span>`).join("")}</div></div>` : ""}
        ${Object.keys(hashes).length ? `<div class="mt-2 rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Hashes</div>${Object.entries(hashes).map(([k, v]) => `<div class="mt-1 font-mono text-[10px] text-slate-400 break-all">${esc(k)}: ${esc(String(v))}</div>`).join("")}</div>` : ""}
        <div class="mt-3">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Observations (${observations.length})</div>
          ${observations.length === 0 ? `<div class="text-xs text-slate-500">No observations yet.</div>` : `
            <div class="space-y-1">${observations.slice(0, 12).map((o) => `
              <div class="rounded-lg bg-slate-900 px-2 py-1.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="font-mono text-xs text-slate-200 truncate">${esc(o.collector)}${o.collector_version ? ` <span class="text-slate-500">v${esc(o.collector_version)}</span>` : ""}</span>
                  <span class="rounded-full bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-slate-300">${esc(o.source_kind || "")}</span>
                </div>
                <div class="mt-0.5 text-[10px] text-slate-400 break-all">${esc(o.hostname || o.source_id || "")}${o.path ? ` · <span class="text-slate-500">${esc(o.path)}</span>` : ""}</div>
                <div class="mt-0.5 text-[10px] text-slate-500">${esc(o.observed_at ? new Date(o.observed_at).toLocaleString() : "")}</div>
              </div>
            `).join("")}</div>
          `}
        </div>
        <div class="mt-3 font-mono text-[10px] text-slate-500 break-all">identity_key: ${esc(d.identity_key || "")}</div>
      </div>
    `;
  }

  function row(c) {
    const isSel = selected === c.id;
    const last = c.last_seen_at ? new Date(c.last_seen_at).toLocaleString() : "—";
    return `<tr data-component-id="${esc(c.id)}" class="border-t border-slate-800 cursor-pointer ${isSel ? "bg-cyan-500/5" : "hover:bg-slate-900/60"}">
      <td class="px-3 py-2">${abomTypePill(c.type)}</td>
      <td class="px-3 py-2"><div class="text-sm text-slate-100 break-all">${esc(c.name)}</div>${c.manufacturer ? `<div class="text-[10px] text-slate-500">${esc(c.manufacturer)}</div>` : ""}</td>
      <td class="px-3 py-2 font-mono text-xs text-slate-300">${esc(c.version || "—")}</td>
      <td class="px-3 py-2 font-mono text-[10px] text-slate-400 break-all">${esc(c.purl || c.cpe || "—")}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${esc(String(c.observation_count || 0))}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(last)}</td>
    </tr>`;
  }

  function coverageRow(cv) {
    const last = cv.last_seen_at ? new Date(cv.last_seen_at).toLocaleString() : "—";
    const stale = cv.last_seen_at ? (Date.now() - Date.parse(cv.last_seen_at)) > 24 * 60 * 60 * 1000 : true;
    return `<tr class="border-t border-slate-800">
      <td class="px-3 py-2 font-mono text-xs text-slate-200">${esc(cv.collector)}</td>
      <td class="px-3 py-2"><span class="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-300">${esc(cv.source_kind || "—")}</span></td>
      <td class="px-3 py-2 text-xs tabular-nums">${esc(String(cv.observation_count || 0))}</td>
      <td class="px-3 py-2 text-xs ${stale ? "text-amber-300" : "text-slate-300"}">${esc(last)}${stale ? ` <span class="text-[10px] text-amber-400">(stale)</span>` : ""}</td>
    </tr>`;
  }

  function renderDriftBody() {
    if (driftError) {
      return `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load drift: ${esc(driftError)}.</div>`;
    }
    const added = (drift && drift.added) || [];
    const removed = (drift && drift.removed) || [];
    const changed = (drift && drift.version_changed) || [];
    const winLabel = drift && drift.since
      ? `${esc(new Date(drift.since).toLocaleString())} → ${esc(new Date(drift.until || Date.now()).toLocaleString())}`
      : `last ${driftDays}d`;

    const driftRow = (c, tone) => `<tr class="border-t border-slate-800 ${tone}">
      <td class="px-3 py-2">${abomTypePill(c.type)}</td>
      <td class="px-3 py-2"><div class="text-sm text-slate-100 break-all">${esc(c.name)}</div>${c.manufacturer ? `<div class="text-[10px] text-slate-500">${esc(c.manufacturer)}</div>` : ""}</td>
      <td class="px-3 py-2 font-mono text-xs text-slate-300">${esc(c.version || "—")}</td>
      <td class="px-3 py-2 font-mono text-[10px] text-slate-400 break-all">${esc(c.purl || "—")}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(c.first_seen_at ? new Date(c.first_seen_at).toLocaleString() : c.last_seen_at ? new Date(c.last_seen_at).toLocaleString() : "—")}</td>
    </tr>`;
    const versionRow = (v) => `<tr class="border-t border-slate-800">
      <td class="px-3 py-2">${abomTypePill(v.type)}</td>
      <td class="px-3 py-2"><div class="text-sm text-slate-100 break-all">${esc(v.name)}</div>${v.manufacturer ? `<div class="text-[10px] text-slate-500">${esc(v.manufacturer)}</div>` : ""}</td>
      <td class="px-3 py-2 font-mono text-xs"><span class="text-slate-500 line-through">${esc(v.from_version || "—")}</span> <span class="text-slate-500">→</span> <span class="text-emerald-300">${esc(v.to_version || "—")}</span></td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(v.to_first_seen_at ? new Date(v.to_first_seen_at).toLocaleString() : "—")}</td>
    </tr>`;

    return `
      ${card(`
        <div class="flex flex-wrap items-center gap-4">
          ${riskMetricCard("Added", added.length, added.length > 0 ? "emerald" : "slate")}
          ${riskMetricCard("Removed", removed.length, removed.length > 0 ? "rose" : "slate")}
          ${riskMetricCard("Version changed", changed.length, changed.length > 0 ? "amber" : "slate")}
          <div class="ml-auto flex flex-col leading-tight">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Window</span>
            <div class="mt-1 flex flex-wrap gap-1" id="driftWindowPicker">
              ${[1, 7, 30, 90].map((d) => `
                <button type="button" data-drift-days="${d}" class="rounded-full px-2 py-1 text-[11px] ${driftDays === d ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${d}d</button>
              `).join("")}
            </div>
          </div>
          <div class="text-[11px] text-slate-500">${winLabel}</div>
        </div>
      `)}
      <div class="grid gap-4 lg:grid-cols-2">
        ${card(`
          <div class="font-semibold">Added <span class="text-xs text-slate-500">(${added.length})</span></div>
          <p class="mt-1 text-xs text-slate-500">Components whose first sighting falls inside the window. New install, new repo dep, fresh cloud resource — all land here.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
                <th class="px-3 py-2">Type</th><th class="px-3 py-2">Name</th><th class="px-3 py-2">Version</th><th class="px-3 py-2">PURL</th><th class="px-3 py-2">First seen</th>
              </tr></thead>
              <tbody>
                ${added.length === 0 ? `<tr><td colspan="5" class="px-3 py-6 text-center text-xs text-slate-500">Nothing new.</td></tr>` : added.slice(0, 200).map((c) => driftRow(c, "")).join("")}
              </tbody>
            </table>
          </div>
        `)}
        ${card(`
          <div class="font-semibold">Removed <span class="text-xs text-slate-500">(${removed.length})</span></div>
          <p class="mt-1 text-xs text-slate-500">Components a collector hasn't seen since before the window. Uninstall, deleted repo, decommissioned host — flagged here.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
                <th class="px-3 py-2">Type</th><th class="px-3 py-2">Name</th><th class="px-3 py-2">Version</th><th class="px-3 py-2">PURL</th><th class="px-3 py-2">Last seen</th>
              </tr></thead>
              <tbody>
                ${removed.length === 0 ? `<tr><td colspan="5" class="px-3 py-6 text-center text-xs text-slate-500">Nothing removed.</td></tr>` : removed.slice(0, 200).map((c) => driftRow(c, "")).join("")}
              </tbody>
            </table>
          </div>
        `)}
      </div>
      ${card(`
        <div class="font-semibold">Version changed <span class="text-xs text-slate-500">(${changed.length})</span></div>
        <p class="mt-1 text-xs text-slate-500">Old version's identity_key disappeared and a new one with the same (type, name, manufacturer) appeared inside the window.</p>
        <div class="mt-3 overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
              <th class="px-3 py-2">Type</th><th class="px-3 py-2">Name</th><th class="px-3 py-2">Version</th><th class="px-3 py-2">First seen (new)</th>
            </tr></thead>
            <tbody>
              ${changed.length === 0 ? `<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No version changes.</td></tr>` : changed.slice(0, 200).map(versionRow).join("")}
            </tbody>
          </table>
        </div>
      `)}
    `;
  }

  function render() {
    const typeCounts = {};
    for (const c of components) typeCounts[c.type] = (typeCounts[c.type] || 0) + 1;
    const distinctTypes = Object.keys(typeCounts).sort();
    const typesForPicker = ["all", ...Object.keys(ABOM_TYPE_TONE).filter((t) => typeCounts[t] || typeFilter === t)];
    const totalDevices = (typeCounts["device"] || 0) + (typeCounts["device-driver"] || 0) + (typeCounts["firmware"] || 0);
    const totalSoftware = (typeCounts["library"] || 0) + (typeCounts["application"] || 0) + (typeCounts["framework"] || 0) + (typeCounts["container"] || 0);
    const totalMl = typeCounts["machine-learning-model"] || 0;
    const pager = simplePager({ total, state: tablePager, idPrefix: "bom" });

    const tabsHtml = `
      <div class="flex flex-wrap gap-2">
        ${tabButton("components", "Components", tab === "components")}
        ${tabButton("drift", `Drift${drift && drift.summary ? ` (${drift.summary.added + drift.summary.removed + drift.summary.version_changed})` : ""}`, tab === "drift")}
      </div>
    `;
    $("#app").innerHTML = `
      <div class="space-y-4">
        ${loadError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load BOM: ${esc(loadError)}.</div>` : ""}
        ${tabsHtml}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            ${riskMetricCard("Components", total, "slate")}
            ${riskMetricCard("Software", totalSoftware, "slate")}
            ${riskMetricCard("Hardware", totalDevices, "emerald")}
            ${riskMetricCard("ML models", totalMl, totalMl > 0 ? "amber" : "slate")}
            ${riskMetricCard("Collectors", coverage.length, coverage.length === 0 ? "rose" : "emerald")}
            <div class="ml-auto flex flex-wrap gap-2">
              <button id="bomExport" type="button" class="rounded-2xl bg-cyan-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400">Export CycloneDX</button>
              <button id="bomExportSigned" type="button" class="rounded-2xl border border-cyan-700 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-500/20" title="Wraps the BOM in an HMAC-SHA256 envelope for evidence-grade exports.">Export Signed</button>
              <button id="bomRefresh" type="button" class="rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Refresh</button>
            </div>
          </div>
        `)}
        ${tab === "drift" ? renderDriftBody() : ""}
        ${tab !== "components" ? "" : `
        ${card(`
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Type</span>
            ${typesForPicker.map((t) => `
              <button type="button" data-type-filter="${esc(t)}" class="rounded-full px-2 py-1 text-[11px] ${typeFilter === t ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">
                ${esc(t === "all" ? "All" : (ABOM_TYPE_TONE[t]?.label || t))}${t !== "all" && typeCounts[t] ? ` <span class="text-slate-500">·${typeCounts[t]}</span>` : ""}
              </button>
            `).join("")}
          </div>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Source</span>
            ${["all", "agent", "repo", "container", "cloud_resource", "ide_workspace"].map((s) => `
              <button type="button" data-source-filter="${esc(s)}" class="rounded-full px-2 py-1 text-[11px] ${sourceFilter === s ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(s === "all" ? "All" : s)}</button>
            `).join("")}
          </div>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-slate-500">Freshness</span>
            ${[
              { v: 0, label: "All" },
              { v: 1, label: "Stale >1d" },
              { v: 7, label: "Stale >7d" },
              { v: 30, label: "Stale >30d" },
            ].map((opt) => `
              <button type="button" data-stale-filter="${opt.v}" class="rounded-full px-2 py-1 text-[11px] ${staleDays === opt.v ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(opt.label)}</button>
            `).join("")}
          </div>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <input id="bomSearch" type="search" placeholder="Search by name (substring)…" class="flex-1 min-w-[280px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="${esc(search)}" />
            <div class="text-xs text-slate-400">${total} total · ${distinctTypes.length} types${staleDays > 0 ? ` · stale >${staleDays}d` : ""}</div>
          </div>
        `)}
        <div class="grid gap-4 lg:grid-cols-[1fr_400px]">
          ${card(`
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <thead class="text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th class="px-3 py-2">Type</th>
                    <th class="px-3 py-2">Name</th>
                    <th class="px-3 py-2">Version</th>
                    <th class="px-3 py-2">Identifier</th>
                    <th class="px-3 py-2">Observed</th>
                    <th class="px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody id="bomRows">
                  ${components.length === 0
                    ? `<tr><td colspan="6" class="px-3 py-8 text-center text-sm text-slate-500">${loadError ? "Unable to load." : "No components reported yet. Install the endpoint agent or wait for the first 6h sweep."}</td></tr>`
                    : components.map(row).join("")}
                </tbody>
              </table>
            </div>
            ${total > 0 ? pager.html : ""}
          `)}
          <div>${detailPanel()}</div>
        </div>
        ${card(`
          <div class="font-semibold">Collector coverage</div>
          <p class="mt-1 text-xs text-slate-500">When each collector last reported. Stale rows (>24h) are amber — that's usually a silent agent or a stopped CI job.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
                <th class="px-3 py-2">Collector</th><th class="px-3 py-2">Source</th><th class="px-3 py-2">Observations</th><th class="px-3 py-2">Last reported</th>
              </tr></thead>
              <tbody>
                ${coverage.length === 0
                  ? `<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No collectors have reported yet.</td></tr>`
                  : coverage.map(coverageRow).join("")}
              </tbody>
            </table>
          </div>
        `)}
        `}
      </div>
    `;

    document.querySelectorAll("[data-type-filter]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const next = btn.dataset.typeFilter;
        if (next === typeFilter) return;
        typeFilter = next;
        tablePager.page = 1;
        selected = null;
        selectedDetail = null;
        await load();
        render();
      });
    });
    document.querySelectorAll("[data-source-filter]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const next = btn.dataset.sourceFilter;
        if (next === sourceFilter) return;
        sourceFilter = next;
        tablePager.page = 1;
        selected = null;
        selectedDetail = null;
        await load();
        render();
      });
    });
    const sb = $("#bomSearch");
    if (sb) {
      sb.addEventListener("change", async () => {
        if (sb.value === search) return;
        search = sb.value;
        tablePager.page = 1;
        await load();
        render();
      });
    }
    document.querySelectorAll("#bomRows tr[data-component-id]").forEach((tr) => {
      tr.addEventListener("click", async () => {
        const cid = tr.dataset.componentId;
        selected = (selected === cid) ? null : cid;
        selectedDetail = null;
        if (selected) await loadDetail(selected);
        render();
      });
    });
    const clearBtn = $("#bomClearSelection");
    if (clearBtn) clearBtn.addEventListener("click", () => { selected = null; selectedDetail = null; render(); });
    const exp = $("#bomExport"); if (exp) exp.addEventListener("click", () => exportCycloneDX({ signed: false }));
    const expSigned = $("#bomExportSigned"); if (expSigned) expSigned.addEventListener("click", () => exportCycloneDX({ signed: true }));
    const ref = $("#bomRefresh"); if (ref) ref.addEventListener("click", async () => {
      // Refresh refreshes whichever tab is active so the Refresh button
      // behaves consistently from either sub-view.
      await load();
      if (tab === "drift") await loadDrift();
      render();
    });
    pager.wire(document, async () => { await load(); render(); });

    // Tab bar: switching to Drift triggers a fetch if we haven't loaded
    // it yet; switching back to Components reuses cached data.
    document.querySelectorAll(".sectionTab").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const next = btn.dataset.tab;
        if (!next || next === tab) return;
        tab = next;
        if (tab === "drift" && drift === null) await loadDrift();
        render();
      });
    });

    // Stale-days chips: zero means "no filter"; non-zero passes
    // stale_days through to /customer/abom/components.
    document.querySelectorAll("[data-stale-filter]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const next = Number(btn.dataset.staleFilter || 0);
        if (next === staleDays) return;
        staleDays = next;
        tablePager.page = 1;
        await load();
        render();
      });
    });

    // Drift window picker.
    document.querySelectorAll("[data-drift-days]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const next = Number(btn.dataset.driftDays || 0);
        if (next === driftDays || !next) return;
        driftDays = next;
        await loadDrift();
        render();
      });
    });
  }

  await load();
  render();
}

// Time windows for report generation. Mirrors the compliance picker so
// the operator switches between views without context whiplash.
const REPORT_WINDOWS = [
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d",  label: "Last 7d",  ms: 7  * 24 * 60 * 60 * 1000 },
  { id: "30d", label: "Last 30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All time", ms: null },
];

const REPORT_ICONS = {
  executive:            "🧭",
  ai_risk:              "🤖",
  dlp:                  "🛡️",
  endpoint_health:      "💻",
  policy_effectiveness: "📐",
};

function reportMetricTone(tone) {
  return tone === "rose"    ? "border-rose-900 text-rose-200"
       : tone === "amber"   ? "border-amber-900 text-amber-200"
       : tone === "emerald" ? "border-emerald-900 text-emerald-200"
       :                      "border-slate-800 text-slate-200";
}

function renderReportSection(section) {
  if (!section || typeof section !== "object") return "";
  const title = String(section.title || "");
  if (section.type === "metrics") {
    const metrics = Array.isArray(section.metrics) ? section.metrics : [];
    return `
      <div>
        <div class="text-sm font-semibold mb-2">${esc(title)}</div>
        <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          ${metrics.map((m) => `
            <div class="rounded-2xl border bg-slate-950 p-3 ${reportMetricTone(m.tone)}">
              <div class="text-[10px] uppercase tracking-wider text-slate-500">${esc(String(m.label || ""))}</div>
              <div class="mt-1 text-xl font-semibold tabular-nums">${esc(String(m.value ?? ""))}</div>
            </div>
          `).join("")}
        </div>
      </div>`;
  }
  if (section.type === "table") {
    const cols = Array.isArray(section.columns) ? section.columns : [];
    const rows = Array.isArray(section.rows) ? section.rows : [];
    return `
      <div>
        <div class="text-sm font-semibold mb-2">${esc(title)}</div>
        <div class="overflow-x-auto rounded-xl border border-slate-800">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>${cols.map((c) => `<th class="px-3 py-2">${esc(String(c))}</th>`).join("")}</tr>
            </thead>
            <tbody>
              ${rows.length === 0
                ? `<tr><td colspan="${cols.length || 1}" class="px-3 py-6 text-center text-xs text-slate-500">No rows.</td></tr>`
                : rows.map((row) => `<tr class="border-t border-slate-800">${(Array.isArray(row) ? row : []).map((cell) => `<td class="px-3 py-2 ${typeof cell === "number" ? "tabular-nums" : ""}">${esc(String(cell ?? ""))}</td>`).join("")}</tr>`).join("")}
            </tbody>
          </table>
        </div>
      </div>`;
  }
  if (section.type === "list") {
    const items = Array.isArray(section.items) ? section.items : [];
    return `
      <div>
        <div class="text-sm font-semibold mb-2">${esc(title)}</div>
        ${items.length === 0
          ? `<div class="text-xs text-slate-500">None.</div>`
          : `<ul class="list-disc pl-5 space-y-1 text-sm text-slate-200">${items.map((it) => `<li>${esc(String(it))}</li>`).join("")}</ul>`}
      </div>`;
  }
  if (section.type === "text") {
    return `<div>
      <div class="text-sm font-semibold mb-2">${esc(title)}</div>
      <p class="text-sm text-slate-300 whitespace-pre-wrap">${esc(String(section.body || ""))}</p>
    </div>`;
  }
  return "";
}

async function viewReports() {
  $("#pageTitle").textContent = "Reports";
  $("#pageSubtitle").textContent = "Generate tenant-scoped security, risk, and compliance reports — view inline or download as JSON";

  let catalog = [];
  let catalogError = null;
  try {
    const resp = await api("/api/customer/reports/catalog");
    catalog = (resp && resp.reports) || [];
  } catch (err) {
    catalogError = err.message || "catalog fetch failed";
  }

  // Per-view state: selected window, last-generated report, generation status.
  let windowId = "7d";
  let activeReport = null;        // last generated payload, rendered inline
  let activeStatus = null;        // {reportId, state: "running"|"error", error?}

  function windowBody() {
    const w = REPORT_WINDOWS.find((x) => x.id === windowId);
    if (!w || w.ms == null) return {};
    const until = new Date();
    const since = new Date(until.getTime() - w.ms);
    return { since: since.toISOString(), until: until.toISOString() };
  }

  function reportCardHtml(entry) {
    const isActive = activeReport && activeReport.report_type === entry.id;
    const isLoading = activeStatus && activeStatus.reportId === entry.id && activeStatus.state === "running";
    const hasErr   = activeStatus && activeStatus.reportId === entry.id && activeStatus.state === "error";
    return `
      <div class="rounded-2xl border ${isActive ? "border-cyan-700 bg-cyan-900/10" : "border-slate-800 bg-slate-950"} p-4">
        <div class="flex items-baseline justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="text-lg">${REPORT_ICONS[entry.id] || "📄"}</span>
            <div class="font-semibold text-sm">${esc(entry.title)}</div>
          </div>
        </div>
        <p class="mt-2 text-xs text-slate-400">${esc(entry.description || "")}</p>
        <div class="mt-3 flex flex-wrap gap-2">
          <button class="generateReportBtn rounded-xl bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50" data-report-id="${esc(entry.id)}" type="button" ${isLoading ? "disabled" : ""}>${isLoading ? "Generating…" : "Generate"}</button>
          ${isActive ? `<button class="downloadReportBtn rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800" type="button">Download JSON</button>` : ""}
        </div>
        ${hasErr ? `<div class="mt-2 text-xs text-rose-300">${esc(activeStatus.error || "Failed to generate.")}</div>` : ""}
      </div>`;
  }

  function reportInlineHtml() {
    if (!activeReport) {
      return card(`
        <div class="text-sm text-slate-400">Pick a report above and choose a time window. Reports render here and can be downloaded as JSON for sharing or evidence packs.</div>
      `);
    }
    const r = activeReport;
    const win = r.window || {};
    const winLabel = win.since
      ? `${esc(String(win.since))} → ${esc(String(win.until || "now"))}`
      : "All time";
    const counts = r.counts || {};
    const sections = Array.isArray(r.sections) ? r.sections : [];
    return card(`
      <div class="flex items-baseline justify-between gap-2">
        <div>
          <div class="text-lg font-semibold">${esc(r.title || r.report_type)}</div>
          <div class="mt-1 text-xs text-slate-500">${esc(String(r.generated_at || ""))} · Window: ${winLabel}</div>
          ${r.description ? `<div class="mt-1 text-xs text-slate-400">${esc(r.description)}</div>` : ""}
        </div>
        <div class="text-[10px] text-slate-500 text-right">
          <div>Telemetry: <span class="tabular-nums">${esc(String(counts.telemetry ?? 0))}</span></div>
          <div>Audit: <span class="tabular-nums">${esc(String(counts.audit ?? 0))}</span></div>
          <div>Incidents: <span class="tabular-nums">${esc(String(counts.incidents ?? 0))}</span></div>
          <div>Agents: <span class="tabular-nums">${esc(String(counts.agents ?? 0))}</span></div>
        </div>
      </div>
      <div class="mt-4 space-y-5">
        ${sections.length === 0
          ? `<div class="text-sm text-slate-500">Report returned no sections — try a wider window.</div>`
          : sections.map(renderReportSection).join("")}
      </div>
    `);
  }

  function render() {
    $("#app").innerHTML = `
      <div class="space-y-4">
        ${catalogError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load report catalog: ${esc(catalogError)}.</div>` : ""}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Reports available</span>
              <span class="text-2xl font-semibold tabular-nums">${catalog.length}</span>
            </div>
            <div class="mx-2 h-10 w-px bg-slate-800"></div>
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Time window</span>
              <div class="mt-1 flex flex-wrap gap-1" id="reportWindowPicker">
                ${REPORT_WINDOWS.map((w) => `
                  <button type="button" data-window-id="${w.id}" class="rounded-full px-2 py-1 text-[11px] ${windowId === w.id ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(w.label)}</button>
                `).join("")}
              </div>
            </div>
            <div class="ml-auto flex flex-wrap items-center gap-2">
              <button id="evidenceSummaryBtn" type="button" class="rounded-2xl bg-cyan-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400">Export Summary Evidence</button>
              <button id="evidenceFullBtn"    type="button" class="rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Export Full Evidence</button>
              <span id="evidenceMessage" class="text-xs text-slate-400"></span>
            </div>
          </div>
        `)}
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          ${catalog.map(reportCardHtml).join("")}
        </div>
        <div id="reportInline">${reportInlineHtml()}</div>
      </div>
    `;

    document.querySelectorAll("#reportWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (windowId === btn.dataset.windowId) return;
        windowId = btn.dataset.windowId;
        // Window changes invalidate the current inline report — the
        // metrics it shows came from a different window.
        activeReport = null;
        render();
      });
    });
    document.querySelectorAll(".generateReportBtn").forEach((btn) => {
      btn.addEventListener("click", () => generateReport(btn.dataset.reportId));
    });
    document.querySelectorAll(".downloadReportBtn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (!activeReport) return;
        const fname = `cyberarmor_${session.tenant_id}_${activeReport.report_type}_${new Date().toISOString().slice(0, 10)}.json`;
        downloadJson(fname, activeReport);
      });
    });
    const sumBtn = $("#evidenceSummaryBtn");
    if (sumBtn) sumBtn.addEventListener("click", () => runEvidenceExport("summary"));
    const fullBtn = $("#evidenceFullBtn");
    if (fullBtn) fullBtn.addEventListener("click", () => runEvidenceExport("full"));
  }

  async function generateReport(reportId) {
    if (!reportId) return;
    activeStatus = { reportId, state: "running" };
    render();
    try {
      const r = await api("/api/customer/reports/generate", {
        method: "POST",
        body: JSON.stringify({ report_type: reportId, ...windowBody() }),
      });
      activeReport = r;
      activeStatus = null;
      render();
      $("#reportInline").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      activeStatus = { reportId, state: "error", error: err.message };
      render();
    }
  }

  async function runEvidenceExport(scope) {
    const msg = $("#evidenceMessage");
    msg.textContent = `Preparing ${scope} evidence…`;
    msg.className = "text-xs text-slate-400";
    try {
      const pack = await api(`/api/customer/evidence/export?scope=${encodeURIComponent(scope)}`);
      downloadJson(`cyberarmor_${session.tenant_id}_${scope}_evidence_${new Date().toISOString().slice(0, 10)}.json`, pack);
      msg.textContent = "Evidence export ready.";
      msg.className = "text-xs text-emerald-300";
    } catch (err) {
      msg.textContent = err.message;
      msg.className = "text-xs text-rose-300";
    }
  }

  render();
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

// --- Incidents helpers ---

function decisionPill(decision) {
  const d = String(decision || "unknown").toLowerCase();
  const cls = d === "block"    ? "bg-rose-500/20 text-rose-200"
            : d === "redact"   ? "bg-amber-500/20 text-amber-200"
            : d === "warn"     ? "bg-amber-500/15 text-amber-200"
            : d === "allow"    ? "bg-emerald-500/20 text-emerald-200"
            : d === "sandbox"  ? "bg-blue-500/20 text-blue-200"
            : d === "isolate"  ? "bg-violet-500/20 text-violet-200"
            : "bg-slate-700/40 text-slate-300";
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${cls}">${esc(d)}</span>`;
}

function relativeFromIso(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return relativeSince(Math.max(0, (Date.now() - t) / 60000));
}

const INCIDENT_WINDOWS = [
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d",  label: "Last 7d",  ms: 7  * 24 * 60 * 60 * 1000 },
  { id: "30d", label: "Last 30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All time", ms: null },
];

const INCIDENT_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, informational: 0 };

// Derive a coarse severity for an incident from the worst severity across
// its findings (preferred) or its metadata.severity, falling back to a
// decision-based guess so the chip mix isn't dominated by "—".
function incidentSeverity(r) {
  const meta = r && r.metadata && typeof r.metadata === "object" ? r.metadata : {};
  const fromMeta = String(meta.severity || "").toLowerCase();
  if (fromMeta in INCIDENT_SEVERITY_RANK) return fromMeta === "informational" ? "info" : fromMeta;
  const findings = Array.isArray(r && r.findings) ? r.findings : [];
  let best = -1;
  let bestName = "";
  for (const f of findings) {
    const s = String((f && f.severity) || "").toLowerCase();
    const rank = INCIDENT_SEVERITY_RANK[s];
    if (rank != null && rank > best) { best = rank; bestName = s === "informational" ? "info" : s; }
  }
  if (bestName) return bestName;
  const d = String((r && r.decision) || "").toLowerCase();
  if (d === "block") return "high";
  if (d === "redact" || d === "warn") return "medium";
  return "info";
}

async function viewIncidents() {
  $("#pageTitle").textContent = "Incidents";
  $("#pageSubtitle").textContent = "Runtime decisions, findings, and evidence — investigate what enforcement actually did";
  const incidents = await api("/api/customer/incidents?limit=500");
  const allRows = Array.isArray(incidents) ? incidents : [];

  // Pre-decorate so we don't recompute severity / parsed timestamps on
  // every keystroke or filter toggle.
  for (const r of allRows) {
    r._sev = incidentSeverity(r);
    r._ts = r.received_at ? Date.parse(r.received_at) : 0;
  }

  const state = {
    windowId: "7d",
    decisionFilter: "all",
    severityFilter: "all",
    search: "",
  };

  function inWindow(r) {
    const w = INCIDENT_WINDOWS.find((x) => x.id === state.windowId);
    if (!w || w.ms == null) return true;
    return Number.isFinite(r._ts) && r._ts >= (Date.now() - w.ms);
  }
  function matchesSearch(r) {
    if (!state.search) return true;
    const q = state.search.toLowerCase();
    if (String(r.event_type || "").toLowerCase().includes(q)) return true;
    if (String(r.request_id || "").toLowerCase().includes(q)) return true;
    if (String(r.agent_id || "").toLowerCase().includes(q)) return true;
    if (String(r.user_id || "").toLowerCase().includes(q)) return true;
    for (const reason of (r.reasons || [])) if (String(reason).toLowerCase().includes(q)) return true;
    for (const f of (r.findings || [])) {
      for (const v of Object.values(f || {})) if (typeof v === "string" && v.toLowerCase().includes(q)) return true;
    }
    return false;
  }
  // Rows visible after window filtering — chip counts reflect this set so
  // numbers track the selected time range.
  function windowedRows() { return allRows.filter(inWindow); }
  function visibleRows() {
    return windowedRows().filter((r) => {
      if (state.decisionFilter !== "all" && String(r.decision || "").toLowerCase() !== state.decisionFilter) return false;
      if (state.severityFilter !== "all" && r._sev !== state.severityFilter) return false;
      if (!matchesSearch(r)) return false;
      return true;
    });
  }
  function chipCls(active) {
    return active
      ? "rounded-full bg-cyan-500/20 text-cyan-100 border border-cyan-400/40 px-3 py-1 text-xs"
      : "rounded-full bg-slate-900 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1 text-xs";
  }

  function render() {
    const windowed = windowedRows();
    const filtered = visibleRows();

    // Counts are computed off the windowed (not fully filtered) set so chips
    // show "how many of this decision/severity exist in this window".
    const decisionCounts = { block: 0, redact: 0, warn: 0, allow: 0, sandbox: 0, isolate: 0, other: 0 };
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const uniqueAgents = new Set();
    const uniqueEventTypes = new Set();
    for (const r of windowed) {
      const d = String(r.decision || "").toLowerCase();
      if (decisionCounts[d] != null) decisionCounts[d]++; else decisionCounts.other++;
      if (severityCounts[r._sev] != null) severityCounts[r._sev]++;
      if (r.agent_id) uniqueAgents.add(r.agent_id);
      if (r.event_type) uniqueEventTypes.add(r.event_type);
    }
    const decisionOrder = ["block", "redact", "warn", "allow", "sandbox", "isolate", "other"].filter((k) => decisionCounts[k] > 0);
    const severityOrder = ["critical", "high", "medium", "low", "info"].filter((k) => severityCounts[k] > 0);

    $("#app").innerHTML = `
      <div class="space-y-4">
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            ${riskMetricCard("Total", windowed.length, "slate")}
            ${riskMetricCard("Blocked", decisionCounts.block, decisionCounts.block ? "rose" : "emerald")}
            ${riskMetricCard("Redacted", decisionCounts.redact, decisionCounts.redact ? "amber" : "emerald")}
            ${riskMetricCard("Critical / High", severityCounts.critical + severityCounts.high, (severityCounts.critical + severityCounts.high) > 0 ? "rose" : "emerald")}
            ${riskMetricCard("Unique agents", uniqueAgents.size, "slate")}
            ${riskMetricCard("Event types", uniqueEventTypes.size, "slate")}
            <div class="ml-auto flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Time window</span>
              <div class="mt-1 flex flex-wrap gap-1" id="incidentsWindowPicker">
                ${INCIDENT_WINDOWS.map((w) => `
                  <button type="button" data-window-id="${w.id}" class="rounded-full px-2 py-1 text-[11px] ${state.windowId === w.id ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(w.label)}</button>
                `).join("")}
              </div>
            </div>
          </div>
        `)}
        ${card(`
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Decision</span>
              <button data-decision-chip="all" class="${chipCls(state.decisionFilter === "all")}">All <span class="text-slate-500">·${windowed.length}</span></button>
              ${decisionOrder.map((d) =>
                `<button data-decision-chip="${esc(d)}" class="${chipCls(state.decisionFilter === d)}">${esc(d)} <span class="text-slate-500">·${decisionCounts[d]}</span></button>`
              ).join("")}
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Severity</span>
              <button data-severity-chip="all" class="${chipCls(state.severityFilter === "all")}">All <span class="text-slate-500">·${windowed.length}</span></button>
              ${severityOrder.map((s) =>
                `<button data-severity-chip="${esc(s)}" class="${chipCls(state.severityFilter === s)}">${esc(s)} <span class="text-slate-500">·${severityCounts[s]}</span></button>`
              ).join("")}
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <input id="incidentSearch" type="search" placeholder="Search event type, request, agent, user, reason, finding…" class="flex-1 min-w-[280px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="${esc(state.search)}" />
              <div class="text-xs text-slate-400">${filtered.length} of ${windowed.length} shown</div>
            </div>
          </div>
        `)}
        <div id="incidentsList"></div>
      </div>
    `;

    mountListView({
      container: $("#incidentsList"),
      rows: filtered,
      filename: `incidents_${session.tenant_id || "tenant"}`,
      columns: [
        { key: "received_at", label: "Time", type: "date",
          value: (r) => r.received_at || "",
          render: (r) => `<span class="text-xs text-slate-400 tabular-nums" title="${esc(fmt(r.received_at))}">${esc(relativeFromIso(r.received_at))}</span>` },
        { key: "decision", label: "Decision", type: "enum",
          value: (r) => String(r.decision || "unknown").toLowerCase(),
          render: (r) => decisionPill(r.decision) },
        { key: "_sev", label: "Severity", type: "enum",
          enumValues: ["critical", "high", "medium", "low", "info"],
          value: (r) => r._sev,
          render: (r) => severityBadgeHtml(r._sev) },
        { key: "event_type", label: "Event", type: "text",
          value: (r) => r.event_type || "",
          render: (r) => {
            const reasons = Array.isArray(r.reasons) ? r.reasons : [];
            const teaser = reasons.length ? reasons[0] : "";
            return `<div class="leading-tight">
              <span class="font-mono text-xs text-slate-100">${esc(r.event_type || "")}</span>
              ${teaser ? `<div class="mt-0.5 truncate text-[11px] text-slate-500" title="${esc(reasons.join(" · "))}">${esc(teaser)}</div>` : ""}
            </div>`;
          } },
        { key: "request_id", label: "Request", type: "text", sortable: false,
          value: (r) => r.request_id || "",
          render: (r) => r.request_id ? `<span class="font-mono text-[10px] text-slate-500">${esc((r.request_id || "").slice(0, 14))}…</span>` : `<span class="text-slate-700">—</span>` },
        { key: "findings", label: "Findings", type: "number", sortable: false,
          value: (r) => Array.isArray(r.findings) ? r.findings.length : 0,
          render: (r) => {
            const n = Array.isArray(r.findings) ? r.findings.length : 0;
            return n
              ? `<span class="inline-flex items-center rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-200">${n} finding${n === 1 ? "" : "s"}</span>`
              : `<span class="text-slate-700">—</span>`;
          },
          csv: (r) => JSON.stringify(r.findings || []) },
      ],
      onRowClick: (incident) => {
        const reasons = Array.isArray(incident.reasons) ? incident.reasons : [];
        const findings = Array.isArray(incident.findings) ? incident.findings : [];
        const reasonsHtml = reasons.length
          ? `<ul class="list-disc space-y-1 pl-5 text-sm text-slate-300">${reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
          : `<div class="text-xs text-slate-500">No reasons recorded.</div>`;
        const findingsHtml = findings.length
          ? `<ul class="space-y-2">${findings.map((f) => {
              const label = f.label || f.classification || f.type || "finding";
              const detail = f.detail || f.value || f.description || "";
              const sev = f.severity || "";
              return `<li class="rounded-xl border border-slate-800 bg-slate-900/50 px-3 py-2">
                <div class="flex items-baseline justify-between gap-2">
                  <span class="font-mono text-xs text-slate-100">${esc(label)}</span>
                  ${sev ? severityBadgeHtml(sev) : ""}
                </div>
                ${detail ? `<div class="mt-1 truncate text-xs text-slate-400">${esc(String(detail).slice(0, 200))}</div>` : ""}
              </li>`;
            }).join("")}</ul>`
          : `<div class="text-xs text-slate-500">No findings recorded.</div>`;
        openReadOnlyModal({
          title: `Incident — ${(incident.event_type || "")} → ${incident.decision || "unknown"}`,
          record: incident,
          fields: [
            { key: "received_at", label: "Time", render: (r) => `${esc(fmt(r.received_at))}<div class="text-xs text-slate-500">${esc(relativeFromIso(r.received_at))}</div>` },
            { key: "decision",   label: "Decision",   render: (r) => decisionPill(r.decision) },
            { key: "event_type", label: "Event Type" },
            { key: "request_id", label: "Request ID", render: (r) => `<span class="font-mono text-xs">${esc(r.request_id || "")}</span>` },
            { key: "reasons",    label: "Reasons",    render: () => reasonsHtml },
            { key: "findings",   label: `Findings (${findings.length})`, render: () => findingsHtml },
            { key: "tenant_id",  label: "Tenant" },
            { key: "user_id",    label: "User" },
            { key: "agent_id",   label: "Agent" },
            { key: "source",     label: "Source" },
          ],
        });
      },
      emptyMessage: filtered.length === 0 && allRows.length > 0
        ? "No incidents match the current filters."
        : "No incidents found for this tenant. Runtime decisions (block, redact, warn) show up here as enforcement happens.",
    });

    document.querySelectorAll("[data-decision-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.decisionFilter = el.dataset.decisionChip; render(); });
    });
    document.querySelectorAll("[data-severity-chip]").forEach((el) => {
      el.addEventListener("click", () => { state.severityFilter = el.dataset.severityChip; render(); });
    });
    document.querySelectorAll("#incidentsWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (state.windowId === btn.dataset.windowId) return;
        state.windowId = btn.dataset.windowId;
        render();
      });
    });
    const sb = $("#incidentSearch");
    if (sb) {
      // Restore focus + caret on every render so typing doesn't bounce.
      const caret = sb.selectionStart;
      sb.focus();
      if (caret != null) sb.setSelectionRange(caret, caret);
      sb.addEventListener("input", () => { state.search = sb.value; render(); });
    }
  }

  render();
}

// --- AI Providers helpers ---

// Hard-coded display catalog so the grid always shows the same 8 cards,
// even before any are configured. Matches the admin dashboard. Models lists
// are short illustrative examples — the real per-provider model list comes
// from the AI router when status reports back.
const AI_PROVIDER_CATALOG = [
  { id: "openai",     name: "OpenAI",          icon: "🤖", models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3-mini"] },
  { id: "anthropic",  name: "Anthropic",       icon: "🧠", models: ["claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-3-5"] },
  { id: "google",     name: "Google AI",       icon: "🔵", models: ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"] },
  { id: "amazon",     name: "Amazon Bedrock",  icon: "☁️",  models: ["amazon.titan-text-express-v1", "meta.llama3-70b"] },
  { id: "microsoft",  name: "Microsoft Azure", icon: "🪟", models: ["gpt-4o-azure", "gpt-35-turbo"] },
  { id: "xai",        name: "xAI Grok",        icon: "✖️",  models: ["grok-3", "grok-3-mini"] },
  { id: "meta",       name: "Meta LLaMA",      icon: "🦙", models: ["llama-3.3-70b-instruct", "llama-3.1-405b"] },
  { id: "perplexity", name: "Perplexity",      icon: "🔍", models: ["sonar-pro", "sonar", "sonar-reasoning"] },
];

async function viewProviders() {
  $("#pageTitle").textContent = "AI Providers";
  $("#pageSubtitle").textContent = "Configure tenant-scoped credentials for the AI providers your applications use";
  const isAdmin = session.role === "tenant_admin";

  // /api/customer/providers comes back as either an array of provider rows
  // or a {providers:[...]} object depending on the AI router version. Be
  // tolerant of both. Each row has provider_id + configured boolean.
  let configuredMap = {};
  try {
    const resp = await api("/api/customer/providers");
    const rows = Array.isArray(resp) ? resp : (resp && resp.providers) || [];
    rows.forEach((p) => {
      const id = p.provider_id || p.id || p.provider;
      if (id) configuredMap[id] = p;
    });
  } catch {
    // Non-fatal — render the grid in "Unknown" state and let the user
    // configure providers anyway.
  }

  const adminBanner = isAdmin
    ? ""
    : `<div class="rounded-2xl border border-amber-900/60 bg-amber-950/30 p-3 text-xs text-amber-200">View only — tenant admins can configure provider credentials.</div>`;

  function providerCard(p) {
    const status = configuredMap[p.id];
    const isCfg = status && status.configured;
    const statusBadge = isCfg
      ? `<span class="inline-flex items-center rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-200">Configured</span>`
      : `<span class="inline-flex items-center rounded-full bg-slate-700/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-300">Not configured</span>`;
    const modelsHtml = p.models.slice(0, 3).map((m) =>
      `<code class="rounded bg-slate-950 px-1.5 py-0.5 text-[10px] font-mono text-cyan-200">${esc(m)}</code>`
    ).join(" ");
    const buttons = isAdmin
      ? `<button class="cfgProviderBtn flex-1 rounded-xl bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400" data-provider="${esc(p.id)}" data-provider-name="${esc(p.name)}" type="button">${isCfg ? "Reconfigure" : "Configure"}</button>${
          isCfg ? `<button class="testProviderBtn rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" data-provider="${esc(p.id)}" data-provider-name="${esc(p.name)}" type="button">Test</button>` : ""
        }`
      : `<div class="flex-1 rounded-xl border border-slate-800 bg-slate-900/40 px-3 py-2 text-center text-xs text-slate-500">${isCfg ? "Configured · admin to change" : "Awaiting admin setup"}</div>`;
    return `
      <div class="rounded-2xl border border-slate-800 bg-slate-950 p-5">
        <div class="flex items-start justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="text-2xl">${p.icon}</span>
            <div>
              <div class="font-semibold">${esc(p.name)}</div>
              <div class="text-xs text-slate-400">${p.models.length} models</div>
            </div>
          </div>
          ${statusBadge}
        </div>
        <div class="mt-3 flex flex-wrap gap-1.5">${modelsHtml}</div>
        <div class="mt-4 flex gap-2">${buttons}</div>
      </div>`;
  }

  $("#app").innerHTML = `
    <div class="space-y-4">
      ${adminBanner}
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">${AI_PROVIDER_CATALOG.map(providerCard).join("")}</div>
      <div id="providerPanel"></div>
    </div>
  `;

  function openConfigurePanel(pid, pname) {
    const panel = $("#providerPanel");
    if (!panel) return;
    panel.innerHTML = card(`
      <div class="flex items-baseline justify-between">
        <div class="text-lg font-semibold">Configure ${esc(pname)}</div>
        <button id="cfgProviderClose" type="button" class="text-xs text-slate-400 hover:text-slate-200">Cancel</button>
      </div>
      <p class="mt-1 text-xs text-slate-500">Credentials are stored server-side via the secrets service. They never echo back into the browser; the API key field is write-only.</p>
      <div class="mt-4 grid gap-4 md:grid-cols-2">
        <div class="space-y-1 md:col-span-2">
          <label class="text-xs text-slate-300">Provider API key <span class="text-rose-300">*</span></label>
          <input id="prov_key" type="password" autocomplete="off" class="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 font-mono text-sm" placeholder="${esc(pname === "OpenAI" ? "sk-…" : pname === "Anthropic" ? "sk-ant-…" : "<provider api key>")}" />
        </div>
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Base URL (optional)</label>
          <input id="prov_url" class="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="https://api.example.com/v1" />
        </div>
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Default model (optional)</label>
          <input id="prov_model" class="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="e.g. gpt-4o" />
        </div>
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Rate limit (req/min)</label>
          <input id="prov_rate" type="number" min="1" class="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="60" />
        </div>
        <div class="space-y-1">
          <label class="text-xs text-slate-300">Monthly budget (USD)</label>
          <input id="prov_budget" type="number" min="0" step="10" class="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="500" />
        </div>
      </div>
      <div class="mt-4 flex flex-wrap items-center gap-2">
        <button id="cfgProviderSave" type="button" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Save credentials</button>
        <span id="cfgProviderMsg" class="text-xs text-slate-400"></span>
      </div>
    `);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    $("#cfgProviderClose").addEventListener("click", () => { panel.innerHTML = ""; });
    $("#cfgProviderSave").addEventListener("click", async () => {
      const apiKey = $("#prov_key").value.trim();
      const msg = $("#cfgProviderMsg");
      if (!apiKey) { msg.textContent = "API key is required."; msg.className = "text-xs text-rose-300"; return; }
      msg.textContent = "Saving…";
      msg.className = "text-xs text-slate-400";
      try {
        await api(`/api/customer/providers/${encodeURIComponent(pid)}/configure`, {
          method: "POST",
          body: JSON.stringify({
            api_key: apiKey,
            base_url: $("#prov_url").value.trim() || null,
            default_model: $("#prov_model").value.trim() || null,
            rate_limit_per_minute: parseInt($("#prov_rate").value || "60", 10),
            monthly_budget_usd: parseFloat($("#prov_budget").value || "500"),
          }),
        });
        msg.textContent = `${pname} configured.`;
        msg.className = "text-xs text-emerald-300";
        // Refresh the grid so the badge flips to "Configured".
        setTimeout(() => viewProviders(), 600);
      } catch (err) {
        msg.textContent = err.message || "Save failed";
        msg.className = "text-xs text-rose-300";
      }
    });
  }

  async function runProviderTest(pid, pname) {
    const panel = $("#providerPanel");
    panel.innerHTML = card(`<div class="text-sm text-slate-400">Testing ${esc(pname)}…</div>`);
    try {
      const status = await api(`/api/customer/providers/${encodeURIComponent(pid)}/status`);
      const ok = status && (status.configured === true || status.status === "configured");
      panel.innerHTML = card(`
        <div class="flex items-baseline justify-between">
          <div class="font-semibold">${esc(pname)} test</div>
          <button id="testProviderClose" type="button" class="text-xs text-slate-400 hover:text-slate-200">Close</button>
        </div>
        <div class="mt-3">
          ${ok
            ? `<div class="rounded-xl border border-emerald-900 bg-emerald-950/30 p-3 text-sm text-emerald-200">Credentials present. The AI router can resolve ${esc(pname)} for this tenant.</div>`
            : `<div class="rounded-xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">No credentials resolved for ${esc(pname)} on this tenant.</div>`}
        </div>
        <details class="mt-3 rounded-xl border border-slate-800 bg-slate-900/40 p-3">
          <summary class="cursor-pointer text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Raw status</summary>
          <pre class="mt-2 overflow-auto text-xs text-slate-300">${esc(JSON.stringify(status, null, 2))}</pre>
        </details>
      `);
      $("#testProviderClose").addEventListener("click", () => { panel.innerHTML = ""; });
    } catch (err) {
      panel.innerHTML = card(`<div class="text-sm text-rose-300">${esc(err.message)}</div>`);
    }
  }

  document.querySelectorAll(".cfgProviderBtn").forEach((btn) => {
    btn.addEventListener("click", () => openConfigurePanel(btn.dataset.provider, btn.dataset.providerName));
  });
  document.querySelectorAll(".testProviderBtn").forEach((btn) => {
    btn.addEventListener("click", () => runProviderTest(btn.dataset.provider, btn.dataset.providerName));
  });
}

// Time windows for the Agent Directory. Filters client-side off the
// merged risk-events feed (same convention as the Action Graph).
const AGENT_WINDOWS = [
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d",  label: "Last 7d",  ms: 7  * 24 * 60 * 60 * 1000 },
  { id: "30d", label: "Last 30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All time", ms: null },
];

const AGENT_KIND_META = {
  endpoint:  { label: "Endpoint",  tone: "emerald", icon: "💻" },
  extension: { label: "Extension", tone: "cyan",    icon: "🧩" },
  sdk:       { label: "SDK",       tone: "violet",  icon: "📦" },
  proxy:     { label: "Proxy",     tone: "amber",   icon: "🛰" },
  unknown:   { label: "Unknown",   tone: "slate",   icon: "❓" },
};

function agentKindPill(kind) {
  const meta = AGENT_KIND_META[kind] || AGENT_KIND_META.unknown;
  const cls = {
    emerald: "bg-emerald-500/20 text-emerald-200",
    cyan:    "bg-cyan-500/20    text-cyan-200",
    violet:  "bg-violet-500/20  text-violet-200",
    amber:   "bg-amber-500/20   text-amber-200",
    slate:   "bg-slate-700/40   text-slate-200",
  }[meta.tone] || "bg-slate-700/40 text-slate-200";
  return `<span class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${cls}">${meta.icon} ${esc(meta.label)}</span>`;
}

// Infer agent kind from the underlying event source. The risk-events
// projection carries the raw telemetry source in details.source for
// endpoint/extension writes; audit-graph events carry source on the row.
function inferAgentKind(events, endpointAgentIds) {
  if (events.some((ev) => endpointAgentIds.has(ev.agent_id))) return "endpoint";
  const sources = new Set();
  for (const ev of events) {
    const s = String(((ev.details && ev.details.source) || ev.provider || ev.source || "")).toLowerCase();
    if (s) sources.add(s);
  }
  if (sources.has("browser_extension")) return "extension";
  if (sources.has("endpoint") || sources.has("endpoint_clipboard_helper")) return "endpoint";
  if (sources.has("proxy_agent") || sources.has("rasp")) return "proxy";
  if (sources.has("sdk") || sources.has("runtime")) return "sdk";
  return "unknown";
}

async function viewAgents() {
  $("#pageTitle").textContent = "Agent Directory";
  $("#pageSubtitle").textContent = "AI agent identities seen in tenant audit + telemetry, plus endpoint fleet";

  let tab = "ai";          // "ai" | "endpoints"
  let windowId = "7d";
  let kindFilter = "all";  // "all" | one of AGENT_KIND_META keys
  let search = "";
  let selectedAgentId = null;
  const aiPager = { page: 1, pageSize: 50 };

  let allEvents = [];
  let sources = null;
  let endpointAgents = [];
  let eventsError = null;
  let endpointsError = null;

  async function load() {
    const [evRes, agRes] = await Promise.allSettled([
      api("/api/customer/risk/events?limit=500"),
      api("/api/customer/agents?limit=500"),
    ]);
    if (evRes.status === "fulfilled") {
      const r = evRes.value;
      allEvents = Array.isArray(r) ? r : (r && r.events) || [];
      sources = (r && r.sources) || null;
      eventsError = null;
    } else {
      allEvents = []; eventsError = evRes.reason?.message || "event fetch failed";
    }
    if (agRes.status === "fulfilled") {
      endpointAgents = Array.isArray(agRes.value) ? agRes.value : [];
      endpointsError = null;
    } else {
      endpointAgents = []; endpointsError = agRes.reason?.message || "agent fetch failed";
    }
  }

  function eventsInWindow() {
    const w = AGENT_WINDOWS.find((x) => x.id === windowId);
    if (!w || w.ms == null) return allEvents;
    const cutoff = Date.now() - w.ms;
    return allEvents.filter((ev) => {
      const t = Date.parse(ev.timestamp || "");
      return Number.isFinite(t) && t >= cutoff;
    });
  }

  // Aggregate per-agent stats. The directory is a *union* of:
  //   - agents seen as ev.agent_id in audit/telemetry
  //   - registered endpoint agents that may not have events in window
  // Endpoint agents with no events still show up so an operator can
  // confirm they're enrolled but quiet.
  function buildAgents(events) {
    const endpointIds = new Set(endpointAgents.map((a) => a.agent_id).filter(Boolean));
    const endpointByAgentId = new Map(endpointAgents.map((a) => [a.agent_id, a]));
    const map = new Map();

    for (const ev of events) {
      const aid = ev.agent_id;
      if (!aid) continue;
      let a = map.get(aid);
      if (!a) {
        a = {
          agent_id: aid, kind: "unknown", events: 0, blocked: 0, redacted: 0,
          providers: new Set(), models: new Set(), tools: new Set(), actions: new Set(),
          users: new Set(), hosts: new Set(), latestTs: 0, _events: [],
        };
        map.set(aid, a);
      }
      a._events.push(ev);
      a.events++;
      const outcome = String(ev.outcome || "").toLowerCase();
      if (outcome === "blocked") a.blocked++;
      if (outcome === "redacted") a.redacted++;
      const det = ev.details || {};
      if (ev.provider) a.providers.add(ev.provider);
      if (det.provider) a.providers.add(det.provider);
      if (ev.model) a.models.add(ev.model);
      if (det.model || det.model_id) a.models.add(det.model || det.model_id);
      if (det.tool_name || det.tool) a.tools.add(det.tool_name || det.tool);
      if (ev.action || ev.event_type) a.actions.add(ev.action || ev.event_type);
      const user = ev.human_id || det.user_id || det.username || det.human_id;
      if (user) a.users.add(user);
      if (ev.hostname || det.hostname) a.hosts.add(ev.hostname || det.hostname);
      const ts = Date.parse(ev.timestamp || "") || 0;
      if (ts > a.latestTs) a.latestTs = ts;
    }

    // Backfill endpoints that have no events in the window so the
    // operator can still see they're enrolled. Marked kind=endpoint.
    for (const ep of endpointAgents) {
      const aid = ep.agent_id;
      if (!aid) continue;
      if (!map.has(aid)) {
        map.set(aid, {
          agent_id: aid, kind: "endpoint", events: 0, blocked: 0, redacted: 0,
          providers: new Set(), models: new Set(), tools: new Set(), actions: new Set(),
          users: new Set(ep.username ? [ep.username] : []),
          hosts: new Set(ep.hostname ? [ep.hostname] : []),
          latestTs: ep.last_seen ? Date.parse(ep.last_seen) || 0 : 0,
          _events: [], _endpoint: ep,
        });
      } else {
        map.get(aid)._endpoint = ep;
      }
    }

    // Resolve kind for every entry.
    for (const a of map.values()) {
      a.kind = inferAgentKind(a._events, endpointIds);
      if (a._endpoint && a.kind === "unknown") a.kind = "endpoint";
    }
    return [...map.values()];
  }

  function passesFilter(a) {
    if (kindFilter !== "all" && a.kind !== kindFilter) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    if (a.agent_id && a.agent_id.toLowerCase().includes(q)) return true;
    for (const u of a.users) if (String(u).toLowerCase().includes(q)) return true;
    for (const h of a.hosts) if (String(h).toLowerCase().includes(q)) return true;
    for (const p of a.providers) if (String(p).toLowerCase().includes(q)) return true;
    for (const m of a.models) if (String(m).toLowerCase().includes(q)) return true;
    return false;
  }

  function summaryRow(agents, events) {
    const kinds = {};
    let blocked = 0;
    const providers = new Set();
    for (const a of agents) {
      kinds[a.kind] = (kinds[a.kind] || 0) + 1;
      blocked += a.blocked;
      for (const p of a.providers) providers.add(p);
    }
    return `
      <div class="flex flex-wrap items-center gap-4">
        <div class="flex flex-col leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">Total agents</span>
          <span class="text-2xl font-semibold tabular-nums">${agents.length}</span>
        </div>
        <div class="mx-2 h-10 w-px bg-slate-800"></div>
        ${Object.entries(AGENT_KIND_META).filter(([k]) => k !== "unknown" || kinds.unknown).map(([k, meta]) => `
          <div class="flex items-center gap-2 rounded-2xl border border-slate-800 bg-slate-900/60 px-3 py-2">
            <span class="text-sm">${meta.icon}</span>
            <div class="flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">${esc(meta.label)}</span>
              <span class="font-mono text-sm tabular-nums">${kinds[k] || 0}</span>
            </div>
          </div>
        `).join("")}
        <div class="mx-2 h-10 w-px bg-slate-800"></div>
        <div class="flex flex-col leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">Events</span>
          <span class="font-mono text-sm tabular-nums">${events.length}</span>
        </div>
        <div class="flex flex-col leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">Blocked</span>
          <span class="font-mono text-sm tabular-nums ${blocked > 0 ? "text-rose-300" : ""}">${blocked}</span>
        </div>
        <div class="flex flex-col leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">Providers</span>
          <span class="font-mono text-sm tabular-nums">${providers.size}</span>
        </div>
        <div class="ml-auto flex flex-col leading-tight">
          <span class="text-[10px] uppercase tracking-wider text-slate-500">Time window</span>
          <div class="mt-1 flex flex-wrap gap-1" id="agentsWindowPicker">
            ${AGENT_WINDOWS.map((w) => `
              <button type="button" data-window-id="${w.id}" class="rounded-full px-2 py-1 text-[11px] ${windowId === w.id ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(w.label)}</button>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  }

  function filtersRow() {
    const allBtn = (k, label) => {
      const isOn = kindFilter === k;
      return `<button data-kind-filter="${k}" type="button" class="agentKindFilter rounded-full px-2 py-1 text-[11px] ${isOn ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(label)}</button>`;
    };
    return `
      <div class="flex flex-wrap items-center gap-2">
        <input id="agentSearch" type="search" placeholder="Search agent ID, user, host, provider, model…" class="flex-1 min-w-[260px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="${esc(search)}" />
        <div class="flex flex-wrap gap-1">
          ${allBtn("all", "All")}
          ${Object.entries(AGENT_KIND_META).map(([k, m]) => allBtn(k, m.label)).join("")}
        </div>
      </div>
    `;
  }

  function aiAgentRow(a) {
    const sel = selectedAgentId === a.agent_id;
    const lastSeen = a.latestTs ? new Date(a.latestTs).toLocaleString() : "—";
    const peers = [...a.providers].slice(0, 2).join(", ");
    return `<tr class="border-t border-slate-800 cursor-pointer ${sel ? "bg-cyan-500/5" : "hover:bg-slate-900/60"}" data-agent-id="${esc(a.agent_id)}">
      <td class="px-3 py-2"><div class="font-mono text-xs text-slate-100 break-all">${esc(a.agent_id)}</div>${peers ? `<div class="text-[10px] text-slate-500">${esc(peers)}</div>` : ""}</td>
      <td class="px-3 py-2">${agentKindPill(a.kind)}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${a.events}</td>
      <td class="px-3 py-2 text-xs tabular-nums ${a.blocked > 0 ? "text-rose-300" : ""}">${a.blocked}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${a.providers.size}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${a.models.size + a.tools.size}</td>
      <td class="px-3 py-2 text-xs tabular-nums">${a.users.size}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(lastSeen)}</td>
    </tr>`;
  }

  function detailPanel(agents) {
    if (!selectedAgentId) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
        <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Inspector</div>
        Click any agent in the table to see providers, models, recent events, and (if applicable) endpoint details.
      </div>`;
    }
    const a = agents.find((x) => x.agent_id === selectedAgentId);
    if (!a) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">Agent not in current filter/window.</div>`;
    }
    const recent = (a._events || []).slice(0, 8);
    const setRow = (label, set) => set.size === 0
      ? `<div class="rounded-lg bg-slate-900 px-2 py-1.5 text-xs text-slate-500">${esc(label)}: none</div>`
      : `<div class="rounded-lg bg-slate-900 px-2 py-1.5">
          <div class="text-[10px] uppercase tracking-wider text-slate-500">${esc(label)} (${set.size})</div>
          <div class="mt-1 flex flex-wrap gap-1">${[...set].map((v) => `<span class="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-200">${esc(String(v))}</span>`).join("")}</div>
        </div>`;
    const endpointBlock = a._endpoint ? `
      <div class="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Endpoint enrollment</div>
        <div class="text-xs text-slate-200">${esc(a._endpoint.hostname || "—")}</div>
        <div class="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-400">
          <span>OS: ${esc(a._endpoint.platform || a._endpoint.os || "—")}</span>
          <span>v${esc(a._endpoint.version || "—")}</span>
          <span>Health: ${esc(a._endpoint.health || "unknown")}</span>
        </div>
      </div>` : "";
    return `
      <div class="rounded-2xl border border-slate-800 bg-slate-950 p-4">
        <div class="flex items-baseline justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[10px] uppercase tracking-wider text-slate-500">Agent</div>
            <div class="font-mono text-sm text-slate-100 break-all">${esc(a.agent_id)}</div>
          </div>
          <button id="agentClearSelection" type="button" class="text-xs text-slate-400 hover:text-slate-200">Clear</button>
        </div>
        <div class="mt-2">${agentKindPill(a.kind)}</div>
        <div class="mt-3 grid grid-cols-3 gap-2">
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Events</div><div class="text-lg font-semibold tabular-nums">${a.events}</div></div>
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Blocked</div><div class="text-lg font-semibold tabular-nums ${a.blocked > 0 ? "text-rose-300" : ""}">${a.blocked}</div></div>
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Redacted</div><div class="text-lg font-semibold tabular-nums ${a.redacted > 0 ? "text-amber-300" : ""}">${a.redacted}</div></div>
        </div>
        ${endpointBlock}
        <div class="mt-3 space-y-1">
          ${setRow("Providers", a.providers)}
          ${setRow("Models", a.models)}
          ${setRow("Tools", a.tools)}
          ${setRow("Users", a.users)}
          ${setRow("Hosts", a.hosts)}
        </div>
        <div class="mt-4">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Recent events (${recent.length} of ${a._events.length})</div>
          ${recent.length === 0 ? `<div class="text-xs text-slate-500">No events in window.</div>` : `
            <div class="space-y-1">${recent.map((ev) => {
              const outcome = String(ev.outcome || "ok").toLowerCase();
              const tone = outcome === "blocked" ? "bg-rose-500/20 text-rose-200"
                         : outcome === "warn" || outcome === "redacted" ? "bg-amber-500/20 text-amber-200"
                         : "bg-slate-700/40 text-slate-200";
              return `<div class="rounded-lg bg-slate-900 px-2 py-1.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="font-mono text-xs text-slate-200 truncate">${esc(String(ev.action || ev.event_type || ""))}</span>
                  <span class="rounded-full px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${tone}">${esc(outcome)}</span>
                </div>
                <div class="mt-0.5 text-[10px] text-slate-500">${esc(ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "")}</div>
              </div>`;
            }).join("")}</div>
          `}
        </div>
        <div class="mt-3 flex flex-wrap gap-2">
          <a class="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800" href="#/graph">Open in Action Graph</a>
          ${a._endpoint ? `<a class="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-800" href="#/endpoints">Endpoints page</a>` : ""}
        </div>
      </div>
    `;
  }

  async function renderAiTab() {
    const events = eventsInWindow();
    const agents = buildAgents(events);
    const filtered = agents.filter(passesFilter)
      .sort((a, b) => (b.blocked - a.blocked) || (b.events - a.events) || (b.latestTs - a.latestTs));

    const pager = simplePager({ total: filtered.length, state: aiPager, idPrefix: "agentDir" });
    const pageRows = pager.sliced(filtered);
    return `
      <div class="space-y-4">
        ${eventsError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load events: ${esc(eventsError)}.</div>` : ""}
        ${card(summaryRow(filtered, events))}
        ${card(filtersRow())}
        <div class="grid gap-4 lg:grid-cols-[1fr_380px]">
          ${card(`
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <thead class="text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th class="px-3 py-2">Agent</th>
                    <th class="px-3 py-2">Kind</th>
                    <th class="px-3 py-2">Events</th>
                    <th class="px-3 py-2">Blocked</th>
                    <th class="px-3 py-2">Providers</th>
                    <th class="px-3 py-2">Models / Tools</th>
                    <th class="px-3 py-2">Users</th>
                    <th class="px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody id="aiAgentRows">
                  ${pageRows.length === 0
                    ? `<tr><td colspan="8" class="px-3 py-8 text-center text-sm text-slate-500">No agents match the current filter / window.</td></tr>`
                    : pageRows.map(aiAgentRow).join("")}
                </tbody>
              </table>
            </div>
            ${filtered.length > 0 ? pager.html : ""}
            ${sources ? `<div class="mt-3 text-[11px] text-slate-500">Sources: ${sources.audit_graph ?? 0} audit + ${sources.telemetry ?? 0} telemetry</div>` : ""}
          `)}
          <div>${detailPanel(filtered)}</div>
        </div>
      </div>
    `;
  }

  async function render() {
    const tabsHtml = `
      <div class="flex flex-wrap gap-2">
        ${tabButton("ai", `AI Agents`, tab === "ai")}
        ${tabButton("endpoints", `Endpoint Agents`, tab === "endpoints")}
      </div>
    `;

    if (tab === "endpoints") {
      // Defer to the existing endpoints view — it owns its summary cards,
      // table, and downloads section. Then inject our tab bar at the top
      // so the operator can still switch back to AI Agents.
      await viewEndpoints();
      $("#pageTitle").textContent = "Agent Directory";
      $("#pageSubtitle").textContent = "AI agent identities seen in tenant audit + telemetry, plus endpoint fleet";
      const appEl = $("#app");
      if (appEl) appEl.insertAdjacentHTML("afterbegin", `<div class="mb-3">${tabsHtml}</div>`);
      wireTabs();
      return;
    }

    const body = await renderAiTab();
    $("#app").innerHTML = `<div class="space-y-3">${tabsHtml}${body}</div>`;
    wireTabs();
    wireAiTab();
  }

  function wireTabs() {
    document.querySelectorAll(".sectionTab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const t = btn.dataset.tab;
        if (!t || t === tab) return;
        tab = t;
        // Reset transient inspector state when leaving AI tab.
        if (tab !== "ai") selectedAgentId = null;
        render();
      });
    });
  }

  function wireAiTab() {
    document.querySelectorAll("#agentsWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (windowId === btn.dataset.windowId) return;
        windowId = btn.dataset.windowId;
        selectedAgentId = null;
        aiPager.page = 1;
        render();
      });
    });
    document.querySelectorAll(".agentKindFilter").forEach((btn) => {
      btn.addEventListener("click", () => {
        kindFilter = btn.dataset.kindFilter;
        selectedAgentId = null;
        aiPager.page = 1;
        render();
      });
    });
    {
      // Recompute total against the same filter the render pass used so
      // the pager renders consistent button states.
      const events = eventsInWindow();
      const filtered = buildAgents(events).filter(passesFilter);
      const pager = simplePager({ total: filtered.length, state: aiPager, idPrefix: "agentDir" });
      pager.wire(document, () => render());
    }
    const sb = $("#agentSearch");
    if (sb) {
      sb.addEventListener("input", () => {
        search = sb.value;
        // Search changes invalidate the page index. Re-render rows in
        // place to avoid losing input focus on every keypress.
        aiPager.page = 1;
        const events = eventsInWindow();
        const filtered = buildAgents(events).filter(passesFilter)
          .sort((a, b) => (b.blocked - a.blocked) || (b.events - a.events) || (b.latestTs - a.latestTs));
        const pager = simplePager({ total: filtered.length, state: aiPager, idPrefix: "agentDir" });
        const pageRows = pager.sliced(filtered);
        const tbody = $("#aiAgentRows");
        if (tbody) {
          tbody.innerHTML = pageRows.length === 0
            ? `<tr><td colspan="8" class="px-3 py-8 text-center text-sm text-slate-500">No agents match the current filter / window.</td></tr>`
            : pageRows.map(aiAgentRow).join("");
          bindRowClicks();
        }
      });
    }
    bindRowClicks();
    const clearBtn = $("#agentClearSelection");
    if (clearBtn) clearBtn.addEventListener("click", () => { selectedAgentId = null; render(); });
  }

  function bindRowClicks() {
    document.querySelectorAll("#aiAgentRows tr[data-agent-id]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const aid = tr.dataset.agentId;
        selectedAgentId = (selectedAgentId === aid) ? null : aid;
        render();
      });
    });
  }

  await load();
  await render();
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

// Time windows for the action graph. Matches the convention used by the
// compliance and telemetry views. All filtering is client-side because
// /customer/risk/events is limit-based; we ask for the cap and prune.
const GRAPH_WINDOWS = [
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d",  label: "Last 7d",  ms: 7  * 24 * 60 * 60 * 1000 },
  { id: "30d", label: "Last 30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All time", ms: null },
];

const GRAPH_NODE_STYLE = {
  human:    { fill: "#1e3a8a", stroke: "#93c5fd", icon: "👤", label: "Human"    },
  agent:    { fill: "#064e3b", stroke: "#6ee7b7", icon: "🤖", label: "Agent"    },
  provider: { fill: "#713f12", stroke: "#fcd34d", icon: "🛰", label: "Provider" },
  model:    { fill: "#4c1d95", stroke: "#c4b5fd", icon: "🧠", label: "Model"    },
  tool:     { fill: "#7c2d12", stroke: "#fdba74", icon: "🔧", label: "Tool"     },
  action:   { fill: "#7f1d1d", stroke: "#fca5a5", icon: "⚡", label: "Action"   },
};

const GRAPH_OUTCOME_TONE = {
  blocked:  "#f43f5e",
  warn:     "#f59e0b",
  redacted: "#f59e0b",
  allow:    "#10b981",
  ok:       "#22d3ee",
};

async function viewGraph() {
  $("#pageTitle").textContent = "Action Graph";
  $("#pageSubtitle").textContent = "Tenant agent ↔ provider ↔ model/tool action chains, derived from audit + endpoint telemetry";

  // Local view state. `windowId` persists across re-renders; `selected` is
  // the clicked node key (or null) and drives the right-side detail panel.
  let windowId = "7d";
  let selected = null;
  let allEvents = [];
  let sources = null;
  let fetchError = null;
  const recentPager = { page: 1, pageSize: 25 };

  async function load() {
    try {
      const resp = await api("/api/customer/risk/events?limit=500");
      allEvents = Array.isArray(resp) ? resp : (resp && resp.events) || [];
      sources = (resp && resp.sources) || null;
      fetchError = null;
    } catch (err) {
      allEvents = [];
      fetchError = err.message || "event fetch failed";
    }
  }

  function eventsInWindow() {
    const w = GRAPH_WINDOWS.find((x) => x.id === windowId);
    if (!w || w.ms == null) return allEvents;
    const cutoff = Date.now() - w.ms;
    return allEvents.filter((ev) => {
      const t = Date.parse(ev.timestamp || "");
      return Number.isFinite(t) && t >= cutoff;
    });
  }

  // Build the columnar graph: human(0) → agent(1) → provider(2) → model/tool(3) → action(4).
  // Nodes are keyed by `${type}:${id}` so the same string appearing as both
  // a model and a tool stays distinct. Edges are aggregated by (from,to) and
  // tinted by the worst outcome observed across them.
  function buildGraph(events) {
    const nodes = new Map();
    const edgeMap = new Map();
    const addNode = (type, id, column) => {
      if (!id) return null;
      const key = `${type}:${id}`;
      if (!nodes.has(key)) {
        nodes.set(key, { key, type, id, column, events: 0, blocked: 0, latestTs: 0 });
      }
      return key;
    };
    const addEdge = (from, to, outcome, ts) => {
      if (!from || !to) return;
      const key = `${from}|${to}`;
      let e = edgeMap.get(key);
      if (!e) { e = { from, to, count: 0, blocked: 0, latestTs: 0, outcomes: {} }; edgeMap.set(key, e); }
      e.count++;
      e.outcomes[outcome] = (e.outcomes[outcome] || 0) + 1;
      if (outcome === "blocked") e.blocked++;
      if (ts > e.latestTs) e.latestTs = ts;
    };
    const bumpNode = (key, outcome, ts) => {
      const n = nodes.get(key);
      if (!n) return;
      n.events++;
      if (outcome === "blocked") n.blocked++;
      if (ts > n.latestTs) n.latestTs = ts;
    };

    for (const ev of events) {
      const ts = Date.parse(ev.timestamp || "") || 0;
      const outcome = String(ev.outcome || "ok").toLowerCase();
      const human = ev.human_id || (ev.details && (ev.details.human_id || ev.details.user_id || ev.details.username));
      const agent = ev.agent_id || (ev.details && ev.details.agent_id);
      const provider = ev.provider || (ev.details && ev.details.provider);
      const model = ev.model || (ev.details && (ev.details.model || ev.details.model_id));
      const tool = ev.details && (ev.details.tool_name || ev.details.tool);
      const action = ev.action || ev.event_type || "event";

      const hk = addNode("human", human, 0);
      const ak = addNode("agent", agent, 1);
      const pk = addNode("provider", provider, 2);
      const mk = addNode("model", model, 3);
      const tk = addNode("tool", tool, 3);
      const xk = addNode("action", action, 4);

      [hk, ak, pk, mk, tk, xk].forEach((k) => { if (k) bumpNode(k, outcome, ts); });
      // Chain edges; skip missing links so a thin event (e.g., agent → action
      // only) still draws a line rather than dropping out of the graph.
      const chain = [hk, ak, pk || mk || tk, mk || tk, xk].filter(Boolean);
      for (let i = 0; i < chain.length - 1; i++) addEdge(chain[i], chain[i + 1], outcome, ts);
      // Cross-link model ↔ tool when both present so callers see the pair.
      if (mk && tk) addEdge(mk, tk, outcome, ts);
    }
    return { nodes: [...nodes.values()], edges: [...edgeMap.values()] };
  }

  function renderSvg(graph) {
    const { nodes, edges } = graph;
    if (nodes.length === 0) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-8 text-center text-sm text-slate-400">No graph data in this window yet. Send telemetry, run an SDK workflow, or pick a wider time range.</div>`;
    }
    const cols = new Map();
    for (const n of nodes) {
      if (!cols.has(n.column)) cols.set(n.column, []);
      cols.get(n.column).push(n);
    }
    // Stable per-column ordering: most-used nodes near the top so the chart
    // reads top-down by signal strength rather than insertion order.
    for (const list of cols.values()) list.sort((a, b) => b.events - a.events || a.id.localeCompare(b.id));
    const colCount = 5;
    const maxRows = Math.max(1, ...[...cols.values()].map((l) => l.length));
    const W = 1180;
    const H = Math.max(380, maxRows * 78 + 80);
    const xFor = (c) => 90 + c * ((W - 180) / (colCount - 1));
    const yFor = (n) => {
      const list = cols.get(n.column) || [];
      const idx = list.findIndex((x) => x.key === n.key);
      const gap = H / (list.length + 1);
      return Math.round(gap * (idx + 1));
    };

    const edgeSvg = edges.map((e) => {
      const f = nodes.find((n) => n.key === e.from);
      const t = nodes.find((n) => n.key === e.to);
      if (!f || !t) return "";
      const x1 = xFor(f.column) + 60;
      const y1 = yFor(f);
      const x2 = xFor(t.column) - 60;
      const y2 = yFor(t);
      const midX = Math.round((x1 + x2) / 2);
      const dominantOutcome = Object.entries(e.outcomes).sort((a, b) => b[1] - a[1])[0]?.[0] || "ok";
      const stroke = e.blocked > 0 ? GRAPH_OUTCOME_TONE.blocked : (GRAPH_OUTCOME_TONE[dominantOutcome] || "#64748b");
      const width = Math.max(1, Math.min(5, 1 + Math.log2(e.count + 1)));
      const isFaded = selected && selected !== e.from && selected !== e.to;
      const opacity = isFaded ? 0.15 : 0.9;
      return `<path d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}" stroke="${stroke}" stroke-width="${width}" fill="none" opacity="${opacity}" marker-end="url(#graphArrow)"></path>
        <title>${esc(`${e.count} event${e.count === 1 ? "" : "s"}${e.blocked ? ` · ${e.blocked} blocked` : ""}`)}</title>`;
    }).join("");

    const nodeSvg = nodes.map((n) => {
      const s = GRAPH_NODE_STYLE[n.type] || GRAPH_NODE_STYLE.action;
      const x = xFor(n.column);
      const y = yFor(n);
      const isSel = selected === n.key;
      const isFaded = selected && !isSel;
      const opacity = isFaded ? 0.3 : 1;
      const strokeW = isSel ? 2.5 : 1.5;
      const ringR = isSel ? 32 : 0;
      const blockedDot = n.blocked > 0
        ? `<circle cx="50" cy="-22" r="9" fill="#0f172a" stroke="${GRAPH_OUTCOME_TONE.blocked}" stroke-width="1.5"></circle><text x="50" y="-19" text-anchor="middle" fill="${GRAPH_OUTCOME_TONE.blocked}" font-size="10" font-weight="700">${n.blocked > 9 ? "9+" : n.blocked}</text>`
        : "";
      const labelTxt = String(n.id).slice(0, 18) + (String(n.id).length > 18 ? "…" : "");
      return `<g class="graphNode" data-node-key="${esc(n.key)}" style="cursor:pointer;opacity:${opacity}" transform="translate(${x},${y})">
        ${isSel ? `<circle r="${ringR}" fill="none" stroke="${s.stroke}" stroke-width="1.5" stroke-dasharray="3 3" opacity="0.7"></circle>` : ""}
        <rect x="-60" y="-24" width="120" height="48" rx="14" fill="${s.fill}" stroke="${s.stroke}" stroke-width="${strokeW}"></rect>
        <text x="-48" y="6" font-size="16">${s.icon}</text>
        <text x="-28" y="-4" fill="#f8fafc" font-size="10" font-weight="700">${esc(s.label.toUpperCase())}</text>
        <text x="-28" y="11" fill="#cbd5e1" font-size="10" font-family="monospace">${esc(labelTxt)}</text>
        ${blockedDot}
        <title>${esc(n.id)} · ${n.events} event${n.events === 1 ? "" : "s"}${n.blocked ? ` · ${n.blocked} blocked` : ""}</title>
      </g>`;
    }).join("");

    return `
      <div class="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-950">
        <svg id="actionGraphSvg" viewBox="0 0 ${W} ${H}" class="min-w-[1080px] w-full" role="img" aria-label="Tenant action graph">
          <defs>
            <marker id="graphArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"></path>
            </marker>
          </defs>
          ${edgeSvg}${nodeSvg}
        </svg>
      </div>`;
  }

  function detailPanel(events, graph) {
    if (!selected) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
        <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Inspector</div>
        Click any node in the graph to see its events, peers, and decisions.
      </div>`;
    }
    const node = graph.nodes.find((n) => n.key === selected);
    if (!node) {
      return `<div class="rounded-2xl border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">Selected node is no longer in this window.</div>`;
    }
    const s = GRAPH_NODE_STYLE[node.type] || GRAPH_NODE_STYLE.action;
    const nodeEvents = events.filter((ev) => eventReferencesNode(ev, node));
    const peerMap = new Map();
    for (const e of graph.edges) {
      if (e.from !== node.key && e.to !== node.key) continue;
      const peerKey = e.from === node.key ? e.to : e.from;
      const peer = graph.nodes.find((n) => n.key === peerKey);
      if (!peer) continue;
      const p = peerMap.get(peerKey) || { peer, count: 0, blocked: 0 };
      p.count += e.count;
      p.blocked += e.blocked;
      peerMap.set(peerKey, p);
    }
    const peers = [...peerMap.values()].sort((a, b) => b.count - a.count).slice(0, 8);
    const recent = nodeEvents.slice(0, 8);
    return `
      <div class="rounded-2xl border border-slate-800 bg-slate-950 p-4">
        <div class="flex items-baseline justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="inline-flex h-7 w-7 items-center justify-center rounded-lg" style="background:${s.fill}1a;color:${s.stroke}">${s.icon}</span>
            <div>
              <div class="text-[10px] uppercase tracking-wider text-slate-500">${esc(s.label)}</div>
              <div class="font-mono text-sm text-slate-100 break-all">${esc(node.id)}</div>
            </div>
          </div>
          <button id="graphClearSelection" type="button" class="text-xs text-slate-400 hover:text-slate-200">Clear</button>
        </div>
        <div class="mt-3 grid grid-cols-3 gap-2">
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Events</div><div class="text-lg font-semibold tabular-nums">${node.events}</div></div>
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Blocked</div><div class="text-lg font-semibold tabular-nums ${node.blocked > 0 ? "text-rose-300" : ""}">${node.blocked}</div></div>
          <div class="rounded-xl bg-slate-900 px-3 py-2"><div class="text-[10px] uppercase tracking-wider text-slate-500">Last seen</div><div class="text-xs text-slate-300">${node.latestTs ? esc(new Date(node.latestTs).toLocaleString()) : "—"}</div></div>
        </div>
        <div class="mt-4">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Peers (${peers.length})</div>
          ${peers.length === 0 ? `<div class="text-xs text-slate-500">No peers in this window.</div>` : `
            <div class="space-y-1">${peers.map((p) => {
              const ps = GRAPH_NODE_STYLE[p.peer.type] || GRAPH_NODE_STYLE.action;
              return `<button data-node-key="${esc(p.peer.key)}" class="graphPeerBtn flex w-full items-center justify-between rounded-lg bg-slate-900 px-2 py-1.5 text-left hover:bg-slate-800">
                <span class="flex items-center gap-2 min-w-0">
                  <span class="text-sm">${ps.icon}</span>
                  <span class="font-mono text-xs text-slate-200 truncate">${esc(p.peer.id)}</span>
                </span>
                <span class="flex items-center gap-2 text-[10px] text-slate-400">
                  <span>${p.count}</span>
                  ${p.blocked > 0 ? `<span class="rounded-full bg-rose-500/20 px-1.5 py-0.5 text-rose-200">${p.blocked} blk</span>` : ""}
                </span>
              </button>`;
            }).join("")}</div>
          `}
        </div>
        <div class="mt-4">
          <div class="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Recent events (${recent.length} of ${nodeEvents.length})</div>
          ${recent.length === 0 ? `<div class="text-xs text-slate-500">No events for this node in window.</div>` : `
            <div class="space-y-1">${recent.map((ev) => {
              const tone = String(ev.outcome || "").toLowerCase() === "blocked" ? "bg-rose-500/20 text-rose-200"
                         : String(ev.outcome || "").toLowerCase() === "warn"    ? "bg-amber-500/20 text-amber-200"
                         : "bg-slate-700/40 text-slate-200";
              return `<div class="rounded-lg bg-slate-900 px-2 py-1.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="font-mono text-xs text-slate-200 truncate">${esc(String(ev.action || ev.event_type || ""))}</span>
                  <span class="rounded-full px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${tone}">${esc(String(ev.outcome || "ok"))}</span>
                </div>
                <div class="mt-0.5 text-[10px] text-slate-500">${esc(ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "")}</div>
              </div>`;
            }).join("")}</div>
          `}
        </div>
      </div>`;
  }

  function eventReferencesNode(ev, node) {
    const det = ev.details || {};
    switch (node.type) {
      case "human":    return (ev.human_id || det.human_id || det.user_id || det.username) === node.id;
      case "agent":    return (ev.agent_id || det.agent_id) === node.id;
      case "provider": return (ev.provider || det.provider) === node.id;
      case "model":    return (ev.model || det.model || det.model_id) === node.id;
      case "tool":     return (det.tool_name || det.tool) === node.id;
      case "action":   return (ev.action || ev.event_type) === node.id;
      default: return false;
    }
  }

  function render() {
    const events = eventsInWindow();
    const graph = buildGraph(events);

    const blockedCount = events.filter((ev) => String(ev.outcome || "").toLowerCase() === "blocked").length;
    const countByType = (t) => graph.nodes.filter((n) => n.type === t).length;

    $("#app").innerHTML = `
      <div class="space-y-4">
        ${fetchError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load events: ${esc(fetchError)}.</div>` : ""}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            ${riskMetricCard("Humans",    countByType("human"),    "slate")}
            ${riskMetricCard("Agents",    countByType("agent"),    "emerald")}
            ${riskMetricCard("Providers", countByType("provider"), "amber")}
            ${riskMetricCard("Models",    countByType("model"),    "slate")}
            ${riskMetricCard("Tools",     countByType("tool"),     "slate")}
            ${riskMetricCard("Edges",     graph.edges.length,      "slate")}
            ${riskMetricCard("Blocked",   blockedCount,            blockedCount > 0 ? "rose" : "emerald")}
            <div class="ml-auto flex flex-col leading-tight">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Time window</span>
              <div class="mt-1 flex flex-wrap gap-1" id="graphWindowPicker">
                ${GRAPH_WINDOWS.map((w) => `
                  <button type="button" data-window-id="${w.id}" class="rounded-full px-2 py-1 text-[11px] ${windowId === w.id ? "bg-cyan-500 text-slate-950 font-semibold" : "bg-slate-900 border border-slate-700 text-slate-300 hover:bg-slate-800"}">${esc(w.label)}</button>
                `).join("")}
              </div>
            </div>
            <button id="graphRefreshBtn" type="button" class="rounded-2xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Refresh</button>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-400">
            ${Object.entries(GRAPH_NODE_STYLE).map(([k, s]) => `
              <span class="inline-flex items-center gap-1.5"><span class="inline-block h-2.5 w-2.5 rounded-full" style="background:${s.stroke}"></span>${esc(s.label)}</span>
            `).join("")}
            <span class="ml-2 text-slate-600">·</span>
            <span class="inline-flex items-center gap-1.5"><span class="inline-block h-0.5 w-6" style="background:${GRAPH_OUTCOME_TONE.blocked}"></span>Blocked</span>
            <span class="inline-flex items-center gap-1.5"><span class="inline-block h-0.5 w-6" style="background:${GRAPH_OUTCOME_TONE.warn}"></span>Warn / Redact</span>
            <span class="inline-flex items-center gap-1.5"><span class="inline-block h-0.5 w-6" style="background:${GRAPH_OUTCOME_TONE.ok}"></span>OK / Allow</span>
            ${sources ? `<span class="ml-auto text-[11px] text-slate-500">Sources: ${sources.audit_graph ?? 0} audit + ${sources.telemetry ?? 0} telemetry</span>` : ""}
          </div>
        `)}
        <div class="grid gap-4 lg:grid-cols-[1fr_360px]">
          <div>${renderSvg(graph)}</div>
          <div>${detailPanel(events, graph)}</div>
        </div>
        ${(() => {
          const pager = simplePager({ total: events.length, state: recentPager, idPrefix: "graphRecent" });
          const pageEvents = pager.sliced(events);
          return card(`
          <div class="font-semibold">Recent actions <span class="text-xs text-slate-500">(${events.length} total)</span></div>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500"><tr>
                <th class="px-3 py-2">Time</th><th class="px-3 py-2">Human</th><th class="px-3 py-2">Agent</th><th class="px-3 py-2">Provider</th><th class="px-3 py-2">Model / Tool</th><th class="px-3 py-2">Action</th><th class="px-3 py-2">Outcome</th>
              </tr></thead>
              <tbody>${pageEvents.map((ev) => {
                const det = ev.details || {};
                const outcome = String(ev.outcome || "ok").toLowerCase();
                const tone = outcome === "blocked" ? "bg-rose-500/20 text-rose-200"
                           : outcome === "warn" || outcome === "redacted" ? "bg-amber-500/20 text-amber-200"
                           : outcome === "allow" ? "bg-emerald-500/20 text-emerald-200"
                           : "bg-slate-700/40 text-slate-200";
                return `<tr class="border-t border-slate-800">
                  <td class="px-3 py-2 text-xs text-slate-400">${esc(ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—")}</td>
                  <td class="px-3 py-2 font-mono text-xs">${esc(String(ev.human_id || det.human_id || det.user_id || "—").slice(0, 22))}</td>
                  <td class="px-3 py-2 font-mono text-xs">${esc(String(ev.agent_id || "—").slice(0, 22))}</td>
                  <td class="px-3 py-2 font-mono text-xs">${esc(String(ev.provider || det.provider || "—").slice(0, 18))}</td>
                  <td class="px-3 py-2 font-mono text-xs">${esc(String(ev.model || det.model || det.tool_name || "—").slice(0, 24))}</td>
                  <td class="px-3 py-2 font-mono text-xs">${esc(String(ev.action || ev.event_type || "").slice(0, 26))}</td>
                  <td class="px-3 py-2"><span class="rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${tone}">${esc(outcome)}</span></td>
                </tr>`;
              }).join("") || `<tr><td colspan="7" class="px-3 py-8 text-center text-sm text-slate-500">No actions in this window.</td></tr>`}</tbody>
            </table>
          </div>
          ${events.length > 0 ? pager.html : ""}
        `);
        })()}
      </div>
    `;
    {
      const pager = simplePager({ total: events.length, state: recentPager, idPrefix: "graphRecent" });
      pager.wire(document, () => render());
    }

    // Wire up: time window picker
    document.querySelectorAll("#graphWindowPicker button").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (windowId === btn.dataset.windowId) return;
        windowId = btn.dataset.windowId;
        selected = null;
        recentPager.page = 1;
        render();
      });
    });
    // Refresh
    const refreshBtn = $("#graphRefreshBtn");
    if (refreshBtn) refreshBtn.addEventListener("click", async () => {
      refreshBtn.disabled = true;
      refreshBtn.textContent = "Loading…";
      await load();
      render();
    });
    // Node clicks (SVG)
    document.querySelectorAll(".graphNode").forEach((g) => {
      g.addEventListener("click", () => {
        const key = g.getAttribute("data-node-key");
        selected = (selected === key) ? null : key;
        render();
      });
    });
    // Peer buttons in side panel
    document.querySelectorAll(".graphPeerBtn").forEach((btn) => {
      btn.addEventListener("click", () => { selected = btn.dataset.nodeKey; render(); });
    });
    // Clear selection
    const clearBtn = $("#graphClearSelection");
    if (clearBtn) clearBtn.addEventListener("click", () => { selected = null; render(); });
  }

  await load();
  render();
}

// --- AI Risk Dashboard helpers ---

// Maps an audit-graph event to a 0..1 risk score. Prefers explicit
// risk_score fields when the SDK / agent emitted one, otherwise derives
// from the outcome + a small heuristic over event type and action.
function riskScoreFromEvent(ev) {
  const explicit = ev && (ev.risk_score ?? (ev.details && ev.details.risk_score));
  if (typeof explicit === "number" && !Number.isNaN(explicit)) {
    return Math.max(0, Math.min(1, explicit));
  }
  const outcome = String(ev.outcome || "").toLowerCase();
  const action  = String(ev.action || ev.event_type || "").toLowerCase();
  if (outcome === "blocked" || action.includes("block")) return 0.85;
  if (outcome === "denied")                              return 0.75;
  if (outcome === "warn" || action.includes("warn"))     return 0.55;
  if (outcome === "redacted" || action.includes("redact")) return 0.55;
  if (outcome === "error" || outcome === "failed")       return 0.45;
  return 0.1;
}

function riskGaugeHtml(score) {
  const pct = Math.max(0, Math.min(100, Math.round(score * 100)));
  const tone = score > 0.7 ? "bg-rose-500" : score > 0.4 ? "bg-amber-400" : "bg-emerald-400";
  return `<div class="flex items-center gap-2">
    <div class="flex-1 h-2 rounded-full bg-slate-800"><div class="${tone} h-2 rounded-full" style="width:${pct}%"></div></div>
    <span class="text-xs font-mono w-9 text-right tabular-nums text-slate-300">${pct}%</span>
  </div>`;
}

function riskMetricCard(label, value, tone, sub) {
  const cls = tone === "rose"    ? "border-rose-900 text-rose-200"
            : tone === "amber"   ? "border-amber-900 text-amber-200"
            : tone === "emerald" ? "border-emerald-900 text-emerald-200"
            : "border-slate-800 text-slate-200";
  return `<div class="rounded-2xl border ${cls} bg-slate-950 p-4">
    <div class="text-[10px] uppercase tracking-wider text-slate-500">${esc(label)}</div>
    <div class="mt-1 text-2xl font-semibold tabular-nums">${esc(String(value))}</div>
    ${sub ? `<div class="mt-1 text-[11px] text-slate-500">${esc(sub)}</div>` : ""}
  </div>`;
}

async function viewRisk() {
  $("#pageTitle").textContent = "AI Risk Dashboard";
  $("#pageSubtitle").textContent = "Aggregate posture across audit events: blocked actions, risky agents, and recommendations";

  let events = [];
  let sourceBreakdown = null;
  let fetchError = null;
  try {
    const resp = await api("/api/customer/risk/events?limit=500");
    events = Array.isArray(resp) ? resp : (resp && resp.events) || [];
    if (resp && resp.sources) sourceBreakdown = resp.sources;
  } catch (err) {
    fetchError = err.message || "event fetch failed";
  }

  // Aggregate. agentRisk[id] = {events, blocked, riskSum, latestTs, models}
  const agentRisk = {};
  let blocked = 0, highRisk = 0, riskTotal = 0;
  for (const ev of events) {
    const aid = ev.agent_id || "unknown";
    const a = (agentRisk[aid] ||= { events: 0, blocked: 0, riskSum: 0, latestTs: 0, models: new Set() });
    a.events++;
    const rs = riskScoreFromEvent(ev);
    a.riskSum += rs;
    riskTotal += rs;
    if (rs > 0.7) highRisk++;
    if (String(ev.outcome || "").toLowerCase() === "blocked" || /block/i.test(ev.action || "")) {
      a.blocked++;
      blocked++;
    }
    const model = ev.model || (ev.details && ev.details.model);
    if (model) a.models.add(model);
    const ts = ev.timestamp ? Date.parse(ev.timestamp) : 0;
    if (ts > a.latestTs) a.latestTs = ts;
  }
  const avgRisk = events.length ? riskTotal / events.length : 0;

  // Top 10 agents by avg-risk score (highest first)
  const topAgents = Object.entries(agentRisk)
    .map(([id, r]) => ({ id, ...r, avg: r.events ? r.riskSum / r.events : 0 }))
    .sort((a, b) => b.avg - a.avg)
    .slice(0, 10);

  // High-risk events list (top 8 by score, recent first as tiebreaker)
  const highRiskItems = events
    .map((e) => ({ e, score: riskScoreFromEvent(e), ts: e.timestamp ? Date.parse(e.timestamp) : 0 }))
    .filter((x) => x.score > 0.5)
    .sort((a, b) => b.score - a.score || b.ts - a.ts)
    .slice(0, 8);

  // Heuristic recommendations
  const recs = [];
  if (events.length === 0) {
    recs.push({ tone: "slate", icon: "ℹ️", text: "No audit-graph events yet. Integrate the CyberArmor SDK / RASP / endpoint agent to start populating the risk dashboard." });
  }
  if (blocked > 5) {
    recs.push({ tone: "rose", icon: "🚨", text: `${blocked} blocked actions in the last ${events.length} events. Review your most-violated policies and the agents driving the blocks below.` });
  }
  if (avgRisk > 0.5) {
    recs.push({ tone: "amber", icon: "⚠️", text: `Fleet-average risk score ${(avgRisk * 100).toFixed(0)}% is elevated. Consider tightening allow-list rules or enabling redact-mode for high-risk providers.` });
  }
  if (highRisk > 0 && blocked === 0) {
    recs.push({ tone: "amber", icon: "👀", text: `${highRisk} high-risk event${highRisk === 1 ? "" : "s"} but zero blocks. Either policies are too permissive or the events are warns-only.` });
  }
  if (avgRisk <= 0.3 && events.length > 0 && blocked === 0) {
    recs.push({ tone: "emerald", icon: "✅", text: `Risk posture is healthy. Average ${(avgRisk * 100).toFixed(0)}%, no blocks in the sampled window. Continue monitoring.` });
  }
  if (recs.length === 0 && events.length > 0) {
    recs.push({ tone: "slate", icon: "ℹ️", text: "No standout signals in the last sample. The dashboard re-evaluates on every load." });
  }

  const recCard = (r) => {
    const border = r.tone === "rose"    ? "border-rose-900/50 bg-rose-950/20"
                 : r.tone === "amber"   ? "border-amber-900/50 bg-amber-950/20"
                 : r.tone === "emerald" ? "border-emerald-900/50 bg-emerald-950/20"
                 : "border-slate-800 bg-slate-900/50";
    return `<div class="flex items-start gap-3 rounded-2xl border ${border} p-3"><span>${r.icon}</span><div class="text-sm text-slate-200">${esc(r.text)}</div></div>`;
  };

  const agentRows = topAgents.length === 0
    ? `<tr><td colspan="4" class="px-3 py-6 text-center text-sm text-slate-500">No agent activity yet</td></tr>`
    : topAgents.map((r) => `
        <tr class="border-t border-slate-800 hover:bg-slate-900/40">
          <td class="px-3 py-2 font-mono text-xs text-slate-200">${esc(r.id.slice(0, 26))}${r.id.length > 26 ? "…" : ""}</td>
          <td class="px-3 py-2 w-44">${riskGaugeHtml(r.avg)}</td>
          <td class="px-3 py-2 text-right tabular-nums text-sm">${r.events}</td>
          <td class="px-3 py-2 text-right tabular-nums">${r.blocked > 0 ? `<span class="text-rose-300">${r.blocked}</span>` : `<span class="text-slate-600">0</span>`}</td>
        </tr>`).join("");

  const highRiskRows = highRiskItems.length === 0
    ? `<div class="rounded-2xl border border-emerald-900/40 bg-emerald-950/15 p-4 text-sm text-emerald-200">No high-risk events detected — system is clean ✓</div>`
    : `<div class="space-y-2">${highRiskItems.map(({ e, score }) => {
        const tone = score > 0.7 ? "bg-rose-500/20 text-rose-200" : "bg-amber-500/20 text-amber-200";
        const action = e.action || e.event_type || "unknown";
        const agent  = e.agent_id || "—";
        const model  = e.model || (e.details && e.details.model) || "—";
        const isBlocked = String(e.outcome || "").toLowerCase() === "blocked" || /block/i.test(action);
        return `<div class="flex items-start gap-3 rounded-2xl border border-slate-800 bg-slate-900/40 p-3">
          <span class="text-lg">${isBlocked ? "🚫" : "⚠️"}</span>
          <div class="min-w-0 flex-1">
            <div class="truncate text-sm font-medium text-slate-100">${esc(action)}</div>
            <div class="truncate text-xs text-slate-500">${esc(agent)} → ${esc(model)}</div>
            <div class="text-[11px] text-slate-500 tabular-nums">${esc(relativeFromIso(e.timestamp))}</div>
          </div>
          <span class="shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${tone}">${Math.round(score * 100)}%</span>
        </div>`;
      }).join("")}</div>`;

  $("#app").innerHTML = `
    <div class="space-y-4">
      ${fetchError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load events: ${esc(fetchError)}. The dashboard renders with zero events.</div>` : ""}
      ${sourceBreakdown ? `<div class="flex flex-wrap items-baseline gap-3 text-xs text-slate-500">
        <span class="uppercase tracking-wider">Sources</span>
        <span>Endpoint / extension telemetry: <span class="font-mono tabular-nums text-slate-300">${sourceBreakdown.telemetry ?? 0}</span></span>
        <span>SDK / RASP / proxy (audit-graph): <span class="font-mono tabular-nums text-slate-300">${sourceBreakdown.audit_graph ?? 0}</span></span>
        ${sourceBreakdown.audit_graph === 0 && sourceBreakdown.telemetry > 0 ? `<span class="text-amber-300">Tip: SDK / RASP integrations write to audit-graph and unlock richer risk scoring per agent.</span>` : ""}
      </div>` : ""}

      <div class="grid grid-cols-2 gap-3 md:grid-cols-4">
        ${riskMetricCard("Avg risk score", `${(avgRisk * 100).toFixed(1)}%`,
            avgRisk > 0.7 ? "rose" : avgRisk > 0.4 ? "amber" : "emerald",
            `${events.length} events sampled`)}
        ${riskMetricCard("Total events", events.length, "slate", "Audit-graph last 500")}
        ${riskMetricCard("Blocked actions", blocked,
            blocked > 0 ? "rose" : "emerald",
            blocked > 0 ? "Policy enforcement fired" : "No blocks in window")}
        ${riskMetricCard("High-risk events", highRisk,
            highRisk > 0 ? "amber" : "emerald",
            "Score > 70%")}
      </div>

      <div class="grid gap-4 lg:grid-cols-2">
        ${card(`
          <div class="font-semibold">Top agents by risk</div>
          <p class="mt-1 text-xs text-slate-500">Highest average-risk agents in the sample, with event volume and block count.</p>
          <div class="mt-3 overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500">
                <tr><th class="px-3 py-2">Agent</th><th class="px-3 py-2">Risk</th><th class="px-3 py-2 text-right">Events</th><th class="px-3 py-2 text-right">Blocked</th></tr>
              </thead>
              <tbody>${agentRows}</tbody>
            </table>
          </div>
        `)}
        ${card(`
          <div class="font-semibold">High-risk events</div>
          <p class="mt-1 text-xs text-slate-500">Top 8 events with risk score above 50%, sorted high to low.</p>
          <div class="mt-3">${highRiskRows}</div>
        `)}
      </div>

      ${card(`
        <div class="font-semibold">Recommendations</div>
        <p class="mt-1 text-xs text-slate-500">Heuristic guidance derived from the current event sample. Re-evaluates on every load.</p>
        <div class="mt-3 space-y-2">${recs.map(recCard).join("")}</div>
      `)}
    </div>
  `;
}

function delegationStatusPill(d) {
  const exp = d.expires_at ? Date.parse(d.expires_at) : null;
  const expired = exp != null && Number.isFinite(exp) && exp < Date.now();
  const raw = String(d.status || "active").toLowerCase();
  if (raw === "revoked") {
    return `<span class="inline-flex items-center rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-rose-200">revoked</span>`;
  }
  if (expired) {
    return `<span class="inline-flex items-center rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">expired</span>`;
  }
  return `<span class="inline-flex items-center rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-200">active</span>`;
}

async function viewDelegations() {
  $("#pageTitle").textContent = "Delegation Manager";
  $("#pageSubtitle").textContent = "Human → agent delegation chains scoped to this tenant — issue, scope, and revoke";
  const isAdmin = session.role === "tenant_admin";

  let delegations = [];
  let stats = null;        // {upstream_total, scoped_to_agents, upstream_unavailable}
  let agentChoices = [];   // [{agent_id, hostname?, username?}]
  let loadError = null;
  let statusFilter = "all"; // all | active | revoked | expired
  let search = "";
  let createMessage = null;
  const delPager = { page: 1, pageSize: 50 };

  async function load() {
    try {
      const [dResp, aResp] = await Promise.allSettled([
        api("/api/customer/delegations?limit=500"),
        api("/api/customer/agents?limit=500"),
      ]);
      if (dResp.status === "fulfilled") {
        const r = dResp.value || {};
        delegations = Array.isArray(r) ? r : (r.delegations || []);
        stats = {
          upstream_total: r.upstream_total ?? delegations.length,
          scoped_to_agents: r.scoped_to_agents ?? null,
          upstream_unavailable: !!r.upstream_unavailable,
        };
      } else {
        delegations = []; loadError = dResp.reason?.message || "delegation fetch failed";
      }
      if (aResp.status === "fulfilled") {
        agentChoices = Array.isArray(aResp.value) ? aResp.value : [];
      }
    } catch (err) {
      loadError = err.message || "load failed";
    }
  }

  function effectiveStatus(d) {
    const raw = String(d.status || "active").toLowerCase();
    if (raw === "revoked") return "revoked";
    const exp = d.expires_at ? Date.parse(d.expires_at) : null;
    if (exp != null && Number.isFinite(exp) && exp < Date.now()) return "expired";
    return "active";
  }

  function visible() {
    return delegations.filter((d) => {
      if (statusFilter !== "all" && effectiveStatus(d) !== statusFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      if (String(d.chain_id || "").toLowerCase().includes(q)) return true;
      if (String(d.parent_human_id || "").toLowerCase().includes(q)) return true;
      if (String(d.agent_id || "").toLowerCase().includes(q)) return true;
      for (const s of (d.scope || [])) if (String(s).toLowerCase().includes(q)) return true;
      return false;
    });
  }

  function rowHtml(d) {
    const created = d.created_at ? new Date(d.created_at).toLocaleString() : "—";
    const exp = d.expires_at ? new Date(d.expires_at).toLocaleString() : "—";
    const scope = Array.isArray(d.scope) ? d.scope : [];
    const status = effectiveStatus(d);
    const canRevoke = isAdmin && status === "active";
    return `<tr class="border-t border-slate-800">
      <td class="px-3 py-2 font-mono text-[10px] text-slate-300 break-all">${esc(d.chain_id || "")}</td>
      <td class="px-3 py-2 text-xs text-slate-200 break-all">${esc(d.parent_human_id || "—")}</td>
      <td class="px-3 py-2 font-mono text-[11px] text-slate-200 break-all">${esc(d.agent_id || "—")}</td>
      <td class="px-3 py-2">${delegationStatusPill(d)}</td>
      <td class="px-3 py-2">
        ${scope.length === 0 ? `<span class="text-xs text-slate-500">—</span>` : `<div class="flex flex-wrap gap-1">${scope.slice(0, 6).map((s) => `<span class="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-200">${esc(String(s))}</span>`).join("")}${scope.length > 6 ? `<span class="text-[10px] text-slate-500">+${scope.length - 6}</span>` : ""}</div>`}
      </td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(created)}</td>
      <td class="px-3 py-2 text-xs text-slate-400">${esc(exp)}</td>
      <td class="px-3 py-2 text-right">
        ${canRevoke ? `<button class="revokeDelegationBtn rounded-lg border border-rose-700 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 hover:bg-rose-500/20" data-chain-id="${esc(d.chain_id || "")}" type="button">Revoke</button>` : ""}
      </td>
    </tr>`;
  }

  function chipCls(active) {
    return active
      ? "rounded-full bg-cyan-500/20 text-cyan-100 border border-cyan-400/40 px-3 py-1 text-xs"
      : "rounded-full bg-slate-900 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1 text-xs";
  }

  function statusCounts() {
    const c = { active: 0, revoked: 0, expired: 0 };
    for (const d of delegations) c[effectiveStatus(d)]++;
    return c;
  }

  function render() {
    const filtered = visible();
    const counts = statusCounts();
    $("#app").innerHTML = `
      <div class="space-y-4">
        ${loadError ? `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-3 text-sm text-rose-200">Could not load delegations: ${esc(loadError)}.</div>` : ""}
        ${stats && stats.upstream_unavailable ? `<div class="rounded-2xl border border-amber-900 bg-amber-950/20 p-3 text-sm text-amber-200">Agent-identity service is unavailable — showing empty list.</div>` : ""}
        ${card(`
          <div class="flex flex-wrap items-center gap-4">
            ${riskMetricCard("Total chains", delegations.length, "slate")}
            ${riskMetricCard("Active", counts.active, "emerald")}
            ${riskMetricCard("Revoked", counts.revoked, counts.revoked ? "rose" : "emerald")}
            ${riskMetricCard("Expired", counts.expired, counts.expired ? "amber" : "emerald")}
            ${riskMetricCard("Tenant agents", stats && stats.scoped_to_agents != null ? stats.scoped_to_agents : "—", "slate")}
            ${!isAdmin ? `<div class="ml-auto text-xs text-slate-500">View only — admins can create / revoke.</div>` : ""}
          </div>
        `)}
        ${isAdmin ? card(`
          <div class="flex flex-wrap items-baseline justify-between gap-2 mb-3">
            <div class="font-semibold">Issue delegation</div>
            <div class="text-[11px] text-slate-500">Human → Agent, with scope and optional expiry. Agent must belong to this tenant.</div>
          </div>
          <form id="delegationCreateForm" class="grid gap-3 md:grid-cols-2">
            <label class="text-xs text-slate-400">Parent human ID
              <input id="delHuman" required class="mt-1 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" placeholder="user@example.com or human-uuid" />
            </label>
            <label class="text-xs text-slate-400">Agent
              <select id="delAgent" required class="mt-1 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm">
                <option value="">— select tenant agent —</option>
                ${agentChoices.map((a) => {
                  // Show the agent's kind so the operator can tell at a
                  // glance whether they're delegating to an endpoint, a
                  // browser extension, an SDK-registered AI agent, etc.
                  const src = String(a.source || "").toLowerCase();
                  const kind = src.includes("extension") ? "Extension"
                             : src.includes("proxy") || src.includes("rasp") ? "Proxy"
                             : src.includes("sdk") || src.includes("runtime") ? "SDK"
                             : src.includes("clipboard") ? "Clipboard"
                             : src.includes("endpoint") ? "Endpoint"
                             : (a.status === "registered" ? "Endpoint" : "Agent");
                  const label = `[${kind}] ${a.agent_id || ""}${a.hostname ? ` · ${a.hostname}` : ""}`;
                  return `<option value="${esc(a.agent_id || "")}">${esc(label)}</option>`;
                }).join("")}
              </select>
            </label>
            <label class="text-xs text-slate-400 md:col-span-2">Scope (comma-separated; use <span class="font-mono">*</span> for all)
              <input id="delScope" class="mt-1 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm font-mono" placeholder="ai:inference, ai:audit" value="*" />
            </label>
            <label class="text-xs text-slate-400">Expires at (optional)
              <input id="delExpires" type="datetime-local" class="mt-1 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" />
            </label>
            <div class="flex items-end gap-2">
              <button type="submit" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Create</button>
              <div id="delCreateMessage" class="text-xs ${createMessage && createMessage.kind === "ok" ? "text-emerald-300" : "text-rose-300"}">${createMessage ? esc(createMessage.text) : ""}</div>
            </div>
          </form>
        `) : ""}
        ${card(`
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-[10px] uppercase tracking-wider text-slate-500">Status</span>
              <button data-status-chip="all" class="${chipCls(statusFilter === "all")}">All <span class="text-slate-500">·${delegations.length}</span></button>
              <button data-status-chip="active" class="${chipCls(statusFilter === "active")}">active <span class="text-slate-500">·${counts.active}</span></button>
              <button data-status-chip="revoked" class="${chipCls(statusFilter === "revoked")}">revoked <span class="text-slate-500">·${counts.revoked}</span></button>
              <button data-status-chip="expired" class="${chipCls(statusFilter === "expired")}">expired <span class="text-slate-500">·${counts.expired}</span></button>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <input id="delSearch" type="search" placeholder="Search chain ID, human, agent, scope…" class="flex-1 min-w-[280px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm" value="${esc(search)}" />
              <div class="text-xs text-slate-400">${filtered.length} of ${delegations.length} shown</div>
            </div>
          </div>
        `)}
        ${(() => {
          const pager = simplePager({ total: filtered.length, state: delPager, idPrefix: "del" });
          const pageRows = pager.sliced(filtered);
          return card(`
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th class="px-3 py-2">Chain</th>
                  <th class="px-3 py-2">Human</th>
                  <th class="px-3 py-2">Agent</th>
                  <th class="px-3 py-2">Status</th>
                  <th class="px-3 py-2">Scope</th>
                  <th class="px-3 py-2">Created</th>
                  <th class="px-3 py-2">Expires</th>
                  <th class="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                ${pageRows.length === 0
                  ? `<tr><td colspan="8" class="px-3 py-8 text-center text-sm text-slate-500">${delegations.length === 0 ? "No delegations yet. Issue one above to create the first chain." : "No delegations match the current filters."}</td></tr>`
                  : pageRows.map(rowHtml).join("")}
              </tbody>
            </table>
          </div>
          ${filtered.length > 0 ? pager.html : ""}
        `);
        })()}
      </div>
    `;
    {
      const pager = simplePager({ total: filtered.length, state: delPager, idPrefix: "del" });
      pager.wire(document, () => render());
    }

    document.querySelectorAll("[data-status-chip]").forEach((btn) => {
      btn.addEventListener("click", () => { statusFilter = btn.dataset.statusChip; delPager.page = 1; render(); });
    });
    const sb = $("#delSearch");
    if (sb) {
      const caret = sb.selectionStart;
      sb.focus(); if (caret != null) sb.setSelectionRange(caret, caret);
      sb.addEventListener("input", () => { search = sb.value; delPager.page = 1; render(); });
    }
    document.querySelectorAll(".revokeDelegationBtn").forEach((btn) => {
      btn.addEventListener("click", () => revoke(btn.dataset.chainId));
    });
    const form = $("#delegationCreateForm");
    if (form) form.addEventListener("submit", onCreate);
  }

  async function onCreate(ev) {
    ev.preventDefault();
    const human = $("#delHuman").value.trim();
    const agent = $("#delAgent").value;
    const scopeRaw = ($("#delScope").value || "").trim();
    const expRaw = $("#delExpires").value;
    if (!human || !agent) {
      createMessage = { kind: "err", text: "Human and agent are required." };
      render();
      return;
    }
    const scope = scopeRaw
      ? scopeRaw.split(",").map((s) => s.trim()).filter(Boolean)
      : ["*"];
    const body = { parent_human_id: human, agent_id: agent, scope };
    if (expRaw) {
      // Local datetime → ISO with timezone offset preserved as the browser
      // produced it; the backend parses ISO-8601 tolerantly.
      const dt = new Date(expRaw);
      if (!Number.isNaN(dt.getTime())) body.expires_at = dt.toISOString();
    }
    createMessage = { kind: "ok", text: "Creating…" };
    render();
    try {
      await api("/api/customer/delegations", { method: "POST", body: JSON.stringify(body) });
      createMessage = { kind: "ok", text: "Delegation created." };
      await load();
      render();
    } catch (err) {
      createMessage = { kind: "err", text: err.message || "Create failed." };
      render();
    }
  }

  async function revoke(chainId) {
    if (!chainId) return;
    if (!confirm(`Revoke delegation ${chainId}?\nThis cannot be undone.`)) return;
    try {
      await api(`/api/customer/delegations/${encodeURIComponent(chainId)}`, { method: "DELETE" });
      await load();
      render();
    } catch (err) {
      alert(`Revoke failed: ${err.message}`);
    }
  }

  await load();
  render();
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
  //
  // Pick order: prefer the Chromium browser extension specifically (works in
  // Chrome / Edge / Brave / Opera) → any browser_extension → nothing. IDE
  // extensions (category "extension": VS Code, Cursor, Kiro, Office 365)
  // are NOT a browser extension and must not match here.
  const list = Array.isArray(catalog) ? catalog : [];
  const ext = list.find((p) => p.package_key === "edge-extension")
           || list.find((p) => p.category === "browser_extension");
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
  const rows = users.map((user) => {
    const last = user.last_login_at;
    const lastCell = last
      ? `<span title="${esc(fmt(last))}">${esc(relativeFromIso(last))}</span>`
      : `<span class="text-slate-600">never</span>`;
    return `
      <tr class="border-t border-slate-800">
        <td class="px-3 py-3">${esc(user.email)}</td>
        <td class="px-3 py-3">${badge(user.role, user.role === "tenant_admin" ? "green" : "cyan")}</td>
        <td class="px-3 py-3">${badge(user.status, user.status === "active" ? "green" : "amber")}</td>
        <td class="px-3 py-3 text-xs text-slate-400 tabular-nums">${lastCell}</td>
      </tr>`;
  }).join("");
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
    if (routeName === "upload-discovery") return await viewUploadDiscovery();
    if (routeName === "bom") return await viewBillOfMaterials();
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
