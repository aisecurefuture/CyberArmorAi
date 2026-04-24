import { mountPolicyBuilder } from "/shared/policy-builder.js";

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
  const res = await fetch(path, {
    credentials: "same-origin",
    headers,
    ...options,
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
  $("#pageTitle").textContent = "Customer Portal";
  $("#pageSubtitle").textContent = "Security posture overview for your tenant";
  const [settings, overview] = await Promise.all([
    api("/api/customer/settings"),
    api("/api/customer/overview"),
  ]);
  $("#app").innerHTML = `
    <div class="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
      ${metricCard("Policies", overview.policy_count ?? "0", "cyan")}
      ${metricCard("Endpoints", overview.agent_count ?? "0", "green")}
      ${metricCard("Telemetry", overview.telemetry_count ?? "0", "cyan")}
      ${metricCard("Incidents", overview.incident_count ?? "0", "amber")}
      ${metricCard("AI Providers", overview.provider_count ?? "0", "green")}
      ${metricCard("Audit Events", overview.audit_count ?? "0", "slate")}
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

async function viewApiKeys() {
  $("#pageTitle").textContent = "API Keys";
  $("#pageSubtitle").textContent = "Tenant-scoped API keys";
  if (session.role !== "tenant_admin") {
    $("#app").innerHTML = requireAdminMarkup();
    return;
  }
  const keys = await api("/api/customer/api-keys");
  const rows = keys.map((key) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 font-mono text-xs">${esc(key.key)}</td>
      <td class="px-3 py-3">${esc(key.role || "analyst")}</td>
      <td class="px-3 py-3">${badge(key.active ? "active" : "disabled", key.active ? "green" : "slate")}</td>
      <td class="px-3 py-3 text-right">${key.active ? `<button class="disableApiKey rounded-xl border border-amber-900 px-3 py-2 text-xs text-amber-100 hover:bg-amber-950" data-key="${esc(key.key)}">Disable</button>` : ""}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`
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
      <div class="min-w-0 flex-1 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-xs uppercase tracking-[0.18em] text-slate-500">
            <tr><th class="px-3 py-2">Key</th><th class="px-3 py-2">Role</th><th class="px-3 py-2">Status</th><th class="px-3 py-2"></th></tr>
          </thead>
          <tbody>${rows || emptyRow("No tenant API keys yet.", 4)}</tbody>
        </table>
      </div>
    </div>
  `);
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
      $("#apiKeyMessage").textContent = `Created key ${created.key}`;
      await viewApiKeys();
    } catch (error) {
      $("#apiKeyMessage").className = "mt-3 text-sm text-rose-300";
      $("#apiKeyMessage").textContent = error.message;
    }
  });
  document.querySelectorAll(".disableApiKey").forEach((button) => {
    button.addEventListener("click", async () => {
      await api(`/api/customer/api-keys/${encodeURIComponent(button.dataset.key)}/disable`, { method: "PATCH" });
      await viewApiKeys();
    });
  });
}

async function viewProxy() {
  await tenantScopedConfigPage("proxy", "Proxy Controls", "Tenant proxy policy posture", [
    { title: "Prompt Controls", body: "Review tenant-level prompt inspection, redaction, and block strategy before routing AI requests.", badge: "tenant enforced", tone: "green" },
    { title: "Allowed Destinations", body: "Prepare provider and endpoint routing rules scoped to this tenant's AI traffic.", badge: "per-tenant", tone: "cyan" },
    { title: "Response Handling", body: "Track response redaction and policy outcomes for the active tenant only.", badge: "audit-backed", tone: "slate" },
  ], { prompt_controls: { inspect: true, redact: true, block_high_risk: true }, allowed_destinations: [], response_handling: "audit" });
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
  const rows = (Array.isArray(policies) ? policies : []).map((p) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 font-mono text-xs">${esc(p.name || p.id || "")}</td>
      <td class="px-3 py-3">${esc(p.description || "")}</td>
      <td class="px-3 py-3">${badge(p.action || "monitor", p.action === "block" ? "amber" : "cyan")}</td>
      <td class="px-3 py-3">${badge(p.enabled === false ? "disabled" : "enabled", p.enabled === false ? "slate" : "green")}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Name</th><th class="px-3 py-2">Description</th><th class="px-3 py-2">Action</th><th class="px-3 py-2">Status</th></tr></thead><tbody>${rows || emptyRow("No policies found for this tenant.", 4)}</tbody></table>`);
}

async function viewEndpoints() {
  $("#pageTitle").textContent = "Endpoints";
  $("#pageSubtitle").textContent = "Tenant-scoped endpoint and agent inventory";
  const agents = await api("/api/customer/agents?limit=500");
  const rows = agents.map((a) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 font-mono text-xs">${esc(a.agent_id || "")}</td>
      <td class="px-3 py-3">${esc(a.hostname || "")}</td>
      <td class="px-3 py-3">${esc(a.username || "")}</td>
      <td class="px-3 py-3">${badge(a.status || "unknown", a.status === "running" ? "green" : "slate")}</td>
      <td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(a.last_seen))}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Agent ID</th><th class="px-3 py-2">Hostname</th><th class="px-3 py-2">User</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Last Seen</th></tr></thead><tbody>${rows || emptyRow("No endpoints found for this tenant.", 5)}</tbody></table>`);
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
    { title: "Response Actions", body: "Connect DLP findings to redact, block, escalate, or audit-only policy outcomes.", badge: "enforcement ready", tone: "slate" },
  ], { labels: ["Public", "Internal", "Confidential", "Restricted"], patterns: ["pii", "secrets", "credentials"], default_action: "redact" }, true);
}

async function viewReports() {
  await tenantScopedConfigPage("reports", "Reports", "Tenant security and compliance reports", [
    { title: "Compliance Report", body: "Generate a tenant-scoped summary of framework assessment results and evidence gaps.", badge: "SOC 2 / NIST / GDPR", tone: "green" },
    { title: "DLP Activity Report", body: "Summarize tenant data-classification hits, DLP detections, and response outcomes.", badge: "tenant data only", tone: "cyan" },
    { title: "AI Risk Report", body: "Package tenant AI providers, agents, policy decisions, incidents, and audit findings.", badge: "executive ready", tone: "amber" },
  ], { enabled_reports: ["compliance", "dlp", "ai_risk"], schedule: "manual", recipients: [] });
}

async function viewTelemetry() {
  $("#pageTitle").textContent = "Telemetry";
  $("#pageSubtitle").textContent = "Recent tenant-scoped events";
  const events = await api("/api/customer/telemetry?limit=250");
  const rows = events.map((event) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(event.occurred_at || event.created_at))}</td>
      <td class="px-3 py-3">${badge(event.source || "unknown", "slate")}</td>
      <td class="px-3 py-3">${esc(event.event_type || "")}</td>
      <td class="px-3 py-3">${esc(event.hostname || event.agent_id || "")}</td>
      <td class="px-3 py-3 max-w-lg truncate text-xs text-slate-400">${esc(JSON.stringify(event.payload || {}))}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Time</th><th class="px-3 py-2">Source</th><th class="px-3 py-2">Event</th><th class="px-3 py-2">Asset</th><th class="px-3 py-2">Details</th></tr></thead><tbody>${rows || emptyRow("No telemetry found for this tenant.", 5)}</tbody></table>`);
}

async function viewAudit() {
  $("#pageTitle").textContent = "Audit Logs";
  $("#pageSubtitle").textContent = "Tenant-scoped audit trail";
  const events = await api("/api/customer/audit?limit=250");
  const rows = events.map((event) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(event.created_at))}</td>
      <td class="px-3 py-3">${esc(event.method || "")} ${esc(event.path || "")}</td>
      <td class="px-3 py-3">${badge(event.status || "", String(event.status || "").startsWith("2") ? "green" : "amber")}</td>
      <td class="px-3 py-3 max-w-md truncate text-xs text-slate-400">${esc(JSON.stringify(event.meta || {}))}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Time</th><th class="px-3 py-2">Action</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Details</th></tr></thead><tbody>${rows || emptyRow("No audit logs found for this tenant.", 4)}</tbody></table>`);
}

async function viewIncidents() {
  $("#pageTitle").textContent = "Incidents";
  $("#pageSubtitle").textContent = "Tenant-scoped incidents";
  const incidents = await api("/api/customer/incidents?limit=250");
  const rows = incidents.map((incident) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3 font-mono text-xs">${esc(incident.request_id || "")}</td>
      <td class="px-3 py-3">${esc(incident.event_type || "")}</td>
      <td class="px-3 py-3">${badge(incident.decision || "unknown", incident.decision === "block" ? "amber" : "cyan")}</td>
      <td class="px-3 py-3 text-xs text-slate-400">${esc(fmt(incident.received_at))}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Request</th><th class="px-3 py-2">Type</th><th class="px-3 py-2">Decision</th><th class="px-3 py-2">Received</th></tr></thead><tbody>${rows || emptyRow("No incidents found for this tenant.", 4)}</tbody></table>`);
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
  await tenantScopedConfigPage("policy-studio", "Policy Studio", "AI-aware tenant policy decisions and risk scoring", [
    { title: "Decision Types", body: "Author allow, monitor, redact, step-up, and block decisions for tenant AI workflows.", badge: "tenant scoped", tone: "green" },
    { title: "Risk Score", body: "Tune policy priority and AI risk thresholds before rollout.", badge: "draftable", tone: "cyan" },
    { title: "Provider Rules", body: "Map policy rules to the AI providers approved for this tenant.", badge: "provider aware", tone: "slate" },
  ], { decision_types: ["allow", "monitor", "redact", "step_up", "block"], risk_thresholds: { warn: 50, block: 80 }, provider_rules: [] }, true);
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

async function viewOnboarding() {
  const snippets = [
    { title: "Node.js", body: "Install the CyberArmor SDK and set the tenant API key created from this portal.", badge: "npm", tone: "green" },
    { title: "Python", body: "Configure the Python client with tenant-scoped policy and audit settings.", badge: "pip", tone: "cyan" },
    { title: "Go / Java / .NET", body: "Use tenant-scoped credentials and validate audit events after integration.", badge: "server SDKs", tone: "slate" },
    { title: "Browser Extensions", body: "Enroll browser-side controls against this tenant's policy boundary.", badge: "endpoint ready", tone: "amber" },
    { title: "Verification", body: "Run a login, provider call, policy decision, and audit-log check before production rollout.", badge: "QA checklist", tone: "green" },
    { title: "SSO", body: "Configure OIDC under Identity / SSO or Settings before inviting tenant users at scale.", badge: "tenant admin", tone: "cyan" },
  ];
  await tenantScopedConfigPage("onboarding", "SDK & Onboarding", "Tenant quickstart guides and integration checklist", snippets, {
    checklist: ["create_api_key", "configure_sdk", "send_test_event", "verify_policy_decision", "confirm_audit_log"],
    sdk_languages: ["nodejs", "python", "go", "java", "dotnet"],
  });
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

async function init() {
  renderNav();
  $("#logout").addEventListener("click", logout);
  await hydrateSession();
  window.addEventListener("hashchange", route);
  await route();
}

init().catch(() => {
  window.location.replace("/login.html");
});
