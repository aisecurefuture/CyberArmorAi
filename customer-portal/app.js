const $ = (selector) => document.querySelector(selector);

const navItems = [
  { id: "overview", label: "Overview", hash: "#/overview" },
  { id: "policies", label: "Policies", hash: "#/policies" },
  { id: "endpoints", label: "Endpoints", hash: "#/endpoints" },
  { id: "telemetry", label: "Telemetry", hash: "#/telemetry" },
  { id: "incidents", label: "Incidents", hash: "#/incidents" },
  { id: "providers", label: "AI Providers", hash: "#/providers" },
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
    slate: "border-slate-800 bg-slate-900 text-slate-200",
  };
  return `<span class="inline-flex rounded-full border px-2.5 py-1 text-xs ${colors[tone] || colors.slate}">${esc(text)}</span>`;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
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
    <p class="mt-2 text-sm text-slate-400">Your account can view tenant data, but user management is limited to tenant admins.</p>
  `);
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
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/endpoints">Endpoints</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/telemetry">Telemetry</a>
          <a class="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 hover:bg-slate-800" href="#/users">Users</a>
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
  $("#pageTitle").textContent = "AI Providers";
  $("#pageSubtitle").textContent = "Tenant-scoped provider visibility";
  const data = await api("/api/customer/providers");
  const providers = Array.isArray(data.providers) ? data.providers : [];
  const rows = providers.map((provider) => `
    <tr class="border-t border-slate-800">
      <td class="px-3 py-3">${esc(provider.name || provider.id || provider.provider || "")}</td>
      <td class="px-3 py-3">${badge(provider.status || "available", provider.status === "configured" ? "green" : "slate")}</td>
      <td class="px-3 py-3 text-xs text-slate-400">${esc(provider.description || "")}</td>
    </tr>
  `).join("");
  $("#app").innerHTML = card(`<table class="w-full text-left text-sm"><thead class="text-xs uppercase tracking-[0.18em] text-slate-500"><tr><th class="px-3 py-2">Provider</th><th class="px-3 py-2">Status</th><th class="px-3 py-2">Details</th></tr></thead><tbody>${rows || emptyRow("No provider data available for this tenant.", 3)}</tbody></table>`);
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
    if (routeName === "endpoints") return await viewEndpoints();
    if (routeName === "telemetry") return await viewTelemetry();
    if (routeName === "incidents") return await viewIncidents();
    if (routeName === "providers") return await viewProviders();
    if (routeName === "audit") return await viewAudit();
    if (routeName === "users") return await viewUsers();
    if (routeName === "settings") return await viewSettings();
    return await viewOverview();
  } catch (error) {
    $("#app").innerHTML = card(`<div class="text-rose-300">${esc(error.message)}</div>`);
  }
}

async function logout() {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
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
