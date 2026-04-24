// Shared CyberArmor policy builder.
//
// Mounted into both admin-dashboard and customer-portal via an nginx
// volume. Both portals import `mountPolicyBuilder` and pass a small
// adapter so the same UI calls the right backend.
//
// Adapter shape (all fields required unless noted):
//   {
//     container: HTMLElement,                    // where to render
//     tenantId: string,                          // tenant id injected into saved policies
//     fetchJson: async (path, init?) => any,     // parse-or-throw fetch wrapper
//     paths: {
//       artifacts: "/api/customer/artifacts" |   // list artifacts for autocomplete
//                  "http://policy/artifacts/<tid>",
//       createPolicy: "/api/customer/policies" | // POST target for Save
//                     "http://policy/policies",
//     },
//     notify: ({type, message}) => void,         // toast/inline message sink
//     onSaved?: (policy) => void,                // called after a successful save
//     readOnly?: boolean,                        // hide Save/edit controls
//     initialPolicy?: object,                    // prefill for edit mode
//   }

const OPERATORS = [
  "equals", "not_equals",
  "contains", "not_contains",
  "starts_with", "ends_with",
  "matches", "regex",
  "in", "not_in",
  "greater_than", "greater_than_or_equals",
  "less_than", "less_than_or_equals",
  "exists", "not_exists",
  "is_empty", "is_not_empty",
];

// Fields that the proxy/ext-authz integrations actually emit, grouped
// for the dropdown. Operators can still enter a custom field if their
// context carries something unusual.
const FIELD_GROUPS = [
  {
    label: "Request",
    fields: [
      "request.url", "request.host", "request.path",
      "request.method", "request.source_ip", "request.user_agent",
    ],
  },
  {
    label: "Identity",
    fields: [
      "request.user_id", "request.user_email", "request.user_group",
      "request.username", "request.tenant_id",
    ],
  },
  {
    label: "Endpoint / Agent",
    fields: [
      "agent.agent_id", "agent.hostname", "agent.username",
      "agent.os", "endpoint.hostname", "endpoint.ip",
    ],
  },
  {
    label: "Prompt / Response",
    fields: [
      "prompt.text", "prompt.classification", "prompt.pii",
      "response.text", "response.classification", "response.pii",
    ],
  },
  {
    label: "AI provider",
    fields: [
      "provider", "model", "tool_name", "route.destination",
    ],
  },
  {
    label: "Event",
    fields: [
      "event.event_type", "event.severity", "event.source",
    ],
  },
];

const ALL_FIELD_SUGGESTIONS = FIELD_GROUPS.flatMap((g) => g.fields);

function esc(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function emptyGroup() {
  return { __id: uid(), operator: "AND", rules: [] };
}

function emptyRule() {
  return { __id: uid(), field: "", operator: "equals", value: "" };
}

// Deep-copy the engine condition tree into the internal working shape
// (__id tags so React-free rendering can target nodes without path math
// breaking when siblings reorder).
function fromEngineTree(node) {
  if (!node || typeof node !== "object") return emptyGroup();
  if (Array.isArray(node.rules)) {
    return {
      __id: uid(),
      operator: node.operator || "AND",
      rules: node.rules.map((child) => {
        if (child && Array.isArray(child.rules)) return fromEngineTree(child);
        return {
          __id: uid(),
          field: child?.field || "",
          operator: child?.operator || child?.op || "equals",
          value: child?.value ?? "",
        };
      }),
    };
  }
  return emptyGroup();
}

function toEngineTree(node) {
  const out = { operator: node.operator || "AND", rules: [] };
  for (const child of node.rules || []) {
    if (child && Array.isArray(child.rules)) {
      out.rules.push(toEngineTree(child));
    } else {
      let value = child.value ?? "";
      if (typeof value === "string" && ["in", "not_in"].includes(child.operator)) {
        // Split comma/newline lists into arrays unless it's an artifact ref.
        if (!value.startsWith("$artifact:")) {
          value = value
            .split(/[,\n]/)
            .map((s) => s.trim())
            .filter(Boolean);
        }
      }
      out.rules.push({
        field: child.field || "",
        operator: child.operator || "equals",
        value,
      });
    }
  }
  return out;
}

function findNode(root, id, parent = null, index = -1) {
  if (root.__id === id) return { node: root, parent, index };
  for (let i = 0; i < (root.rules || []).length; i++) {
    const child = root.rules[i];
    if (child.__id === id) return { node: child, parent: root, index: i };
    if (Array.isArray(child.rules)) {
      const found = findNode(child, id, root, i);
      if (found) return found;
    }
  }
  return null;
}

export function mountPolicyBuilder(options) {
  const {
    container,
    tenantId,
    fetchJson,
    paths,
    notify,
    onSaved,
    readOnly = false,
    initialPolicy = null,
  } = options;

  if (!container) throw new Error("mountPolicyBuilder: container required");
  if (!fetchJson) throw new Error("mountPolicyBuilder: fetchJson required");
  if (!paths || !paths.createPolicy) throw new Error("mountPolicyBuilder: paths.createPolicy required");

  const state = {
    name: initialPolicy?.name || "",
    description: initialPolicy?.description || "",
    action: initialPolicy?.action || "monitor",
    scope: initialPolicy?.scope || "general",
    priority: initialPolicy?.priority ?? 100,
    enabled: initialPolicy?.enabled !== false,
    frameworks: Array.isArray(initialPolicy?.compliance_frameworks)
      ? initialPolicy.compliance_frameworks.join(", ")
      : (initialPolicy?.compliance_frameworks || ""),
    tree: initialPolicy?.conditions ? fromEngineTree(initialPolicy.conditions) : emptyGroup(),
    artifacts: [],
  };

  function buildFieldDatalist() {
    const groups = FIELD_GROUPS.map((group) =>
      group.fields.map((f) => `<option value="${esc(f)}" label="${esc(group.label)}"></option>`).join("")
    ).join("");
    return `<datalist id="cpb_fields">${groups}</datalist>`;
  }

  function buildArtifactDatalist() {
    const opts = state.artifacts.map((a) =>
      `<option value="$artifact:${esc(a.name)}" label="${esc(a.kind)}"></option>`
    ).join("");
    return `<datalist id="cpb_artifacts">${opts}</datalist>`;
  }

  function renderRule(rule) {
    const valueList = ["in", "not_in", "equals", "contains", "regex"].includes(rule.operator)
      ? "cpb_artifacts"
      : "";
    const valueDisabled = ["exists", "not_exists", "is_empty", "is_not_empty"].includes(rule.operator);
    return `<div class="flex flex-wrap items-center gap-2 ml-6 mb-2" data-rule="${esc(rule.__id)}">
      <input
        class="w-52 px-2 py-1 text-xs rounded-lg bg-slate-900 border border-slate-800 font-mono"
        list="cpb_fields"
        data-field="field"
        placeholder="request.user_email"
        value="${esc(rule.field || "")}"
      />
      <select class="text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800" data-field="operator">
        ${OPERATORS.map((op) => `<option value="${op}" ${rule.operator === op ? "selected" : ""}>${op}</option>`).join("")}
      </select>
      <input
        class="flex-1 min-w-[160px] px-2 py-1 text-xs rounded-lg bg-slate-900 border border-slate-800 font-mono"
        ${valueList ? `list="${valueList}"` : ""}
        ${valueDisabled ? "disabled" : ""}
        data-field="value"
        placeholder="${valueDisabled ? "(n/a)" : "value or $artifact:name"}"
        value="${esc(Array.isArray(rule.value) ? rule.value.join(", ") : rule.value ?? "")}"
      />
      ${readOnly ? "" : `<button class="text-xs text-rose-400 hover:text-rose-300" data-action="remove-rule" title="Remove rule">✕</button>`}
    </div>`;
  }

  function renderGroup(group, depth = 0) {
    const isOr = group.operator === "OR";
    const toneCls = depth === 0
      ? "border border-slate-800 bg-slate-950/40"
      : (isOr ? "border border-amber-900/60 bg-amber-950/10" : "border border-slate-800 bg-slate-900/40");
    const header = `<div class="flex items-center gap-2">
      <select class="text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 font-semibold" data-field="operator">
        <option value="AND" ${!isOr ? "selected" : ""}>AND</option>
        <option value="OR" ${isOr ? "selected" : ""}>OR</option>
        <option value="NOT" ${group.operator === "NOT" ? "selected" : ""}>NOT</option>
      </select>
      ${readOnly ? "" : `<button class="text-xs px-2 py-1 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900" data-action="add-rule">+ Rule</button>`}
      ${readOnly ? "" : `<button class="text-xs px-2 py-1 rounded-lg bg-amber-900/40 text-amber-200 border border-amber-900" data-action="add-group">+ Group</button>`}
      ${(!readOnly && depth > 0) ? `<button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-action="remove-group">Remove group</button>` : ""}
    </div>`;
    const children = (group.rules || []).map((child) => {
      if (child && Array.isArray(child.rules)) return renderGroup(child, depth + 1);
      return renderRule(child);
    }).join("");
    return `<div class="rounded-2xl p-3 mb-3 ${toneCls}" data-group="${esc(group.__id)}">
      ${header}
      <div class="mt-3 space-y-1">${children || `<div class="text-xs text-slate-500 ml-6">No rules yet.</div>`}</div>
    </div>`;
  }

  function render() {
    container.innerHTML = `
      ${buildFieldDatalist()}
      ${buildArtifactDatalist()}
      <section class="rounded-3xl border border-slate-800 bg-slate-950/70 p-5">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Policy name</label>
            <input id="cpb_name" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="block-prompt-injection" value="${esc(state.name)}" ${readOnly ? "disabled" : ""} />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Description</label>
            <input id="cpb_description" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="What this policy does" value="${esc(state.description)}" ${readOnly ? "disabled" : ""} />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Action</label>
            <select id="cpb_action" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" ${readOnly ? "disabled" : ""}>
              ${["monitor", "warn", "block", "allow"].map((a) => `<option value="${a}" ${state.action === a ? "selected" : ""}>${a}</option>`).join("")}
            </select>
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Scope</label>
            <select id="cpb_scope" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" ${readOnly ? "disabled" : ""}>
              ${["general", "proxy", "endpoint", "identity"].map((s) => `<option value="${s}" ${state.scope === s ? "selected" : ""}>${s}</option>`).join("")}
            </select>
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Priority (lower = evaluated first)</label>
            <input id="cpb_priority" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" value="${esc(state.priority)}" ${readOnly ? "disabled" : ""} />
          </div>
          <div class="space-y-1">
            <label class="text-xs text-slate-300">Compliance frameworks (comma-separated)</label>
            <input id="cpb_frameworks" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="SOC2, NIST-CSF, GDPR" value="${esc(state.frameworks)}" ${readOnly ? "disabled" : ""} />
          </div>
        </div>

        <div class="flex items-center justify-between mb-2">
          <div class="text-sm font-semibold text-slate-200">Conditions</div>
          <div class="text-xs text-slate-500">
            Tip: type <span class="font-mono text-cyan-200">$artifact:name</span> to reference a tenant list or regex
          </div>
        </div>
        <div id="cpb_tree">${renderGroup(state.tree, 0)}</div>

        <div class="mt-4 flex flex-wrap gap-2">
          ${readOnly ? "" : `<button id="cpb_save" class="px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-semibold hover:bg-cyan-400 text-sm">Save policy</button>`}
          <button id="cpb_preview" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm">Preview JSON</button>
          <div id="cpb_message" class="self-center text-sm text-slate-400"></div>
        </div>
        <pre id="cpb_json" class="mt-4 p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono overflow-x-auto hidden"></pre>
      </section>
    `;
    bind();
  }

  function bind() {
    container.querySelectorAll("[data-group]").forEach((el) => {
      const groupId = el.dataset.group;
      const found = findNode(state.tree, groupId);
      if (!found) return;
      const group = found.node;

      const opSel = el.querySelector(":scope > div > select[data-field='operator']");
      if (opSel) {
        opSel.addEventListener("change", (event) => {
          group.operator = event.target.value;
        });
      }

      el.querySelectorAll(":scope > div > button[data-action='add-rule']").forEach((btn) => {
        btn.addEventListener("click", () => {
          group.rules.push(emptyRule());
          render();
        });
      });
      el.querySelectorAll(":scope > div > button[data-action='add-group']").forEach((btn) => {
        btn.addEventListener("click", () => {
          group.rules.push(emptyGroup());
          render();
        });
      });
      el.querySelectorAll(":scope > div > button[data-action='remove-group']").forEach((btn) => {
        btn.addEventListener("click", () => {
          if (!found.parent) return;
          found.parent.rules.splice(found.index, 1);
          render();
        });
      });
    });

    container.querySelectorAll("[data-rule]").forEach((el) => {
      const ruleId = el.dataset.rule;
      const found = findNode(state.tree, ruleId);
      if (!found) return;
      const rule = found.node;
      el.querySelectorAll("[data-field]").forEach((input) => {
        const field = input.dataset.field;
        const handler = () => {
          rule[field] = input.value;
          if (field === "operator") render();
        };
        input.addEventListener("input", handler);
        input.addEventListener("change", handler);
      });
      const remove = el.querySelector("[data-action='remove-rule']");
      if (remove) {
        remove.addEventListener("click", () => {
          if (!found.parent) return;
          found.parent.rules.splice(found.index, 1);
          render();
        });
      }
    });

    const nameInput = container.querySelector("#cpb_name");
    if (nameInput) nameInput.addEventListener("input", (event) => { state.name = event.target.value; });
    const descInput = container.querySelector("#cpb_description");
    if (descInput) descInput.addEventListener("input", (event) => { state.description = event.target.value; });
    const actionSel = container.querySelector("#cpb_action");
    if (actionSel) actionSel.addEventListener("change", (event) => { state.action = event.target.value; });
    const scopeSel = container.querySelector("#cpb_scope");
    if (scopeSel) scopeSel.addEventListener("change", (event) => { state.scope = event.target.value; });
    const priorityInput = container.querySelector("#cpb_priority");
    if (priorityInput) priorityInput.addEventListener("input", (event) => { state.priority = parseInt(event.target.value || "100", 10); });
    const frameworksInput = container.querySelector("#cpb_frameworks");
    if (frameworksInput) frameworksInput.addEventListener("input", (event) => { state.frameworks = event.target.value; });

    const previewBtn = container.querySelector("#cpb_preview");
    if (previewBtn) {
      previewBtn.addEventListener("click", () => {
        const pre = container.querySelector("#cpb_json");
        pre.textContent = JSON.stringify(buildPolicyJson(), null, 2);
        pre.classList.toggle("hidden");
      });
    }

    const saveBtn = container.querySelector("#cpb_save");
    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        const msg = container.querySelector("#cpb_message");
        msg.className = "self-center text-sm text-slate-400";
        const json = buildPolicyJson();
        if (!json.name) {
          msg.className = "self-center text-sm text-rose-300";
          msg.textContent = "Policy name is required.";
          return;
        }
        if (!json.conditions || !json.conditions.rules || json.conditions.rules.length === 0) {
          msg.className = "self-center text-sm text-rose-300";
          msg.textContent = "Add at least one rule.";
          return;
        }
        msg.textContent = "Saving...";
        try {
          const saved = await fetchJson(paths.createPolicy, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(json),
          });
          msg.className = "self-center text-sm text-emerald-300";
          msg.textContent = `Saved policy ${saved?.name || json.name}.`;
          if (notify) notify({ type: "success", message: "Policy saved." });
          if (onSaved) onSaved(saved || json);
        } catch (error) {
          msg.className = "self-center text-sm text-rose-300";
          msg.textContent = error.message;
          if (notify) notify({ type: "error", message: error.message });
        }
      });
    }
  }

  function buildPolicyJson() {
    return {
      tenant_id: tenantId,
      name: (state.name || "").trim(),
      description: (state.description || "").trim(),
      action: state.action || "monitor",
      scope: state.scope || "general",
      priority: Number.isFinite(state.priority) ? state.priority : 100,
      enabled: state.enabled !== false,
      conditions: toEngineTree(state.tree),
      compliance_frameworks: (state.frameworks || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      rules: {},
    };
  }

  async function loadArtifacts() {
    if (!paths.artifacts) return;
    try {
      const rows = await fetchJson(paths.artifacts);
      state.artifacts = Array.isArray(rows) ? rows.filter((a) => a.enabled !== false && !a.archived_at) : [];
    } catch (error) {
      // non-fatal — the builder still works without the artifact dropdown
      state.artifacts = [];
    }
  }

  (async () => {
    await loadArtifacts();
    render();
  })();

  return {
    getJson: () => buildPolicyJson(),
    setPolicy: (policy) => {
      Object.assign(state, {
        name: policy?.name || "",
        description: policy?.description || "",
        action: policy?.action || "monitor",
        scope: policy?.scope || "general",
        priority: policy?.priority ?? 100,
        frameworks: Array.isArray(policy?.compliance_frameworks) ? policy.compliance_frameworks.join(", ") : "",
        tree: policy?.conditions ? fromEngineTree(policy.conditions) : emptyGroup(),
      });
      render();
    },
    destroy: () => { container.innerHTML = ""; },
  };
}

export { FIELD_GROUPS, ALL_FIELD_SUGGESTIONS, OPERATORS };
