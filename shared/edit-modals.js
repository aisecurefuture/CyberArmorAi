/**
 * Shared edit-modal helpers for the customer portal and admin dashboard.
 *
 * Exports
 * -------
 *   openPolicyDetailModal({ policy, fetchJson, paths, canEdit, onSaved })
 *     Read-only details by default. "Edit" button reveals two tabs:
 *       - Builder: re-uses mountPolicyBuilder from /shared/policy-builder.js
 *       - JSON:    raw editable JSON with parse validation on Save
 *     Save sticky footer with Save / Cancel. Save target is paths.updatePolicy
 *     (PUT) when policy.id is set, otherwise paths.createPolicy.
 *
 *   openArtifactDetailModal({ artifact, fetchJson, paths, canEdit, onSaved })
 *     Read-only details + Edit/Save/Cancel. Edits label, description, body
 *     (CSV / regex / JSON depending on kind), enabled.
 *
 *   openReadOnlyModal({ title, record, fields })
 *     Generic read-only key/value modal for incidents, audit, telemetry,
 *     endpoints, agents, tenants, api-keys, etc.
 *
 * All modals use openModal/closeModal from /shared/list-view.js, which
 * gives ESC + backdrop-click + × button + unsaved-changes guard.
 */

import { openModal, esc, fmt, badge, card } from "/shared/list-view.js";
import { mountPolicyBuilder } from "/shared/policy-builder.js";

const ACTIONS = ["allow", "warn", "redact", "sandbox", "block", "isolate", "route", "audit-only", "monitor"];

// ─── Generic read-only details ────────────────────────────────────────────

export function openReadOnlyModal({ title, record, fields }) {
  // fields: [{ key, label, render?: row=>html }]
  const rows = fields.map((f) => {
    const value = f.render ? f.render(record) : esc(record?.[f.key] ?? "");
    return `
      <div class="grid grid-cols-3 gap-3 border-b border-slate-900 py-2">
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(f.label)}</div>
        <div class="col-span-2 break-words text-sm text-slate-200">${value || '<span class="text-slate-600">—</span>'}</div>
      </div>`;
  }).join("");

  const rawJson = JSON.stringify(record, null, 2);
  const handle = openModal(`
    <div class="space-y-4">
      <div>${rows}</div>
      <details class="rounded-2xl border border-slate-800 bg-slate-900/40 p-3">
        <summary class="cursor-pointer text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">View raw JSON</summary>
        <pre class="mt-3 max-h-64 overflow-auto rounded-xl bg-slate-950 p-3 text-xs text-slate-300">${esc(rawJson)}</pre>
      </details>
    </div>
  `, { title, width: "max-w-2xl" });

  return handle;
}

// ─── Policy detail + edit ─────────────────────────────────────────────────

export function openPolicyDetailModal({
  policy,
  tenantId,
  fetchJson,
  paths,                     // { artifacts, createPolicy, updatePolicy }
  canEdit = true,
  onSaved = null,
  notify = null,
}) {
  let mode = "view";              // "view" | "edit"
  let activeTab = "builder";      // "builder" | "json"
  let builderHandle = null;
  let modalHandle = null;
  let originalJson = JSON.stringify(policy);
  let dirty = false;

  function dirtyCheck() {
    if (mode !== "edit") return false;
    if (activeTab === "builder" && builderHandle) {
      try {
        const current = JSON.stringify(builderHandle.getJson());
        // Compare against the canonicalised original — if user added a rule,
        // current will differ. Approximate is fine here.
        return current !== JSON.stringify(_canonicaliseForBuilder(policy, tenantId));
      } catch { return dirty; }
    }
    if (activeTab === "json") {
      const ta = modalHandle?.body.querySelector("#policy_json_textarea");
      if (ta && ta.value !== JSON.stringify(policy, null, 2)) return true;
    }
    return dirty;
  }

  function renderViewMode() {
    const conditionsHtml = `<pre class="max-h-64 overflow-auto rounded-xl bg-slate-950 p-3 text-xs text-slate-300">${esc(JSON.stringify(policy.conditions || {}, null, 2))}</pre>`;
    // Path B (Step 3): show redact_classes as cyan chips when present.
    // Hidden when the policy isn't a redact policy or has no classes.
    const redactClasses = Array.isArray(policy.redact_classes) ? policy.redact_classes : [];
    const redactRow = (policy.action === "redact" || redactClasses.length)
      ? [["Redact classes", redactClasses.length
            ? redactClasses.map((c) => `<span class="inline-flex items-center rounded-md border border-cyan-700 bg-cyan-900/40 px-1.5 py-0.5 mr-1 mb-1 font-mono text-[11px] text-cyan-100">${esc(c)}</span>`).join("")
            : `<span class="text-[11px] text-amber-300">none — falls back to caller-detected classes</span>`]]
      : [];

    const fieldsHtml = [
      ["ID", esc(policy.id || "")],
      ["Name", esc(policy.name || "")],
      ["Description", esc(policy.description || "")],
      ["Action", badge(policy.action || "monitor", policy.action === "block" ? "amber" : policy.action === "redact" ? "cyan" : "cyan")],
      ["Scope", esc(policy.scope || "")],
      ["Priority", esc(String(policy.priority ?? 100))],
      ["Status", badge(policy.enabled === false ? "disabled" : "enabled", policy.enabled === false ? "slate" : "green")],
      ["Frameworks", Array.isArray(policy.compliance_frameworks) ? policy.compliance_frameworks.map((f) => badge(f, "slate")).join(" ") : esc(policy.compliance_frameworks || "")],
      ...redactRow,
      ["Tenant", esc(policy.tenant_id || tenantId || "")],
      ["Created", esc(fmt(policy.created_at))],
      ["Updated", esc(fmt(policy.updated_at))],
    ].map(([label, val]) => `
      <div class="grid grid-cols-3 gap-3 border-b border-slate-900 py-2">
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(label)}</div>
        <div class="col-span-2 break-words text-sm text-slate-200">${val || '<span class="text-slate-600">—</span>'}</div>
      </div>
    `).join("");

    return `
      <div class="space-y-4">
        <div class="flex items-center justify-end gap-2">
          ${canEdit ? `<button type="button" id="policy_edit_btn" class="rounded-xl bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-slate-50 hover:bg-cyan-500">Edit</button>` : ""}
        </div>
        <div>${fieldsHtml}</div>
        <div>
          <div class="text-xs uppercase tracking-[0.18em] text-slate-500 mb-2">Conditions</div>
          ${conditionsHtml}
        </div>
      </div>
    `;
  }

  function renderEditMode() {
    return `
      <div class="space-y-4">
        <div class="flex items-center gap-2 border-b border-slate-800">
          <button type="button" data-tab="builder" class="px-4 py-2 text-sm font-semibold ${activeTab === "builder" ? "border-b-2 border-cyan-500 text-cyan-300" : "text-slate-400 hover:text-slate-200"}">Builder</button>
          <button type="button" data-tab="json" class="px-4 py-2 text-sm font-semibold ${activeTab === "json" ? "border-b-2 border-cyan-500 text-cyan-300" : "text-slate-400 hover:text-slate-200"}">JSON</button>
        </div>
        <div id="policy_edit_pane"></div>
        <div id="policy_save_msg" class="text-sm"></div>
        <div class="sticky bottom-0 -mx-6 -mb-5 flex items-center justify-end gap-2 border-t border-slate-800 bg-slate-950/95 px-6 py-3">
          <button type="button" id="policy_cancel_btn" class="rounded-xl border border-slate-800 px-4 py-2 text-sm text-slate-300 hover:bg-slate-900">Cancel</button>
          <button type="button" id="policy_save_btn" class="rounded-xl bg-cyan-600 px-4 py-2 text-sm font-semibold text-slate-50 hover:bg-cyan-500">Save</button>
        </div>
      </div>
    `;
  }

  function _canonicaliseForBuilder(p, tid) {
    return {
      tenant_id: p.tenant_id || tid,
      name: (p.name || "").trim(),
      description: (p.description || "").trim(),
      action: p.action || "monitor",
      scope: p.scope || "general",
      priority: Number.isFinite(p.priority) ? p.priority : 100,
      enabled: p.enabled !== false,
      conditions: p.conditions || { rules: [] },
      compliance_frameworks: Array.isArray(p.compliance_frameworks) ? p.compliance_frameworks : [],
      rules: {},
    };
  }

  function mountBuilderPane() {
    const pane = modalHandle.body.querySelector("#policy_edit_pane");
    pane.innerHTML = `<div id="policy_builder_host" class="rounded-2xl border border-slate-800 bg-slate-900/40 p-3"></div>`;
    const host = pane.querySelector("#policy_builder_host");
    builderHandle = mountPolicyBuilder({
      container: host,
      tenantId: policy.tenant_id || tenantId,
      fetchJson,
      paths: {
        artifacts: paths.artifacts,
        createPolicy: paths.createPolicy,
        updatePolicy: paths.updatePolicy,
      },
      notify: notify || (() => {}),
      onSaved: null,                     // we drive Save ourselves from the footer
      initialPolicy: policy,
    });
    // Hide the builder's internal save button — we use the modal footer instead
    setTimeout(() => {
      const internalSave = host.querySelector("#cpb_save");
      if (internalSave) internalSave.style.display = "none";
    }, 0);
  }

  function mountJsonPane() {
    const pane = modalHandle.body.querySelector("#policy_edit_pane");
    pane.innerHTML = `
      <div class="space-y-2">
        <label class="text-xs uppercase tracking-[0.18em] text-slate-500">Policy JSON</label>
        <textarea id="policy_json_textarea" class="h-96 w-full rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-200" spellcheck="false">${esc(JSON.stringify(policy, null, 2))}</textarea>
        <div id="policy_json_err" class="text-xs text-rose-300"></div>
      </div>
    `;
  }

  function setActiveTab(tab) {
    // Capture state from the tab we're leaving
    if (activeTab === "builder" && builderHandle) {
      try { policy = builderHandle.getJson(); policy.id = builderHandle._id || policy.id; } catch { /* noop */ }
    } else if (activeTab === "json") {
      const ta = modalHandle.body.querySelector("#policy_json_textarea");
      if (ta) {
        try {
          const parsed = JSON.parse(ta.value);
          policy = parsed;
        } catch (err) {
          // keep as-is; parse error will surface on Save
        }
      }
    }
    activeTab = tab;
    refreshEditMode();
  }

  function refreshEditMode() {
    modalHandle.setContent(renderEditMode());
    if (activeTab === "builder") mountBuilderPane();
    else mountJsonPane();
    wireEditButtons();
  }

  function wireEditButtons() {
    modalHandle.body.querySelectorAll("[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => setActiveTab(btn.dataset.tab));
    });
    modalHandle.body.querySelector("#policy_cancel_btn").addEventListener("click", () => {
      modalHandle.requestClose("cancel");
    });
    modalHandle.body.querySelector("#policy_save_btn").addEventListener("click", save);
  }

  async function save() {
    const msg = modalHandle.body.querySelector("#policy_save_msg");
    msg.className = "text-sm text-slate-400";
    msg.textContent = "Saving...";

    let payload;
    try {
      if (activeTab === "json") {
        const ta = modalHandle.body.querySelector("#policy_json_textarea");
        try {
          payload = JSON.parse(ta.value);
        } catch (err) {
          msg.className = "text-sm text-rose-300";
          msg.textContent = `JSON parse error: ${err.message}`;
          return;
        }
      } else {
        if (!builderHandle) throw new Error("Builder not mounted");
        payload = builderHandle.getJson();
      }
    } catch (err) {
      msg.className = "text-sm text-rose-300";
      msg.textContent = err.message;
      return;
    }

    const id = policy.id || payload.id;
    const isUpdate = Boolean(id && paths.updatePolicy);
    const url = isUpdate
      ? paths.updatePolicy.replace("{id}", encodeURIComponent(id))
      : paths.createPolicy;

    try {
      const saved = await fetchJson(url, {
        method: isUpdate ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      msg.className = "text-sm text-emerald-300";
      msg.textContent = "Saved.";
      if (onSaved) onSaved(saved || payload);
      setTimeout(() => modalHandle.close("saved"), 600);
    } catch (err) {
      msg.className = "text-sm text-rose-300";
      msg.textContent = err.message || "Save failed.";
    }
  }

  function wireViewButtons() {
    const editBtn = modalHandle.body.querySelector("#policy_edit_btn");
    if (editBtn) editBtn.addEventListener("click", () => {
      mode = "edit";
      activeTab = "builder";
      refreshEditMode();
    });
  }

  modalHandle = openModal(renderViewMode(), {
    title: `Policy — ${policy.name || policy.id || "(unnamed)"}`,
    width: "max-w-5xl",
  });
  modalHandle.setUnsavedGuard(dirtyCheck);
  wireViewButtons();
  return modalHandle;
}

// ─── Artifact detail + edit ───────────────────────────────────────────────

export function openArtifactDetailModal({
  artifact,
  fetchJson,
  paths,                     // { update: '/api/.../artifacts/id/{id}' }
  canEdit = true,
  onSaved = null,
}) {
  let mode = "view";
  let modalHandle;

  function renderView() {
    const fields = [
      ["ID", esc(artifact.id || "")],
      ["Kind", esc(artifact.kind || "")],
      ["Name", esc(artifact.name || "")],
      ["Description", esc(artifact.description || "")],
      ["Status", badge(artifact.enabled === false ? "disabled" : "enabled", artifact.enabled === false ? "slate" : "green")],
      ["Tenant", esc(artifact.tenant_id || "")],
      ["Created", esc(fmt(artifact.created_at))],
      ["Updated", esc(fmt(artifact.updated_at))],
    ];
    const fieldsHtml = fields.map(([k, v]) => `
      <div class="grid grid-cols-3 gap-3 border-b border-slate-900 py-2">
        <div class="text-xs uppercase tracking-[0.18em] text-slate-500">${esc(k)}</div>
        <div class="col-span-2 break-words text-sm text-slate-200">${v || '<span class="text-slate-600">—</span>'}</div>
      </div>`).join("");
    const body = artifact.body || artifact.values || artifact.pattern || "";
    const bodyDisplay = typeof body === "string" ? body : JSON.stringify(body, null, 2);
    return `
      <div class="space-y-4">
        <div class="flex items-center justify-end">
          ${canEdit ? `<button type="button" id="artifact_edit_btn" class="rounded-xl bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-slate-50 hover:bg-cyan-500">Edit</button>` : ""}
        </div>
        <div>${fieldsHtml}</div>
        <div>
          <div class="text-xs uppercase tracking-[0.18em] text-slate-500 mb-2">Body</div>
          <pre class="max-h-64 overflow-auto rounded-xl bg-slate-950 p-3 text-xs text-slate-300">${esc(bodyDisplay)}</pre>
        </div>
      </div>`;
  }

  function renderEdit() {
    const body = artifact.body || artifact.values || artifact.pattern || "";
    const bodyText = typeof body === "string" ? body : JSON.stringify(body, null, 2);
    return `
      <div class="space-y-3">
        <div>
          <label class="text-xs uppercase tracking-[0.18em] text-slate-500">Name</label>
          <input id="art_name" type="text" value="${esc(artifact.name || "")}" class="mt-1 w-full rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
        </div>
        <div>
          <label class="text-xs uppercase tracking-[0.18em] text-slate-500">Description</label>
          <input id="art_desc" type="text" value="${esc(artifact.description || "")}" class="mt-1 w-full rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
        </div>
        <div>
          <label class="text-xs uppercase tracking-[0.18em] text-slate-500">Body (${esc(artifact.kind || "")})</label>
          <textarea id="art_body" class="mt-1 h-48 w-full rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-200" spellcheck="false">${esc(bodyText)}</textarea>
        </div>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input id="art_enabled" type="checkbox" ${artifact.enabled === false ? "" : "checked"} />
          Enabled
        </label>
        <div id="art_save_msg" class="text-sm"></div>
        <div class="sticky bottom-0 -mx-6 -mb-5 flex items-center justify-end gap-2 border-t border-slate-800 bg-slate-950/95 px-6 py-3">
          <button type="button" id="art_cancel_btn" class="rounded-xl border border-slate-800 px-4 py-2 text-sm text-slate-300 hover:bg-slate-900">Cancel</button>
          <button type="button" id="art_save_btn" class="rounded-xl bg-cyan-600 px-4 py-2 text-sm font-semibold text-slate-50 hover:bg-cyan-500">Save</button>
        </div>
      </div>`;
  }

  function dirty() {
    if (mode !== "edit") return false;
    const name = modalHandle.body.querySelector("#art_name")?.value;
    const desc = modalHandle.body.querySelector("#art_desc")?.value;
    return (name !== undefined && name !== (artifact.name || ""))
        || (desc !== undefined && desc !== (artifact.description || ""));
  }

  async function save() {
    const msg = modalHandle.body.querySelector("#art_save_msg");
    msg.className = "text-sm text-slate-400";
    msg.textContent = "Saving...";
    const name = modalHandle.body.querySelector("#art_name").value;
    const desc = modalHandle.body.querySelector("#art_desc").value;
    const bodyRaw = modalHandle.body.querySelector("#art_body").value;
    const enabled = modalHandle.body.querySelector("#art_enabled").checked;

    let bodyValue = bodyRaw;
    // Try to parse JSON-ish bodies; fall back to raw string
    if (bodyRaw.trim().startsWith("{") || bodyRaw.trim().startsWith("[")) {
      try { bodyValue = JSON.parse(bodyRaw); } catch { /* keep raw */ }
    }

    const url = paths.update.replace("{id}", encodeURIComponent(artifact.id));
    try {
      const saved = await fetchJson(url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          description: desc.trim(),
          body: bodyValue,
          enabled,
        }),
      });
      msg.className = "text-sm text-emerald-300";
      msg.textContent = "Saved.";
      if (onSaved) onSaved(saved || { ...artifact, name, description: desc, body: bodyValue, enabled });
      setTimeout(() => modalHandle.close("saved"), 600);
    } catch (err) {
      msg.className = "text-sm text-rose-300";
      msg.textContent = err.message || "Save failed.";
    }
  }

  function wireView() {
    const btn = modalHandle.body.querySelector("#artifact_edit_btn");
    if (btn) btn.addEventListener("click", () => {
      mode = "edit";
      modalHandle.setContent(renderEdit());
      wireEdit();
    });
  }
  function wireEdit() {
    modalHandle.body.querySelector("#art_cancel_btn").addEventListener("click", () => modalHandle.requestClose("cancel"));
    modalHandle.body.querySelector("#art_save_btn").addEventListener("click", save);
  }

  modalHandle = openModal(renderView(), {
    title: `Artifact — ${artifact.name || artifact.id || "(unnamed)"}`,
    width: "max-w-3xl",
  });
  modalHandle.setUnsavedGuard(dirty);
  wireView();
  return modalHandle;
}
