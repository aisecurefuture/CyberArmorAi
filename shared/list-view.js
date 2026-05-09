/**
 * Shared list-view module for the customer portal and admin dashboard.
 *
 * Exports
 * -------
 *   mountListView({container, rows, columns, filename, onRowClick, role})
 *     Renders a sortable, filterable, exportable table into `container`.
 *     Each column may be `text`, `enum`, or `date`. Filters are per-column
 *     with a × clear button each. CSV export honors current sort+filter.
 *
 *   openModal(htmlOrNode, options)  -> { close, setContent, isOpen, setUnsavedGuard }
 *     Slide-up modal centered on screen. Closes on ESC, backdrop click,
 *     or × button. Unsaved-changes guard prompts before close when set.
 *
 *   closeModal()  -> closes the topmost modal
 *
 *   esc(s), fmt(d), badge(text, tone), card(html), tableBadge(...)
 *     Small render helpers shared with portal app.js code.
 *
 * Conventions
 * -----------
 *   columns: [
 *     { key, label, type: 'text'|'enum'|'date'|'number', value: row=>any,
 *       render: row=>html, csv: row=>string, sortable=true, filterable=true,
 *       enumValues?: ['allow','block',...] }
 *   ]
 *   - `value(row)`   raw value used for sort + filter + CSV
 *   - `render(row)`  HTML for the cell (defaults to escaped value)
 *   - `csv(row)`     plain string for CSV (defaults to value)
 *
 * Filter types
 * ------------
 *   text:   case-insensitive substring against value(row)
 *   enum:   <select> populated from enumValues or distinct values
 *   date:   two <input type=date> for from/to range; row value parsed as Date
 *   number: <input type=number> for "from" only (>= filter); easy to extend
 */

// ─── small helpers ────────────────────────────────────────────────────────

export function esc(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function fmt(value) {
  if (!value) return "";
  try { return new Date(value).toLocaleString(); } catch { return String(value); }
}

export function card(content) {
  return `<section class="rounded-3xl border border-slate-800 bg-slate-950/80 p-5 shadow-xl shadow-slate-950/40">${content}</section>`;
}

const BADGE_COLORS = {
  cyan:  "border-cyan-900 bg-cyan-950/50 text-cyan-100",
  green: "border-emerald-900 bg-emerald-950/50 text-emerald-100",
  amber: "border-amber-900 bg-amber-950/50 text-amber-100",
  red:   "border-rose-900 bg-rose-950/50 text-rose-100",
  slate: "border-slate-800 bg-slate-900 text-slate-200",
};

export function badge(text, tone = "slate") {
  return `<span class="inline-flex rounded-full border px-2.5 py-1 text-xs ${BADGE_COLORS[tone] || BADGE_COLORS.slate}">${esc(text)}</span>`;
}

// ─── modal stack ──────────────────────────────────────────────────────────

const _modalStack = [];

function _ensureModalRoot() {
  let root = document.getElementById("ca-modal-root");
  if (!root) {
    root = document.createElement("div");
    root.id = "ca-modal-root";
    document.body.appendChild(root);
  }
  return root;
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && _modalStack.length) {
    event.preventDefault();
    _modalStack[_modalStack.length - 1].requestClose("esc");
  }
});

export function openModal(content, options = {}) {
  const {
    title = "",
    width = "max-w-3xl",
    onClose = null,
    closeOnBackdrop = true,
  } = options;

  const root = _ensureModalRoot();
  const overlay = document.createElement("div");
  overlay.className = "fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/70 backdrop-blur p-4 md:p-8";
  overlay.innerHTML = `
    <div class="modal-panel w-full ${width} rounded-3xl border border-slate-800 bg-slate-950 shadow-2xl shadow-slate-950/80 my-8" role="dialog" aria-modal="true" tabindex="-1">
      <div class="flex items-start justify-between gap-4 border-b border-slate-800 px-6 py-4">
        <div class="modal-title text-base font-semibold text-slate-100">${esc(title)}</div>
        <button type="button" class="modal-close rounded-full p-1 text-slate-400 hover:bg-slate-900 hover:text-slate-100" aria-label="Close">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 5l10 10M15 5L5 15"/></svg>
        </button>
      </div>
      <div class="modal-body px-6 py-5"></div>
    </div>
  `;
  root.appendChild(overlay);

  const panel = overlay.querySelector(".modal-panel");
  const body = overlay.querySelector(".modal-body");
  if (typeof content === "string") body.innerHTML = content;
  else if (content instanceof Node) body.appendChild(content);

  let unsavedGuard = null;
  let closed = false;

  const handle = {
    overlay, panel, body,
    isOpen: () => !closed,
    setContent(next) {
      if (typeof next === "string") body.innerHTML = next;
      else { body.innerHTML = ""; body.appendChild(next); }
    },
    setTitle(next) { overlay.querySelector(".modal-title").textContent = next; },
    setUnsavedGuard(fn) { unsavedGuard = fn; },
    requestClose(reason = "manual") {
      if (closed) return;
      if (unsavedGuard && unsavedGuard()) {
        const ok = window.confirm("Discard unsaved changes?");
        if (!ok) return;
      }
      handle.close(reason);
    },
    close(reason = "manual") {
      if (closed) return;
      closed = true;
      const idx = _modalStack.indexOf(handle);
      if (idx >= 0) _modalStack.splice(idx, 1);
      overlay.remove();
      if (onClose) try { onClose(reason); } catch { /* noop */ }
    },
  };

  overlay.addEventListener("click", (event) => {
    if (event.target === overlay && closeOnBackdrop) handle.requestClose("backdrop");
  });
  overlay.querySelector(".modal-close").addEventListener("click", () => handle.requestClose("button"));

  _modalStack.push(handle);
  // Focus the panel for ESC handling
  setTimeout(() => panel.focus(), 0);
  return handle;
}

export function closeModal() {
  if (_modalStack.length) _modalStack[_modalStack.length - 1].requestClose("api");
}

// ─── CSV export ───────────────────────────────────────────────────────────

function _csvEscape(value) {
  if (value == null) return "";
  const s = String(value);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function rowsToCsv(rows, columns) {
  const header = columns.map((c) => _csvEscape(c.label)).join(",");
  const body = rows.map((row) =>
    columns.map((c) => {
      const v = c.csv ? c.csv(row) : (c.value ? c.value(row) : row[c.key]);
      return _csvEscape(v);
    }).join(",")
  ).join("\r\n");
  return header + "\r\n" + body + "\r\n";
}

export function downloadCsv(filename, csv) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// ─── sort / filter engine ─────────────────────────────────────────────────

function _coerceSortValue(col, row) {
  const raw = col.value ? col.value(row) : row[col.key];
  if (raw == null || raw === "") return null;
  if (col.type === "number") {
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }
  if (col.type === "date") {
    const t = Date.parse(raw);
    return Number.isFinite(t) ? t : null;
  }
  return String(raw).toLowerCase();
}

function _matchesFilter(col, row, filter) {
  if (!filter) return true;
  const raw = col.value ? col.value(row) : row[col.key];
  const s = raw == null ? "" : String(raw);
  if (col.type === "enum") {
    if (!filter.value) return true;
    return s === filter.value;
  }
  if (col.type === "date") {
    if (!filter.from && !filter.to) return true;
    const t = Date.parse(s);
    if (!Number.isFinite(t)) return false;
    if (filter.from) {
      const f = Date.parse(filter.from);
      if (Number.isFinite(f) && t < f) return false;
    }
    if (filter.to) {
      // "to" is inclusive — extend to end of day
      const tt = Date.parse(filter.to);
      if (Number.isFinite(tt) && t > tt + 86399999) return false;
    }
    return true;
  }
  if (col.type === "number") {
    if (filter.from === "" || filter.from == null) return true;
    const n = Number(s);
    return Number.isFinite(n) && n >= Number(filter.from);
  }
  // text
  if (!filter.value) return true;
  return s.toLowerCase().includes(String(filter.value).toLowerCase());
}

function _applySortFilter(rows, columns, state) {
  let out = rows.filter((row) =>
    columns.every((col) => _matchesFilter(col, row, state.filters[col.key]))
  );
  if (state.sortKey) {
    const col = columns.find((c) => c.key === state.sortKey);
    if (col) {
      out = out.slice().sort((a, b) => {
        const va = _coerceSortValue(col, a);
        const vb = _coerceSortValue(col, b);
        if (va == null && vb == null) return 0;
        if (va == null) return 1;
        if (vb == null) return -1;
        if (va < vb) return state.sortDir === "asc" ? -1 : 1;
        if (va > vb) return state.sortDir === "asc" ? 1 : -1;
        return 0;
      });
    }
  }
  return out;
}

// ─── filter cell renderers ────────────────────────────────────────────────

function _filterCellHtml(col, filter, idx) {
  if (col.filterable === false) {
    return `<th class="px-3 py-1"></th>`;
  }
  const id = `flt-${idx}`;
  if (col.type === "enum") {
    const values = col.enumValues || [];
    const opts = ['<option value="">(any)</option>']
      .concat(values.map((v) => `<option value="${esc(v)}"${filter?.value === v ? " selected" : ""}>${esc(v)}</option>`))
      .join("");
    return `
      <th class="px-3 py-1 align-top">
        <div class="flex items-center gap-1">
          <select data-flt="${id}" data-flt-kind="enum" class="w-full rounded-lg border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200">${opts}</select>
          <button type="button" data-flt-clear="${id}" class="rounded p-1 text-slate-500 hover:text-rose-300 ${filter?.value ? "" : "invisible"}" aria-label="Clear">×</button>
        </div>
      </th>`;
  }
  if (col.type === "date") {
    const from = filter?.from || "";
    const to = filter?.to || "";
    const active = from || to;
    return `
      <th class="px-3 py-1 align-top">
        <div class="flex items-center gap-1">
          <input type="date" data-flt="${id}" data-flt-kind="date-from" value="${esc(from)}" class="w-28 rounded-lg border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200" />
          <span class="text-xs text-slate-600">–</span>
          <input type="date" data-flt="${id}" data-flt-kind="date-to" value="${esc(to)}" class="w-28 rounded-lg border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200" />
          <button type="button" data-flt-clear="${id}" class="rounded p-1 text-slate-500 hover:text-rose-300 ${active ? "" : "invisible"}" aria-label="Clear">×</button>
        </div>
      </th>`;
  }
  if (col.type === "number") {
    const v = filter?.from ?? "";
    return `
      <th class="px-3 py-1 align-top">
        <div class="flex items-center gap-1">
          <input type="number" data-flt="${id}" data-flt-kind="num-from" value="${esc(v)}" placeholder="≥" class="w-full rounded-lg border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200" />
          <button type="button" data-flt-clear="${id}" class="rounded p-1 text-slate-500 hover:text-rose-300 ${v !== "" ? "" : "invisible"}" aria-label="Clear">×</button>
        </div>
      </th>`;
  }
  // text
  const v = filter?.value || "";
  return `
    <th class="px-3 py-1 align-top">
      <div class="flex items-center gap-1">
        <input type="text" data-flt="${id}" data-flt-kind="text" value="${esc(v)}" placeholder="filter" class="w-full rounded-lg border border-slate-800 bg-slate-950 px-2 py-1 text-xs text-slate-200" />
        <button type="button" data-flt-clear="${id}" class="rounded p-1 text-slate-500 hover:text-rose-300 ${v ? "" : "invisible"}" aria-label="Clear">×</button>
      </div>
    </th>`;
}

// ─── mountListView ────────────────────────────────────────────────────────

export function mountListView(opts) {
  const {
    container,
    rows = [],
    columns = [],
    filename = "export",
    onRowClick = null,
    emptyMessage = "No records found.",
  } = opts;

  // Auto-populate enumValues from data when not specified
  for (const col of columns) {
    if (col.type === "enum" && !col.enumValues) {
      const values = new Set();
      for (const row of rows) {
        const v = col.value ? col.value(row) : row[col.key];
        if (v != null && v !== "") values.add(String(v));
      }
      col.enumValues = Array.from(values).sort();
    }
  }

  const state = {
    sortKey: null,
    sortDir: "asc",
    filters: Object.fromEntries(columns.map((c) => [c.key, _initialFilter(c)])),
    rows,
    columns,
  };

  function _initialFilter(col) {
    if (col.type === "date") return { from: "", to: "" };
    if (col.type === "number") return { from: "" };
    if (col.type === "enum") return { value: "" };
    return { value: "" };
  }

  function visibleRows() {
    return _applySortFilter(state.rows, state.columns, state);
  }

  function clearAllFilters() {
    for (const col of columns) state.filters[col.key] = _initialFilter(col);
    render();
  }

  function clearOneFilter(idx) {
    const col = columns[idx];
    if (!col) return;
    state.filters[col.key] = _initialFilter(col);
    render();
  }

  function exportCsv() {
    const visible = visibleRows();
    const csv = rowsToCsv(visible, columns);
    const date = new Date().toISOString().slice(0, 10);
    downloadCsv(`${filename}_${date}.csv`, csv);
  }

  function _sortIndicator(key) {
    if (state.sortKey !== key) return `<span class="ml-1 text-slate-700">⇅</span>`;
    return state.sortDir === "asc"
      ? `<span class="ml-1 text-cyan-300">▲</span>`
      : `<span class="ml-1 text-cyan-300">▼</span>`;
  }

  function _toggleSort(key) {
    const col = columns.find((c) => c.key === key);
    if (!col || col.sortable === false) return;
    if (state.sortKey !== key) { state.sortKey = key; state.sortDir = "asc"; }
    else if (state.sortDir === "asc") { state.sortDir = "desc"; }
    else { state.sortKey = null; state.sortDir = "asc"; }
    render();
  }

  function render() {
    const visible = visibleRows();
    const headerCells = columns.map((c) => {
      const sortable = c.sortable !== false;
      const click = sortable ? `data-sort="${c.key}"` : "";
      const cursor = sortable ? "cursor-pointer hover:text-cyan-200" : "";
      return `<th class="px-3 py-2 text-left text-xs uppercase tracking-[0.18em] text-slate-500 ${cursor}" ${click}>
        <span class="select-none">${esc(c.label)}${sortable ? _sortIndicator(c.key) : ""}</span>
      </th>`;
    }).join("");
    const filterCells = columns.map((c, i) => _filterCellHtml(c, state.filters[c.key], i)).join("");
    const bodyRows = visible.map((row, ri) => {
      const cells = columns.map((c) => {
        const html = c.render ? c.render(row) : esc(c.value ? c.value(row) : row[c.key] ?? "");
        return `<td class="px-3 py-3 align-top">${html}</td>`;
      }).join("");
      const cursor = onRowClick ? "cursor-pointer hover:bg-slate-900/60" : "";
      return `<tr data-row-idx="${ri}" class="border-t border-slate-800 ${cursor}">${cells}</tr>`;
    }).join("");
    const emptyHtml = !bodyRows
      ? `<tr><td class="px-3 py-8 text-center text-slate-500" colspan="${columns.length}">${esc(state.rows.length ? "No rows match the current filters." : emptyMessage)}</td></tr>`
      : "";
    const anyFilters = Object.entries(state.filters).some(([, f]) =>
      (f.value && f.value !== "") || (f.from && f.from !== "") || (f.to && f.to !== "")
    );

    container.innerHTML = `
      <section class="rounded-3xl border border-slate-800 bg-slate-950/80 p-4 shadow-xl shadow-slate-950/40">
        <div class="flex flex-wrap items-center justify-between gap-3 px-1 py-2">
          <div class="text-xs text-slate-400">
            Showing <span class="font-mono text-slate-200">${visible.length}</span> of
            <span class="font-mono text-slate-200">${state.rows.length}</span> rows
          </div>
          <div class="flex items-center gap-2">
            <button type="button" data-action="clear-filters" class="rounded-xl border border-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-900 ${anyFilters ? "" : "opacity-40 pointer-events-none"}">× Clear filters</button>
            <button type="button" data-action="export-csv" class="rounded-xl bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-slate-50 hover:bg-cyan-500">Export CSV</button>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead><tr>${headerCells}</tr><tr class="border-t border-slate-800">${filterCells}</tr></thead>
            <tbody>${bodyRows || emptyHtml}</tbody>
          </table>
        </div>
      </section>
    `;
    _wire();
  }

  function _wire() {
    container.querySelectorAll("[data-sort]").forEach((th) => {
      th.addEventListener("click", () => _toggleSort(th.dataset.sort));
    });
    container.querySelector('[data-action="clear-filters"]').addEventListener("click", clearAllFilters);
    container.querySelector('[data-action="export-csv"]').addEventListener("click", exportCsv);

    container.querySelectorAll("[data-flt]").forEach((input) => {
      const id = input.dataset.flt;
      const idx = Number(id.replace(/^flt-/, ""));
      const col = columns[idx];
      const kind = input.dataset.fltKind;
      const handler = () => {
        const f = state.filters[col.key] || _initialFilter(col);
        if (kind === "text") f.value = input.value;
        else if (kind === "enum") f.value = input.value;
        else if (kind === "date-from") f.from = input.value;
        else if (kind === "date-to") f.to = input.value;
        else if (kind === "num-from") f.from = input.value;
        state.filters[col.key] = f;
        render();
      };
      input.addEventListener("input", handler);
      input.addEventListener("change", handler);
    });

    container.querySelectorAll("[data-flt-clear]").forEach((btn) => {
      const id = btn.dataset.fltClear;
      const idx = Number(id.replace(/^flt-/, ""));
      btn.addEventListener("click", () => clearOneFilter(idx));
    });

    if (onRowClick) {
      container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
        tr.addEventListener("click", () => {
          const ri = Number(tr.dataset.rowIdx);
          const visible = visibleRows();
          if (visible[ri]) onRowClick(visible[ri]);
        });
      });
    }
  }

  render();

  return {
    refresh(nextRows) {
      if (nextRows) state.rows = nextRows;
      render();
    },
    getVisibleRows: visibleRows,
    state,
  };
}
