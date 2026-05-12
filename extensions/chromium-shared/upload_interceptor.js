// MAIN-world script: wraps fetch() and XMLHttpRequest so multipart uploads
// run through tenant policy before the network request goes out.
//
// Why MAIN world: content scripts run in an isolated world and can't see
// page-script fetch calls — to actually intercept ChatGPT / Claude / etc.,
// we have to replace window.fetch and XMLHttpRequest.prototype.send on the
// real page object. MV3 supports this via "world": "MAIN" in the manifest.
//
// Protocol: this script asks the isolated-world content script for a
// decision via window.postMessage; the content script forwards to the
// background's policy evaluator and posts the result back. Pending
// requests are tracked by random id.

(() => {
  if (window.__cyberarmor_upload_interceptor_installed) return;
  window.__cyberarmor_upload_interceptor_installed = true;

  const pending = new Map(); // id -> { resolve, reject, timer }
  const REQUEST_TIMEOUT_MS = 2500; // never let an upload hang on policy

  function newId() {
    try { return crypto.randomUUID(); }
    catch { return "ul-" + Math.random().toString(36).slice(2) + Date.now().toString(36); }
  }

  // The isolated-world content script answers with this exact shape.
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.type !== "cyberarmor:upload_decision") return;
    const entry = pending.get(msg.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    pending.delete(msg.id);
    entry.resolve(msg);
  });

  function askPolicy(url, files) {
    return new Promise((resolve) => {
      const id = newId();
      const timer = setTimeout(() => {
        pending.delete(id);
        // Fail open on timeout so a misbehaving extension doesn't break the
        // page; telemetry on the content side records the timeout.
        resolve({ id, action: "allow", timedOut: true });
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, timer });
      window.postMessage({
        type: "cyberarmor:upload_request",
        id,
        url: String(url || ""),
        files,
      }, "*");
    });
  }

  function summarizeFormData(body) {
    const files = [];
    try {
      for (const [, v] of body.entries()) {
        if (v && typeof v === "object" && (v instanceof File || v instanceof Blob)) {
          files.push({
            name: (v && v.name) ? String(v.name) : "",
            type: (v && v.type) ? String(v.type) : "",
            size: (v && typeof v.size === "number") ? v.size : 0,
          });
        }
      }
    } catch { /* some entries() iterators are touchy — best-effort only */ }
    return files;
  }

  // --- fetch() wrapper -------------------------------------------------

  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = async function patchedFetch(input, init) {
      try {
        const body = init && init.body;
        // FormData → multipart upload candidate. Blob/File bodies on their
        // own are valid too (PUT to S3-style endpoints), but skip strings
        // and ArrayBuffers — those are JSON / opaque uploads we can't
        // meaningfully summarize for a policy.
        let files = null;
        if (typeof FormData !== "undefined" && body instanceof FormData) {
          files = summarizeFormData(body);
        } else if (typeof Blob !== "undefined" && body instanceof Blob && body.size > 0) {
          files = [{
            name: body.name || "",
            type: body.type || "application/octet-stream",
            size: body.size,
          }];
        }
        if (files && files.length > 0) {
          const url = typeof input === "string"
            ? input
            : (input && input.url) ? input.url : String(input || "");
          const decision = await askPolicy(url, files);
          if (decision && decision.action === "block_upload") {
            // Throw an AbortError so the caller's existing error handlers
            // surface a reasonable message and the request never goes out.
            const err = new DOMException(
              `CyberArmor blocked upload (${decision.policy || "policy"})`,
              "AbortError",
            );
            throw err;
          }
        }
      } catch (innerErr) {
        // Only rethrow our own AbortError; everything else means the
        // policy ask failed and we should fall through to the original
        // fetch so the page isn't broken.
        if (innerErr && innerErr.name === "AbortError" && /CyberArmor/.test(innerErr.message)) {
          throw innerErr;
        }
      }
      return origFetch.apply(this, arguments);
    };
  }

  // --- XMLHttpRequest wrapper -----------------------------------------
  //
  // XHR.send is synchronous from the caller's POV. We can't await the
  // policy decision before send() returns, so the strategy is:
  //   1. Capture URL on .open()
  //   2. On .send(), if body is FormData with files, optimistically let
  //      the request go but ask policy in parallel
  //   3. When the decision comes back, if it's block_upload, abort the
  //      already-flying XHR. The server may have already received bytes
  //      but the response will never be processed by the page.
  //
  // This is a known race for very fast endpoints. For the demo (and most
  // multi-MB uploads) the round-trip to policy beats the upload finish.
  // Modern AI sites use fetch() anyway — this is the fallback path.

  try {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__cyberarmor_url = String(url || "");
      return origOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function (body) {
      try {
        if (typeof FormData !== "undefined" && body instanceof FormData) {
          const files = summarizeFormData(body);
          if (files.length > 0) {
            const xhr = this;
            askPolicy(this.__cyberarmor_url || "", files).then((decision) => {
              if (decision && decision.action === "block_upload") {
                try { xhr.abort(); } catch { /* ignore */ }
              }
            });
          }
        }
      } catch { /* fall through to original send */ }
      return origSend.apply(this, arguments);
    };
  } catch { /* environments without XHR (workers) — ignore */ }
})();
