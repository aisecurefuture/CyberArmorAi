# URL / Context Trust Gate

> Status: scaffold. Code lives at `services/url-trust-gate/`. Consumer hooks scaffolded at `extensions/chromium-shared/url_trust_gate.js` and `rasp/python/cyberarmor_rasp_url_trust_gate.py`. Most ML scoring, the detonation sandbox, and external reputation feed adapters are TODO.

## Premise

Traditional URL filters answer: *"Is this site malicious for a human?"*

CyberArmor needs to answer a stronger question: *"Is this site safe for a human, a browser, AND an AI agent to consume?"*

The new attack surface is **indirect prompt injection** and **promptware**: malicious instructions hidden in web pages, documents, metadata, email footers, and images that are later ingested by an AI system. OWASP lists prompt injection as the top LLM risk, and existing Safe Browsing / SmartScreen / VirusTotal feeds do not detect AI-context attacks.

The URL / Context Trust Gate sits between consumers (humans, browsers, endpoint agents, RASP-instrumented apps, AI agents) and the open web. Before any consumer follows a URL or ingests external content, the gate canonicalises, fetches safely, scores, and decides — preserving evidence as it goes.

## The wedge

> **Safe Browsing for AI agents and enterprise AI workflows — with policy enforcement and evidence.**

Buyers already understand Safe Browsing, phishing protection, URL reputation, browser isolation, DLP, and AI prompt injection. The gate combines them around a new trust boundary: **external content before AI ingestion or agent action**.

## Pipeline

```
consumer ─► /evaluate
            │
            ├─ canonicalise + querystring redaction        (canonicalize.py)
            ├─ reputation cache + tenant allow/block       (reputation.py)
            ├─ safe crawl (SSRF-guarded, no creds)         (crawler.py)         [standard, deep]
            ├─ detonation sandbox (headless render)        (detonation.py)      [deep]
            ├─ signal extraction + IOC scrape              (extractors.py)
            ├─ ML scoring fan-out → detection service      (services/detection)
            ├─ policy decision → policy service            (services/policy)
            ├─ evidence write → audit service              (evidence.py)
            └─ optional incident → response service        (services/response)
```

## Decision actions

| Action | Meaning |
| --- | --- |
| `allow` | Below thresholds. Evidence skipped on `depth=fast` cache hits. |
| `warn` | Non-blocking interstitial / toast. Logged. |
| `redact` | Strip suspicious instruction blocks before AI ingestion. URL still loads. |
| `sandbox` | Send the user / agent to a remote browser isolation session. |
| `block` | Hard-block. Browser extension shows phishing interstitial; RASP raises `URLBlockedByTrustGate`. |
| `isolate` | Same as block + post-incident: revoke / rotate session tokens that may have leaked. |

## Where the gate is called from

| Consumer | Hook | Default depth |
| --- | --- | --- |
| Browser extension | `webNavigation.onBeforeNavigate` | `fast`, with async `standard` backfill |
| Endpoint agent | Outbound DNS / HTTP filter | `standard` |
| Proxy | Pre-request L7 interceptor | `standard` |
| RASP (Python) | Patched `requests` / `httpx` / `urllib3` | `fast` |
| AI router | Before tool-call URL retrieval | `deep` |
| Email / Office extensions | Link rewrite / hover preview | `standard` |

## Latency design

| Depth | Budget | Notes |
| --- | --- | --- |
| `fast` | ~10ms | Cache + canonicalisation. Browser-extension click-time. |
| `standard` | <500ms | Adds safe crawl. Default for endpoint / proxy / RASP. |
| `deep` | seconds | Adds detonation. Use for unknown URLs or `/feedback` recheck. |

Cache fingerprint = SHA-256 of `(scheme, host, port, path, sorted(non-sensitive querystring keys))`. URLs with rotating session tokens collapse to a single entry. Sensitive querystring values are redacted *before* logging or evidence write — they never leave the request handler.

## Production traps (deliberately bounded in code)

The architecture review called these out; each has a code-level guard plus a TODO for the production hardening:

1. **Latency.** Reputation-first + cache + tight fast-path timeout in the browser hook. Async backfill for cache misses so the next visit is protected.
2. **Privacy.** Querystring keys classified by name; sensitive values never logged. Redacted form is what enters evidence.
3. **Crawler safety.** GET only, no cookies, no env trust, no HTTP/2, redirect chain re-validated each hop. Python-level SSRF check rejects RFC1918/loopback/link-local/cloud-metadata IPs. **Real boundary is the network namespace** — production deployment MUST land the crawler in an isolated egress container with no internal route.
4. **Side effects.** Detonation never reuses profiles. POST/PUT and form interaction are explicitly opt-in and off by default.
5. **Dynamic content.** Detonation captures JS-rendered DOM, CSS-hidden text, and Unicode-tag/zero-width promptware that the safe crawler cannot see.
6. **False positives.** Hidden text alone is a SIGNAL, not a verdict. Heuristic scores are modest; the ML detection layer is what confirms. Tenant `/feedback` flips into the training queue.

## Evidence + training-data flywheel

Every gate decision (other than `depth=fast` cache hits) writes an evidence record to the audit service. The schema is the contract; see `services/url-trust-gate/evidence.py`. Records carry:

- `request_id`, `tenant_id`, `source`, consumer identity (user / app / agent)
- `canonical_url` (redacted), `url_fingerprint`, `redirect_chain`
- `content_hash` (post-fetch), `screenshot_hash` (post-detonation)
- `scores` (full vector), `iocs[]`, `decision`
- `crawled` / `detonated` flags

Tenant SOC analysts mark FP/FN via `POST /feedback`. An offline job joins evidence + feedback, then emits a labelled training shard for the detection service's ML models. **Control produces evidence; evidence produces training data; training data improves detection; detection improves control.**

## Post-phishing mitigation angle

The gate is also the pivot for after-the-click defence. When a consumer reaches a credential-harvesting page despite earlier checks, downstream signals (form submit, password input on non-corporate domain, OAuth consent for risky scopes, suspicious download, agent-issued API call after hostile content) feed back through `POST /feedback` with high severity, which can:

- block the form submit (browser extension)
- isolate the browser session
- trigger token rotation for exposed credentials (via response service → identity service)
- create a SOC incident with full evidence chain
- promote the URL to the tenant block list automatically

This bridges phishing defence, browser security, AI agent security, and evidence-backed incident response in one decision lineage.

## Open work

- Detonation sandbox worker pool (Playwright in one-shot containers).
- External reputation feed adapters: Safe Browsing v4, SmartScreen, VirusTotal.
- Tenant allow/block list endpoint on the policy service (lighter than full `/evaluate`).
- Prometheus metrics exposition.
- Training-shard exporter from the audit store.
- AI-framework hooks: LangChain `BaseTool._run`, LlamaIndex readers, Anthropic / OpenAI tool-use URL fields. (Higher value than raw HTTP-client patches because they intercept the URL the *agent* chose.)
