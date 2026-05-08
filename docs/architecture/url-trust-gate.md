# URL / Context Trust Gate

> **Status: pilot-ready.** The URL Trust Gate runs end-to-end. A 15-minute
> PoC installer (`scripts/poc/install.sh`) brings up the full stack on any
> developer laptop and submits four crafted attack pages — benign, display:none
> promptware, zero-width injection, credential-harvest — all producing live
> verdicts in under 120 ms. See `scripts/poc/README.md` for setup and
> `docs/architecture/capability-status.md` for the full capability status table.

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

The architecture review called these out; each has a code-level guard and documented production-hardening steps:

1. **Latency.** Reputation-first + cache + tight fast-path timeout in the browser hook. Async backfill for cache misses so the next visit is protected.
2. **Privacy.** Querystring keys classified by name; sensitive values never logged. Redacted form is what enters evidence.
3. **Crawler safety.** GET only, no cookies, no env trust, no HTTP/2, redirect chain re-validated each hop. Python-level SSRF check rejects RFC1918/loopback/link-local/cloud-metadata IPs. **Real boundary is the network namespace** — production deployment MUST land the crawler in an isolated egress container with no internal route.
4. **Side effects.** Detonation never reuses profiles. POST/PUT and form interaction are explicitly opt-in and off by default.
5. **Dynamic content.** Detonation captures JS-rendered DOM, CSS-hidden text, and Unicode-tag/zero-width promptware that the safe crawler cannot see.
6. **False positives.** Hidden text alone is a SIGNAL, not a verdict. Heuristic scores are modest; the ML detection layer is what confirms. Tenant `/feedback` flips into the training queue.

## Evidence

Every gate decision (other than `depth=fast` cache hits) writes an evidence record to the audit service via `POST /events`. The schema is the contract; see `services/url-trust-gate/evidence.py`. Records carry:

- `request_id`, `tenant_id`, `source`, consumer identity (user / app / agent)
- `canonical_url` (redacted), `url_fingerprint`, `redirect_chain`
- `content_hash` (post-fetch), `screenshot_hash` (post-detonation)
- `scores` (full vector), `iocs[]`, `decision`
- `crawled` / `detonated` flags

Evidence writes are best-effort and non-blocking — a failed write never delays the gate decision. Tenant SOC analysts can mark FP/FN via `POST /feedback`.

## Post-phishing mitigation angle

The gate is also the pivot for after-the-click defence. When a consumer reaches a credential-harvesting page despite earlier checks, downstream signals (form submit, password input on non-corporate domain, OAuth consent for risky scopes, suspicious download, agent-issued API call after hostile content) feed back through `POST /feedback` with high severity, which can:

- block the form submit (browser extension)
- isolate the browser session
- trigger token rotation for exposed credentials (via response service → identity service)
- create a SOC incident with full evidence chain
- promote the URL to the tenant block list automatically

This bridges phishing defence, browser security, AI agent security, and evidence-backed incident response in one decision lineage.

## Detonation worker

Detonation does NOT run in the gate process. It lives in a separate service
(`services/detonation-worker/`) built on Microsoft's official Playwright
image (`mcr.microsoft.com/playwright/python:v1.49.0-jammy`). Two reasons:

1. **Network isolation.** Mixing fetches of attacker-controlled URLs with
   calls into internal services (detection, policy, audit) is the wrong
   shape. The compose stack puts the worker on a dedicated `detonation`
   network. The gate joins both `default` and `detonation`; the worker
   joins only `detonation`. A hostile page that escapes Chromium cannot
   reach internal services because the routes don't exist.
2. **Image hygiene.** Microsoft's published image tracks Chromium and the
   font/GTK/NSS stack it needs. Trying to install
   `playwright install --with-deps chromium` onto a generic Debian PQC
   base hits Ubuntu/Debian package-name mismatches.

The gate's [`detonation.py`](../../services/url-trust-gate/detonation.py)
is a thin HTTP client. It POSTs `{url, tenant_id, request_id}` to the
worker's `/render` endpoint and maps the response into the same
`DetonationResult` dataclass the extractors and evidence layer already
understand. If the worker is unreachable or unset, deep-mode requests
return `DetonationResult(error=...)` and the gate downgrades to
standard-depth behaviour.

Production hardening expected on top of compose isolation: container
CPU/memory/pids limits (already declared in compose), Kubernetes
`NetworkPolicy` allowing ingress only from the gate's pod and no
egress to internal CIDR ranges or the cloud-metadata IP, dedicated
node pool for browser workloads.

## Completed since initial architecture doc

The following items were previously listed as "open work" and are now shipped:

| Item | Status | Location |
| --- | --- | --- |
| SmartScreen reputation feed adapter | **Done** | `services/url-trust-gate/feeds.py` — `SmartScreenFeed` |
| VirusTotal v3 reputation feed adapter | **Done** | `services/url-trust-gate/feeds.py` — `VirusTotalFeed` |
| Tenant allow/block list endpoint on policy service | **Done** | `GET /policies?tenant_id=…&scope=url-trust-gate` |
| Prometheus `/metrics` exposition | **Done** | `text/plain; version=0.0.4` content-type on port 8014 |
| LangChain `BaseTool._run` / `_arun` hook | **Done** | `sdks/python/cyberarmor/frameworks/langchain_url_trust_gate.py` |
| LlamaIndex reader / node-parser hook | **Done** | `sdks/python/cyberarmor/frameworks/llamaindex.py` |

## Remaining open work

- **OpenAI / Anthropic tool-use URL field wrappers** — intercept URLs in tool-call response objects before the agent fetches them. Higher value than raw HTTP-client patches.
- **Kubernetes NetworkPolicy** for the detonation worker pod — ingress only from gate, no egress to internal CIDRs or cloud-metadata IP. Compose isolation is in place; K8s policy is not yet written.
- **Production-hardening configuration** (enforced mTLS, Redis-backed reputation cache, `CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false`) — all code paths exist, requires operator configuration. See `scripts/poc/README.md` § "Hardening before real traffic".
