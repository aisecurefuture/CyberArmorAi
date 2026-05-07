# URL / Context Trust Gate

Pre-ingestion control point for URLs and external content destined for
humans, browsers, endpoint agents, RASP-instrumented applications, and
AI agents. Before any consumer follows a URL or ingests external
content, the gate canonicalizes the destination, fetches it safely,
scores it for phishing / hidden prompt injection / promptware /
data-exfil / IOC signals, and applies a policy decision. Evidence is
preserved for proof and as training data for the detection layer.

## Why a separate control point

Traditional URL filters answer *"Is this site malicious for a human?"*.
Enterprise AI security needs to answer a stronger question: *"Is this
site safe for a human, a browser, AND an AI agent to consume?"*

The new attack surface is **indirect prompt injection** and
**promptware**: malicious instructions hidden in web pages, documents,
metadata, and email footers that are later ingested by an AI system.
Existing Safe Browsing / SmartScreen / VirusTotal feeds are useful for
the older phishing/malware question but do not detect AI-context
attacks like CSS-hidden text, Unicode-tag-encoded instructions, or
zero-width-space-encoded payloads that are invisible to humans but
read verbatim by LLMs.

The gate combines URL reputation, safe crawl, headless-browser
detonation, ML scoring, policy enforcement, and evidence into one
trust boundary at **external content before AI ingestion or agent
action**.

## Pipeline

```
consumer ─► /evaluate
            │
            ├─ canonicalize URL + classify querystring sensitivity
            ├─ reputation cache + tenant allow/block list lookup
            ├─ safe crawl (SSRF-guarded, no creds)               [standard, deep]
            ├─ detonation sandbox (Playwright headless render)   [deep]
            ├─ extract signals + scrape IOCs
            ├─ fan out to detection service for ML scoring
            ├─ external feeds (Safe Browsing v4)
            ├─ policy decision via policy service
            ├─ evidence write to audit service
            └─ optional incident dispatch to response service
```

## Decision actions

| Action | Meaning |
| --- | --- |
| `allow` | Below thresholds. |
| `warn` | Non-blocking interstitial / toast. Logged. |
| `redact` | Strip suspicious instruction blocks before AI ingestion. URL still loads. |
| `sandbox` | Send the user / agent to a remote browser isolation session. |
| `block` | Hard block. Browser shows phishing interstitial; RASP raises `URLBlockedByTrustGate`. |
| `isolate` | Block + post-incident: revoke / rotate session tokens that may have leaked. |

## Where the gate is called from

| Consumer | Hook | Default depth |
| --- | --- | --- |
| Browser extension | `webNavigation.onBeforeNavigate` | `fast`, async `standard` backfill |
| Endpoint agent | Outbound DNS / HTTP advisory + loopback IPC daemon at `127.0.0.1:48515` | `fast` |
| Proxy | Pre-request L7 interceptor | `standard` |
| RASP (Python) | Patched `requests` / `httpx` / `urllib3` | `fast` |
| AI router | Before tool-call URL retrieval | `deep` |
| LangChain SDK | `wrap_tool` / `wrap_agent_tools` / `make_guarded_browser_tool` | `deep` |
| Email / Office extensions | Link rewrite / hover preview | `standard` |

## Latency budgets

| Depth | Budget | Notes |
| --- | --- | --- |
| `fast` | ~10ms | Cache + canonicalisation. Browser-extension click-time. |
| `standard` | <500ms | Adds safe crawl. Default for endpoint agent / proxy / RASP. |
| `deep` | seconds | Adds Playwright detonation. Best-effort, used for unknown URLs. |

The cache fingerprint is `SHA-256(scheme, host, port, path,
sorted(non-sensitive querystring keys))`. URLs with rotating session
tokens collapse to a single cache entry. Sensitive querystring values
are redacted *before* logging or evidence write.

## Production hardening

The gate makes outbound requests to attacker-controlled URLs **only via
the detonation worker**. The worker is a separate service built on
Microsoft's official Playwright image and runs on a dedicated
`detonation` Docker network. The gate joins both the default backend
network and `detonation`; the worker joins only `detonation`. A hostile
page that escapes Chromium cannot reach `policy`, `detection`, `audit`,
or any other internal service — those routes don't exist on its
network namespace.

The gate also has Python-level guards on its own safe crawl path: SSRF
address checks, redirect-hop re-validation, no-cookie /
no-Authorization fetches, hard size / time / redirect caps. The network
namespace is still the real boundary — the Python checks are
belt-and-braces.

For Kubernetes deployments, a `NetworkPolicy` should allow ingress to
the worker pod only from the gate, and forbid egress to internal CIDR
ranges and the cloud-metadata IP. A dedicated node pool for browser
workloads is recommended.

## Evidence + training-data flywheel

Every gate decision (other than `depth=fast` cache hits) writes an
evidence record to the audit service:

- `request_id`, `tenant_id`, `source`, consumer identity (user / app / agent)
- `canonical_url` (redacted), `url_fingerprint`, `redirect_chain`
- `content_hash` (post-fetch), `screenshot_hash` (post-detonation)
- `scores` (full vector), `iocs[]`, `decision`
- `crawled` / `detonated` flags

Tenant SOC analysts mark false positives / false negatives via
`POST /feedback`. An offline job joins evidence + feedback and emits a
labelled training shard for the detection service's ML models.

> Control produces evidence; evidence produces training data; training
> data improves detection; detection improves control.

## Service map

| Endpoint | Purpose |
| --- | --- |
| `POST /evaluate` | Main entry point. Returns a `TrustGateResponse` with the action. |
| `POST /feedback` | SOC analyst FP/FN feedback. Feeds the training-data flywheel. |
| `GET /health` | Liveness. |
| `GET /ready` | Readiness. |
| `GET /metrics` | Prometheus exposition (counters + latency histograms). |
| `GET /pki/public-key` | Standard service identity. |

Auth: `x-api-key: $URL_TRUST_GATE_API_SECRET`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `URL_TRUST_GATE_API_SECRET` | `change-me-url-trust-gate` | Inbound API key. |
| `DETECTION_SERVICE_URL` | `http://detection-service:8002` | |
| `POLICY_SERVICE_URL` | `http://policy-service:8001` | |
| `RESPONSE_SERVICE_URL` | `http://response-service:8003` | |
| `AUDIT_SERVICE_URL` | `http://audit-service:8004` | |
| `SAFE_BROWSING_API_KEY` | (empty) | Optional Google Safe Browsing v4 key. Gate works without it. |
| `URL_TRUST_GATE_DETONATION_DEFAULT` | `off` | Set to `on` to run detonation by default for `depth=deep`. |
| `URL_TRUST_GATE_CRAWLER_TIMEOUT_S` | `4.0` | Per-request crawler timeout. |
| `URL_TRUST_GATE_CRAWLER_MAX_BYTES` | `1048576` | Hard cap on fetched body size. |
| `URL_TRUST_GATE_CRAWLER_MAX_REDIRECTS` | `5` | Each hop re-validated against SSRF rules. |
| `URL_TRUST_GATE_CACHE_TTL_S` | `900` | Reputation cache TTL. |

## Files in the repo

- `services/url-trust-gate/` — service (FastAPI + Playwright + safe crawler + reputation cache + Prometheus metrics + tests).
- `extensions/chromium-shared/url_trust_gate.js` — browser extension hook.
- `agents/endpoint-agent/monitors/url_trust_gate.py` — endpoint agent gate client + loopback IPC daemon + `network_monitor` advisory.
- `rasp/python/cyberarmor_rasp_url_trust_gate.py` — RASP outbound HTTP hook.
- `sdks/python/cyberarmor/frameworks/langchain_url_trust_gate.py` — LangChain tool wrapper.
- `docs/architecture/url-trust-gate.md` — deep-dive architecture doc with production traps mapped to code-level guards.
