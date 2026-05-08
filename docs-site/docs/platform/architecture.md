# Architecture

CyberArmor is designed as a layered AI security platform rather than a single
point product. It combines runtime enforcement, model-aware detection, endpoint
and integration visibility, secrets management, and evidence capture across the
AI stack.

## Architectural model

At a high level, the platform operates across five responsibilities:

1. **Gate** external content before any human, browser, or AI agent ingests it
2. **Discover** AI tools, agents, APIs, and unmanaged usage
3. **Govern** with policy tied to tenant, user, service, and agent context
4. **Protect** at runtime with detection and enforcement
5. **Prove** with auditable, attributable evidence

## Core layers

### Public surfaces

- `cyberarmor.ai` for product and company messaging
- `app.cyberarmor.ai` for customer-facing bootstrap and portal flows
- `admin.cyberarmor.ai` for operator/admin workflows
- `docs.cyberarmor.ai` for technical guidance
- `support.cyberarmor.ai` for support guidance

### Pre-ingestion trust layer

- `url-trust-gate` (port 8014) is the pre-ingestion control point for external
  URLs and content. Before any consumer follows a URL or ingests content from
  the web, the gate canonicalizes, fetches safely (SSRF-guarded), optionally
  detonates in an isolated Playwright sandbox, scores for phishing / hidden
  prompt injection / promptware / IOC signals, and applies a policy decision —
  `allow`, `warn`, `redact`, `sandbox`, `block`, or `isolate`. Evidence is
  written to audit on every non-cached decision.
- `detonation-worker` (port 8015, internal only) is the isolated Playwright
  service the gate calls for deep-mode renders. It runs on a dedicated
  `detonation` Docker network with no route to internal services, so a hostile
  page that escapes Chromium cannot reach `policy`, `detection`, `audit`, or
  any other platform service.
- Consumer hooks ship in the repo: browser extension
  (`extensions/chromium-shared/url_trust_gate.js`), endpoint agent
  (`agents/endpoint-agent/monitors/url_trust_gate.py`), RASP Python
  (`rasp/python/cyberarmor_rasp_url_trust_gate.py`), LangChain SDK
  (`sdks/python/cyberarmor/frameworks/langchain_url_trust_gate.py`), and
  LlamaIndex SDK (`sdks/python/cyberarmor/frameworks/llamaindex.py`).
- Optional reputation feeds: Google Safe Browsing v4, Microsoft SmartScreen
  (Defender Threat Intelligence), VirusTotal v3 — each configurable via env
  var; the gate works without them.

See [URL Trust Gate](url-trust-gate.md) for the full pipeline, latency budgets,
decision actions, evidence schema, and production hardening steps.

### Control and policy layer

- `control-plane` handles tenants, API context, bootstrap flows, audit-facing
  API interactions, and agent registration
- `policy` evaluates runtime decisions using nested AND/OR logic, priority, and
  enforcement actions

### Detection and response layer

- `detection` performs prompt injection, sensitive data, toxicity, and
  output-safety analysis
- `response` turns incidents into actions such as blocking, webhook dispatch, or
  other response orchestration

### Identity, routing, and integration layer

- `identity` supports workforce identity integration
- `agent-identity` issues and validates AI agent identities
- `ai-router` normalizes AI provider access and governance
- `integration-control` inventories SaaS and AI integrations and evaluates risk

### Secrets and trust layer

- `secrets-service` is the CyberArmor control layer for secrets operations
- `openbao` provides the underlying secret and cryptographic engine
- `/pki/public-key` exposes public PQC material for clients that need
  encrypted/authenticated transport

### Endpoint and runtime layer

- endpoint agents monitor AI usage on macOS, Windows, and Linux
- RASP packages instrument application runtimes in multiple languages
- browser and IDE extensions extend discovery and policy visibility closer to
  the user

### Evidence and export layer

- `audit` captures immutable or tamper-resistant activity records
- `siem-connector` forwards events to external security operations platforms
- `compliance` maps evidence to control and framework views

## Deployment shape

The current repo is commonly deployed as a single-host Docker Compose stack
fronted by Caddy. Backend services bind to loopback or internal container
networking while public domains terminate at the edge.

That means a healthy deployment depends on two things being true at once:

- each backend service is actually healthy
- each public route is correctly proxied to the intended backend path

## Current product boundary

The architecture is real and deployable today for demos, internal operations,
staging, and guided pilots. At the same time, some public-facing experience
surfaces are still maturing. Treat the docs as the clearest description of the
working system as it exists in this repository today.
