# CyberArmor Platform — Capability Status

> Last updated: 2026-05-07. This table is the authoritative, buyer-facing
> statement of what works, what requires configuration, and what is on the
> roadmap. Update it whenever a capability ships or its status changes.

## Status legend

| Status | Meaning |
| --- | --- |
| **Working** | Runs end-to-end in the current codebase. Tested. |
| **Configurable** | Code is implemented; requires one or more env vars or operator steps to activate. |
| **Pilot** | Functional in controlled settings; expanding through design-partner work. |
| **Roadmap** | Not yet implemented. |

---

## URL / Context Trust Gate

| Capability | Status | Notes |
| --- | --- | --- |
| URL evaluation API — `POST /evaluate` end-to-end | **Working** | Heuristic-only mode runs without HuggingFace downloads |
| 15-minute PoC installer + 4 crafted attack pages | **Working** | `scripts/poc/install.sh`, `uninstall.sh`, `run_url_trust_gate_demo.py` |
| Canonicalisation, querystring redaction, homoglyph / punycode normalisation | **Working** | `canonicalize.py` |
| SSRF-guarded safe crawler | **Working** | Deployment isolation required in production; see `scripts/poc/README.md` |
| Heuristic detection ensemble | **Working** | Prompt injection, credential harvest, brand impersonation, zero-width stripping |
| ML-based detection (DeBERTa, BERT NER, toxic-bert, BART zero-shot) | **Configurable** | Set `TRANSFORMERS_OFFLINE=0` and allow model download on first start |
| Playwright detonation sandbox (port 8015) | **Working** | Must run in isolated Docker `detonation` network |
| Google Safe Browsing v4 reputation feed | **Configurable** | Set `SAFE_BROWSING_API_KEY` |
| Microsoft SmartScreen (Defender Threat Intelligence) feed | **Configurable** | Set `SMARTSCREEN_TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET` |
| VirusTotal v3 URL reputation feed | **Configurable** | Set `VIRUSTOTAL_API_KEY`; results cached for `VIRUSTOTAL_CACHE_TTL_S` |
| Tenant URL allow / block lists | **Working** | Via `GET /policies?tenant_id=…&scope=url-trust-gate` on policy service |
| Evidence writes to audit service | **Working** | `POST /events`; best-effort, non-blocking |
| `/health`, `/ready`, `/metrics`, `/pki/public-key` endpoints | **Working** | Prometheus `text/plain; version=0.0.4` |
| Score-based fallback policy decision | **Working** | Applied when policy returns no-match |
| LangChain URL Trust Gate hook | **Working** | `sdks/python/cyberarmor/frameworks/langchain_url_trust_gate.py` |
| LlamaIndex URL Trust Gate hook | **Working** | `sdks/python/cyberarmor/frameworks/llamaindex.py` |
| RASP Python hook | **Working** | `rasp/python/cyberarmor_rasp_url_trust_gate.py` |
| Browser extension hook | **Working** | `extensions/chromium-shared/url_trust_gate.js` |
| Endpoint agent URL Trust Gate hook | **Working** | `agents/endpoint-agent/monitors/url_trust_gate.py` |
| OpenAI / Anthropic tool-use URL field wrappers | **Roadmap** | Next on build queue |
| Feedback-driven detection fine-tuning pipeline | **Roadmap** | Evidence + `/feedback` exist; offline trainer not yet built |
| Enforced mTLS between services | **Configurable** | Set `CYBERARMOR_ENFORCE_MTLS=true` and provision certs |
| Redis-backed reputation cache (multi-replica) | **Configurable** | In-process cache works for single-node; Redis for multi-replica |
| Kubernetes NetworkPolicy for detonation worker | **Roadmap** | Compose isolation in place; K8s NetworkPolicy not yet written |

---

## Control Plane, Detection & Policy

| Capability | Status | Notes |
| --- | --- | --- |
| Policy evaluation engine (OPA-backed, Python fallback) | **Working** | `services/policy/` |
| Tenant-scoped policy rules, artifacts, API-key flows | **Working** | |
| Detection service — prompt injection, sensitive data, toxicity | **Working** | `services/detection/` |
| AI provider routing and resolution | **Working** | `services/response/` |
| Agent identity registration and delegation chains | **Working** | |
| Audit logs, telemetry, incidents, evidence capture | **Working** | `services/audit/` |
| Compliance engine (14 frameworks) | **Pilot** | Working API; expanding with design partners |
| Production SIEM / SOAR integration workflows | **Pilot** | |

---

## Consumer Surfaces

| Surface | Status | Notes |
| --- | --- | --- |
| Endpoint agent (Linux / macOS / Windows) | **Working** | `agents/endpoint-agent/` |
| Chromium browser extension | **Working** | `extensions/chromium-shared/` |
| VS Code extension | **Pilot** | `extensions/vscode/` |
| Office add-in | **Pilot** | `extensions/office/` |
| Python RASP | **Working** | `rasp/python/` |
| Go RASP | **Pilot** | `rasp/go/` |
| Java RASP | **Pilot** | `rasp/java/` |
| Node.js RASP | **Pilot** | `rasp/nodejs/` |
| LangChain SDK wrapper | **Working** | `sdks/python/cyberarmor/frameworks/` |
| LlamaIndex SDK wrapper | **Working** | `sdks/python/cyberarmor/frameworks/` |
| OpenAI tool-use URL wrapper | **Roadmap** | |
| Anthropic tool-use URL wrapper | **Roadmap** | |
| macOS / Windows kernel sensors | **Pilot** | `kernel/` — verify scope before claiming in demos |

---

## Production Hardening Checklist

Before routing non-test traffic through any component:

- [ ] Set `CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false`
- [ ] Set `CYBERARMOR_ENFORCE_SECURE_SECRETS=true`
- [ ] Remove `URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST` (PoC-only)
- [ ] Add real `SAFE_BROWSING_API_KEY`
- [ ] Detonation worker on isolated Docker / K8s network with no internal route
- [ ] `CYBERARMOR_ENFORCE_MTLS=true` with provisioned certs
- [ ] K8s `NetworkPolicy` for detonation worker pod
- [ ] Redis-backed reputation cache for multi-replica deployments
