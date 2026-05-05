# Services

CyberArmor ships as a set of cooperating services. This page is the
operator-facing service map for the current repo.

## Core service map

| Service | Port | Purpose |
| --- | ---: | --- |
| `control-plane` | 8000 | tenant APIs, bootstrap redemption, agent registration, audit-facing API coordination |
| `policy` | 8001 | policy evaluation, enforcement decisions, tenant policy retrieval |
| `detection` | 8002 | prompt injection, sensitive data, toxicity, output-safety analysis |
| `response` | 8003 | response orchestration and response actions |
| `identity` | 8004 | workforce identity and SSO integrations |
| `siem-connector` | 8005 | external SIEM export |
| `compliance` | 8006 | evidence-backed compliance scoring and reporting |
| `agent-identity` | 8008 | AI agent identity and delegation material |
| `ai-router` | 8009 | governed AI provider routing, credential handling, cost/usage control |
| `proxy-agent` | 8010 | local runtime enforcement and policy decision path |
| `audit` | 8011 | audit evidence and action graph support |
| `integration-control` | 8012 | SaaS and AI integration inventory and control actions |
| `secrets-service` | 8013 | CyberArmor-facing secrets and cryptography layer over OpenBao |

## Infrastructure dependencies

| Component | Role |
| --- | --- |
| PostgreSQL | persistence for platform state and service data |
| Redis | cache and coordination where enabled |
| OpenBao | underlying KV/transit/key-management engine |
| Caddy | public TLS termination and domain routing |

## Detection coverage

The `detection` service currently covers:

- prompt injection
- sensitive data / PII
- toxicity
- output safety

Transformer-backed models are typically warmed and cached locally so the hosted
stack does not depend on live downloads after initial startup.

## Endpoint and package surfaces

The broader product surface also includes:

- endpoint agents for macOS, Windows, and Linux
- RASP packages across multiple languages
- browser extensions
- IDE integrations

These are not all standalone public services, but they matter operationally
because they enroll through `control-plane`, rely on `/pki/public-key`, and
sync policy or telemetry back into the platform.

## Operational advice

If a public feature looks broken, test the service path in this order:

1. backend service health
2. local route on the server
3. reverse-proxy route
4. public domain route

That sequence narrows most deployment issues quickly, especially around
bootstrap redemption, `/agents/register`, `/policies/...`, and `/pki/public-key`.
