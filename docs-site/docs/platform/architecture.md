# Architecture

CyberArmor is designed as a layered AI security platform rather than a single
point product. It combines runtime enforcement, model-aware detection, endpoint
and integration visibility, secrets management, and evidence capture across the
AI stack.

## Architectural model

At a high level, the platform operates across four responsibilities:

1. **Discover** AI tools, agents, APIs, and unmanaged usage
2. **Govern** with policy tied to tenant, user, service, and agent context
3. **Protect** at runtime with detection and enforcement
4. **Prove** with auditable, attributable evidence

## Core layers

### Public surfaces

- `cyberarmor.ai` for product and company messaging
- `app.cyberarmor.ai` for customer-facing bootstrap and portal flows
- `admin.cyberarmor.ai` for operator/admin workflows
- `docs.cyberarmor.ai` for technical guidance
- `support.cyberarmor.ai` for support guidance

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
