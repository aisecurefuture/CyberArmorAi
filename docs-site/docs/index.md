# CyberArmor AI Docs

CyberArmor AI is an enterprise AI security and cyber trust platform for teams
that need to discover AI usage, enforce policy at runtime, protect sensitive
data, and prove what happened with auditable evidence.

This documentation site is the technical companion to
[cyberarmor.ai](https://cyberarmor.ai). It is built for operators, security
architects, platform teams, and customer engineering teams who need to deploy,
operate, and integrate the platform in real environments.

## What you can do here

<div class="grid cards" markdown>

-   :material-link-lock: **URL Trust Gate — 15-minute PoC**

    ---

    Run `bash scripts/poc/install.sh` to see the URL Trust Gate block
    phishing, hidden prompt injection, and promptware payloads with live
    verdicts in under 120 ms — no full-stack setup required.

    [:octicons-arrow-right-24: URL Trust Gate](platform/url-trust-gate.md)

-   :material-rocket-launch: **Deploy the platform**

    ---

    Bring up the Docker Compose stack, understand the public domains, and move
    from local evaluation to a hardened hosted environment.

    [:octicons-arrow-right-24: Start with installation](getting-started/index.md)

-   :material-shield-crown-outline: **Understand the platform**

    ---

    See how the control plane, policy engine, detection services, endpoint
    agents, integrations, and secrets architecture fit together.

    [:octicons-arrow-right-24: Review the architecture](platform/architecture.md)

-   :material-laptop-account: **Roll out endpoint coverage**

    ---

    Enroll the endpoint agent, understand what it monitors, and validate
    heartbeat, policy sync, and telemetry paths.

    [:octicons-arrow-right-24: Endpoint agent guide](platform/endpoint-agent.md)

-   :material-lifebuoy: **Get support**

    ---

    Use the support center for deployment triage, enrollment issues, and the
    details we need to troubleshoot incidents quickly.

    [:octicons-arrow-right-24: Open the support center](support/index.md)

-   :material-monitor-dashboard: **Operate tenant portals**

    ---

    Use Mission Control, guided onboarding, admin readiness, and evidence export
    to move a tenant from blank state to demo-ready.

    [:octicons-arrow-right-24: Customer portal guide](customer-portal/index.md)

-   :material-presentation-play: **Run polished demos**

    ---

    Follow CISO, security architect, and AppSec demo paths with seed/reset
    scripts and buyer-specific talk tracks.

    [:octicons-arrow-right-24: Demo runbooks](demos/index.md)

</div>

## Product boundary

The URL Trust Gate runs end-to-end and is pilot-ready: the 15-minute PoC
installer brings up the full gate stack on any developer laptop, and optional
reputation feeds (Google Safe Browsing, Microsoft SmartScreen, VirusTotal) are
configurable via environment variables.

The broader platform — control plane, policy, detection, response, secrets, and
endpoint agent — is deployable and testable today in controlled pilots, internal
deployments, and operator-led staging environments. Some customer-facing SaaS
surfaces are still evolving.

The docs reflect the working product as it exists in the repo. See
[capability-status](../docs/architecture/capability-status.md) for the
authoritative status table.

## Core platform services

CyberArmor currently includes:

- `control-plane` for tenant, bootstrap, audit, and control APIs
- `policy` for runtime policy evaluation and enforcement decisions
- `detection` for prompt injection, sensitive data, toxicity, and output-safety
- `response` for incident response actions
- `url-trust-gate` for pre-ingestion URL safety — phishing, hidden prompt
  injection, and promptware checks before content reaches a human, browser, or
  AI agent
- `secrets-service` plus `openbao` for secrets and PQC key material
- `ai-router`, `agent-identity`, `integration-control`, `siem-connector`, and
  `compliance` for the broader enterprise operating model
- endpoint agents, RASP packages, browser extensions, and IDE integrations for
  workload and user-side coverage

## Recommended reading order

1. [Getting Started](getting-started/index.md)
2. [Install](getting-started/install.md)
3. [Architecture](platform/architecture.md)
4. [Services](platform/services.md)
5. [Deployment](operations/deployment.md)
6. [Customer Portal](customer-portal/index.md)
7. [Evidence Export](evidence/export.md)
8. [Demo Runbooks](demos/index.md)
9. [Support Center](support/index.md)
