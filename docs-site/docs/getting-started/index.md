# Getting Started

This section is the fastest route from repository checkout to a working
CyberArmor environment.

## Who this is for

Use this path if you are:

- evaluating CyberArmor in a lab, pilot, or staging environment
- preparing a hosted deployment on a single Linux server
- validating endpoint-agent enrollment and policy sync
- learning how the public domains map to the running services

## What the platform includes

A standard hosted deployment can expose these public surfaces:

- `cyberarmor.ai` for the marketing site
- `app.cyberarmor.ai` for the customer portal and package/bootstrap flows
- `admin.cyberarmor.ai` for the operator/admin dashboard
- `docs.cyberarmor.ai` for technical documentation
- `support.cyberarmor.ai` for the support landing page

Behind those public domains, the core platform includes:

- `url-trust-gate` — pre-ingestion URL safety gate (pilot-ready; 15-minute PoC available)
- `detonation-worker` — isolated Playwright sandbox used by the trust gate
- `control-plane`
- `policy`
- `detection`
- `response`
- `identity`
- `agent-identity`
- `ai-router`
- `audit`
- `integration-control`
- `secrets-service`
- `openbao`
- `siem-connector`
- `compliance`

## Fastest path to a live demo

To see the URL Trust Gate block crafted attack pages in under 15 minutes
without standing up the full stack:

```bash
git clone https://github.com/aisecurefuture/CyberArmorAi.git
cd CyberArmorAi
bash scripts/poc/install.sh
```

The installer generates secrets, brings up only the services the gate
needs, and runs the demo script automatically. See
`scripts/poc/README.md` for prerequisites and hardening steps.

## Recommended path

1. [Install the platform](install.md)
2. [Review the architecture](../platform/architecture.md)
3. [Review the service map](../platform/services.md)
4. [Read the deployment guide](../operations/deployment.md)
5. [Use the support center](../support/index.md) if you hit a bootstrap,
   routing, or endpoint-agent issue

## Best first validation checks

After install, verify these before going deeper:

- public domains resolve correctly
- `control-plane`, `policy`, and `detection` health endpoints return `200`
- `/pki/public-key` works on both the internal and public routes
- endpoint-agent bootstrap redemption returns the public control-plane URL
- endpoint agents can register, sync policy, and emit heartbeat/telemetry

## Where the detail lives

This docs site is intentionally practical. It draws from the working repo,
service READMEs, and deployment runbooks so the guidance matches what actually
ships today.
