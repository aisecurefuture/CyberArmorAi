# Support Center

Welcome to CyberArmor support.

This page is the fastest way to understand where to look when a deployment,
bootstrap, endpoint-agent, or public routing issue shows up.

## What this page is for

Use this support page if you are dealing with:

- installation or deployment failures
- bootstrap token redemption issues
- endpoint-agent registration or heartbeat failures
- policy sync or telemetry problems
- public-domain routing issues such as `302`, `404`, `500`, or `502`
- detection model warm-up, cache, or Hugging Face startup issues

## Fast triage path

When something looks broken, test in this order:

1. backend service health
2. local server route
3. reverse-proxy route
4. public domain route

This keeps routing problems from being mistaken for service problems.

## High-value checks

### Bootstrap and agent enrollment

Verify:

- `POST /bootstrap/redeem`
- `POST /agents/register`
- `GET /policies/{tenant_id}`
- `POST /agents/{agent_id}/heartbeat`
- `POST /agents/{agent_id}/telemetry`

### Trust and secrets path

Verify:

- `GET /pki/public-key`
- `secrets-service` health
- OpenBao health and mount/bootstrap state

### Detection path

Verify:

- `GET /health` on `detection`
- model warm-up requests for prompt injection, sensitive data, toxicity, and
  output safety
- no cache-permission errors in detection logs

## What to collect before escalating

If you need help from the CyberArmor team, gather:

- environment name
- public hostname involved
- exact failing URL or API path
- timestamp of the failure
- service logs around the event
- whether the same path fails locally on the server
- whether the issue is stable or intermittent

## Common issue patterns

### `302 Found`

Usually indicates a public route is landing on an auth or portal surface rather
than the intended backend API.

### `404 Not Found`

Usually indicates the public route exists at the domain level but the upstream
application does not have the expected path.

### `500` or `502`

Usually means the proxy path is present, but the upstream dependency chain is
broken. For example:

- missing OpenBao mounts
- secrets-service backing failures
- broken nginx/Caddy route wiring

### Agent appears to reinstall as a new machine every time

The endpoint agent now preserves a stable `agent_id`, so if you still see
identity churn, inspect the local `agent.json` and confirm the installed
version picked up the latest runtime and installer logic.

## Related docs

- [Install](../getting-started/install.md)
- [Architecture](../platform/architecture.md)
- [Services](../platform/services.md)
- [Endpoint Agent](../platform/endpoint-agent.md)
- [Deployment](../operations/deployment.md)
