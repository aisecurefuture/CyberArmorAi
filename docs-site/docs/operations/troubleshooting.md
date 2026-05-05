# Troubleshooting

This page captures the most common live deployment and public-routing issues for
the current CyberArmor stack.

## Recommended debug order

Always test in this sequence:

1. backend service health
2. local route on the server
3. internal reverse-proxy route
4. public domain route

This avoids treating routing failures as service failures.

## Common symptoms

### `302 Found` on agent or bootstrap APIs

Usually means a public path like `/agents/register` or `/bootstrap/redeem` is
being handled by a login or portal surface instead of proxying to
`control-plane`.

Check:

- customer-portal nginx routes
- public Caddy routing
- the final upstream path reaching `control-plane`

### `404 Not Found` on support or docs-adjacent pages

Usually means the domain exists, but the upstream app does not actually have the
route being requested.

Check:

- whether the target app defines the route
- whether the domain should instead be served by docs
- whether a rewrite is still pointing at a missing marketing path

### `500` or `502` on `/pki/public-key`

Usually means the proxy is in place but the trust/secrets path is broken.

Check:

- `control-plane` health
- `secrets-service` health
- OpenBao health and mount/bootstrap state
- whether `/pki/public-key` works locally on the host before testing it
  publicly

### Endpoint agent registers but policy sync fails

Check:

- public `GET /policies/{tenant_id}`
- `control-plane` and `policy` health
- proxy timeouts or transient public routing instability
- whether the agent has the correct public `control_plane_url`

### Detection uses fallback logic unexpectedly

Check:

- detection logs for model load failures
- Hugging Face cache permissions
- whether the warmed models are present
- whether `TRANSFORMERS_OFFLINE=1` is being overridden by Compose env
  precedence

## High-value paths to test

- `POST /bootstrap/redeem`
- `POST /agents/register`
- `GET /policies/{tenant_id}`
- `GET /pki/public-key`
- `POST /agents/{agent_id}/heartbeat`
- `POST /agents/{agent_id}/telemetry`

## What to capture before escalation

- exact hostname and path
- timestamp of the failure
- backend logs around the event
- whether the same path works locally on the host
- whether the failure is constant or intermittent

## Related docs

- [Deployment](deployment.md)
- [Support Center](../support/index.md)
- [Endpoint Agent](../platform/endpoint-agent.md)
