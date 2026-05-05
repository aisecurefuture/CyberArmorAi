# Endpoint Agent

The CyberArmor endpoint agent provides user- and host-side visibility for AI
tool usage on macOS, Windows, and Linux.

## What it does

The current endpoint agent supports:

- process monitoring for known AI applications and tools
- network monitoring for AI service connections
- file monitoring for AI-related data movement signals
- DLP scanning and classification hooks
- runtime policy sync from the control plane
- heartbeat and telemetry emission back to the platform

## Supported platforms

| Platform | Native integration focus |
| --- | --- |
| macOS | launchd, quarantine, Gatekeeper, TCC-aware deployment shape |
| Windows | service installation plus kernel-bridge support |
| Linux | service install with Linux-side policy/runtime hooks |

## Recommended enrollment flow

Use bootstrap redemption instead of a long-lived tenant credential:

1. issue a one-time bootstrap token
2. redeem it with the endpoint package
3. persist the returned install-scoped API key and tenant metadata
4. confirm the agent can register and sync policy

## Validation checklist

After install, confirm:

- `POST /bootstrap/redeem` returns the public control-plane URL
- `POST /agents/register` returns `200`
- `GET /policies/{tenant_id}` returns `200`
- heartbeats return `200`
- telemetry returns `202` or `200`

## Common live issues

### Registration returns `302`

This usually means the public domain is routing agent API traffic to a login
surface instead of proxying it to `control-plane`.

### Public key endpoint fails

If `/pki/public-key` fails publicly or locally, verify:

- `control-plane` health
- `secrets-service` health
- OpenBao mount/bootstrap state
- the public reverse-proxy route

### Policy sync timeouts

Intermittent timeouts can happen during restarts or edge-path instability.
Recent agent runtime updates add retry and jitter so transient failures are less
noisy.

### Log location on macOS

On macOS launchd installs:

- primary runtime logs should land in `agent.log`
- historical stderr/runtime exceptions may appear in `agent.err`

## Operator note

The endpoint agent now preserves a stable `agent_id` across reinstalls and
normal restarts so inventory churn is reduced and host identity is easier to
track over time.
