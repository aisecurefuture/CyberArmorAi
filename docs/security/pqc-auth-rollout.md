# PQC Auth Rollout Guide

This guide explains how to move CyberArmor services from plaintext `x-api-key` headers to PQC-wrapped API key transport in production.

## What Changed

The platform now has a shared PQC auth path in [auth.py](/Users/patrickkelly/Documents/CyberArmorAi/libs/cyberarmor-core/cyberarmor_core/crypto/auth.py) that provides:

- inbound `x-api-key` decryption and verification for `PQC:<base64...>` headers
- per-service public-key exposure at `GET /pki/public-key`
- outbound PQC header generation with short-lived public-key caching
- staged rollout support with plaintext fallback or strict PQC mode

## Services Wired for Shared PQC Auth

- control-plane
- policy
- detection
- response
- identity
- agent-identity
- compliance
- integration-control
- audit
- ai-router
- proxy-agent

Internal callers updated to emit PQC auth headers when enabled:

- runtime -> detection, policy, response, compliance, control-plane
- control-plane -> policy, integration-control
- ai-router -> audit
- proxy-agent -> policy
- proxy -> policy, detection, telemetry

## New Runtime Flags

These env vars control the rollout:

- `CYBERARMOR_PQC_AUTH_ENABLED`
  - `false` by default
  - when `true`, outbound service-to-service callers attempt PQC header encryption

- `CYBERARMOR_PQC_OUTBOUND_STRICT`
  - `false` by default
  - when `true`, outbound calls fail instead of falling back to plaintext if public-key fetch or encryption fails

- `CYBERARMOR_PQC_ALLOW_PLAINTEXT`
  - `true` by default
  - when `false`, services reject plaintext `x-api-key` headers

- `CYBERARMOR_PQC_REQUIRE_ENCRYPTED`
  - `false` by default
  - when `true`, services require `PQC:` headers and reject plaintext completely

- `CYBERARMOR_PQC_KEY_STORE_PATH`
  - optional global default key store path

- `<SERVICE>_PQC_KEY_STORE_PATH`
  - optional per-service override
  - example: `POLICY_PQC_KEY_STORE_PATH=/var/lib/cyberarmor/pqc/policy`

- `CYBERARMOR_PQC_PUBLIC_KEY_CACHE_TTL_SECONDS`
  - default `300`

- `CYBERARMOR_PQC_PUBLIC_KEY_TIMEOUT_SECONDS`
  - default `3`

- `CYBERARMOR_PQC_ROTATION_INTERVAL_SECONDS`
  - default `86400`

- `CYBERARMOR_PQC_BACKEND`
  - default `filesystem`
  - set to `secrets-service` to persist PQC key state through the CyberArmor secrets service instead of local `key_state.json` files

## Recommended Production Rollout

### Phase 1: Enable PQC outbound, keep plaintext fallback

Set:

```bash
CYBERARMOR_PQC_AUTH_ENABLED=true
CYBERARMOR_PQC_OUTBOUND_STRICT=false
CYBERARMOR_PQC_ALLOW_PLAINTEXT=true
CYBERARMOR_PQC_REQUIRE_ENCRYPTED=false
```

Use this phase to confirm:

- every service exposes `GET /pki/public-key`
- internal service-to-service requests succeed with PQC
- any not-yet-migrated callers still work via plaintext fallback

### Phase 2: Disable plaintext acceptance on upgraded services

After all known callers are updated:

```bash
CYBERARMOR_PQC_AUTH_ENABLED=true
CYBERARMOR_PQC_OUTBOUND_STRICT=true
CYBERARMOR_PQC_ALLOW_PLAINTEXT=false
CYBERARMOR_PQC_REQUIRE_ENCRYPTED=true
```

This is the actual PQC-only mode.

## Key Material Guidance

For production, do not leave service keys in ephemeral container paths.

Each service should have its own key store path, ideally backed by a mounted persistent volume or secret-management workflow.

If you enable:

```bash
CYBERARMOR_PQC_BACKEND=secrets-service
SECRETS_SERVICE_URL=http://secrets-service:8013
SECRETS_SERVICE_API_SECRET=<strong-secret>
```

the shared PQC key manager will persist state through the secrets service instead of local filesystem JSON files. This is the recommended path for the new OpenBao-backed architecture.

Suggested layout:

```bash
/var/lib/cyberarmor/pqc/control-plane
/var/lib/cyberarmor/pqc/policy
/var/lib/cyberarmor/pqc/detection
/var/lib/cyberarmor/pqc/response
/var/lib/cyberarmor/pqc/identity
/var/lib/cyberarmor/pqc/agent-identity
/var/lib/cyberarmor/pqc/compliance
/var/lib/cyberarmor/pqc/integration-control
/var/lib/cyberarmor/pqc/audit
/var/lib/cyberarmor/pqc/ai-router
/var/lib/cyberarmor/pqc/proxy-agent
```

Then set matching env vars per service.

## Important Operational Note

The crypto wrapper currently supports native ML-KEM-1024 only when `liboqs` is available. Otherwise it falls back to X25519/HKDF in [pqc_kem.py](/Users/patrickkelly/Documents/CyberArmorAi/libs/cyberarmor-core/cyberarmor_core/crypto/pqc_kem.py#L1).

For true PQC production posture, you should deploy with native `liboqs` support available everywhere PQC auth is enabled.

## Remaining Client Work

The platform services are now wired for shared PQC auth, but any external clients that still send plaintext `x-api-key` headers must also be upgraded before strict PQC-only mode is enabled.

That includes, as applicable:

- endpoint agents
- ROS agent
- browser/IDE extensions
- operational scripts that call service APIs directly
- any external automation hitting admin/service endpoints

## Validation Checklist

Before switching to strict PQC-only mode:

- `GET /pki/public-key` works on every upgraded service
- internal traffic succeeds with `CYBERARMOR_PQC_AUTH_ENABLED=true`
- logs show no auth fallback errors
- smoke tests pass
- deployment scripts and admin tooling are updated
- key-store paths are persistent and backed up
