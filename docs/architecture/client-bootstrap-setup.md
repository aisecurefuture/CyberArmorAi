# Client Bootstrap Setup

## Goal

Use one short-lived, one-time bootstrap token to enroll any CyberArmor client package without shipping a tenant-wide long-lived secret.

This guide is the shared setup reference for:

- Endpoint and kernel-adjacent agents
- RASP runtimes
- Server-side SDKs
- Browser extensions
- IDE extensions
- Microsoft 365 add-ins

## Shared Enrollment Flow

1. An admin downloads a package from the customer portal or admin dashboard.
2. The portal or dashboard issues a one-time bootstrap token for the target package and tenant.
3. The client package starts with its control plane URL plus bootstrap token.
4. The client calls `POST /bootstrap/redeem`.
5. The control plane burns the token and returns install-scoped credentials plus tenant-aware config.
6. The client keeps only its own issued credential for ongoing API calls.

## Common Environment Variables

Use these names consistently across package families whenever possible.

| Variable | Purpose | Notes |
|----------|---------|-------|
| `CYBERARMOR_CONTROL_PLANE_URL` | Base URL for the CyberArmor control plane | Preferred canonical variable |
| `CYBERARMOR_URL` | Legacy/fallback control plane URL | Still supported by several packages |
| `CYBERARMOR_BOOTSTRAP_TOKEN` | One-time bootstrap token | Short-lived, single-use |
| `CYBERARMOR_API_KEY` | Install-scoped credential after redemption | Do not pre-bake a tenant-wide secret |
| `CYBERARMOR_TENANT_ID` | Tenant identifier | Preferred canonical variable |
| `CYBERARMOR_TENANT` | Legacy/fallback tenant identifier | Still supported by several packages |
| `CYBERARMOR_RASP_SUBJECT_NAME` | Friendly runtime/install name for RASP enrollments | Optional |
| `CYBERARMOR_AGENT_ID` | Explicit agent identity for packages that support it | Optional |
| `CYBERARMOR_MODE` | Runtime enforcement mode such as `monitor` or `block` | Package-specific behavior may vary |

## Minimum Bootstrap Configuration

For a fresh install, the minimum safe setup is:

```env
CYBERARMOR_CONTROL_PLANE_URL=https://your-cyberarmor-server
CYBERARMOR_BOOTSTRAP_TOKEN=your-one-time-bootstrap-token
```

Optional but commonly useful:

```env
CYBERARMOR_TENANT_ID=your-tenant
CYBERARMOR_RASP_SUBJECT_NAME=payments-api-prod-01
CYBERARMOR_MODE=monitor
```

After successful redemption, the client should use the returned install-scoped `api_key` and any returned tenant metadata for normal operations.

## When To Use Bootstrap vs Direct API Key

Use bootstrap tokens when:

- distributing installers or packages to customers
- onboarding new machines, runtimes, or extensions
- enrolling browser-visible or user-distributed clients
- avoiding shared long-lived tenant secrets

Use a direct API key only when:

- you are operating a trusted server-side service
- you already have an install-scoped or service-scoped credential
- you are rotating or recovering an existing deployment

## Package Family Notes

### Endpoint Agents

- Prefer installer arguments or env vars that pass `CYBERARMOR_CONTROL_PLANE_URL` and `CYBERARMOR_BOOTSTRAP_TOKEN`
- Store the redeemed credential in the local service config

### RASP Runtimes

- Bootstrap is now supported across all 9 language targets
- Prefer `CYBERARMOR_RASP_SUBJECT_NAME` to label the runtime instance clearly
- After redemption, use the issued API key for telemetry and policy sync

### SDKs

- Server-side SDKs may bootstrap on first use, then persist the install-scoped credential in the host application config
- Browser-delivered SDKs must not contain private long-lived secrets

### Browser Extensions

- Treat bootstrap tokens as short-lived and one-time-use
- Expect enrollment through the options page or extension setup UI
- Never embed tenant-wide private secrets in the packaged extension

### IDE Extensions And Add-ins

- Use the bootstrap token during first-run setup or explicit “Connect” flows
- Persist only the redeemed install-scoped credential

## Package Key Reference

Current bootstrap-aware package keys include the following:

| Package family | Package key |
|----------------|-------------|
| Endpoint agent | `endpoint-agent` |
| Python SDK | `sdk-python` |
| Python RASP | `rasp-python` |
| Node.js RASP | `rasp-nodejs` |
| Go RASP | `rasp-go` |
| Java RASP | `rasp-java` |
| .NET RASP | `rasp-dotnet` |
| PHP RASP | `rasp-php` |
| Ruby RASP | `rasp-ruby` |
| Rust RASP | `rasp-rust` |
| C/C++ RASP | `rasp-c-cpp` |
| VS Code extension | package-specific extension flow |
| Cursor extension | package-specific extension flow |
| Kiro extension | package-specific extension flow |
| Chromium extension (Chrome, Edge, Brave, Opera, others) | `edge-extension` |
| Firefox extension | `firefox-extension` |

Some UI-driven packages rely on their own setup flows while still using the same `POST /bootstrap/redeem` backend contract.

## API Endpoints

- `GET /bootstrap/catalog`
- `GET /bootstrap/packages/{package_key}`
- `POST /bootstrap/tokens`
- `POST /bootstrap/redeem`

Customer-scoped variants:

- `GET /customer/downloads/catalog`
- `GET /customer/downloads/packages/{package_key}`
- `POST /customer/bootstrap-tokens`

## Security Rules

- Do not base64-encode secrets as a “security” measure.
- Do not hardcode tenant-wide secrets into distributed clients.
- Do not ship browser-visible private credentials.
- Keep bootstrap tokens short-lived and one-time-use.
- Prefer one credential per install over one credential per tenant.
- Rotate and revoke install-scoped credentials when compromise is suspected.

## Recommended Operator Pattern

1. Issue a package-specific bootstrap token from the portal or dashboard.
2. Deliver the package and token through the customer’s approved install path.
3. Let the client redeem once and persist only the returned install-scoped key.
4. Rotate or revoke install-scoped keys without reissuing a tenant-wide secret.

## Related Docs

- [Bootstrap Credential Flow](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/bootstrap-credential-flow.md)
- [Endpoint Agent README](/Users/patrickkelly/Documents/CyberArmorAi/agents/endpoint-agent/README.md)
