# Bootstrap Credential Flow

## Goal

Distribute endpoint agents, RASP packages, SDKs, browser extensions, IDE extensions, and Office add-ins without embedding a shared long-lived secret.

For the operator-facing setup guide, shared environment variables, and package-family install conventions, see [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Flow

1. A tenant admin or platform admin downloads a package from the customer portal or admin dashboard.
2. The portal/dashboard issues a one-time bootstrap token for that package and tenant.
3. The package, installer, or enrollment helper calls `POST /bootstrap/redeem` with the bootstrap token.
4. The control plane burns the token, mints a tenant-scoped service API key, and returns install-ready config.
5. The installed component stores only its own install-scoped credential.

## Current Control Plane Endpoints

- `GET /bootstrap/catalog`
- `GET /bootstrap/packages/{package_key}`
- `POST /bootstrap/tokens`
- `POST /bootstrap/redeem`

Customer-portal scoped variants:

- `GET /customer/downloads/catalog`
- `GET /customer/downloads/packages/{package_key}`
- `POST /customer/bootstrap-tokens`

## Security Properties

- Package ZIPs do not contain tenant API keys.
- Bootstrap tokens are one-time-use and expire.
- Redeemed credentials are per-install instead of globally shared.
- Replay of a redeemed bootstrap token is rejected.
- Agent lifecycle endpoints now accept active minted API keys, not only the global default secret.

## Current Package UX

- Customer portal:
  - Endpoint download cards
  - SDK / RASP / add-in download cards
  - Bootstrap token issuance for tenant admins
- Admin dashboard:
  - Endpoint / extension / browser package download cards
  - SDK / RASP / add-in package download cards
  - Bootstrap token issuance for admins

## Current Client Rollout

- Endpoint agent installer supports:
  - `--bootstrap-token`
  - `--subject-name`

The installer redeems the bootstrap token and writes the returned install-scoped configuration locally.

Bootstrap redemption helpers are now in place across the currently supported client package families. Package-specific setup conventions are documented in [Client Bootstrap Setup](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/client-bootstrap-setup.md).

## Recommended Direction

- Keep bootstrap redemption server-side and tenant-scoped.
- Treat browser-visible tokens as short-lived and one-time-use only.
- Prefer per-install credentials over a single tenant-wide service secret.
- Add rotation and revoke UX once the first client helpers are in place.
