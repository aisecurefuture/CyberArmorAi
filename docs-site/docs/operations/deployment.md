# Deployment

This page summarizes the current recommended hosted deployment model for the
repo as it exists today.

## Recommended first hosted shape

For operator-led pilots and controlled production-style validation:

- Ubuntu 24.04
- Docker Compose
- Caddy for public TLS termination
- PostgreSQL and Redis
- OpenBao plus `secrets-service`
- warmed local transformer model cache for detection

## Public domains

The current public domain split is:

- `cyberarmor.ai` — marketing site
- `app.cyberarmor.ai` — customer portal and bootstrap-facing public app routes
- `admin.cyberarmor.ai` — operator/admin dashboard
- `docs.cyberarmor.ai` — technical documentation
- `support.cyberarmor.ai` — support landing page

## Backend routing model

Public domains terminate at Caddy, which reverse-proxies into the appropriate
container:

- marketing app
- customer portal nginx
- dashboard nginx
- docs site

Because of that, route correctness matters just as much as service health. A
service can be healthy internally while the public path still fails because a
proxy route is missing or miswired.

## Deployment priorities

Before exposing the stack, verify:

1. secrets are rotated away from placeholders
2. OpenBao bootstrap has completed
3. `control-plane`, `policy`, and `detection` are healthy
4. public `/pki/public-key` works
5. bootstrap redemption returns the public control-plane URL
6. endpoint agents can register and sync policy

## Detection model warm-up

Warm the detection models before relying on offline behavior:

- prompt injection
- sensitive data
- toxicity
- output safety

Then set `TRANSFORMERS_OFFLINE=1` so restarts continue using the warmed cache.

## Current deployment caveats

The repo is deployable today, but the hosted surface is still evolving. In
practice that means:

- some public routes need careful validation after deploy
- docs and support need to reflect the real working product boundary
- customer-facing polish is still catching up to the backend platform maturity

## Deeper runbooks

For more detailed operator guidance, the repo already contains:

- `docs/deployment/hetzner-ubuntu-vm.md`
- `docs/deployment/hetzner-first-server-checklist.md`
- `docs/architecture/client-bootstrap-setup.md`

Those documents remain the deeper operational references behind this docs page.
