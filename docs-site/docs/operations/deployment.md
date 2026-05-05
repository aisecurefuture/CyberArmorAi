# Deployment

*Placeholder — to be expanded from the Hetzner deployment runbook in the
internal repo.*

## Topology

A production deployment runs every service inside Docker Compose, fronted by
a `caddy` reverse proxy that terminates TLS for all customer-facing
hostnames:

- `cyberarmor.ai` — marketing site
- `app.cyberarmor.ai` — customer portal
- `admin.cyberarmor.ai` — admin dashboard
- `docs.cyberarmor.ai` — this site
- `support.cyberarmor.ai` — support page

Backend service ports are bound to `127.0.0.1` so only Caddy is exposed to
the public network.

## Steps

1. Provision a hardened Ubuntu 22.04+ host
2. Point DNS A records for the five hostnames at the host
3. Clone the repo and create `/etc/cyberarmor/demo.env` (root-owned, mode 0600)
4. Run the deploy script:

    ```bash
    sudo CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env \
         bash scripts/deployment/deploy_hetzner_demo_and_marketing.sh
    ```

The script brings up the full Compose stack with the `prod` profile (which
activates Caddy and binds backend services to loopback).

## TLS certificates

Caddy issues and renews Let's Encrypt certificates automatically. No certbot
timer or systemd renewal hook is needed.
