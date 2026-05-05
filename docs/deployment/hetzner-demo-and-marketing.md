# Hetzner Demo + Marketing Deployment

This guide deploys the CyberArmor public surfaces onto one Hetzner Ubuntu server:

- `cyberarmor.ai` and `www.cyberarmor.ai`: the marketing site from this repo's `marketing/` app
- `docs.cyberarmor.ai`: the static docs site from this repo's `docs-site/`
- `support.cyberarmor.ai`: the `/support` route inside the marketing app
- `app.cyberarmor.ai`: the tenant-scoped customer portal from this repo
- `admin.cyberarmor.ai`: the global admin dashboard from this repo

It uses Caddy in Docker Compose for automatic Let's Encrypt issuance and renewal, so certificates stay valid without host-level Nginx or Certbot.

If the host uses `systemd-resolved` with the stub resolver at `127.0.0.53`, keep the default `CADDY_DNS_1` and `CADDY_DNS_2` values in the server env file so the Caddy container can resolve ACME endpoints directly.

Before first public boot, use:

- [`.env.production.example`](/Users/patrickkelly/Documents/CyberArmorAi/infra/docker-compose/.env.production.example)
- [`setup_hetzner_demo_env.sh`](/Users/patrickkelly/Documents/CyberArmorAi/scripts/deployment/setup_hetzner_demo_env.sh)
- [`hetzner-demo-first-boot-checklist.md`](/Users/patrickkelly/Documents/CyberArmorAi/docs/deployment/hetzner-demo-first-boot-checklist.md)
- [`validate_hetzner_native_pqc.sh`](/Users/patrickkelly/Documents/CyberArmorAi/scripts/deployment/validate_hetzner_native_pqc.sh)

## What this setup assumes

- Ubuntu `24.04` on Hetzner
- one VM for both properties
- the CyberArmor stack, marketing site, docs site, and Caddy all run with Docker Compose from this repo
- `app.cyberarmor.ai` points to the customer portal by default
- `admin.cyberarmor.ai` points to the global admin dashboard by default

## Recommended DNS

Create A records:

- `cyberarmor.ai` -> your Hetzner server IPv4
- `www.cyberarmor.ai` -> your Hetzner server IPv4
- `docs.cyberarmor.ai` -> your Hetzner server IPv4
- `support.cyberarmor.ai` -> your Hetzner server IPv4
- `app.cyberarmor.ai` -> your Hetzner server IPv4
- `admin.cyberarmor.ai` -> your Hetzner server IPv4

## Repo layout on the server

A clean layout is:

```text
/opt/cyberarmor/CyberArmorAi
```

Example:

```bash
sudo mkdir -p /opt/cyberarmor
sudo chown -R "$USER":"$USER" /opt/cyberarmor
cd /opt/cyberarmor

git clone <your-demo-repo-url> CyberArmorAi
```

## 1. Harden the Ubuntu host

Run:

```bash
cd /opt/cyberarmor/CyberArmorAi
sudo ADMIN_USER="$USER" bash scripts/deployment/hetzner_harden_ubuntu_demo_host.sh
```

What it does:

- installs core hardening utilities
- enables unattended security updates
- configures UFW for SSH, HTTP, and HTTPS
- enables fail2ban for SSH
- disables SSH password auth and root SSH login
- applies baseline kernel/network hardening sysctls

## 2. Prepare the demo stack environment

From the demo repo, either:

1. generate a root-owned server env file, recommended:

```bash
cd /opt/cyberarmor/CyberArmorAi
sudo APP_DOMAIN=app.cyberarmor.ai \
     ADMIN_DOMAIN=admin.cyberarmor.ai \
     MARKETING_DOMAIN=cyberarmor.ai \
     WWW_MARKETING_DOMAIN=www.cyberarmor.ai \
     ADMIN_DASHBOARD_ALLOWED_EMAILS=admin@cyberarmor.ai \
     bash scripts/deployment/setup_hetzner_demo_env.sh
sudoedit /etc/cyberarmor/demo.env
```

2. or copy and edit the example manually:

```bash
cd /opt/cyberarmor/CyberArmorAi/infra/docker-compose
cp .env.production.example .env
```

The deployment script automatically prefers `/etc/cyberarmor/demo.env` if it exists.

Edit the env file and replace placeholder values before exposure.

At minimum, replace:

- `CYBERARMOR_API_SECRET`
- `CYBERARMOR_JWT_SECRET`
- `POLICY_API_SECRET`
- `DETECTION_API_SECRET`
- `IDENTITY_API_SECRET`
- `SIEM_API_SECRET`
- `COMPLIANCE_API_SECRET`
- `PROXY_AGENT_API_SECRET`
- `RESPONSE_API_SECRET`
- `INTEGRATION_CONTROL_API_SECRET`
- `SECRETS_SERVICE_API_SECRET`
- `OPENBAO_DEV_ROOT_TOKEN`
- `POSTGRES_PASSWORD`
- both SMTP password values

Recommended first-server values:

```bash
ROUTER_USE_SECRETS_SERVICE=true
ROUTER_REQUIRE_SECRETS_SERVICE=false
OPENBAO_ADDR=http://openbao:8200
SECRETS_SERVICE_URL=http://secrets-service:8013
CYBERARMOR_ENFORCE_MTLS=false
CYBERARMOR_ENABLE_NATIVE_TLS_LISTENER=false
CYBERARMOR_REQUIRE_CLIENT_CERT=false
CYBERARMOR_ENFORCE_SECURE_SECRETS=true
CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false
```

## 3. Deploy both apps

Run the deployment script from the demo repo:

```bash
cd /opt/cyberarmor/CyberArmorAi

sudo \
  DEMO_REPO_DIR=/opt/cyberarmor/CyberArmorAi \
  DEMO_ENV_FILE=/etc/cyberarmor/demo.env \
  bash scripts/deployment/deploy_hetzner_demo_and_marketing.sh
```

## What the deployment script does

- installs Docker if missing
- builds shared native-PQC Python base images locally for faster service rebuilds
- starts the compose stack with the `prod` profile
- builds and runs:
  - marketing site container
  - docs site container
  - customer portal container
  - admin dashboard container
  - Caddy reverse proxy with automatic Let's Encrypt certificates

## 4. Automatic certificate renewal

Caddy manages certificate issuance and renewal automatically. There is no host-level Certbot timer to maintain.

Check the Caddy logs:

```bash
cd /opt/cyberarmor/CyberArmorAi/infra/docker-compose
CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env docker compose --env-file /etc/cyberarmor/demo.env --profile prod logs caddy --tail=100
```

## 5. Operational checks

CyberArmor stack:

```bash
cd /opt/cyberarmor/CyberArmorAi/infra/docker-compose
CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env docker compose --env-file /etc/cyberarmor/demo.env --profile prod ps
CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env docker compose --env-file /etc/cyberarmor/demo.env --profile prod logs --tail=100
```

## 6. Updating later

Marketing site:

```bash
cd /opt/cyberarmor/cyberarmor-ai
git pull
npm ci
npm run build
sudo systemctl restart cyberarmor-marketing.service
```

Demo stack:

```bash
cd /opt/cyberarmor/CyberArmorAi
git pull
sudo DEMO_REPO_DIR=/opt/cyberarmor/CyberArmorAi \
     DEMO_ENV_FILE=/etc/cyberarmor/demo.env \
     MARKETING_SITE_DIR=/opt/cyberarmor/cyberarmor-ai \
     DEPLOY_USER="$USER" \
     MARKETING_DOMAIN=cyberarmor.ai \
     WWW_MARKETING_DOMAIN=www.cyberarmor.ai \
     APP_DOMAIN=app.cyberarmor.ai \
     ADMIN_DOMAIN=admin.cyberarmor.ai \
     LE_EMAIL=ops@cyberarmor.ai \
     bash scripts/deployment/deploy_hetzner_demo_and_marketing.sh
```

## 7. Notes

- The demo Docker Compose file publishes many ports by default. The deployment script adds a Hetzner override to bind them to loopback only so Nginx remains the exposed surface.
- `docker-compose.hetzner.override.yml` is created by [`deploy_hetzner_demo_and_marketing.sh`](/Users/patrickkelly/Documents/CyberArmorAi/scripts/deployment/deploy_hetzner_demo_and_marketing.sh) on the server. It is not expected to exist in a fresh local checkout.
- `app.cyberarmor.ai` fronts the customer portal on port `3001`.
- `admin.cyberarmor.ai` fronts the global admin dashboard on port `3000`.
- The recommended production secret source for this compose deployment is a root-owned env file at `/etc/cyberarmor/demo.env`, not inline shell exports and not committed repo files.
- The runtime images now include a native `liboqs` install path for the PQC-aware Python services, but you should still validate the deployment after rebuild with [`validate_hetzner_native_pqc.sh`](/Users/patrickkelly/Documents/CyberArmorAi/scripts/deployment/validate_hetzner_native_pqc.sh).
- For a polished demo, make sure the marketing and app DNS records are in place before you request certificates.
