# Hetzner First-Boot Checklist

Use this checklist before you expose the demo server publicly.

## DNS

Create A records pointing at the Hetzner VM IPv4:

- `cyberarmor.ai`
- `www.cyberarmor.ai`
- `app.cyberarmor.ai`
- `admin.cyberarmor.ai`

## Secrets And Identities

Have these values ready before first boot:

- Let's Encrypt email:
  - example: `ops@cyberarmor.ai`
- Global admin email allowlist:
  - `ADMIN_DASHBOARD_ALLOWED_EMAILS`
- SMTP settings for login-code delivery:
  - `ADMIN_DASHBOARD_SMTP_HOST`
  - `ADMIN_DASHBOARD_SMTP_PORT`
  - `ADMIN_DASHBOARD_SMTP_USER`
  - `ADMIN_DASHBOARD_SMTP_PASSWORD`
  - `ADMIN_DASHBOARD_SMTP_FROM`
  - `CUSTOMER_PORTAL_SMTP_HOST`
  - `CUSTOMER_PORTAL_SMTP_PORT`
  - `CUSTOMER_PORTAL_SMTP_USER`
  - `CUSTOMER_PORTAL_SMTP_PASSWORD`
  - `CUSTOMER_PORTAL_SMTP_FROM`
- Repo checkout paths on server:
  - demo repo, for example `/opt/cyberarmor/CyberArmorAi`
  - marketing repo, for example `/opt/cyberarmor/cyberarmor-ai`

## Server-Side Env File

Recommended shape:

- keep production secrets in `/etc/cyberarmor/demo.env`
- owner: `root:root`
- permissions: `600`
- do not store real production values in the repo checkout
- do not pass secrets inline in shell commands unless you must

Create the file from the generator:

```bash
cd /opt/cyberarmor/CyberArmorAi
sudo APP_DOMAIN=app.cyberarmor.ai \
     ADMIN_DOMAIN=admin.cyberarmor.ai \
     MARKETING_DOMAIN=cyberarmor.ai \
     WWW_MARKETING_DOMAIN=www.cyberarmor.ai \
     ADMIN_DASHBOARD_ALLOWED_EMAILS=admin@cyberarmor.ai \
     bash scripts/deployment/setup_hetzner_demo_env.sh
```

Then review and edit:

```bash
sudoedit /etc/cyberarmor/demo.env
```

Minimum manual edits after generation:

- fill both SMTP sections with real values
- confirm `ADMIN_DASHBOARD_ALLOWED_EMAILS`
- confirm `CUSTOMER_PORTAL_PUBLIC_URL=https://app.cyberarmor.ai`
- confirm `POSTGRES_*` and `DATABASE_URL` stayed aligned if edited

## Recommended Pre-Deploy Values

These should stay set for an internet-facing demo:

```bash
CYBERARMOR_ENFORCE_SECURE_SECRETS=true
CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false
ADMIN_DASHBOARD_AUTH_DEV_CODE_ECHO=false
CUSTOMER_PORTAL_AUTH_DEV_CODE_ECHO=false
ADMIN_DASHBOARD_COOKIE_SECURE=true
CUSTOMER_PORTAL_COOKIE_SECURE=true
ROUTER_USE_SECRETS_SERVICE=true
CYBERARMOR_PQC_BACKEND=secrets-service
```

## Deployment Order

1. Harden the host.
2. Generate `/etc/cyberarmor/demo.env`.
3. Review the env file and add SMTP values.
4. Deploy marketing + app + admin.
5. Confirm HTTPS and login flows.
6. Then optionally enable PQC rollout flags.

## PQC Reality Check

What the repo supports today:

- PQC-wrapped internal `x-api-key` service auth
- PQC key state persistence via `secrets-service`
- staged rollout from plaintext fallback to strict encrypted-only mode

What is not automatic yet:

- browser-facing HTTPS is still normal TLS terminated by nginx/certbot
- native ML-KEM / ML-DSA requires `liboqs` in the service runtime images

So for this server:

- you can enable CyberArmor PQC auth for internal service-to-service traffic
- you should not describe the external website TLS itself as PQC unless you also deploy a PQ-capable TLS stack

## Phase-1 PQC Flags

After base deployment and smoke testing, these are the safest first PQC settings:

```bash
CYBERARMOR_PQC_AUTH_ENABLED=true
CYBERARMOR_PQC_OUTBOUND_STRICT=false
CYBERARMOR_PQC_ALLOW_PLAINTEXT=true
CYBERARMOR_PQC_REQUIRE_ENCRYPTED=false
```

Validate:

- service health is green
- internal calls still succeed
- `GET /pki/public-key` works on upgraded services

## Before Calling It Production-Grade PQC

Plan these follow-ups:

- extend the runtime images to include `liboqs`
- verify native ML-KEM / ML-DSA is active rather than fallback crypto
- rotate and persist PQC key state through `secrets-service`
- only then move to strict encrypted-only mode

## Native PQC Validation

After rebuilding and restarting the stack with the updated images, run:

```bash
cd /opt/cyberarmor/CyberArmorAi
sudo bash scripts/deployment/validate_hetzner_native_pqc.sh
```

Success means:

- the containers can import `oqs`
- the runtime crypto layer reports native support
- live `/pki/public-key` endpoints advertise `ML-KEM-1024` and `ML-DSA-87`

Failure means at least one service is still using fallback crypto.

To reduce rebuild time on Hetzner, the deployment flow now builds shared local base images first:

- `cyberarmor-python311-pqc:local`
- `cyberarmor-python312-pqc:local`

You can refresh them manually with:

```bash
cd /opt/cyberarmor/CyberArmorAi
bash scripts/docker/build_pqc_base_images.sh
```
