# Stripe Fulfillment

CyberArmor's Stripe checkout is wired in the marketing app, but fulfillment is
lightweight by design:

- every successful checkout sends an internal purchase notification
- every successful checkout sends a customer email
- instant-download products can attach a PDF directly from a server-only path
- custom deliverables send intake instructions so the team can begin fulfillment

## Current product behavior

- `CHECKLIST`: sends the deliverable as a PDF attachment when
  `STRIPE_FULFILLMENT_CHECKLIST_PATH` is configured
- `SNAPSHOT`: sends intake instructions by email
- `QA`: sends intake instructions by email
- `BRIEF`: sends intake instructions by email
- `ADVISORY`: application-only, not direct checkout

## Server-only asset location

Do not commit paid deliverables to the repo.

Recommended pattern on the server:

```bash
mkdir -p /opt/cyberarmor/fulfillment
```

Place the PDF there, for example:

```text
/opt/cyberarmor/fulfillment/CyberArmor-AI-Security-Executive-Checklist.pdf
```

Then set the environment variable in `/etc/cyberarmor/demo.env`:

```env
STRIPE_FULFILLMENT_CHECKLIST_PATH=/opt/cyberarmor/fulfillment/CyberArmor-AI-Security-Executive-Checklist.pdf
```

## Deployment notes

After changing fulfillment env vars, rebuild and restart the marketing service:

```bash
cd /opt/CyberArmorAi/infra/docker-compose
CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env docker compose --env-file /etc/cyberarmor/demo.env build --no-cache marketing
CYBERARMOR_ENV_FILE=/etc/cyberarmor/demo.env docker compose --env-file /etc/cyberarmor/demo.env up -d --force-recreate marketing caddy
```

## Lightweight limitations

- attachment delivery is currently file-path based, not object-storage based
- there is no persistent fulfillment audit log yet
- there is no automated intake portal yet for custom written deliverables
- webhook retries are handled by Stripe, but the app does not yet persist a
  deduplication record for sent emails

That makes this a pragmatic first step, not the final fulfillment architecture.
