# Install

CyberArmor is easiest to evaluate as a Docker Compose stack first, then move to
an operator-managed Linux host when you are ready for a real deployment.

## Local evaluation

From the repo root:

```bash
cd infra/docker-compose
cp .env.example .env
docker compose --env-file .env up -d --build
```

Common local entry points:

- `http://localhost:3000` for the admin dashboard
- `http://localhost:8000/health` for `control-plane`
- `http://localhost:8001/health` for `policy`
- `http://localhost:8002/health` for `detection`

## First hosted deployment

The recommended first hosted shape is:

- Ubuntu 24.04
- Docker Compose
- Caddy for TLS termination
- OpenBao plus `secrets-service`
- local Hugging Face model cache for detection workloads

For the full operational guide, use
[Deployment](../operations/deployment.md).

## Public domains

In the current stack, these domains are expected:

- `cyberarmor.ai`
- `app.cyberarmor.ai`
- `admin.cyberarmor.ai`
- `docs.cyberarmor.ai`
- `support.cyberarmor.ai`

Make sure all public DNS records point at the same host before expecting the
hosted experience to behave consistently.

## Post-install validation

After the stack comes up, validate these in order:

1. `control-plane` health
2. `policy` health
3. `detection` health
4. public `https://app.cyberarmor.ai/pki/public-key`
5. bootstrap redemption via `POST /bootstrap/redeem`
6. endpoint-agent registration, policy sync, and heartbeat

## ML model warm-up

The detection service downloads some transformer assets on first use. For a
cleaner production-like startup:

- warm `prompt-injection`
- warm `sensitive-data`
- warm `toxicity`
- warm `output-safety`

Then set `TRANSFORMERS_OFFLINE=1` so restarts no longer depend on live
Hugging Face traffic.

## Endpoint-agent enrollment

For endpoint-agent enrollment, prefer the bootstrap-token flow rather than
shipping long-lived tenant credentials:

1. issue a one-time bootstrap token
2. redeem it against `POST /bootstrap/redeem`
3. persist the returned install-scoped credential locally
4. confirm agent registration, policy sync, heartbeat, and telemetry

The endpoint-agent specifics are documented in
[Endpoint Agent](../platform/endpoint-agent.md).
