# 15-minute URL Trust Gate PoC

A self-contained installer that brings up the URL Trust Gate plus its
minimum supporting services on a fresh Linux server and runs a live
demo against four crafted attack pages. Designed for evaluators,
analyst hands-on sessions, and pre-pilot conversations.

## What it shows

The runner submits four pages to the gate's `/evaluate` endpoint and
prints the verdict, scores, and pass/fail summary:

| Page | Expected verdict | What it demonstrates |
| --- | --- | --- |
| `benign.html` | `allow` | the gate does not flag normal content |
| `hidden-instruction.html` | `warn` / `redact` / `block` | promptware hidden in a `display:none` block — invisible to humans, read verbatim by an LLM ingesting the page |
| `zero-width-injection.html` | `warn` / `redact` / `block` | instructions interleaved with zero-width characters; the detection service strips them before scoring |
| `credential-harvest.html` | `warn` / `redact` / `block` | a fake Microsoft sign-in form with brand-impersonation keywords, password input, and session-expired language |

## Prerequisites

Linux host (Ubuntu 22.04 / 24.04 tested) with `docker` 24+, the
`docker compose` v2 plugin, `openssl`, `curl`, `python3`, ~4 GB RAM,
~10 GB disk. No outbound internet beyond Docker Hub is required.

## Run it

```bash
git clone https://github.com/aisecurefuture/CyberArmorAi.git
cd CyberArmorAi
bash scripts/poc/install.sh
```

The script:

1. Verifies prerequisites and that the docker daemon is reachable.
2. Generates strong secrets and writes `infra/docker-compose/.env` from
   `.env.example` (idempotent — re-runs reuse existing secrets).
3. Builds and brings up only the services the gate needs:
   `postgres`, `redis`, `opa`, `response`, `audit`, `policy`,
   `detection`, `url-trust-gate`, and a small static `poc-test-server`
   that hosts the test pages.
4. Waits for `url-trust-gate` to report healthy at
   `http://localhost:8014/health`.
5. Runs `scripts/poc/run_url_trust_gate_demo.py`.

Detection runs in heuristic-only mode for the PoC so the first start
does not download ~2 GB of HuggingFace models. The heuristic ensemble
is enough to fire on the four PoC fixtures.

## Inspect any URL after the PoC is up

```bash
curl -fsS -X POST http://localhost:8014/evaluate \
  -H "Content-Type: application/json" \
  -H "x-api-key: $(grep ^URL_TRUST_GATE_API_SECRET= infra/docker-compose/.env | cut -d= -f2)" \
  -d '{"tenant_id":"poc","url":"https://example.com","source":"manual","depth":"standard"}'
```

## Production hardening before real traffic

1. Set `CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false` in `.env`.
2. Set `CYBERARMOR_ENFORCE_SECURE_SECRETS=true`.
3. Drop the `URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST` override — it
   exists only so the gate can reach the same-network test server.
4. Provide a `SAFE_BROWSING_API_KEY` (Google Safe Browsing v4).
5. Bring up the detonation worker on its dedicated `detonation`
   network so attacker-controlled URLs are fetched only inside an
   isolated container.
6. Run mTLS (`CYBERARMOR_ENFORCE_MTLS=true` and provision certs per
   `scripts/security/generate_mtls_materials.sh`).

## Tear down

```bash
bash scripts/poc/uninstall.sh
```

This stops and removes the PoC containers but leaves
`infra/docker-compose/.env` in place so a subsequent installer reuses
the same secrets.
