#!/usr/bin/env bash
# 15-minute PoC installer for the CyberArmor URL Trust Gate.
#
# What this does on a fresh Linux server (Ubuntu / Debian):
#
#   1. Verifies prerequisites (docker, docker compose, openssl, curl, python3).
#   2. Generates strong secrets and writes infra/docker-compose/.env
#      from .env.example (only if .env doesn't already exist).
#   3. Brings up the minimal stack needed to run the URL Trust Gate:
#         postgres, redis, opa, response, audit, policy, detection,
#         url-trust-gate, poc-test-server
#      with the docker-compose.poc.yml overlay (heuristic-only detection,
#      SSRF allowlist for the test server, no Playwright detonation,
#      no Ollama).
#   4. Waits for service health, then runs scripts/poc/run_url_trust_gate_demo.py
#      to exercise four crafted attack pages.
#   5. Prints elapsed wall-clock time and next steps.
#
# Idempotent. Re-running this script will reuse an existing .env, restart
# any containers that have crashed, and re-run the demo.
#
# To tear down afterwards:
#   bash scripts/poc/uninstall.sh
#
# Tested on Ubuntu 22.04 / 24.04 with Docker 24+ and the compose v2 plugin.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="$ROOT_DIR/infra/docker-compose"
ENV_FILE="$COMPOSE_DIR/.env"
ENV_EXAMPLE="$COMPOSE_DIR/.env.example"
COMPOSE_BASE="$COMPOSE_DIR/docker-compose.yml"
COMPOSE_OVERLAY="$COMPOSE_DIR/docker-compose.poc.yml"
DEMO_RUNNER="$ROOT_DIR/scripts/poc/run_url_trust_gate_demo.py"

START_TS=$(date +%s)

# ------------------------------------------------------------------ helpers --

c_blue=$'\033[36m'
c_green=$'\033[32m'
c_yellow=$'\033[33m'
c_red=$'\033[31m'
c_reset=$'\033[0m'

step()    { echo; echo "${c_blue}==>${c_reset} $*"; }
ok()      { echo "    ${c_green}ok${c_reset}: $*"; }
warn()    { echo "    ${c_yellow}warn${c_reset}: $*"; }
fail()    { echo "    ${c_red}fail${c_reset}: $*" >&2; }

elapsed() {
  local now=$(date +%s)
  local secs=$(( now - START_TS ))
  printf "%dm%02ds" $(( secs / 60 )) $(( secs % 60 ))
}

# ----------------------------------------------------------- prerequisites --

step "Checking prerequisites"

missing=()
for cmd in docker openssl curl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done
if (( ${#missing[@]} > 0 )); then
  fail "missing required commands: ${missing[*]}"
  fail "install them and re-run this script"
  exit 1
fi
ok "docker, openssl, curl, python3 are available"

if ! docker compose version >/dev/null 2>&1; then
  fail "the 'docker compose' v2 plugin is required (try: apt install docker-compose-plugin)"
  exit 1
fi
ok "docker compose plugin is available"

if ! docker info >/dev/null 2>&1; then
  fail "the docker daemon is not reachable. start it (or add your user to the 'docker' group) and re-run."
  exit 1
fi
ok "docker daemon is reachable"

# ------------------------------------------------------- env file generation --

step "Generating .env (idempotent)"

if [[ -f "$ENV_FILE" ]]; then
  ok "$ENV_FILE already exists; leaving secrets untouched"
else
  if [[ ! -f "$ENV_EXAMPLE" ]]; then
    fail "missing $ENV_EXAMPLE — repository may be incomplete"
    exit 1
  fi
  cp "$ENV_EXAMPLE" "$ENV_FILE"

  # Replace each `change-me*` value with a strong secret. Uses awk so we
  # don't depend on GNU sed in-place semantics (works on macOS too).
  python3 - "$ENV_FILE" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

out = []
replaced = 0
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key, _, val = line.rstrip("\n").partition("=")
        v = val.strip()
        if v.startswith("change-me") or v in {"openbao-dev-root-token-change-me"}:
            new = secrets.token_hex(24)
            out.append(f"{key}={new}\n")
            replaced += 1
            continue
    out.append(line)

with open(path, "w") as f:
    f.writelines(out)

print(f"replaced {replaced} change-me values with random 48-char hex tokens")
PY
  ok "wrote $ENV_FILE with freshly generated secrets"
  FRESHLY_GENERATED_ENV=1
fi

# Make sure the demo profile gets insecure-defaults allowed (it's already
# the default in the example, but we don't want to assume).
if ! grep -q '^CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true' "$ENV_FILE"; then
  echo 'CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true' >> "$ENV_FILE"
  ok "appended CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true (PoC mode)"
fi

# ---------------------------------------------------- volume hygiene check --
#
# Postgres initialises its data directory once, on first start, using the
# POSTGRES_PASSWORD that was in scope at that moment. After that, the
# password is baked into the volume. If a previous deployment left a
# pgdata volume with a different password, our policy/audit services
# will fail with "password authentication failed for user" — even though
# the new container is running with the new env.
#
# So: if we just generated a fresh .env, wipe any pgdata/redis/openbao
# volumes from a prior run. This is safe for a PoC; nothing of value
# lives there. Production deployments must NOT use this script.

if [[ "${FRESHLY_GENERATED_ENV:-0}" == "1" ]]; then
  STALE_VOLS=()
  for vol in docker-compose_pgdata docker-compose_openbao_data; do
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      STALE_VOLS+=("$vol")
    fi
  done
  if (( ${#STALE_VOLS[@]} > 0 )); then
    step "Removing stale data volumes from a previous deployment"
    warn "found pre-existing volumes: ${STALE_VOLS[*]}"
    warn "they were initialised with different secrets and would block the PoC"
    cd "$COMPOSE_DIR"
    CYBERARMOR_ENV_FILE="$ENV_FILE" \
      docker compose \
        --env-file "$ENV_FILE" \
        -f "$COMPOSE_BASE" \
        -f "$COMPOSE_OVERLAY" \
        --profile poc \
        down -v --remove-orphans 2>/dev/null || true
    for vol in "${STALE_VOLS[@]}"; do
      docker volume rm -f "$vol" >/dev/null 2>&1 || true
    done
    ok "removed stale volumes; postgres + openbao will reinitialise with the new secrets"
  fi
fi

# ----------------------------------------------------------- bring up stack --

step "Building and starting the URL Trust Gate stack"

# Services we need. Order does NOT matter — compose handles depends_on.
SERVICES=(
  postgres redis opa
  response audit policy detection
  url-trust-gate
  poc-test-server
)

cd "$COMPOSE_DIR"

CYBERARMOR_ENV_FILE="$ENV_FILE" \
  docker compose \
    --env-file "$ENV_FILE" \
    -f "$COMPOSE_BASE" \
    -f "$COMPOSE_OVERLAY" \
    --profile poc \
    up -d --build "${SERVICES[@]}"

ok "compose 'up -d' returned (elapsed: $(elapsed))"

# ------------------------------------------------------------- wait_for_health --

step "Waiting for gate health endpoint"

for i in $(seq 1 60); do
  if curl -fsS "http://localhost:8014/health" >/dev/null 2>&1; then
    ok "url-trust-gate is healthy (after ${i}s)"
    break
  fi
  if (( i == 60 )); then
    fail "url-trust-gate did not become healthy after 60s"
    fail "run: docker compose -f $COMPOSE_BASE -f $COMPOSE_OVERLAY --profile poc logs url-trust-gate"
    exit 1
  fi
  sleep 1
done

# ---------------------------------------------------------- run the demo runner --

step "Running URL Trust Gate live demo"

if ! python3 "$DEMO_RUNNER"; then
  fail "demo runner reported failures (elapsed: $(elapsed))"
  fail "this usually means a malicious test page was allowed, or a benign one was blocked"
  fail "see logs:  docker compose -f $COMPOSE_BASE -f $COMPOSE_OVERLAY --profile poc logs detection url-trust-gate"
  exit 1
fi

# ---------------------------------------------------------- summary --

step "PoC complete (total time: $(elapsed))"

cat <<EOF

  Next steps:

    • Inspect the gate API:
        curl -fsS http://localhost:8014/health

    • Submit your own URL:
        curl -fsS -X POST http://localhost:8014/evaluate \\
          -H "Content-Type: application/json" \\
          -H "x-api-key: \$(grep ^URL_TRUST_GATE_API_SECRET= $ENV_FILE | cut -d= -f2)" \\
          -d '{"tenant_id":"poc","url":"https://example.com","source":"manual","depth":"standard"}'

    • Run the demo again:
        python3 scripts/poc/run_url_trust_gate_demo.py

    • Tear everything down:
        bash scripts/poc/uninstall.sh

  PoC test pages (served at http://poc-test-server:8088 inside the docker network):
    • /benign.html               — should ALLOW
    • /hidden-instruction.html   — display:none promptware
    • /zero-width-injection.html — zero-width-encoded instruction
    • /credential-harvest.html   — fake Microsoft sign-in

  Production checklist (read before deploying outside a PoC):
    • Set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=false in .env
    • Set CYBERARMOR_ENFORCE_SECURE_SECRETS=true
    • Drop the URL_TRUST_GATE_CRAWLER_SSRF_ALLOWLIST override (PoC-only)
    • Bring detection up with TRANSFORMERS_OFFLINE unset so the ML
      ensemble runs (first start downloads ~2GB of HuggingFace models).
    • Add a real Google Safe Browsing API key to SAFE_BROWSING_API_KEY.

EOF
