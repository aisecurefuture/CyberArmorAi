#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose/docker-compose.yml"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/infra/docker-compose/.env}"
OPENBAO_VERIFY_KEEP_STACK="${OPENBAO_VERIFY_KEEP_STACK:-true}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
POSTGRES_HOST_PORT_OVERRIDE="${POSTGRES_HOST_PORT:-}"
REDIS_HOST_PORT_OVERRIDE="${REDIS_HOST_PORT:-}"
OPA_HOST_PORT_OVERRIDE="${OPA_HOST_PORT:-}"
OPENBAO_HOST_PORT_OVERRIDE="${OPENBAO_HOST_PORT:-}"
POLICY_HOST_PORT_OVERRIDE="${POLICY_HOST_PORT:-}"
SECRETS_SERVICE_HOST_PORT_OVERRIDE="${SECRETS_SERVICE_HOST_PORT:-}"
AGENT_IDENTITY_HOST_PORT_OVERRIDE="${AGENT_IDENTITY_HOST_PORT:-}"
AI_ROUTER_HOST_PORT_OVERRIDE="${AI_ROUTER_HOST_PORT:-}"
AUDIT_HOST_PORT_OVERRIDE="${AUDIT_HOST_PORT:-}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ -n "$POSTGRES_HOST_PORT_OVERRIDE" ]]; then
  POSTGRES_HOST_PORT="$POSTGRES_HOST_PORT_OVERRIDE"
fi
if [[ -n "$REDIS_HOST_PORT_OVERRIDE" ]]; then
  REDIS_HOST_PORT="$REDIS_HOST_PORT_OVERRIDE"
fi
if [[ -n "$OPA_HOST_PORT_OVERRIDE" ]]; then
  OPA_HOST_PORT="$OPA_HOST_PORT_OVERRIDE"
fi
if [[ -n "$OPENBAO_HOST_PORT_OVERRIDE" ]]; then
  OPENBAO_HOST_PORT="$OPENBAO_HOST_PORT_OVERRIDE"
fi
if [[ -n "$POLICY_HOST_PORT_OVERRIDE" ]]; then
  POLICY_HOST_PORT="$POLICY_HOST_PORT_OVERRIDE"
fi
if [[ -n "$SECRETS_SERVICE_HOST_PORT_OVERRIDE" ]]; then
  SECRETS_SERVICE_HOST_PORT="$SECRETS_SERVICE_HOST_PORT_OVERRIDE"
fi
if [[ -n "$AGENT_IDENTITY_HOST_PORT_OVERRIDE" ]]; then
  AGENT_IDENTITY_HOST_PORT="$AGENT_IDENTITY_HOST_PORT_OVERRIDE"
fi
if [[ -n "$AI_ROUTER_HOST_PORT_OVERRIDE" ]]; then
  AI_ROUTER_HOST_PORT="$AI_ROUTER_HOST_PORT_OVERRIDE"
fi
if [[ -n "$AUDIT_HOST_PORT_OVERRIDE" ]]; then
  AUDIT_HOST_PORT="$AUDIT_HOST_PORT_OVERRIDE"
fi

POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
REDIS_HOST_PORT="${REDIS_HOST_PORT:-6379}"
OPA_HOST_PORT="${OPA_HOST_PORT:-8181}"
OPENBAO_HOST_PORT="${OPENBAO_HOST_PORT:-8200}"
POLICY_HOST_PORT="${POLICY_HOST_PORT:-8001}"
SECRETS_SERVICE_HOST_PORT="${SECRETS_SERVICE_HOST_PORT:-8013}"
AGENT_IDENTITY_HOST_PORT="${AGENT_IDENTITY_HOST_PORT:-8008}"
AI_ROUTER_HOST_PORT="${AI_ROUTER_HOST_PORT:-8009}"
AUDIT_HOST_PORT="${AUDIT_HOST_PORT:-8011}"

COMPOSE_SERVICES=(
  openbao
  secrets-service
  postgres
  redis
  policy
  agent-identity
  audit
  ai-router
)

compose() {
  if [[ -n "$COMPOSE_PROJECT_NAME" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
  else
    docker compose -f "$COMPOSE_FILE" "$@"
  fi
}

cleanup() {
  if [[ "$OPENBAO_VERIFY_KEEP_STACK" == "true" ]]; then
    return 0
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

wait_for_json_health() {
  local url="$1"
  local name="$2"
  local attempt=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [[ "$attempt" -ge 60 ]]; then
      echo "Timed out waiting for $name at $url" >&2
      exit 1
    fi
    sleep 2
  done
}

require_cmd docker
require_cmd curl
require_cmd jq

echo "Starting local verification stack..."
compose up -d "${COMPOSE_SERVICES[@]}"

wait_for_json_health "http://127.0.0.1:${OPENBAO_HOST_PORT}/v1/sys/health" "OpenBao"
wait_for_json_health "http://127.0.0.1:${SECRETS_SERVICE_HOST_PORT}/health" "secrets-service"
wait_for_json_health "http://127.0.0.1:${AGENT_IDENTITY_HOST_PORT}/health" "agent-identity"
wait_for_json_health "http://127.0.0.1:${AI_ROUTER_HOST_PORT}/health" "ai-router"

echo "Bootstrapping OpenBao mounts and transit keys..."
OPENBAO_ADDR="http://127.0.0.1:${OPENBAO_HOST_PORT}" bash "$ROOT_DIR/scripts/openbao/bootstrap_dev.sh" >/tmp/cyberarmor-openbao-bootstrap.out

echo "Verifying secrets-service write/read..."
curl -fsS -X POST "http://127.0.0.1:${SECRETS_SERVICE_HOST_PORT}/v1/secrets/tenant/default/provider-credentials/openai" \
  -H 'Content-Type: application/json' \
  -H "x-api-key: ${SECRETS_SERVICE_API_SECRET}" \
  -d '{"api_key":"sk-verify-secrets-service","base_url":"https://api.openai.com/v1","metadata":{"source":"verify_local"}}' \
  >/tmp/cyberarmor-secrets-write.json

curl -fsS "http://127.0.0.1:${SECRETS_SERVICE_HOST_PORT}/v1/secrets/tenant/default/provider-credentials/openai" \
  -H "x-api-key: ${SECRETS_SERVICE_API_SECRET}" \
  >/tmp/cyberarmor-secrets-read.json

echo "Verifying AI Router configure -> secrets-service..."
curl -fsS -X POST "http://127.0.0.1:${AI_ROUTER_HOST_PORT}/credentials/providers/openai/configure" \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: change-me-router' \
  -d '{"api_key":"sk-verify-ai-router","base_url":"https://api.openai.com/v1"}' \
  >/tmp/cyberarmor-ai-router-configure.json

curl -fsS "http://127.0.0.1:${AI_ROUTER_HOST_PORT}/credentials/providers/openai/status" \
  -H 'x-api-key: change-me-router' \
  >/tmp/cyberarmor-ai-router-status.json

curl -fsS "http://127.0.0.1:${SECRETS_SERVICE_HOST_PORT}/v1/secrets/tenant/default/provider-credentials/openai" \
  -H "x-api-key: ${SECRETS_SERVICE_API_SECRET}" \
  >/tmp/cyberarmor-ai-router-secret.json

echo "Verifying PQC state persistence through secrets-service..."
curl -fsS "http://127.0.0.1:${AGENT_IDENTITY_HOST_PORT}/pki/public-key" >/tmp/cyberarmor-agent-identity-public-key.json

curl -fsS "http://127.0.0.1:${SECRETS_SERVICE_HOST_PORT}/v1/keys/pqc/agent-identity/state?initialize_if_missing=true" \
  -H "x-api-key: ${SECRETS_SERVICE_API_SECRET}" \
  >/tmp/cyberarmor-agent-identity-pqc-state.json

AI_ROUTER_DISK_STATE="$(compose exec -T ai-router sh -lc 'find /app -path "*/key_state.json" -o -path "/app/data/*" 2>/dev/null | sort')"
AGENT_IDENTITY_DISK_STATE="$(compose exec -T agent-identity sh -lc 'find /app -path "*/key_state.json" -o -path "/app/data/*" 2>/dev/null | sort')"

echo
echo "Verification summary"
echo "- secrets-service stored key: $(jq -r '.api_key' /tmp/cyberarmor-secrets-read.json)"
echo "- ai-router backend: $(jq -r '.secret_backend' /tmp/cyberarmor-ai-router-status.json)"
echo "- ai-router secret key: $(jq -r '.api_key' /tmp/cyberarmor-ai-router-secret.json)"
echo "- agent-identity PQC key id: $(jq -r '.state.current.key_id' /tmp/cyberarmor-agent-identity-pqc-state.json)"
echo "- ai-router local PQC files: ${AI_ROUTER_DISK_STATE:-<none>}"
echo "- agent-identity local PQC files: ${AGENT_IDENTITY_DISK_STATE:-<none>}"

if [[ "$(jq -r '.api_key' /tmp/cyberarmor-secrets-read.json)" != "sk-verify-secrets-service" ]]; then
  echo "secrets-service verification failed" >&2
  exit 1
fi

if [[ "$(jq -r '.secret_backend' /tmp/cyberarmor-ai-router-status.json)" != "secrets-service" ]]; then
  echo "AI Router backend verification failed" >&2
  exit 1
fi

if [[ "$(jq -r '.api_key' /tmp/cyberarmor-ai-router-secret.json)" != "sk-verify-ai-router" ]]; then
  echo "AI Router secret propagation verification failed" >&2
  exit 1
fi

if [[ -n "${AI_ROUTER_DISK_STATE}" || -n "${AGENT_IDENTITY_DISK_STATE}" ]]; then
  echo "PQC local-disk persistence verification failed" >&2
  exit 1
fi

echo
echo "All local OpenBao/CyberArmor verification checks passed."
