#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${SECURITY_REPORT_DIR:-$ROOT_DIR/reports/security}"
REPORT_FILE="$REPORT_DIR/openbao-integration.txt"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cyberarmor-openbao-ci}"
OPENBAO_VERIFY_KEEP_STACK="${OPENBAO_VERIFY_KEEP_STACK:-false}"
POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-15432}"
REDIS_HOST_PORT="${REDIS_HOST_PORT:-16379}"
OPA_HOST_PORT="${OPA_HOST_PORT:-18181}"
OPENBAO_HOST_PORT="${OPENBAO_HOST_PORT:-18200}"
POLICY_HOST_PORT="${POLICY_HOST_PORT:-18001}"
AGENT_IDENTITY_HOST_PORT="${AGENT_IDENTITY_HOST_PORT:-18008}"
AI_ROUTER_HOST_PORT="${AI_ROUTER_HOST_PORT:-18009}"
AUDIT_HOST_PORT="${AUDIT_HOST_PORT:-18011}"
SECRETS_SERVICE_HOST_PORT="${SECRETS_SERVICE_HOST_PORT:-18013}"

mkdir -p "$REPORT_DIR"

run_verifier() {
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  OPENBAO_VERIFY_KEEP_STACK="$OPENBAO_VERIFY_KEEP_STACK" \
  POSTGRES_HOST_PORT="$POSTGRES_HOST_PORT" \
  REDIS_HOST_PORT="$REDIS_HOST_PORT" \
  OPA_HOST_PORT="$OPA_HOST_PORT" \
  OPENBAO_HOST_PORT="$OPENBAO_HOST_PORT" \
  POLICY_HOST_PORT="$POLICY_HOST_PORT" \
  AGENT_IDENTITY_HOST_PORT="$AGENT_IDENTITY_HOST_PORT" \
  AI_ROUTER_HOST_PORT="$AI_ROUTER_HOST_PORT" \
  AUDIT_HOST_PORT="$AUDIT_HOST_PORT" \
  SECRETS_SERVICE_HOST_PORT="$SECRETS_SERVICE_HOST_PORT" \
  bash "$ROOT_DIR/scripts/openbao/verify_local.sh"
}

if run_verifier >"$REPORT_FILE" 2>&1; then
  printf '[openbao-ci] verification passed\n'
  cat "$REPORT_FILE"
  exit 0
fi

printf '[openbao-ci] verification failed, capturing compose diagnostics\n' >&2
{
  printf '\n===== docker compose ps =====\n'
  docker compose -p "$COMPOSE_PROJECT_NAME" -f "$ROOT_DIR/infra/docker-compose/docker-compose.yml" ps || true
  printf '\n===== docker compose logs =====\n'
  docker compose -p "$COMPOSE_PROJECT_NAME" -f "$ROOT_DIR/infra/docker-compose/docker-compose.yml" logs --no-color || true
} >>"$REPORT_FILE" 2>&1

cat "$REPORT_FILE"
exit 1
