#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-${ROOT_DIR}/infra/docker-compose}"
COMPOSE_FILE="${COMPOSE_FILE:-${COMPOSE_DIR}/docker-compose.yml}"
OVERRIDE_FILE="${OVERRIDE_FILE:-${COMPOSE_DIR}/docker-compose.hetzner.override.yml}"
ENV_FILE="${ENV_FILE:-/etc/cyberarmor/demo.env}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

compose_args=()
if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  compose_args+=(--env-file "${ENV_FILE}")
fi

compose_args+=(-f "${COMPOSE_FILE}")
if [[ -f "${OVERRIDE_FILE}" ]]; then
  compose_args+=(-f "${OVERRIDE_FILE}")
else
  echo "Override file not found, continuing with base compose file only: ${OVERRIDE_FILE}" >&2
fi

services=(
  "control-plane:8000"
  "policy:${POLICY_HOST_PORT:-8001}"
  "detection:8002"
  "response:8003"
  "identity:8004"
  "siem-connector:8005"
  "compliance:8006"
  "agent-identity:${AGENT_IDENTITY_HOST_PORT:-8008}"
  "ai-router:${AI_ROUTER_HOST_PORT:-8009}"
  "proxy-agent:8010"
  "audit:${AUDIT_HOST_PORT:-8011}"
  "integration-control:8012"
  "secrets-service:${SECRETS_SERVICE_HOST_PORT:-8013}"
)

native_failures=0

echo "== CyberArmor native PQC validation =="
echo "Compose dir: ${COMPOSE_DIR}"
echo "Env file: ${ENV_FILE}"
echo

for entry in "${services[@]}"; do
  service="${entry%%:*}"
  port="${entry##*:}"

  echo "-- ${service}"

  docker_json=""
  if ! docker_json="$(
    cd "${COMPOSE_DIR}" &&
    docker compose "${compose_args[@]}" exec -T "${service}" \
      python -c 'import json; from cyberarmor_core.crypto.pqc_kem import PQCKEM; from cyberarmor_core.crypto.pqc_sign import PQCSigner; print(json.dumps({"native_kem": PQCKEM.is_native_pqc_available(), "native_sign": PQCSigner.is_native_pqc_available(), "kem_algorithm": PQCKEM().generate_keypair().algorithm, "sign_algorithm": PQCSigner().generate_keypair().algorithm}))'
  )"; then
    docker_json=""
  fi
  if [[ -z "${docker_json}" ]]; then
    echo "   container check: FAILED"
    native_failures=$((native_failures + 1))
    continue
  fi

  api_json=""
  if ! api_json="$(curl -fsS "http://127.0.0.1:${port}/pki/public-key")"; then
    api_json=""
  fi
  if [[ -z "${api_json}" ]]; then
    echo "   api check: FAILED at http://127.0.0.1:${port}/pki/public-key"
    native_failures=$((native_failures + 1))
    continue
  fi

  container_kem_native="$(printf '%s' "${docker_json}" | jq -r '.native_kem')"
  container_sign_native="$(printf '%s' "${docker_json}" | jq -r '.native_sign')"
  container_kem_alg="$(printf '%s' "${docker_json}" | jq -r '.kem_algorithm')"
  container_sign_alg="$(printf '%s' "${docker_json}" | jq -r '.sign_algorithm')"
  api_kem_alg="$(printf '%s' "${api_json}" | jq -r '.algorithm')"
  api_sign_alg="$(printf '%s' "${api_json}" | jq -r '.sign_algorithm')"

  echo "   container native KEM:   ${container_kem_native}"
  echo "   container native SIGN:  ${container_sign_native}"
  echo "   container KEM alg:      ${container_kem_alg}"
  echo "   container SIGN alg:     ${container_sign_alg}"
  echo "   API KEM alg:            ${api_kem_alg}"
  echo "   API SIGN alg:           ${api_sign_alg}"

  if [[ "${container_kem_native}" != "true" || "${container_sign_native}" != "true" ]]; then
    echo "   RESULT: FALLBACK runtime detected"
    native_failures=$((native_failures + 1))
    continue
  fi
  if [[ "${api_kem_alg}" != "ML-KEM-1024" || "${api_sign_alg}" != "ML-DSA-87" ]]; then
    echo "   RESULT: API still advertising fallback algorithms"
    native_failures=$((native_failures + 1))
    continue
  fi

  echo "   RESULT: native ML-KEM / ML-DSA active"
done

echo
if [[ "${native_failures}" -gt 0 ]]; then
  echo "NATIVE_PQC_VALIDATION_FAILED count=${native_failures}" >&2
  exit 1
fi

echo "NATIVE_PQC_VALIDATION_OK"
