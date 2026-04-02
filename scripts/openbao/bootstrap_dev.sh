#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/infra/docker-compose/.env}"
ENV_OPENBAO_ADDR="${OPENBAO_ADDR:-}"
ENV_OPENBAO_DEV_ROOT_TOKEN="${OPENBAO_DEV_ROOT_TOKEN:-}"
ENV_OPENBAO_KV_MOUNT="${OPENBAO_KV_MOUNT:-}"
ENV_OPENBAO_TRANSIT_MOUNT="${OPENBAO_TRANSIT_MOUNT:-}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

OPENBAO_ADDR="${ENV_OPENBAO_ADDR:-${OPENBAO_ADDR:-http://127.0.0.1:8200}}"
OPENBAO_DEV_ROOT_TOKEN="${ENV_OPENBAO_DEV_ROOT_TOKEN:-${OPENBAO_DEV_ROOT_TOKEN:-}}"
OPENBAO_KV_MOUNT="${ENV_OPENBAO_KV_MOUNT:-${OPENBAO_KV_MOUNT:-cyberarmor-kv}}"
OPENBAO_TRANSIT_MOUNT="${ENV_OPENBAO_TRANSIT_MOUNT:-${OPENBAO_TRANSIT_MOUNT:-cyberarmor-transit}}"

if [[ -z "$OPENBAO_DEV_ROOT_TOKEN" ]]; then
  echo "OPENBAO_DEV_ROOT_TOKEN is required" >&2
  exit 1
fi

auth_header=(-H "X-Vault-Token: ${OPENBAO_DEV_ROOT_TOKEN}")

wait_for_openbao() {
  local attempt=0
  until curl -fsS "${OPENBAO_ADDR}/v1/sys/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [[ "$attempt" -ge 30 ]]; then
      echo "OpenBao did not become ready at ${OPENBAO_ADDR}" >&2
      exit 1
    fi
    sleep 2
  done
}

mount_exists() {
  local mount_name="$1"
  curl -fsS "${auth_header[@]}" "${OPENBAO_ADDR}/v1/sys/mounts" | jq -e --arg mount "${mount_name}/" '.data | has($mount)' >/dev/null
}

enable_kv_v2() {
  if mount_exists "$OPENBAO_KV_MOUNT"; then
    echo "KV mount ${OPENBAO_KV_MOUNT} already enabled"
    return
  fi
  curl -fsS "${auth_header[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"type":"kv","options":{"version":"2"},"description":"CyberArmor versioned secrets"}' \
    "${OPENBAO_ADDR}/v1/sys/mounts/${OPENBAO_KV_MOUNT}" >/dev/null
  echo "Enabled KV v2 mount ${OPENBAO_KV_MOUNT}"
}

enable_transit() {
  if mount_exists "$OPENBAO_TRANSIT_MOUNT"; then
    echo "Transit mount ${OPENBAO_TRANSIT_MOUNT} already enabled"
    return
  fi
  curl -fsS "${auth_header[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"type":"transit","description":"CyberArmor transit crypto"}' \
    "${OPENBAO_ADDR}/v1/sys/mounts/${OPENBAO_TRANSIT_MOUNT}" >/dev/null
  echo "Enabled transit mount ${OPENBAO_TRANSIT_MOUNT}"
}

ensure_transit_key() {
  local key_name="$1"
  if curl -fsS "${auth_header[@]}" "${OPENBAO_ADDR}/v1/${OPENBAO_TRANSIT_MOUNT}/keys/${key_name}" >/dev/null 2>&1; then
    echo "Transit key ${key_name} already exists"
    return
  fi
  curl -fsS "${auth_header[@]}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"type":"aes256-gcm96"}' \
    "${OPENBAO_ADDR}/v1/${OPENBAO_TRANSIT_MOUNT}/keys/${key_name}" >/dev/null
  echo "Created transit key ${key_name}"
}

wait_for_openbao
enable_kv_v2
enable_transit
ensure_transit_key "router-master"
ensure_transit_key "audit-signing"
ensure_transit_key "tenant-default-provider-creds"

echo "OpenBao bootstrap complete"
