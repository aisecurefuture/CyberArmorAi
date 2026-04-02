#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

auth_header_value() {
  local service_url="$1"
  local secret="$2"
  python3 "$ROOT_DIR/scripts/security/pqc_auth_header.py" "$service_url" "$secret"
}

auth_header_line() {
  local service_url="$1"
  local secret="$2"
  printf 'x-api-key: %s' "$(auth_header_value "$service_url" "$secret")"
}
