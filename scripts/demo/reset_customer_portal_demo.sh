#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PERSONA="${PERSONA:-ciso}"
TENANT_ID="${TENANT_ID:-demo-reset-$(date +%Y%m%d%H%M%S)}"
TENANT_NAME="${TENANT_NAME:-CyberArmor Reset Demo ${TENANT_ID}}"
ADMIN_EMAIL="${ADMIN_EMAIL:-demo-admin@cyberarmor.ai}"

echo "Creating a fresh demo tenant instead of destructively deleting existing data."
bash "$ROOT_DIR/scripts/demo/seed_customer_portal_demo.sh" \
  --tenant "$TENANT_ID" \
  --name "$TENANT_NAME" \
  --admin "$ADMIN_EMAIL" \
  --persona "$PERSONA"
