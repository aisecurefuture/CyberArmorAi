#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

bash "$ROOT_DIR/scripts/demo/seed_customer_portal_demo.sh" --tenant "${TENANT_ID:-demo-architect}" --name "Security Architect Control Demo" --admin "${ADMIN_EMAIL:-demo-admin@cyberarmor.ai}" --persona architect

cat <<'EOF'

Security Architect Demo Narrative
1. Open Admin Portal > Overview and show tenant readiness.
2. Open Policies and Policy Studio to show runtime decisioning.
3. Open Onboarding to show bootstrap, SDK, extension, and endpoint paths.
4. Open Reports and export the full evidence pack.
5. Close with: CyberArmor.AI connects control plane, policy, telemetry, and audit evidence.
EOF
