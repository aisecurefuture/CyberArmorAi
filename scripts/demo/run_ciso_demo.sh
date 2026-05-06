#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

bash "$ROOT_DIR/scripts/demo/seed_customer_portal_demo.sh" --tenant "${TENANT_ID:-demo-ciso}" --name "CISO Board Evidence Demo" --admin "${ADMIN_EMAIL:-demo-admin@cyberarmor.ai}" --persona ciso

cat <<'EOF'

CISO Demo Narrative
1. Open Customer Portal > Mission Control.
2. Show tenant readiness and next best actions.
3. Open Reports > Export Evidence > Export Summary.
4. Open Incidents and explain the policy decision record.
5. Close with: CyberArmor.AI turns AI governance into controls and evidence.
EOF
