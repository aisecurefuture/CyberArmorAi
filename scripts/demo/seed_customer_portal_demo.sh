#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/lib/pqc_auth.sh"

TENANT_ID="demo-ciso"
TENANT_NAME="CyberArmor Demo Tenant"
ADMIN_EMAIL="demo-admin@cyberarmor.ai"
PERSONA="ciso"
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8000}"
POLICY_URL="${POLICY_URL:-http://localhost:8001}"
CP_KEY="${CP_KEY:-${CYBERARMOR_API_SECRET:-change-me}}"
POLICY_KEY="${POLICY_KEY:-${POLICY_API_SECRET:-change-me-policy}}"

usage() {
  cat <<EOF
Usage: $0 [--tenant TENANT_ID] [--name TENANT_NAME] [--admin EMAIL] [--persona ciso|architect|appsec]

Seeds a tenant with policies, endpoint telemetry, incidents, and audit-ready
events for customer-portal Mission Control and evidence export demos.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant) TENANT_ID="$2"; shift 2 ;;
    --name) TENANT_NAME="$2"; shift 2 ;;
    --admin) ADMIN_EMAIL="$2"; shift 2 ;;
    --persona) PERSONA="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "$PERSONA" in
  ciso|architect|appsec) ;;
  *) echo "Unsupported persona: $PERSONA" >&2; exit 1 ;;
esac

cp_hdr="$(auth_header_line "$CONTROL_PLANE_URL" "$CP_KEY")"
policy_hdr="$(auth_header_line "$POLICY_URL" "$POLICY_KEY")"
now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
agent_id="${TENANT_ID}-endpoint-01"
request_id="${TENANT_ID}-${PERSONA}-$(date +%s)"

echo "== CyberArmor customer portal demo seed =="
echo "Tenant: $TENANT_ID"
echo "Persona: $PERSONA"

tenant_body="$(printf '{"id":"%s","name":"%s","first_admin_email":"%s"}' "$TENANT_ID" "$TENANT_NAME" "$ADMIN_EMAIL")"
tenant_code="$(curl -sS -o /tmp/cyberarmor_seed_tenant.json -w "%{http_code}" -X POST "$CONTROL_PLANE_URL/tenants" -H "Content-Type: application/json" -H "$cp_hdr" -d "$tenant_body" || true)"
if [[ "$tenant_code" == "201" || "$tenant_code" == "200" ]]; then
  echo "Created tenant"
elif [[ "$tenant_code" == "409" ]]; then
  echo "Tenant already exists"
else
  echo "Tenant create returned HTTP $tenant_code"
  cat /tmp/cyberarmor_seed_tenant.json || true
fi

policy_name="${PERSONA}-runtime-ai-control"
policy_desc="Demo policy for ${PERSONA} narrative: monitor risky AI usage and preserve evidence."
if [[ "$PERSONA" == "appsec" ]]; then
  policy_desc="AppSec demo policy: detect prompt injection and sensitive-data exposure in AI-bound requests."
elif [[ "$PERSONA" == "architect" ]]; then
  policy_desc="Security architect demo policy: show policy decisioning, provider context, and evidence flow."
fi

curl -sS -X POST "$POLICY_URL/policies" \
  -H "Content-Type: application/json" \
  -H "$policy_hdr" \
  -d "$(printf '{"tenant_id":"%s","name":"%s","description":"%s","action":"warn","priority":10,"enabled":true,"scope":"ai_runtime","conditions":{"any":[{"field":"provider","operator":"exists","value":true},{"field":"prompt","operator":"contains","value":"ignore previous instructions"}]},"compliance_frameworks":["NIST AI RMF","OWASP GenAI","ISO/IEC 42001"]}' "$TENANT_ID" "$policy_name" "$policy_desc")" >/dev/null || true

curl -sS -X POST "$CONTROL_PLANE_URL/agents/register" \
  -H "Content-Type: application/json" \
  -H "$cp_hdr" \
  -d "$(printf '{"agent_id":"%s","tenant_id":"%s","hostname":"%s-demo-laptop","os":"macos","version":"demo-2026.05"}' "$agent_id" "$TENANT_ID" "$PERSONA")" >/dev/null || true

curl -sS -X POST "$CONTROL_PLANE_URL/agents/${agent_id}/heartbeat" \
  -H "Content-Type: application/json" \
  -H "$cp_hdr" \
  -d "$(printf '{"tenant_id":"%s","status":"running","uptime_seconds":7200,"active_monitors":["network","process","ai_tool_detector","dlp"],"hostname":"%s-demo-laptop","os":"macos","version":"demo-2026.05"}' "$TENANT_ID" "$PERSONA")" >/dev/null || true

curl -sS -X POST "$CONTROL_PLANE_URL/telemetry/ingest" \
  -H "Content-Type: application/json" \
  -H "$cp_hdr" \
  -d "$(printf '{"tenant_id":"%s","agent_id":"%s","user_id":"demo-user","source":"endpoint","event_type":"ai_service_connection_detected","hostname":"%s-demo-laptop","metadata":{"provider":"openai","domain":"api.openai.com","severity":"medium","persona":"%s","timestamp":"%s"}}' "$TENANT_ID" "$agent_id" "$PERSONA" "$PERSONA" "$now")" >/dev/null || true

curl -sS -X POST "$CONTROL_PLANE_URL/incidents/ingest" \
  -H "Content-Type: application/json" \
  -H "$cp_hdr" \
  -d "$(printf '{"tenant_id":"%s","request_id":"%s","event_type":"runtime_decision","decision":"warn","reasons":["demo_policy_match","evidence_capture"],"metadata":{"persona":"%s","provider":"openai","policy":"%s","ts":"%s"}}' "$TENANT_ID" "$request_id" "$PERSONA" "$policy_name" "$now")" >/dev/null || true

echo
echo "Seeded demo data."
echo "Tenant ID: $TENANT_ID"
echo "Tenant admin email: $ADMIN_EMAIL"
echo "Request ID: $request_id"
echo
echo "Open:"
echo "  Customer portal: https://app.cyberarmor.ai"
echo "  Admin portal:    https://admin.cyberarmor.ai"
echo "  Local customer:  http://localhost:3001"
