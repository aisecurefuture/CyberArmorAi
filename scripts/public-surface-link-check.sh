#!/usr/bin/env bash
set -euo pipefail

# Checks the public CyberArmor buyer and portal surfaces after a deployment.
# Override URLs for staging:
#   MARKETING_URL=https://staging.cyberarmor.ai bash scripts/public-surface-link-check.sh

MARKETING_URL="${MARKETING_URL:-https://cyberarmor.ai}"
SUPPORT_URL="${SUPPORT_URL:-https://support.cyberarmor.ai}"
APP_URL="${APP_URL:-https://app.cyberarmor.ai}"
ADMIN_URL="${ADMIN_URL:-https://admin.cyberarmor.ai}"
DOCS_URL="${DOCS_URL:-https://docs.cyberarmor.ai}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"

TMP_DIR="${TMPDIR:-/tmp}/cyberarmor-public-link-check.$$"
mkdir -p "${TMP_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

failures=()

fail() {
  failures+=("$1")
}

fetch_surface() {
  local name="$1"
  local url="$2"
  local out="${TMP_DIR}/${name}.html"
  local code

  code="$(curl -sS -L --max-time "${TIMEOUT_SECONDS}" -o "${out}" -w "%{http_code}" "${url}" || true)"
  if [[ ! "${code}" =~ ^2 ]]; then
    fail "${name}: expected 2xx from ${url}, got ${code}"
  fi
  printf '%s\n' "${out}"
}

require_contains() {
  local name="$1"
  local file="$2"
  local pattern="$3"
  local detail="$4"

  if ! grep -Eiq "${pattern}" "${file}"; then
    fail "${name}: missing ${detail}"
  fi
}

require_not_contains() {
  local name="$1"
  local file="$2"
  local pattern="$3"
  local detail="$4"

  if grep -Eiq "${pattern}" "${file}"; then
    fail "${name}: found forbidden ${detail}"
  fi
}

homepage="$(fetch_surface homepage "${MARKETING_URL}/")"
demo="$(fetch_surface demo "${MARKETING_URL}/contact")"
support="$(fetch_surface support "${SUPPORT_URL}/")"
customer="$(fetch_surface customer "${APP_URL}/")"
admin="$(fetch_surface admin "${ADMIN_URL}/")"
docs="$(fetch_surface docs "${DOCS_URL}/")"

require_contains homepage "${homepage}" "Product Availability" "Product Availability section"
require_contains homepage "${homepage}" "Available Today" "available-today product boundary"
require_contains homepage "${homepage}" "In Pilot / Design Partner Phase" "pilot/design-partner product boundary"
require_contains homepage "${homepage}" "Framework Alignment" "framework alignment band"
require_contains homepage "${homepage}" "Founder-Led|Built by a Security Practitioner" "founder credibility block"
require_contains homepage "${homepage}" "Official Brand and Domains|CyberArmor\\.AI is the public brand" "brand clarification block"
require_contains homepage "${homepage}" "IBM Cost of a Data Breach 2025|IBM" "IBM source in Why Now"
require_contains homepage "${homepage}" "OWASP GenAI Security Project|OWASP" "OWASP source in Why Now"
require_contains homepage "${homepage}" "NIST AI RMF" "NIST AI RMF source in Why Now"
require_contains homepage "${homepage}" "ISO/IEC 42001" "ISO/IEC 42001 source in Why Now"
require_contains homepage "${homepage}" "EU AI Act" "EU AI Act source in Why Now"
require_contains homepage "${homepage}" "Shadow AI refers to" "crawlable FAQ answer content"
require_not_contains homepage "${homepage}" "Patent-Pending AI Security Innovations Patent-Pending Innovations" "duplicate patent-pending badge text"
require_not_contains homepage "${homepage}" "AI Assets Discovered|Trust Evidence Records|1,284|94,201" "unsourced mock hero metrics"

require_contains demo "${demo}" "Request a Demo|Talk to CISOs|Contact CyberArmor" "demo/contact page copy"
require_contains support "${support}" "Support Center" "support center heading"
require_contains support "${support}" "Severity guide|What to collect before escalation" "support triage content"
require_contains support "${support}" "Open Support Ticket|Secure log upload" "support ticket form with log upload"
require_contains customer "${customer}" "Customer Portal" "customer portal login"
require_contains admin "${admin}" "Platform Admin" "admin portal login"
require_contains docs "${docs}" "CyberArmor AI Documentation|CyberArmor AI Docs" "docs homepage"

if ((${#failures[@]})); then
  printf 'Public surface link check failed:\n' >&2
  printf ' - %s\n' "${failures[@]}" >&2
  exit 1
fi

printf 'Public surface link check passed for:\n'
printf ' - Marketing: %s\n' "${MARKETING_URL}"
printf ' - Demo/contact: %s/contact\n' "${MARKETING_URL}"
printf ' - Support: %s\n' "${SUPPORT_URL}"
printf ' - Customer app: %s\n' "${APP_URL}"
printf ' - Admin portal: %s\n' "${ADMIN_URL}"
printf ' - Docs: %s\n' "${DOCS_URL}"
