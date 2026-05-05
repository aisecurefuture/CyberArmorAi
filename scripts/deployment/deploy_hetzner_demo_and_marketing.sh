#!/usr/bin/env bash
set -euo pipefail

# Deploy the CyberArmor production/demo surfaces from one repo checkout.
#
# Public surfaces served by Caddy:
# - cyberarmor.ai / www.cyberarmor.ai     -> marketing Next.js container
# - docs.cyberarmor.ai                    -> mkdocs static docs container
# - support.cyberarmor.ai                 -> /support route inside marketing
# - app.cyberarmor.ai                     -> customer portal
# - admin.cyberarmor.ai                   -> admin dashboard
#
# Run as root on the target Ubuntu host:
#   sudo DEMO_REPO_DIR=/opt/cyberarmor/CyberArmorAi \
#        DEMO_ENV_FILE=/etc/cyberarmor/demo.env \
#        bash scripts/deployment/deploy_hetzner_demo_and_marketing.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_REPO_DIR="${DEMO_REPO_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
DEMO_COMPOSE_DIR="${DEMO_REPO_DIR}/infra/docker-compose"
DEFAULT_SERVER_ENV_FILE="/etc/cyberarmor/demo.env"
DEFAULT_COMPOSE_ENV_FILE="${DEMO_COMPOSE_DIR}/.env.production"
DEMO_ENV_FILE="${DEMO_ENV_FILE:-}"

if [[ -z "${DEMO_ENV_FILE}" ]]; then
  if [[ -f "${DEFAULT_SERVER_ENV_FILE}" ]]; then
    DEMO_ENV_FILE="${DEFAULT_SERVER_ENV_FILE}"
  else
    DEMO_ENV_FILE="${DEFAULT_COMPOSE_ENV_FILE}"
  fi
fi

log() {
  printf '[deploy] %s\n' "$*"
}

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 1
  }
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return
  fi
  log "Installing Docker Engine and Compose plugin"
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list >/dev/null
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable docker
  systemctl restart docker
}

validate_inputs() {
  if [[ ! -d "${DEMO_REPO_DIR}" ]]; then
    echo "Demo repo directory not found: ${DEMO_REPO_DIR}" >&2
    exit 1
  fi
  if [[ ! -f "${DEMO_COMPOSE_DIR}/docker-compose.yml" ]]; then
    echo "Missing docker compose file in ${DEMO_COMPOSE_DIR}" >&2
    exit 1
  fi
  if [[ ! -f "${DEMO_REPO_DIR}/marketing/package.json" ]]; then
    echo "Missing marketing app in ${DEMO_REPO_DIR}/marketing" >&2
    exit 1
  fi
  if [[ ! -f "${DEMO_REPO_DIR}/docs-site/mkdocs.yml" ]]; then
    echo "Missing docs site in ${DEMO_REPO_DIR}/docs-site" >&2
    exit 1
  fi
  if [[ ! -f "${DEMO_ENV_FILE}" ]]; then
    echo "Demo env file missing: ${DEMO_ENV_FILE}" >&2
    echo "Create it from infra/docker-compose/.env.production.example or run scripts/deployment/setup_hetzner_demo_env.sh first." >&2
    exit 1
  fi
}

build_pqc_base_images() {
  log "Building shared native PQC base images"
  (
    cd "${DEMO_REPO_DIR}"
    bash scripts/docker/build_pqc_base_images.sh
  )
}

deploy_stack() {
  log "Starting CyberArmor stack with Caddy, marketing, docs, support, customer portal, and admin dashboard"
  (
    cd "${DEMO_COMPOSE_DIR}"
    CYBERARMOR_ENV_FILE="${DEMO_ENV_FILE}" \
      docker compose --env-file "${DEMO_ENV_FILE}" --profile prod up -d --build
  )
}

show_next_steps() {
  cat <<EOF

[deploy] Deployment complete
- Marketing site: https://\${MARKETING_DOMAIN:-cyberarmor.ai}
- Support page:   https://\${SUPPORT_DOMAIN:-support.cyberarmor.ai}
- Documentation: https://\${DOCS_DOMAIN:-docs.cyberarmor.ai}
- Customer app:   https://\${APP_DOMAIN:-app.cyberarmor.ai}
- Admin portal:   https://\${ADMIN_DOMAIN:-admin.cyberarmor.ai}

Helpful checks:
  cd ${DEMO_COMPOSE_DIR}
  CYBERARMOR_ENV_FILE=${DEMO_ENV_FILE} docker compose --env-file ${DEMO_ENV_FILE} --profile prod ps
  CYBERARMOR_ENV_FILE=${DEMO_ENV_FILE} docker compose --env-file ${DEMO_ENV_FILE} --profile prod logs caddy --tail=100
  CYBERARMOR_ENV_FILE=${DEMO_ENV_FILE} docker compose --env-file ${DEMO_ENV_FILE} --profile prod logs marketing docs --tail=100

EOF
}

ensure_cmd curl
ensure_cmd gpg
validate_inputs
install_docker
build_pqc_base_images
deploy_stack
show_next_steps
