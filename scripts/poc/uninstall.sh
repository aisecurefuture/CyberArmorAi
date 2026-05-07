#!/usr/bin/env bash
# Tear down the URL Trust Gate PoC stack and remove its containers,
# networks, and the poc-test-server. The .env is left in place so a
# subsequent `install.sh` reuses the same secrets.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="$ROOT_DIR/infra/docker-compose"
ENV_FILE="$COMPOSE_DIR/.env"

cd "$COMPOSE_DIR"

echo "==> Stopping URL Trust Gate PoC services"

if [[ -f "$ENV_FILE" ]]; then
  CYBERARMOR_ENV_FILE="$ENV_FILE" \
    docker compose \
      --env-file "$ENV_FILE" \
      -f docker-compose.yml \
      -f docker-compose.poc.yml \
      --profile poc \
      down --remove-orphans
else
  docker compose \
    -f docker-compose.yml \
    -f docker-compose.poc.yml \
    --profile poc \
    down --remove-orphans
fi

echo "==> Done. .env left in place at $ENV_FILE."
echo "    To wipe secrets too: rm -f $ENV_FILE"
