#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JENKINS_DIR="$ROOT_DIR/infra/jenkins"
COMPOSE_FILE="$JENKINS_DIR/docker-compose.security.yml"

cd "$JENKINS_DIR"
docker compose -f "$COMPOSE_FILE" up -d --build

cat <<EOF
Jenkins security container is starting.

- URL: http://localhost:8088
- Compose file: $COMPOSE_FILE
- Pipeline: $ROOT_DIR/Jenkinsfile.security

Next:
1. Open Jenkins at http://localhost:8088
2. Create a Pipeline job or Multibranch Pipeline
3. Point it at this repo and use Jenkinsfile.security
4. Set SCAN_PROFILE to pr, integration, or scheduled
EOF
