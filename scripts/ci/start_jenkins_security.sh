#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JENKINS_DIR="$ROOT_DIR/infra/jenkins"
COMPOSE_FILE="$JENKINS_DIR/docker-compose.security.yml"
HOST_JENKINS_WORK_ROOT="${HOST_JENKINS_WORK_ROOT:-/tmp/cyberarmor-jenkins}"
HOST_JENKINS_JOB_WORKDIR="$HOST_JENKINS_WORK_ROOT/CyberArmorAI"

mkdir -p "$HOST_JENKINS_WORK_ROOT"
rm -rf "$HOST_JENKINS_JOB_WORKDIR"
mkdir -p "$HOST_JENKINS_JOB_WORKDIR"

rsync_common_args=(
  -a
  --delete
  --exclude='.git/'
  --exclude='reports/security/'
  --exclude='node_modules/'
  --exclude='*/node_modules/'
  --exclude='dist/'
  --exclude='*/dist/'
  --exclude='out/'
  --exclude='*/out/'
  --exclude='__pycache__/'
  --exclude='*/__pycache__/'
  --exclude='.pytest_cache/'
  --exclude='*/.pytest_cache/'
  --exclude='.mypy_cache/'
  --exclude='*/.mypy_cache/'
  --exclude='.venv/'
  --exclude='*/.venv/'
)

rsync "${rsync_common_args[@]}" \
  "$ROOT_DIR/Jenkinsfile.security" \
  "$ROOT_DIR/Makefile" \
  "$ROOT_DIR/README.md" \
  "$HOST_JENKINS_JOB_WORKDIR/"

rsync_paths=(
  agents
  libs/cyberarmor-core
  scripts
  services
  sdks/python
  infra/security
  infra/docker-compose
)

for path in "${rsync_paths[@]}"; do
  mkdir -p "$HOST_JENKINS_JOB_WORKDIR/$(dirname "$path")"
  rsync "${rsync_common_args[@]}" "$ROOT_DIR/$path/" "$HOST_JENKINS_JOB_WORKDIR/$path/"
done

cd "$JENKINS_DIR"
HOST_JENKINS_WORK_ROOT="$HOST_JENKINS_WORK_ROOT" docker compose -f "$COMPOSE_FILE" up -d --build

cat <<EOF
Jenkins security container is starting.

- URL: http://localhost:8088
- Compose file: $COMPOSE_FILE
- Pipeline: $ROOT_DIR/Jenkinsfile.security
- Mounted repo path in container: /repo/CyberArmorAi
- Host-mounted Jenkins work root: $HOST_JENKINS_WORK_ROOT
- Host-prepared CyberArmorAI workdir: $HOST_JENKINS_JOB_WORKDIR

Next:
1. Open Jenkins at http://localhost:8088
2. Open the seeded CyberArmorAI job
3. Set SCAN_PROFILE to pr, integration, or scheduled

The container seeds/updates the CyberArmorAI job from the mounted Jenkinsfile.security
on startup, which avoids stale pasted Pipeline scripts in the Jenkins UI.

If Jenkins was already running, this command rebuilds the image and restarts the container so plugin and permission changes take effect.
EOF
