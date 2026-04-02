#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_cmd docker

log "running scheduled security sweep"

log "broad semgrep sweep"
run_semgrep_configs scheduled "$REPORT_DIR/semgrep-scheduled.sarif"

log "full pip-audit sweep"
mapfile -t requirements_files < <(find "$ROOT_DIR" -type f \( -name 'requirements*.txt' -o -name 'pyproject.toml' \) \
  -not -path '*/node_modules/*' \
  -not -path '*/dist/*' \
  -not -path '*/out/*' | sort)
mapfile -d '' -t pip_ignore_args < <(pip_audit_ignore_args)
for req_file in "${requirements_files[@]}"; do
  rel="${req_file#$ROOT_DIR/}"
  safe_name="$(tr '/.' '__' <<<"$rel")"
  docker run --rm \
    -v "$ROOT_DIR:/src" \
    -w /src \
    python:3.12-slim \
    bash -lc "pip install --quiet --disable-pip-version-check pip-audit && if [[ '$rel' == *.txt ]]; then pip-audit -r '$rel' ${pip_ignore_args[*]} --format json --output '${REPORT_DIR#$ROOT_DIR/}/pip-audit-${safe_name}.json'; else pip-audit --path \"\$(dirname '$rel')\" ${pip_ignore_args[*]} --format json --output '${REPORT_DIR#$ROOT_DIR/}/pip-audit-${safe_name}.json'; fi"
done

log "full npm audit sweep"
while IFS= read -r workspace; do
  safe_name="$(tr '/.' '__' <<<"$workspace")"
  docker run --rm \
    -v "$ROOT_DIR:/workspace" \
    -w "/workspace/$workspace" \
    node:20-bookworm \
    bash -lc "npm install --package-lock-only --ignore-scripts --include=dev >/tmp/npm-lock.log 2>&1 && npm audit --audit-level=${NPM_AUDIT_FAIL_LEVEL} --json > '/workspace/${REPORT_DIR#$ROOT_DIR/}/npm-audit-${safe_name}.json'"
done < <(list_extension_workspaces)

log "owasp dependency-check full repo scan"
docker run --rm \
  -v "$ROOT_DIR:/src" \
  -v "$ROOT_DIR/.dependency-check-data:/usr/share/dependency-check/data" \
  owasp/dependency-check:latest \
  --scan /src \
  --suppression "/src/${DEPENDENCY_CHECK_SUPPRESSIONS_FILE#$ROOT_DIR/}" \
  --format "HTML" \
  --format "JSON" \
  --out "/src/${REPORT_DIR#$ROOT_DIR/}/dependency-check"

log "docker scout scheduled image sweep"
project_name="security-scheduled"
mapfile -t services < <(comma_to_lines "$SCOUT_BUILD_SERVICES")
compose_build_services "$project_name" "${services[@]}"
for service in "${services[@]}"; do
  image_id="$(docker compose -p "$project_name" -f "$DOCKER_COMPOSE_FILE" images -q "$service" | tail -n1)"
  [[ -n "$image_id" ]] || continue
  run_docker_scout_scan "local://${image_id}" "$REPORT_DIR/docker-scout-${service}.sarif" "$DOCKER_SCOUT_SCHEDULED_SEVERITIES"
done

log "prowler scheduled scan"
mkdir -p "$REPORT_DIR/prowler"
prowler_extra_args=()
while IFS= read -r check_id; do
  [[ -n "$check_id" ]] || continue
  prowler_extra_args+=(--excluded-checks "$check_id")
done < <(non_comment_lines "$PROWLER_EXCLUDE_CHECKS_FILE")

docker run --rm \
  -v "$ROOT_DIR/$REPORT_DIR/prowler:/output" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION \
  toniblyx/prowler:latest \
  "$PROWLER_PROVIDER" \
  -M json-asff csv html \
  -o /output \
  "${prowler_extra_args[@]}" \
  $PROWLER_ARGS

if [[ -n "$ZAP_TARGET_URL" ]]; then
  log "zap baseline scan against $ZAP_TARGET_URL"
  docker run --rm \
    -v "$ROOT_DIR:/workspace:rw" \
    -w "/workspace/${REPORT_DIR#$ROOT_DIR/}" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$ZAP_TARGET_URL" \
    -c "/workspace/${ZAP_BASELINE_CONFIG_FILE#$ROOT_DIR/}" \
    -J zap-baseline.json \
    -r zap-baseline.html \
    -w zap-baseline.md \
    -d
else
  log "skipping ZAP baseline because ZAP_TARGET_URL is empty"
fi

log "scheduled security sweep complete"
