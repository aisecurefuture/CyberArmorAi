#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_cmd docker
git_fetch_base_ref

log "running PR/CI security gate"
mkdir -p "$REPORT_DIR"
find "$REPORT_DIR" -mindepth 1 -maxdepth 1 -delete

print_gitleaks_summary() {
  local report_file="$1"
  [[ -f "$report_file" ]] || return 0
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi
  log "gitleaks findings summary"
  jq -r '
    .runs[0].results[]? |
    "- rule=" + (.ruleId // "unknown") +
    " file=" + (.locations[0].physicalLocation.artifactLocation.uri // "unknown") +
    " line=" + ((.locations[0].physicalLocation.region.startLine // 0) | tostring) +
    " message=" + (.message.text // "")
  ' "$report_file" || true
}

print_semgrep_summary() {
  local report_file="$1"
  [[ -f "$report_file" ]] || return 0
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi
  log "semgrep findings summary"
  jq -r '
    .runs[0].results[:20][]? |
    "- rule=" + (.ruleId // "unknown") +
    " file=" + (.locations[0].physicalLocation.artifactLocation.uri // "unknown") +
    " line=" + ((.locations[0].physicalLocation.region.startLine // 0) | tostring) +
    " message=" + (.message.text // "")
  ' "$report_file" || true
}

log "gitleaks secret scan"
if ! docker run --rm \
  -v "$ROOT_DIR:/src" \
  ghcr.io/gitleaks/gitleaks:latest \
  detect \
  --source /src \
  --config "/src/${GITLEAKS_CONFIG_FILE#$ROOT_DIR/}" \
  --redact \
  --no-git \
  --report-format sarif \
  --report-path "/src/${REPORT_DIR#$ROOT_DIR/}/gitleaks-pr.sarif"; then
  print_gitleaks_summary "$REPORT_DIR/gitleaks-pr.sarif"
  exit 1
fi

log "trufflehog secret scan"
trufflehog_args=()
if [[ -f "$TRUFFLEHOG_EXCLUDE_PATHS_FILE" ]]; then
  trufflehog_args+=(--exclude-paths "/src/${TRUFFLEHOG_EXCLUDE_PATHS_FILE#$ROOT_DIR/}")
fi
if [[ -d "$ROOT_DIR/.git" ]]; then
  docker run --rm \
    -v "$ROOT_DIR:/src" \
    trufflesecurity/trufflehog:latest \
    git "file:///src" \
    --since-commit "$(git_base_ref)" \
    --branch HEAD \
    --only-verified \
    --fail \
    "${trufflehog_args[@]}" \
    --json >"$REPORT_DIR/trufflehog-pr.json"
else
  log "no .git directory in workdir; using trufflehog filesystem scan"
  docker run --rm \
    -v "$ROOT_DIR:/src" \
    trufflesecurity/trufflehog:latest \
    filesystem /src \
    --only-verified \
    --fail \
    "${trufflehog_args[@]}" \
    --json >"$REPORT_DIR/trufflehog-pr.json"
fi

log "semgrep tuned rules"
if ! run_semgrep_configs pr "$REPORT_DIR/semgrep-pr.sarif"; then
  print_semgrep_summary "$REPORT_DIR/semgrep-pr.sarif"
  exit 1
fi

log "bandit high-severity scan"
bandit_baseline_arg=()
if [[ -f "$BANDIT_BASELINE_FILE" ]]; then
  bandit_baseline_arg=(-b "${BANDIT_BASELINE_FILE#$ROOT_DIR/}")
fi
docker run --rm \
  -v "$ROOT_DIR:/src" \
  -w /src \
  python:3.12-slim \
  bash -lc "pip install --quiet --disable-pip-version-check bandit && bandit -r services agents libs/cyberarmor-core sdks/python scripts -f json -o ${REPORT_DIR#$ROOT_DIR/}/bandit-pr.json -lll -ii ${bandit_baseline_arg[*]}"

log "pip-audit for Python manifests"
mapfile -t requirements_files < <(find "$ROOT_DIR" -type f \( -name 'requirements*.txt' -o -name 'pyproject.toml' \) \
  -not -path '*/node_modules/*' \
  -not -path '*/dist/*' \
  -not -path '*/out/*' | sort)
if [[ "${#requirements_files[@]}" -gt 0 ]]; then
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
fi

log "npm audit for touched extension workspaces"
mapfile -t touched_workspaces < <(touched_extension_workspaces)
if [[ "${#touched_workspaces[@]}" -gt 0 ]]; then
  for workspace in "${touched_workspaces[@]}"; do
    rel="$workspace"
    safe_name="$(tr '/.' '__' <<<"$rel")"
    docker run --rm \
      -v "$ROOT_DIR:/workspace" \
      -w "/workspace/$rel" \
      node:20-bookworm \
      bash -lc "npm install --package-lock-only --ignore-scripts --include=dev >/tmp/npm-lock.log 2>&1 && npm audit --audit-level=${NPM_AUDIT_FAIL_LEVEL} --json > '/workspace/${REPORT_DIR#$ROOT_DIR/}/npm-audit-${safe_name}.json'"
  done
else
  log "no touched extension workspaces detected"
fi

if [[ "${RUN_DOCKER_SCOUT_PR:-false}" == "true" ]]; then
  log "building local images for docker scout"
  project_name="security-pr"
  mapfile -t services < <(comma_to_lines "$SCOUT_BUILD_SERVICES")
  compose_build_services "$project_name" "${services[@]}"
  for service in "${services[@]}"; do
    image_id="$(docker compose -p "$project_name" -f "$DOCKER_COMPOSE_FILE" images -q "$service" | tail -n1)"
    [[ -n "$image_id" ]] || continue
    run_docker_scout_scan "local://${image_id}" "$REPORT_DIR/docker-scout-${service}.sarif" "$DOCKER_SCOUT_PR_SEVERITIES"
  done
fi

log "PR/CI security gate complete"
