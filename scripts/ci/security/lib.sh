#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPORT_DIR="${SECURITY_REPORT_DIR:-$ROOT_DIR/reports/security}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
SCOUT_BUILD_SERVICES="${SCOUT_BUILD_SERVICES:-control-plane,policy,detection,response,identity,siem-connector,compliance,runtime,proxy-agent,transparent-proxy,agent-identity,ai-router,audit,integration-control}"
ZAP_TARGET_URL="${ZAP_TARGET_URL:-}"
PROWLER_PROVIDER="${PROWLER_PROVIDER:-aws}"
PROWLER_ARGS="${PROWLER_ARGS:-}"
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-$ROOT_DIR/infra/docker-compose/docker-compose.yml}"
SEMGREP_PR_CONFIGS="${SEMGREP_PR_CONFIGS:-p/secrets p/python p/javascript p/typescript p/dockerfile p/kubernetes}"
SEMGREP_SCHEDULED_CONFIGS="${SEMGREP_SCHEDULED_CONFIGS:-p/default p/secrets p/dockerfile p/kubernetes p/python p/javascript p/typescript}"
GITLEAKS_CONFIG_FILE="${GITLEAKS_CONFIG_FILE:-$ROOT_DIR/infra/security/gitleaks.toml}"
TRUFFLEHOG_EXCLUDE_PATHS_FILE="${TRUFFLEHOG_EXCLUDE_PATHS_FILE:-$ROOT_DIR/infra/security/trufflehog-exclude-paths.txt}"
SEMGREP_IGNORE_FILE="${SEMGREP_IGNORE_FILE:-$ROOT_DIR/infra/security/.semgrepignore}"
SEMGREP_PR_FAIL_SEVERITIES="${SEMGREP_PR_FAIL_SEVERITIES:-ERROR}"
SEMGREP_SCHEDULED_FAIL_SEVERITIES="${SEMGREP_SCHEDULED_FAIL_SEVERITIES:-ERROR,WARNING}"
BANDIT_BASELINE_FILE="${BANDIT_BASELINE_FILE:-$ROOT_DIR/infra/security/bandit-baseline.json}"
PIP_AUDIT_IGNORE_FILE="${PIP_AUDIT_IGNORE_FILE:-$ROOT_DIR/infra/security/pip-audit-ignore.txt}"
NPM_AUDIT_FAIL_LEVEL="${NPM_AUDIT_FAIL_LEVEL:-high}"
DEPENDENCY_CHECK_SUPPRESSIONS_FILE="${DEPENDENCY_CHECK_SUPPRESSIONS_FILE:-$ROOT_DIR/infra/security/dependency-check-suppressions.xml}"
DOCKER_SCOUT_PR_SEVERITIES="${DOCKER_SCOUT_PR_SEVERITIES:-critical,high}"
DOCKER_SCOUT_SCHEDULED_SEVERITIES="${DOCKER_SCOUT_SCHEDULED_SEVERITIES:-critical,high}"
ZAP_BASELINE_CONFIG_FILE="${ZAP_BASELINE_CONFIG_FILE:-$ROOT_DIR/infra/security/zap-baseline.conf}"
PROWLER_EXCLUDE_CHECKS_FILE="${PROWLER_EXCLUDE_CHECKS_FILE:-$ROOT_DIR/infra/security/prowler-exclude-checks.txt}"

mkdir -p "$REPORT_DIR"

log() {
  printf '[security-ci] %s\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

git_base_ref() {
  if [[ -n "${CHANGE_TARGET:-}" ]]; then
    printf '%s' "$CHANGE_TARGET"
  else
    printf '%s' "$DEFAULT_BRANCH"
  fi
}

git_fetch_base_ref() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git fetch --no-tags origin "$(git_base_ref)" >/dev/null 2>&1 || true
  fi
}

git_diff_range() {
  local base_ref
  base_ref="$(git_base_ref)"
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if git rev-parse --verify "origin/${base_ref}" >/dev/null 2>&1; then
      printf 'origin/%s...HEAD' "$base_ref"
    else
      printf '%s...HEAD' "$base_ref"
    fi
  else
    printf 'HEAD'
  fi
}

changed_files() {
  if [[ -n "${CHANGED_FILES:-}" ]]; then
    printf '%s\n' "$CHANGED_FILES"
    return
  fi
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git diff --name-only "$(git_diff_range)"
  fi
}

list_extension_workspaces() {
  find "$ROOT_DIR/extensions" -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/package.json' ';' -print | sed "s#^$ROOT_DIR/##" | sort
}

touched_extension_workspaces() {
  local changed workspace
  changed="$(changed_files || true)"
  if [[ -z "$changed" ]]; then
    return 0
  fi
  while IFS= read -r workspace; do
    [[ -n "$workspace" ]] || continue
    if grep -q "^${workspace}/" <<<"$changed"; then
      printf '%s\n' "$workspace"
    fi
  done < <(list_extension_workspaces)
}

comma_to_lines() {
  tr ',' '\n' <<<"${1:-}" | sed '/^[[:space:]]*$/d'
}

non_comment_lines() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$file"
}

file_to_json_array() {
  local file="$1"
  if [[ -f "$file" ]]; then
    jq -Rsc 'split("\n") | map(gsub("^\\s+|\\s+$";"")) | map(select(length > 0 and (startswith("#") | not)))' <"$file"
  else
    printf '[]'
  fi
}

run_semgrep_configs() {
  local profile="$1"
  local output_file="$2"
  local config_list
  local severity_list
  if [[ "$profile" == "pr" ]]; then
    config_list="$SEMGREP_PR_CONFIGS"
    severity_list="$SEMGREP_PR_FAIL_SEVERITIES"
  else
    config_list="$SEMGREP_SCHEDULED_CONFIGS"
    severity_list="$SEMGREP_SCHEDULED_FAIL_SEVERITIES"
  fi
  local args=()
  while IFS= read -r cfg; do
    [[ -n "$cfg" ]] || continue
    args+=(--config "$cfg")
  done < <(xargs -n1 <<<"$config_list")
  while IFS= read -r sev; do
    [[ -n "$sev" ]] || continue
    args+=(--severity "$sev")
  done < <(comma_to_lines "$severity_list")
  if [[ -f "$SEMGREP_IGNORE_FILE" ]]; then
    args+=(--exclude-from "$SEMGREP_IGNORE_FILE")
  fi

  docker run --rm \
    -v "$ROOT_DIR:/src" \
    -w /src \
    semgrep/semgrep:latest \
    semgrep scan \
      --metrics=off \
      --exclude=**/node_modules/** \
      --exclude=**/dist/** \
      --exclude=**/.venv/** \
      --exclude=**/out/** \
      --error \
      --sarif \
      --output "/src/${output_file#$ROOT_DIR/}" \
      "${args[@]}" \
      /src
}

run_python_tool() {
  local report_file="$1"
  shift
  docker run --rm \
    -v "$ROOT_DIR:/src" \
    -w /src \
    python:3.12-slim \
    bash -lc "pip install --quiet --disable-pip-version-check bandit pip-audit && $* > /src/${report_file#$ROOT_DIR/}"
}

compose_build_services() {
  local project_name="$1"
  local services=("$@")
  services=("${services[@]:1}")
  docker compose -p "$project_name" -f "$DOCKER_COMPOSE_FILE" build "${services[@]}"
}

compose_image_ids() {
  local project_name="$1"
  shift
  local service
  for service in "$@"; do
    docker compose -p "$project_name" -f "$DOCKER_COMPOSE_FILE" images -q "$service"
  done
}

run_docker_scout_scan() {
  local image_ref="$1"
  local output_file="$2"
  local severities="${3:-$DOCKER_SCOUT_PR_SEVERITIES}"
  docker scout cves \
    --only-severity "$severities" \
    --only-fixed \
    --format sarif \
    --output "$output_file" \
    "$image_ref"
}

pip_audit_ignore_args() {
  local args=()
  while IFS= read -r vuln_id; do
    [[ -n "$vuln_id" ]] || continue
    args+=(--ignore-vuln "$vuln_id")
  done < <(non_comment_lines "$PIP_AUDIT_IGNORE_FILE")
  printf '%s\0' "${args[@]}"
}
