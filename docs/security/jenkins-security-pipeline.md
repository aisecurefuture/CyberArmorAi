# Jenkins Security Pipeline

This repository now includes a containerized Jenkins-ready security pipeline built around open source or low-cost scanners.

## Files

- Pipeline definition: [Jenkinsfile.security](/Users/patrickkelly/Documents/CyberArmorAi/Jenkinsfile.security)
- Jenkins container image: [infra/jenkins/Dockerfile](/Users/patrickkelly/Documents/CyberArmorAi/infra/jenkins/Dockerfile)
- Jenkins docker-compose: [infra/jenkins/docker-compose.security.yml](/Users/patrickkelly/Documents/CyberArmorAi/infra/jenkins/docker-compose.security.yml)
- Jenkins startup helper: [scripts/ci/start_jenkins_security.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/start_jenkins_security.sh)
- Jenkins plugins: [infra/jenkins/plugins.txt](/Users/patrickkelly/Documents/CyberArmorAi/infra/jenkins/plugins.txt)
- PR/CI runner: [scripts/ci/security/run_pr_gate.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/security/run_pr_gate.sh)
- OpenBao integration runner: [scripts/ci/run_openbao_integration.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/run_openbao_integration.sh)
- Scheduled runner: [scripts/ci/security/run_scheduled_scans.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/security/run_scheduled_scans.sh)
- Shared helper functions: [scripts/ci/security/lib.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/security/lib.sh)
- Security allowlists and suppressions: [infra/security](/Users/patrickkelly/Documents/CyberArmorAi/infra/security)

## What The Pipeline Does

### PR / CI Gate

- `gitleaks` workspace secret scan
- `trufflehog` diff-oriented verified secret scan
- tuned `Semgrep`
- `Bandit`
- `pip-audit` across Python manifests
- `npm audit` only for touched extension workspaces
- optional `Docker Scout` image scanning when `RUN_DOCKER_SCOUT_PR=true`

### Scheduled Sweep

- broader `Semgrep`
- full `pip-audit`
- full `npm audit`
- `OWASP Dependency-Check`
- `Docker Scout`
- `Prowler`
- `ZAP` baseline scan when `ZAP_TARGET_URL` is set

### Local OpenBao Integration Verifier

- starts the local OpenBao + secrets-service + AI Router stack with Docker Compose
- bootstraps OpenBao mounts and transit keys
- verifies secrets-service can write/read provider credentials
- verifies AI Router persists provider credentials through the secrets service path
- verifies PQC key state is initialized through the secrets service and not written to local disk
- writes a single text report plus compose diagnostics on failure

## Jenkins Container

Bring up Jenkins:

```bash
cd infra/jenkins
docker compose -f docker-compose.security.yml up -d --build
```

Or use the one-command helper:

```bash
bash scripts/ci/start_jenkins_security.sh
```

Jenkins will be available on `http://localhost:8088`.

The Jenkins container expects access to the host Docker socket:

- `/var/run/docker.sock:/var/run/docker.sock`

That is what allows containerized scanners, docker builds, Docker Scout, and ZAP to run from inside Jenkins.

## Pipeline Parameters

- `SCAN_PROFILE`
  - `pr`: blocking PR/CI gate
  - `integration`: local OpenBao regression verifier
  - `scheduled`: broader periodic security sweep
- `RUN_DOCKER_SCOUT_PR`
  - set `true` when you want PR runs to build and scan local images
- `DEFAULT_BRANCH`
  - base branch for diff-oriented checks, usually `main`
- `SCOUT_BUILD_SERVICES`
  - comma-separated docker compose service list to build and scan
- `ZAP_TARGET_URL`
  - target URL for scheduled baseline DAST
- `PROWLER_PROVIDER`
  - provider/module passed to Prowler, default `aws`
- `PROWLER_ARGS`
  - extra arguments passed directly to Prowler
- `OPENBAO_COMPOSE_PROJECT`
  - compose project name for the local OpenBao integration job

## Recommended Jenkins Jobs

### `cyberarmor-security-pr`

- multibranch or PR-triggered
- uses `Jenkinsfile.security`
- `SCAN_PROFILE=pr`
- `RUN_DOCKER_SCOUT_PR=false` initially

### `cyberarmor-security-scheduled`

- scheduled nightly or a few times per week
- uses `Jenkinsfile.security`
- `SCAN_PROFILE=scheduled`
- `ZAP_TARGET_URL` set to a stable internal test or staging URL
- cloud credentials injected for `Prowler`

### `cyberarmor-openbao-integration`

- on-demand or PR-triggered for changes touching secrets, auth, AI Router, or docker-compose wiring
- uses `Jenkinsfile.security`
- `SCAN_PROFILE=integration`
- Docker socket mounted into Jenkins, same as the security jobs
- optional branch protection gate once the path is stable for a few runs

## Credentials / Environment

The scheduled Prowler stage expects cloud credentials to be available in Jenkins, typically as environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_DEFAULT_REGION`

If you use another cloud/provider mode, set `PROWLER_PROVIDER` and `PROWLER_ARGS` accordingly.

## Reports

All outputs are written under:

```text
reports/security/
```

Jenkins archives that directory at the end of every run.

The OpenBao integration job writes:

- `reports/security/openbao-integration.txt`

## Baselines, Allowlists, And Suppressions

The repo now includes scanner-native files under [infra/security](/Users/patrickkelly/Documents/CyberArmorAi/infra/security):

- `gitleaks.toml`
  - primary allowlist for known fake/demo tokens and generated paths
- `trufflehog-exclude-paths.txt`
  - path regex exclusions for TruffleHog
- `.semgrepignore`
  - repo-local ignore list for Semgrep
- `bandit-baseline.json`
  - Bandit baseline file for accepted findings after triage
- `pip-audit-ignore.txt`
  - one vulnerability ID per line for accepted Python dependency findings
- `dependency-check-suppressions.xml`
  - OWASP Dependency-Check suppressions
- `zap-baseline.conf`
  - ZAP baseline rule tuning and ignores
- `prowler-exclude-checks.txt`
  - one Prowler check ID per line for accepted cloud posture exceptions

Recommended workflow:

1. Run the scanner without suppressions or with only path/demo allowlists.
2. Triage findings into:
   - fix now
   - suppress with justification
   - accept temporarily with owner/date
3. Record accepted exceptions in the matching file under `infra/security`.
4. Re-run the pipeline and make sure only the intended findings disappear.

## Severity Thresholds

Current default thresholds are defined in [scripts/ci/security/lib.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/security/lib.sh):

- `Semgrep` PR gate:
  - `SEMGREP_PR_FAIL_SEVERITIES=ERROR`
- `Semgrep` scheduled:
  - `SEMGREP_SCHEDULED_FAIL_SEVERITIES=ERROR,WARNING`
- `Bandit` PR gate:
  - high severity and high confidence only via `-lll -ii`
- `pip-audit`:
  - fails on any unsuppressed finding
  - note: unlike some other tools, severity handling is not as consistent across Python advisories
- `npm audit`:
  - `NPM_AUDIT_FAIL_LEVEL=high`
- `Docker Scout` PR:
  - `DOCKER_SCOUT_PR_SEVERITIES=critical,high`
- `Docker Scout` scheduled:
  - `DOCKER_SCOUT_SCHEDULED_SEVERITIES=critical,high`

These can all be overridden through Jenkins environment variables or job configuration.

## Tuning Notes

- `Semgrep` config sets are controlled by environment variables in [scripts/ci/security/lib.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/ci/security/lib.sh)
- `npm audit` is intentionally limited to touched extension workspaces in PR mode to reduce noise and time
- `Docker Scout` is optional in PR mode because image builds can be expensive
- `ZAP` is scheduled-only by default because passive DAST is more valuable once a stable deployed surface exists
- `gitleaks` and `TruffleHog` are intentionally strict in PR mode. Keep their allowlists narrow and documented.
- `Bandit` baseline should be treated as temporary debt, not a permanent dump for findings.
- `npm audit` currently uses severity gating rather than a custom allowlist file. If you need package-level exceptions later, the next step would be `audit-ci` or a custom advisory suppression layer.

## Next Improvements

- add SARIF publishing into your preferred dashboard
- add owner/date metadata conventions inside suppression files
- add package-level npm exception handling if audit noise becomes material
- split scheduled sweeps into informational vs paging jobs
