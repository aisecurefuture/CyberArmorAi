#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "== Credential redaction demo =="
echo "Scope: local AI-aware policy engine redaction for AI-bound prompt and response text"
echo

PYTHONPATH="$ROOT_DIR/services/policy" python3 - <<'PY'
from ai_policy_engine import AIRequestContext, AIAwarePolicyEngine, DecisionType

openai_key = "sk-" + ("A" * 48)
github_token = "ghp_" + ("B" * 36)

ctx = AIRequestContext(
    tenant_id="demo-credential-redaction",
    agent_id="demo-appsec-agent",
    provider="openai",
    model="gpt-4o-mini",
    prompt=(
        "Please summarize this incident. The pasted log includes "
        "AWS key AKIA1234567890ABCDEF, GitHub token "
        f"{github_token}, and api_key=abcd1234efgh5678ijkl."
    ),
    response_text=(
        "Suggested retry command: export OPENAI_API_KEY="
        f"{openai_key} and password=hunter22 before running the tool."
    ),
)

decision = AIAwarePolicyEngine().evaluate(ctx)
labels = [finding.get("label") for finding in decision.dlp_findings]

print(f"decision: {decision.decision.value}")
print(f"risk_score: {decision.risk_score}")
print(f"dlp_findings: {', '.join(labels)}")
print()
print("redacted prompt:")
print(decision.redacted_prompt)
print()
print("redacted response:")
print(decision.redacted_response)

required = [
    "[REDACTED-AWS-KEY]",
    "[REDACTED-GITHUB-TOKEN]",
    "[REDACTED-APIKEY]",
    "[REDACTED-OPENAI-KEY]",
    "[REDACTED-PASSWORD]",
]
combined = f"{decision.redacted_prompt or ''}\n{decision.redacted_response or ''}"
if decision.decision != DecisionType.ALLOW_WITH_REDACTION:
    raise SystemExit(f"expected ALLOW_WITH_REDACTION, got {decision.decision.value}")
missing = [token for token in required if token not in combined]
if missing:
    raise SystemExit(f"missing redaction placeholders: {', '.join(missing)}")
for raw in ["AKIA1234567890ABCDEF", github_token, openai_key, "hunter22"]:
    if raw in combined:
        raise SystemExit("raw credential remained in redacted output")
PY

echo
echo "Verified: credential-bearing AI text returns ALLOW_WITH_REDACTION and redacted output."
echo "Related service demo: bash scripts/demo/run_proxy_controls_demo.sh"
echo "Related portal flow: Customer Portal > DLP & Data Class. and Policy Studio"
