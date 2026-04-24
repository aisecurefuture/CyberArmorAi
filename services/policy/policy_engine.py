"""Extensible Policy Evaluation Engine with OPA backend.

Evaluation backends (tried in order):
  1. OPA  – calls the running OPA sidecar via ``opa_client.evaluate()``.
            OPA evaluates ``cyberarmor/policy/matches`` using the base Rego
            module, which receives the full tenant policy list as JSON input.
            Returns the list of matching policies sorted by priority.
  2. Python – fallback recursive AND/OR/NOT engine (always available).

The Python engine is authoritative when OPA is disabled or unreachable; no
functionality is lost, but OPA adds proper policy-as-code auditability and
the ability to load hand-authored Rego policies via ``POST /policies/import``.

Condition Schema (JSON, unchanged from v0.2):
{
    "operator": "AND" | "OR" | "NOT",
    "rules": [
        {"field": "request.url", "operator": "matches", "value": "*.openai.com/*"},
        {
            "operator": "OR",
            "rules": [
                {"field": "content.has_pii", "operator": "equals", "value": true},
                {"field": "content.classification", "operator": "in",
                 "value": ["confidential"]}
            ]
        }
    ]
}
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import opa_client  # local module

logger = logging.getLogger("policy.engine")

OPA_ENABLED = os.getenv("OPA_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}

# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------


@dataclass
class PolicyEvalResult:
    """Result of evaluating a single policy against a context."""

    matched: bool
    policy_id: str
    policy_name: str
    action: str          # monitor | block | warn | allow
    reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)


@dataclass
class EvaluationContext:
    """Context object passed through policy evaluation.

    Fields are accessed via dot notation in policy conditions:
        "request.url"        → context.request["url"]
        "content.has_pii"    → context.content["has_pii"]
        "user.department"    → context.user["department"]
    """

    request: Dict[str, Any] = field(default_factory=dict)
    content: Dict[str, Any] = field(default_factory=dict)
    user: Dict[str, Any] = field(default_factory=dict)
    endpoint: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten to a single dict with dot-notation keys for rule evaluation."""
        result: Dict[str, Any] = {}
        for prefix, section in [
            ("request",  self.request),
            ("content",  self.content),
            ("user",     self.user),
            ("endpoint", self.endpoint),
            ("metadata", self.metadata),
        ]:
            if isinstance(section, dict):
                for k, v in section.items():
                    result[f"{prefix}.{k}"] = v
        return result


# ---------------------------------------------------------------------------
# OPA evaluation backend
# ---------------------------------------------------------------------------


class OPABackend:
    """Evaluates policies by forwarding the full policy list + context to OPA.

    OPA runs the ``cyberarmor/policy/matches`` rule from the base Rego module
    and returns all matching policies sorted by priority (ascending).
    """

    _RULE_PATH = "cyberarmor/policy/matches"

    def evaluate(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[List[PolicyEvalResult]]:
        """Return sorted matching results from OPA, or None if OPA is unavailable."""
        if not OPA_ENABLED or not opa_client.is_available():
            return None

        input_data = {
            "policies": policies,
            "context": context.to_flat_dict(),
        }
        try:
            raw = opa_client.evaluate(self._RULE_PATH, input_data)
        except Exception as exc:
            logger.warning("OPA evaluation failed: %s", exc)
            return None

        if raw is None:
            return None

        # raw is the value of the ``matches`` rule – a list of match objects
        if not isinstance(raw, list):
            logger.warning("OPA returned unexpected type for matches: %s", type(raw))
            return None

        results: List[PolicyEvalResult] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            results.append(
                PolicyEvalResult(
                    matched=True,
                    policy_id=str(item.get("policy_id", "")),
                    policy_name=str(item.get("policy_name", "")),
                    action=str(item.get("action", "monitor")),
                    reason="opa_match",
                    matched_rules=[],
                    compliance_frameworks=list(
                        item.get("compliance_frameworks") or []
                    ),
                )
            )

        # OPA's base module already sorts by priority; re-sort here for safety
        results.sort(key=lambda r: next(
            (p.get("priority", 100) for p in policies if p.get("id") == r.policy_id),
            100,
        ))
        return results

    def evaluate_first_match(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[PolicyEvalResult]:
        results = self.evaluate(policies, context)
        if results is None:
            return None  # OPA unavailable – signal fallback needed
        return results[0] if results else None


# ---------------------------------------------------------------------------
# Python evaluation backend  (always-available fallback)
# ---------------------------------------------------------------------------


class PythonPolicyEngine:
    """Pure-Python recursive AND/OR/NOT condition evaluator.

    This is the original PolicyEngine implementation, kept as a complete
    fallback that requires no external dependencies.
    """

    def evaluate(
        self, policies: List[dict], context: EvaluationContext
    ) -> List[PolicyEvalResult]:
        flat = context.to_flat_dict()
        results: List[PolicyEvalResult] = []
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 100))

        for policy in sorted_policies:
            if not policy.get("enabled", True):
                continue

            conditions = policy.get("conditions")
            matched = False
            matched_rules: List[str] = []

            if conditions:
                matched, matched_rules = self._evaluate_condition_group(
                    conditions, flat
                )
            else:
                rules = policy.get("rules", {})
                if rules:
                    matched = self._evaluate_legacy_rules(rules, flat)
                else:
                    matched = True

            if matched:
                results.append(
                    PolicyEvalResult(
                        matched=True,
                        policy_id=policy.get("id", ""),
                        policy_name=policy.get("name", ""),
                        action=policy.get("action", "monitor"),
                        reason=f"Matched {len(matched_rules)} rule(s)",
                        matched_rules=matched_rules,
                        compliance_frameworks=policy.get("compliance_frameworks") or [],
                    )
                )

        return results

    def evaluate_first_match(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[PolicyEvalResult]:
        results = self.evaluate(policies, context)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _evaluate_condition_group(
        self, conditions: dict, flat_context: dict
    ) -> tuple[bool, list[str]]:
        operator = str(conditions.get("operator", "AND")).upper()
        rules = conditions.get("rules", [])

        if not rules:
            return True, []

        all_matched_rules: List[str] = []
        results: List[bool] = []

        for rule in rules:
            if "rules" in rule:
                matched, sub_rules = self._evaluate_condition_group(rule, flat_context)
                results.append(matched)
                if matched:
                    all_matched_rules.extend(sub_rules)
            else:
                matched = self._evaluate_leaf_rule(rule, flat_context)
                results.append(matched)
                if matched:
                    all_matched_rules.append(
                        f"{rule.get('field', '?')} "
                        f"{rule.get('operator', '?')} "
                        f"{rule.get('value', '?')}"
                    )

        if operator == "AND":
            group_matched = all(results)
        elif operator == "OR":
            group_matched = any(results)
        elif operator == "NOT":
            group_matched = not any(results)
        else:
            group_matched = all(results)

        return group_matched, all_matched_rules if group_matched else []

    def _evaluate_leaf_rule(self, rule: dict, flat_context: dict) -> bool:
        field_path = rule.get("field", "")
        operator = rule.get("operator", "equals")
        expected = rule.get("value")
        actual = flat_context.get(field_path)
        return self._compare(actual, operator, expected)

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        try:
            if operator == "equals":
                return actual == expected
            elif operator == "not_equals":
                return actual != expected
            elif operator == "contains":
                return str(expected) in str(actual) if actual is not None else False
            elif operator == "not_contains":
                return str(expected) not in str(actual) if actual is not None else True
            elif operator == "starts_with":
                return str(actual or "").startswith(str(expected))
            elif operator == "ends_with":
                return str(actual or "").endswith(str(expected))
            elif operator == "matches":
                return fnmatch.fnmatch(str(actual or ""), str(expected))
            elif operator == "regex":
                return bool(re.search(str(expected), str(actual or "")))
            elif operator == "in":
                return actual in expected if isinstance(expected, list) else actual == expected
            elif operator == "not_in":
                return actual not in expected if isinstance(expected, list) else actual != expected
            elif operator == "greater_than":
                return float(actual) > float(expected)
            elif operator == "less_than":
                return float(actual) < float(expected)
            elif operator == "greater_than_or_equals":
                return float(actual) >= float(expected)
            elif operator == "less_than_or_equals":
                return float(actual) <= float(expected)
            elif operator == "exists":
                return actual is not None
            elif operator == "not_exists":
                return actual is None
            elif operator == "is_empty":
                return actual is None or actual == "" or actual == []
            elif operator == "is_not_empty":
                return actual is not None and actual != "" and actual != []
        except (TypeError, ValueError):
            return False
        return False

    def _evaluate_legacy_rules(self, rules: dict, flat_context: dict) -> bool:
        url = flat_context.get("request.url", "")
        blocked_hosts = rules.get("block_hosts", [])
        for host in blocked_hosts:
            if host in url:
                return True
        allowed_hosts = rules.get("allow_hosts", [])
        if allowed_hosts:
            for host in allowed_hosts:
                if host in url:
                    return False
            return True
        return False


# ---------------------------------------------------------------------------
# Unified facade  (OPA with Python fallback)
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Unified policy evaluation facade.

    Tries OPA first; falls back to the Python engine if OPA is disabled,
    unreachable, or returns None.
    """

    def __init__(self) -> None:
        self._opa = OPABackend()
        self._python = PythonPolicyEngine()

    def evaluate(
        self, policies: List[dict], context: EvaluationContext
    ) -> List[PolicyEvalResult]:
        # OPA path
        if OPA_ENABLED:
            opa_results = self._opa.evaluate(policies, context)
            if opa_results is not None:
                return opa_results
        # Python fallback
        return self._python.evaluate(policies, context)

    def evaluate_first_match(
        self, policies: List[dict], context: EvaluationContext
    ) -> Optional[PolicyEvalResult]:
        # OPA path
        if OPA_ENABLED:
            result = self._opa.evaluate_first_match(policies, context)
            if result is not None:
                return result
            # result == None means OPA unavailable; fall through
        # Python fallback
        return self._python.evaluate_first_match(policies, context)


# ---------------------------------------------------------------------------
# Artifact reference resolution
# ---------------------------------------------------------------------------


_ARTIFACT_PREFIX = "$artifact:"


def _artifact_ref(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.startswith(_ARTIFACT_PREFIX):
        return value[len(_ARTIFACT_PREFIX):].strip()
    return None


def _resolve_value(value: Any, operator: str, artifacts: Dict[str, Any]) -> tuple[Any, str]:
    """Resolve $artifact:<name> references in a rule value.

    Returns (resolved_value, effective_operator). The operator is overridden
    to ``regex`` when the referenced artifact is of kind ``regex``.
    """
    name = _artifact_ref(value)
    if name:
        art = artifacts.get(name) or {}
        kind = art.get("kind")
        items = list(art.get("items") or [])
        if kind == "regex":
            joined = "|".join(f"(?:{p})" for p in items) if items else "(?!)"
            return joined, "regex"
        return items, operator
    if isinstance(value, list):
        expanded: List[Any] = []
        for item in value:
            ref = _artifact_ref(item)
            if ref:
                expanded.extend((artifacts.get(ref) or {}).get("items") or [])
            else:
                expanded.append(item)
        return expanded, operator
    return value, operator


def resolve_artifact_references(
    conditions: Optional[Dict[str, Any]],
    artifacts: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Return a deep-copied condition tree with $artifact: references resolved.

    The original input is not mutated. If ``artifacts`` is empty or no
    reference is found, a structural copy is still returned for safety.
    """
    if not conditions:
        return conditions

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            # Condition group: {operator, rules: [...]}
            if "rules" in node and isinstance(node["rules"], list):
                return {**{k: v for k, v in node.items() if k != "rules"},
                        "rules": [walk(r) for r in node["rules"]]}
            # Leaf rule: {field, operator, value}
            if "field" in node or "value" in node:
                value = node.get("value")
                op = node.get("operator", "equals")
                resolved_value, effective_op = _resolve_value(value, op, artifacts)
                out = dict(node)
                out["value"] = resolved_value
                out["operator"] = effective_op
                return out
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(conditions)


# Singleton instance (consumed by main.py via ``from policy_engine import engine``)
engine = PolicyEngine()
