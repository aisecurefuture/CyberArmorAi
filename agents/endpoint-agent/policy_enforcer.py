"""Local Policy Enforcement Engine for CyberArmor Endpoint Agent.

Receives policies from control plane, evaluates events against AND/OR
conditions, and takes action (monitor, warn, redact, block). Caches
policies locally in SQLite for offline operation.

Redact support (Path B Step 2c)
-------------------------------
When a matching policy has ``action="redact"``, the enforcer surfaces
the policy's ``redact_classes`` list on the resulting PolicyAction.
Monitors that handle text payloads (clipboard, file watcher, telemetry
emit paths) can call ``PolicyEnforcer.redact_text(text, classes)`` to
mask matched DLP classes locally before forwarding upstream — keeping
secrets off the wire even when the agent is offline from detection.

The local regex catalog mirrors ``services/detection/main.py``'s
``_REDACT_CLASS_MAP``. Keep them in sync when adding/removing classes.
"""

import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from crypto.pqc import PQCKeyTransport

logger = logging.getLogger("policy_enforcer")


# ---------------------------------------------------------------------------
# Local DLP regex catalog. Mirrors services/detection/main.py REDACT_CLASS_MAP
# so the agent can redact offline without an HTTP round-trip to detection.
# Each tuple is (compiled_pattern, capture_group_or_None_for_whole_match).
# ---------------------------------------------------------------------------

_REDACT_PATTERNS: Dict[str, List[Tuple[re.Pattern, Optional[int]]]] = {
    "pii.email":             [(re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b"), None)],
    "pii.phone":             [(re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"), None)],
    "pii.iban":              [(re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), None)],
    "pii.ssn":               [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
        (re.compile(r"\b(?:ssn|social\s+security(?:\s+number)?|taxpayer\s+id)\b[\s:#=-]{0,12}(\d{9})\b", re.IGNORECASE), 1),
        (re.compile(r"\b(\d{9})\b[\s:#=-]{0,12}(?:ssn|social\s+security(?:\s+number)?|taxpayer\s+id)\b", re.IGNORECASE), 1),
    ],
    "pii.credit_card":       [(re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), None)],
    "secret.aws_access_key": [(re.compile(r"AKIA[0-9A-Z]{16}"), None)],
    "secret.gcp_api_key":    [(re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), None)],
    "secret.github_token":   [(re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"), None)],
    "secret.openai_key":     [(re.compile(r"\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})\b"), None)],
    "secret.anthropic_key":  [(re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{60,}\b"), None)],
    "secret.slack_token":    [(re.compile(r"\bxox[bpoa]-[0-9A-Za-z\-]{10,}\b"), None)],
    "secret.stripe_key":     [(re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), None)],
    "secret.api_key":        [
        (re.compile(r"\b(?:[A-Za-z0-9]+_)*(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.IGNORECASE), 1),
        (re.compile(r"\b(?:sk|api|token)[_\-][A-Za-z0-9]{12,}\b", re.IGNORECASE), None),
    ],
    "secret.password":       [(re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE), 1)],
    "secret.private_key":    [(re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), None)],
    "secret.jwt":            [(re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), None)],
}

REDACT_CLASS_CATALOG: List[str] = sorted(_REDACT_PATTERNS.keys())

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8000")
POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://localhost:8001")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
TENANT_ID = os.getenv("TENANT_ID", "demo")
SYNC_INTERVAL_S = int(os.getenv("POLICY_SYNC_INTERVAL", "60"))
CACHE_DIR = Path(os.getenv("CYBERARMOR_CACHE_DIR", os.path.expanduser("~/.cyberarmor")))


@dataclass
class PolicyAction:
    action: str  # allow | monitor | warn | redact | block
    policy_name: str
    policy_id: str
    reason: str
    matched_rules: List[str] = field(default_factory=list)
    # Path B (Step 2c): when action=="redact", the DLP class names this
    # policy wants masked. Empty list means "fall back to scanner default
    # detections" — handled by the caller; the enforcer just surfaces
    # what the policy declared.
    redact_classes: List[str] = field(default_factory=list)


@dataclass
class EnforcementResult:
    allowed: bool
    actions: List[PolicyAction] = field(default_factory=list)
    highest_action: str = "allow"
    # Convenience: union of redact_classes from every matching redact
    # policy. Monitors that handle text payloads can pass this directly
    # to PolicyEnforcer.redact_text(text, classes).
    redact_classes: List[str] = field(default_factory=list)


class PolicyEnforcer:
    """Evaluates events against cached policies with AND/OR conditions."""

    # Singleton instance -- created on first get_or_create() call
    _instance: Optional["PolicyEnforcer"] = None

    @classmethod
    def instance(cls) -> Optional["PolicyEnforcer"]:
        """Return the singleton instance, or None if not yet created."""
        return cls._instance

    @classmethod
    def get_or_create(cls) -> "PolicyEnforcer":
        """Return the singleton instance, creating it on first call."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.policies: List[dict] = []
        self.db_path = CACHE_DIR / "policy_cache.db"
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._load_cached_policies()

    def update_policies(self, policies: List[dict]) -> None:
        """Replace the active policy set and persist to SQLite cache."""
        self._cache_policies(policies)
        self.policies = policies
        logger.info("PolicyEnforcer updated: %d policies active", len(policies))

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY, name TEXT, tenant_id TEXT,
                enabled INTEGER, action TEXT, priority INTEGER,
                conditions TEXT, rules TEXT, version TEXT,
                updated_at TEXT
            )
        """)
        # Path B (Step 2c): add redact_classes column on existing DBs.
        # SQLite's ALTER TABLE ... ADD COLUMN is idempotent via try/except.
        try:
            conn.execute("ALTER TABLE policies ADD COLUMN redact_classes TEXT")
        except sqlite3.OperationalError:
            pass  # already exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, event_type TEXT, policy_id TEXT,
                policy_name TEXT, action_taken TEXT, details TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _load_cached_policies(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            rows = conn.execute(
                "SELECT id, name, tenant_id, enabled, action, priority, conditions, rules, version, redact_classes FROM policies WHERE tenant_id=?",
                (TENANT_ID,)
            ).fetchall()
            self.policies = []
            for r in rows:
                self.policies.append({
                    "id": r[0], "name": r[1], "tenant_id": r[2],
                    "enabled": bool(r[3]), "action": r[4], "priority": r[5],
                    "conditions": json.loads(r[6]) if r[6] else None,
                    "rules": json.loads(r[7]) if r[7] else {},
                    "version": r[8],
                    "redact_classes": json.loads(r[9]) if r[9] else [],
                })
            conn.close()
            logger.info("Loaded %d cached policies", len(self.policies))
        except Exception as e:
            logger.warning("Failed to load cached policies: %s", e)

    async def sync_policies(self):
        """Fetch policies from control plane and cache locally."""
        headers = {"x-api-key": AGENT_API_KEY}
        if str(os.getenv("CYBERARMOR_PQC_AUTH_ENABLED", "false")).strip().lower() in {"1", "true", "yes", "on"}:
            try:
                async with httpx.AsyncClient(timeout=5.0) as bootstrap_client:
                    pk_resp = await bootstrap_client.get(f"{POLICY_SERVICE_URL.rstrip('/')}/pki/public-key")
                    pk_resp.raise_for_status()
                    public_key_hex = str(pk_resp.json().get("kem_public_key") or "")
                    if public_key_hex:
                        headers["x-api-key"] = PQCKeyTransport().encrypt_header(
                            AGENT_API_KEY,
                            bytes.fromhex(public_key_hex),
                        )
            except Exception:
                if str(os.getenv("CYBERARMOR_PQC_OUTBOUND_STRICT", "false")).strip().lower() in {"1", "true", "yes", "on"}:
                    raise
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{POLICY_SERVICE_URL}/policies/{TENANT_ID}/export",
                    headers=headers,
                )
                if resp.status_code == 200:
                    policies = resp.json()
                    self._cache_policies(policies)
                    self.policies = policies
                    logger.info("Synced %d policies from control plane", len(policies))
                else:
                    logger.warning("Policy sync failed: %s", resp.status_code)
        except Exception as e:
            logger.warning("Policy sync error: %s", e)

    def _cache_policies(self, policies: List[dict]):
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute("DELETE FROM policies WHERE tenant_id=?", (TENANT_ID,))
            for p in policies:
                conn.execute(
                    "INSERT OR REPLACE INTO policies (id,name,tenant_id,enabled,action,priority,conditions,rules,version,updated_at,redact_classes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (p["id"], p["name"], TENANT_ID, int(p.get("enabled", True)),
                     p.get("action", "monitor"), p.get("priority", 100),
                     json.dumps(p.get("conditions")), json.dumps(p.get("rules", {})),
                     p.get("version", ""), datetime.now(timezone.utc).isoformat(),
                     json.dumps(p.get("redact_classes") or [])),
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to cache policies: %s", e)

    def evaluate(self, context: Dict[str, Any]) -> EnforcementResult:
        """Evaluate an event context against all enabled policies."""
        actions = []
        enabled = sorted(
            [p for p in self.policies if p.get("enabled", True)],
            key=lambda p: p.get("priority", 100)
        )
        flat = self._flatten_context(context)

        for policy in enabled:
            conditions = policy.get("conditions")
            matched = False
            matched_rules = []

            if conditions:
                matched, matched_rules = self._eval_group(conditions, flat)
            elif policy.get("rules"):
                matched = self._eval_legacy(policy["rules"], flat)

            if matched:
                pa = PolicyAction(
                    action=policy.get("action", "monitor"),
                    policy_name=policy.get("name", ""),
                    policy_id=policy.get("id", ""),
                    reason=f"Matched {len(matched_rules)} rule(s)",
                    matched_rules=matched_rules,
                    redact_classes=list(policy.get("redact_classes") or []),
                )
                actions.append(pa)
                self._audit_log(pa, context)

        # Path B (Step 2c): redact slots between block and warn — it's not
        # as restrictive as block (request still goes through) but it's a
        # stronger intervention than warn (content is modified, not just
        # tagged). Highest-action precedence: block > redact > warn > monitor > allow.
        highest = "allow"
        if any(a.action == "block" for a in actions):
            highest = "block"
        elif any(a.action == "redact" for a in actions):
            highest = "redact"
        elif any(a.action == "warn" for a in actions):
            highest = "warn"
        elif any(a.action == "monitor" for a in actions):
            highest = "monitor"

        # Union the redact_classes from every matching redact policy so
        # callers get a single list to apply via redact_text().
        union_classes: List[str] = []
        seen = set()
        for a in actions:
            if a.action == "redact":
                for c in a.redact_classes:
                    if c not in seen:
                        seen.add(c)
                        union_classes.append(c)

        return EnforcementResult(
            allowed=highest != "block",
            actions=actions,
            highest_action=highest,
            redact_classes=union_classes,
        )

    # ---------------- Path B (Step 2c) — local redaction helpers ----------

    @staticmethod
    def redact_text(text: str, classes: List[str]) -> Tuple[str, Dict[str, int]]:
        """Mask matches of the requested DLP classes in `text`.

        Mirrors services/detection/main.py `_redact_text`. Returns
        (redacted_text, class_counts). class_counts has per-class match
        counts only — never the matched values themselves, so it's safe
        to log/forward in telemetry.

        Used by monitors that handle text payloads (clipboard, file
        watcher, telemetry emit paths) when EnforcementResult.highest_action
        is ``"redact"``. Pass ``result.redact_classes`` directly:

            res = enforcer.evaluate(ctx)
            if res.highest_action == "redact":
                safe_text, counts = enforcer.redact_text(text, res.redact_classes)
                # forward safe_text in telemetry; log counts for audit
        """
        if not text or not classes:
            return text or "", {}

        spans: List[Tuple[int, int, str]] = []
        for cls in classes:
            for pattern, group in _REDACT_PATTERNS.get(cls, []):
                for m in pattern.finditer(text):
                    if group is not None and m.group(group):
                        s, e = m.span(group)
                    else:
                        s, e = m.span()
                    if s == e:
                        continue
                    spans.append((s, e, cls))

        if not spans:
            return text, {}

        # Sort by start, drop overlaps (keep first), replace right-to-left.
        spans.sort(key=lambda x: (x[0], -x[1]))
        deduped: List[Tuple[int, int, str]] = []
        last_end = -1
        for s, e, cls in spans:
            if s < last_end:
                continue
            deduped.append((s, e, cls))
            last_end = e

        deduped.sort(key=lambda x: x[0], reverse=True)
        out = text
        counts: Dict[str, int] = {}
        for s, e, cls in deduped:
            out = out[:s] + f"[REDACTED:{cls}]" + out[e:]
            counts[cls] = counts.get(cls, 0) + 1
        return out, counts

    def evaluate_and_redact(
        self, context: Dict[str, Any], text: str
    ) -> Tuple[EnforcementResult, str, Dict[str, int]]:
        """Evaluate context, then if action is ``"redact"`` apply masking
        to ``text`` using the policy's redact_classes.

        Convenience wrapper for monitors that already have the text payload
        in hand. Returns (result, possibly_redacted_text, class_counts).
        When highest_action != "redact" the text is returned unchanged and
        class_counts is empty.
        """
        res = self.evaluate(context)
        if res.highest_action == "redact" and res.redact_classes:
            redacted, counts = self.redact_text(text, res.redact_classes)
            return res, redacted, counts
        return res, text, {}

    def _eval_group(self, cond: dict, flat: dict) -> tuple:
        op = cond.get("operator", "AND").upper()
        rules = cond.get("rules", [])
        if not rules:
            return True, []
        results, all_matched = [], []
        for rule in rules:
            if "rules" in rule:
                m, mr = self._eval_group(rule, flat)
                results.append(m)
                if m:
                    all_matched.extend(mr)
            else:
                m = self._eval_leaf(rule, flat)
                results.append(m)
                if m:
                    all_matched.append(f"{rule.get('field','?')} {rule.get('operator','?')} {rule.get('value','?')}")
        group_match = all(results) if op == "AND" else any(results)
        return group_match, all_matched if group_match else []

    def _eval_leaf(self, rule: dict, flat: dict) -> bool:
        actual = flat.get(rule.get("field", ""))
        expected = rule.get("value")
        op = rule.get("operator", "equals")
        try:
            if op == "equals": return actual == expected
            if op == "not_equals": return actual != expected
            if op == "contains": return str(expected) in str(actual or "")
            if op == "not_contains": return str(expected) not in str(actual or "")
            if op == "matches":
                import fnmatch
                return fnmatch.fnmatch(str(actual or ""), str(expected))
            if op == "in": return actual in (expected if isinstance(expected, list) else [expected])
            if op == "exists": return actual is not None
            if op == "regex":
                import re
                return bool(re.search(str(expected), str(actual or "")))
        except Exception:
            return False
        return False

    def _eval_legacy(self, rules: dict, flat: dict) -> bool:
        url = flat.get("request.url", "")
        for host in rules.get("block_hosts", []):
            if host in str(url):
                return True
        return False

    def _flatten_context(self, ctx: dict) -> dict:
        flat = {}
        for prefix, section in ctx.items():
            if isinstance(section, dict):
                for k, v in section.items():
                    flat[f"{prefix}.{k}"] = v
            else:
                flat[prefix] = section
        return flat

    def _audit_log(self, action: PolicyAction, context: dict):
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "INSERT INTO audit_log (timestamp, event_type, policy_id, policy_name, action_taken, details) VALUES (?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), "policy_match",
                 action.policy_id, action.policy_name, action.action,
                 json.dumps({"reason": action.reason, "rules": action.matched_rules})),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("Audit log write failed: %s", e)
