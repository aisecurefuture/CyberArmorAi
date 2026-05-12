#!/usr/bin/env python3
"""CyberArmor clipboard helper.

Runs as a per-user macOS LaunchAgent so it can actually read the user's
pasteboard (LaunchDaemons in the system bootstrap domain cannot). Polls
the pasteboard, detects PII / secrets, and reports findings to the
control plane as telemetry. Optionally redacts the clipboard in place
when policy.action == "redact" / clears it when "block".

Reads config from ~/.config/cyberarmor/helper.json which the install
script provisions from the system agent's /etc/cyberarmor/agent.json so
the helper inherits the same tenant and credentials.
"""

from __future__ import annotations

import os
import sys

# /usr/local/cyberarmor contains a "platform/" sub-package that the endpoint
# agent uses for OS-specific code. Python automatically prepends the script
# directory to sys.path, which shadows the stdlib `platform` module. pyperclip
# lazily imports `platform.system()`; without this scrub it explodes with
# AttributeError("module 'platform' has no attribute 'system'") on first
# pyperclip.paste(). Must happen before any 3rd-party import that touches
# the stdlib platform module.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p) != _SCRIPT_DIR]

import getpass
import json
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import pyperclip  # type: ignore[import-untyped]
except ImportError:
    print("pyperclip not installed in this Python; clipboard helper exiting", flush=True)
    sys.exit(2)

# Replace argv[0] so `ps` and macOS background-activity notifications show
# a friendly name instead of "python3". The launcher wrapper covers the
# OS-level display name; this covers process listings.
try:
    import setproctitle  # type: ignore[import-untyped]
    setproctitle.setproctitle("cyberarmor-clipboard-helper")
except ImportError:
    pass


# Keep in sync with extensions/chromium-shared/content.js PII_PATTERNS and
# agents/endpoint-agent/dlp catalogues. Categories use the same "pii."/
# "secret." prefix so policy.redact_classes lookups work uniformly.
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)),
    ("phone", re.compile(r"\b\d{10}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Za-z0-9]{4}\d{14}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    ("api_key", re.compile(r"\b(?:sk-|pk_|api[_-]?key)[A-Za-z0-9]{16,}\b", re.IGNORECASE)),
]


def detect_pii(text: str) -> list[str]:
    return [label for label, pat in PII_PATTERNS if pat.search(text)]


def redact_text(text: str, allowed: set[str]) -> tuple[str, bool]:
    """Return (redacted_text, changed). If allowed is empty, redact every label."""
    allow_all = not allowed
    out = text
    changed = False
    for label, pat in PII_PATTERNS:
        if not (allow_all or f"pii.{label}" in allowed or f"secret.{label}" in allowed):
            continue
        new_out = pat.sub(f"[REDACTED-{label}]", out)
        if new_out != out:
            out = new_out
            changed = True
    return out, changed


def load_config() -> dict:
    config_path = Path.home() / ".config" / "cyberarmor" / "helper.json"
    if not config_path.exists():
        sys.exit(f"helper.json missing at {config_path}. Run install_clipboard_helper.sh first.")
    return json.loads(config_path.read_text())


def notify(title: str, message: str) -> None:
    """Show a macOS Notification Center banner. Best-effort, non-blocking.

    AppleScript single-quotes are tricky — we escape any double quotes in
    the strings and wrap the whole thing in a single -e arg. osascript is
    in the default macOS PATH; the call returns quickly so we don't need
    to background it.
    """
    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{_esc(message)}" with title "{_esc(title)}"'
    try:
        subprocess.Popen(
            ["/usr/bin/osascript", "-e", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"notify failed: {exc}", flush=True)


def _identity(cfg: dict) -> tuple[str | None, str, str]:
    """Resolve (agent_id, hostname, username) from cfg + the host environment.

    agent_id comes from helper.json (provisioned by install_clipboard_helper.sh
    from /etc/cyberarmor/agent.json). hostname / username are pulled from the
    OS directly so we never report dashes in the portal even if the install
    script missed them — this matches what the proxy and endpoint agent do.
    """
    try:
        host = socket.gethostname() or ""
    except Exception:
        host = ""
    try:
        user = getpass.getuser() or ""
    except Exception:
        user = ""
    return cfg.get("agent_id"), cfg.get("hostname") or host, cfg.get("username") or user


def post_telemetry(cp: str, api_key: str, tenant: str, event_type: str, payload: dict,
                   agent_id: str | None = None, hostname: str = "", username: str = "") -> None:
    body = {
        "tenant_id": tenant,
        "event_type": event_type,
        "source": "endpoint_clipboard_helper",
        "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "payload": payload,
    }
    if agent_id:
        body["agent_id"] = agent_id
    if hostname:
        body["hostname"] = hostname
    if username:
        body["user_id"] = username
    req = urllib.request.Request(
        cp.rstrip("/") + "/telemetry/ingest",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "x-tenant-id": tenant,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"telemetry {event_type} status={resp.status}", flush=True)
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:200]
        print(f"telemetry {event_type} HTTP {exc.code}: {body_text}", flush=True)
    except Exception as exc:  # noqa: BLE001 — best-effort telemetry
        print(f"telemetry {event_type} failed: {exc}", flush=True)


# ── Tenant policy sync + evaluator ──────────────────────────────────────────
#
# Mirrors extensions/chromium-shared/background.js syncPolicies + evaluatePolicy
# so the clipboard helper honors the same policy authoring flow as the browser
# extension. Policies are pulled from /policies/{tenant}/export periodically;
# evaluation matches first-policy-wins with redact_classes unioned across
# stacked redact policies. Action precedence on tie: block > redact > warn >
# monitor > allow.

_POLICY_CACHE: list[dict] = []
_POLICY_LAST_SYNC: float = 0.0
_POLICY_CACHE_PATH = Path.home() / ".config" / "cyberarmor" / "helper_policies.json"


def _load_policies_from_disk() -> list[dict]:
    """Best-effort load of last-synced policies so we still enforce when the
    control plane is unreachable at startup."""
    if not _POLICY_CACHE_PATH.exists():
        return []
    try:
        data = json.loads(_POLICY_CACHE_PATH.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_policies_to_disk(policies: list[dict]) -> None:
    try:
        _POLICY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _POLICY_CACHE_PATH.write_text(json.dumps(policies))
    except Exception as exc:  # noqa: BLE001
        print(f"policy cache write failed: {exc}", flush=True)


def sync_policies(cp: str, api_key: str, tenant: str) -> list[dict] | None:
    """Fetch the tenant's policy export. Returns the list on success and
    None on failure (caller keeps using the cached set)."""
    url = cp.rstrip("/") + f"/policies/{tenant}/export"
    req = urllib.request.Request(
        url,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "x-tenant-id": tenant,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status >= 300:
                print(f"policy sync HTTP {resp.status}", flush=True)
                return None
            body = resp.read()
            data = json.loads(body)
            if not isinstance(data, list):
                print("policy sync: unexpected payload shape", flush=True)
                return None
            return data
    except urllib.error.HTTPError as exc:
        print(f"policy sync HTTP {exc.code}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"policy sync failed: {exc}", flush=True)
    return None


def _get_nested(obj: dict, path: str):
    cur: object = obj
    for part in (path or "").split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _equals_loose(actual, expected) -> bool:
    if actual == expected:
        return True
    if actual is None or expected is None:
        return False
    return str(actual) == str(expected)


def _eval_leaf(rule: dict, context: dict) -> bool:
    actual = _get_nested(context, rule.get("field", ""))
    expected = rule.get("value")
    op = (rule.get("operator") or "").lower()
    if op == "equals":     return _equals_loose(actual, expected)
    if op == "not_equals": return not _equals_loose(actual, expected)
    if op == "contains":
        if isinstance(actual, list):
            return any(_equals_loose(x, expected) or str(expected) in str(x) for x in actual)
        return str(expected) in str(actual or "")
    if op == "not_contains":
        if isinstance(actual, list):
            return all(not _equals_loose(x, expected) and str(expected) not in str(x) for x in actual)
        return str(expected) not in str(actual or "")
    if op == "matches":
        try:
            return bool(re.search(str(expected).replace("*", ".*"), str(actual or "")))
        except re.error:
            return False
    if op == "in":
        if isinstance(expected, list):
            return actual in expected
        return _equals_loose(actual, expected)
    if op == "has_any":
        # actual is a list (e.g. pii_classes); expected is a list of values
        if not isinstance(actual, list):
            return False
        expected_list = expected if isinstance(expected, list) else [expected]
        return any(item in actual for item in expected_list)
    if op == "starts_with": return str(actual or "").startswith(str(expected))
    if op == "ends_with":   return str(actual or "").endswith(str(expected))
    if op == "exists":      return actual is not None
    if op == "not_exists":  return actual is None
    return False


def _eval_conditions(conds: dict, context: dict) -> bool:
    if not isinstance(conds, dict):
        return True
    op = (conds.get("operator") or "AND").upper()
    rules = conds.get("rules") or []
    if not rules:
        return True
    results = [
        _eval_conditions(r, context) if isinstance(r, dict) and "rules" in r else _eval_leaf(r, context)
        for r in rules
    ]
    return any(results) if op == "OR" else all(results)


# Precedence — when multiple policies match, the strongest action wins so
# a single "monitor everything" catch-all can't drown out a targeted block.
_ACTION_RANK = {"block": 4, "redact": 3, "warn": 2, "monitor": 1, "allow": 0}


def evaluate_policy(policies: list[dict], context: dict) -> dict | None:
    """Return {action, redact_classes, policy} for the strongest matching
    policy, or None if nothing matches."""
    winner: dict | None = None
    redact_union: set[str] = set()
    redact_names: list[str] = []
    for p in policies or []:
        if not isinstance(p, dict) or p.get("enabled") is False:
            continue
        conds = p.get("conditions") or {}
        if not _eval_conditions(conds, context):
            continue
        action = str(p.get("action") or "monitor").lower()
        if winner is None or _ACTION_RANK.get(action, 0) > _ACTION_RANK.get(winner["action"], 0):
            winner = {
                "action": action,
                "redact_classes": list(p.get("redact_classes") or []),
                "policy": p.get("name") or p.get("id") or "",
            }
        if action == "redact":
            redact_names.append(p.get("name") or "")
            for c in (p.get("redact_classes") or []):
                redact_union.add(str(c))
    if winner is None:
        return None
    if winner["action"] == "redact":
        # Stack redact policies so a narrow rule doesn't shadow a broad one.
        winner["redact_classes"] = sorted(redact_union)
        if len([n for n in redact_names if n]) > 1:
            winner["policy"] = "+".join(n for n in redact_names if n)
    return winner


def main() -> None:
    global _POLICY_CACHE, _POLICY_LAST_SYNC
    cfg = load_config()
    cp = cfg["control_plane_url"]
    api_key = cfg["service_api_key"]
    tenant = cfg.get("tenant_id", "default")
    poll_s = float(cfg.get("poll_interval_s", 3))
    # Local default — used only when no tenant policy matches the event.
    # Tenant policies (synced from /policies/{tenant}/export) win when they
    # match, so the portal stays the source of truth for clipboard mode.
    fallback_action = (cfg.get("clipboard_action") or "monitor").lower()
    policy_sync_s = float(cfg.get("policy_sync_interval_s", 60))
    notify_on_monitor = bool(cfg.get("notify_on_monitor", False))
    agent_id, hostname, username = _identity(cfg)

    # Seed the policy cache from the last on-disk copy so a startup with no
    # network still enforces the last-known set.
    _POLICY_CACHE = _load_policies_from_disk()
    initial = sync_policies(cp, api_key, tenant)
    if initial is not None:
        _POLICY_CACHE = initial
        _POLICY_LAST_SYNC = time.time()
        _save_policies_to_disk(_POLICY_CACHE)

    print(
        f"clipboard helper starting cp={cp} tenant={tenant} poll={poll_s}s "
        f"fallback_action={fallback_action} policies_loaded={len(_POLICY_CACHE)} "
        f"agent_id={agent_id or '?'} host={hostname or '?'} user={username or '?'}",
        flush=True,
    )

    # SIGTERM from launchctl unload → exit cleanly
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    last_seen = ""
    while True:
        time.sleep(poll_s)

        # Refresh tenant policies on its own cadence — independent of the
        # clipboard poll loop so a slow portal doesn't starve detection.
        now_ts = time.time()
        if now_ts - _POLICY_LAST_SYNC >= policy_sync_s:
            fresh = sync_policies(cp, api_key, tenant)
            if fresh is not None:
                _POLICY_CACHE = fresh
                _save_policies_to_disk(_POLICY_CACHE)
            _POLICY_LAST_SYNC = now_ts

        try:
            content = pyperclip.paste()
        except Exception as exc:  # noqa: BLE001
            time.sleep(poll_s * 3)
            continue
        if not content or content == last_seen:
            continue
        last_seen = content
        labels = detect_pii(content)
        if not labels:
            continue

        pii_classes = [f"pii.{label}" for label in labels]

        # Evaluate tenant policy. Context shape mirrors what the extension
        # passes to evaluatePolicy so the same policy document drives both
        # surfaces. Includes a synthetic "request" so policies authored
        # against navigation paths still match when they're meant to apply
        # to any DLP-bearing event (operators often write hostname=*).
        context = {
            "request": {"type": "clipboard", "hostname": "", "path": "/clipboard"},
            "content": {
                "pii_classes": pii_classes,
                "has_pii": True,
                "labels": labels,
            },
            "source": "endpoint_clipboard_helper",
            "event_type": "clipboard_sensitive_data",
        }
        decision = evaluate_policy(_POLICY_CACHE, context)
        if decision is None:
            action = fallback_action
            policy_name = ""
            allowed_classes: set[str] = set()
        else:
            action = decision["action"]
            policy_name = decision.get("policy") or ""
            allowed_classes = set(decision.get("redact_classes") or [])

        post_telemetry(
            cp, api_key, tenant,
            event_type="clipboard_sensitive_data",
            payload={
                "labels": labels,
                "pii_classes": pii_classes,
                "length": len(content),
                "action": action,
                "policy_name": policy_name,
            },
            agent_id=agent_id, hostname=hostname, username=username,
        )
        if action == "monitor" and notify_on_monitor:
            notify("CyberArmor", f"Detected sensitive clipboard data: {', '.join(labels)}")

        if action == "redact":
            # allowed_classes empty = redact every detected label (catch-all
            # redact policy). Otherwise restrict to the classes the policy
            # explicitly listed, matching the extension's behavior.
            redacted, changed = redact_text(content, allowed=allowed_classes)
            if changed:
                try:
                    pyperclip.copy(redacted)
                    last_seen = redacted
                    post_telemetry(
                        cp, api_key, tenant,
                        event_type="clipboard_sensitive_data_redacted",
                        payload={
                            "labels": labels,
                            "pii_classes": pii_classes,
                            "original_length": len(content),
                            "redacted_length": len(redacted),
                            "policy_name": policy_name,
                            "redact_classes": sorted(allowed_classes),
                        },
                        agent_id=agent_id, hostname=hostname, username=username,
                    )
                    print(f"redacted clipboard labels={labels} policy={policy_name or '(local)'}", flush=True)
                    notify("CyberArmor", f"Redacted sensitive clipboard data: {', '.join(labels)}")
                except Exception as exc:  # noqa: BLE001
                    print(f"redact write failed: {exc}", flush=True)
        elif action == "block":
            try:
                pyperclip.copy("")
                last_seen = ""
                post_telemetry(
                    cp, api_key, tenant,
                    event_type="clipboard_sensitive_data_blocked",
                    payload={
                        "labels": labels,
                        "pii_classes": pii_classes,
                        "policy_name": policy_name,
                    },
                    agent_id=agent_id, hostname=hostname, username=username,
                )
                print(f"cleared clipboard labels={labels} policy={policy_name or '(local)'}", flush=True)
                notify("CyberArmor", f"Blocked sensitive clipboard data: {', '.join(labels)}")
            except Exception as exc:  # noqa: BLE001
                print(f"block write failed: {exc}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
