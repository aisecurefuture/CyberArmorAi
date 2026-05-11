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

import json
import re
import signal
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


def post_telemetry(cp: str, api_key: str, tenant: str, event_type: str, payload: dict) -> None:
    body = {
        "tenant_id": tenant,
        "event_type": event_type,
        "source": "endpoint_clipboard_helper",
        "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "payload": payload,
    }
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


def main() -> None:
    cfg = load_config()
    cp = cfg["control_plane_url"]
    api_key = cfg["service_api_key"]
    tenant = cfg.get("tenant_id", "default")
    poll_s = float(cfg.get("poll_interval_s", 3))
    action = (cfg.get("clipboard_action") or "monitor").lower()
    # monitor mode is informational; default no notification (avoid spam),
    # but allow operators to opt-in via the config.
    notify_on_monitor = bool(cfg.get("notify_on_monitor", False))

    print(
        f"clipboard helper starting cp={cp} tenant={tenant} poll={poll_s}s action={action}",
        flush=True,
    )

    # SIGTERM from launchctl unload → exit cleanly
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    last_seen = ""
    while True:
        time.sleep(poll_s)
        try:
            content = pyperclip.paste()
        except Exception as exc:  # noqa: BLE001
            # GUI session not yet ready, or login window — pyperclip raises
            time.sleep(poll_s * 3)
            continue
        if not content or content == last_seen:
            continue
        last_seen = content
        labels = detect_pii(content)
        if not labels:
            continue

        pii_classes = [f"pii.{label}" for label in labels]
        post_telemetry(
            cp, api_key, tenant,
            event_type="clipboard_sensitive_data",
            payload={
                "labels": labels,
                "pii_classes": pii_classes,
                "length": len(content),
                "action": action,
            },
        )
        if action == "monitor" and notify_on_monitor:
            notify(
                "CyberArmor",
                f"Detected sensitive clipboard data: {', '.join(labels)}",
            )

        if action == "redact":
            redacted, changed = redact_text(content, allowed=set())
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
                        },
                    )
                    print(f"redacted clipboard labels={labels}", flush=True)
                    notify(
                        "CyberArmor",
                        f"Redacted sensitive clipboard data: {', '.join(labels)}",
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"redact write failed: {exc}", flush=True)
        elif action == "block":
            try:
                pyperclip.copy("")
                last_seen = ""
                post_telemetry(
                    cp, api_key, tenant,
                    event_type="clipboard_sensitive_data_blocked",
                    payload={"labels": labels, "pii_classes": pii_classes},
                )
                print(f"cleared clipboard labels={labels}", flush=True)
                notify(
                    "CyberArmor",
                    f"Blocked sensitive clipboard data: {', '.join(labels)}",
                )
            except Exception as exc:  # noqa: BLE001
                print(f"block write failed: {exc}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
