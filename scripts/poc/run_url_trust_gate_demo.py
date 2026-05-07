#!/usr/bin/env python3
"""15-minute PoC demo runner for the URL Trust Gate.

Posts each crafted test URL to the running gate and prints the verdict
plus a pass/fail summary. Exits non-zero if the demo fails (i.e. the
benign page got blocked, or a malicious page got allowed).

Run AFTER ``scripts/poc/install.sh`` brings the stack up. Reads the
gate's API secret from ``infra/docker-compose/.env`` (created by the
installer).

Usage:
    python3 scripts/poc/run_url_trust_gate_demo.py
    python3 scripts/poc/run_url_trust_gate_demo.py --gate-url http://localhost:8014
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / "infra" / "docker-compose" / ".env"

# Test URLs are reached over the public host network — the gate's
# safe crawler resolves the SSRF allowlist hostname `poc-test-server`
# from inside the docker network.
GATE_URL_DEFAULT = "http://localhost:8014"
TEST_BASE_URL_INTERNAL = "http://poc-test-server:8088"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m•\033[0m"


@dataclass
class TestCase:
    name: str
    path: str
    expected_action_set: frozenset
    expected_signal: str  # human-readable description for the report


CASES: List[TestCase] = [
    TestCase(
        name="benign tea-blends article",
        path="/benign.html",
        expected_action_set=frozenset({"allow"}),
        expected_signal="no risk signals",
    ),
    TestCase(
        name="display:none promptware payload",
        path="/hidden-instruction.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="prompt_injection score elevated",
    ),
    TestCase(
        name="zero-width-character injection",
        path="/zero-width-injection.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="prompt_injection / promptware score elevated",
    ),
    TestCase(
        name="credential-harvest sign-in page",
        path="/credential-harvest.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="credential_harvest + brand_impersonation",
    ),
]


def read_env_value(key: str, default: str) -> str:
    """Best-effort .env reader. Avoids dotenv dep so the PoC can run
    on a clean machine with just the stdlib."""
    if not ENV_FILE.exists():
        return os.environ.get(key, default)
    try:
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return os.environ.get(key, default)


def http_post_json(
    url: str, payload: dict, headers: dict, timeout: float
) -> tuple[int, dict | str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(text)
            except json.JSONDecodeError:
                return resp.status, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return e.code, json.loads(text)
        except Exception:
            return e.code, text
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def evaluate(
    gate_url: str, api_key: str, page_url: str, depth: str, tenant: str
) -> dict:
    return http_post_json(
        f"{gate_url.rstrip('/')}/evaluate",
        {
            "tenant_id": tenant,
            "url": page_url,
            "source": "poc-demo-runner",
            "depth": depth,
        },
        {"x-api-key": api_key},
        timeout=20.0,
    )[1]


def wait_for_gate(gate_url: str, max_seconds: int = 60) -> bool:
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"{gate_url.rstrip('/')}/health", timeout=2
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def fmt_scores(scores: dict) -> str:
    if not isinstance(scores, dict):
        return ""
    interesting = [
        (k, v) for k, v in scores.items()
        if isinstance(v, (int, float)) and v >= 0.05
    ]
    interesting.sort(key=lambda kv: kv[1], reverse=True)
    return ", ".join(f"{k}={v:.2f}" for k, v in interesting[:5]) or "all-zero"


def run(gate_url: str, depth: str, tenant: str) -> int:
    api_key = read_env_value("URL_TRUST_GATE_API_SECRET", "change-me-url-trust-gate")

    print(f"{INFO} URL Trust Gate PoC demo")
    print(f"{INFO} gate    : {gate_url}")
    print(f"{INFO} depth   : {depth}")
    print(f"{INFO} tenant  : {tenant}")
    print(f"{INFO} secret  : {'(default — local PoC only)' if api_key == 'change-me-url-trust-gate' else '(from .env)'}")
    print()

    print(f"{INFO} Waiting for gate /health ...")
    if not wait_for_gate(gate_url):
        print(f"  {FAIL} gate did not become ready at {gate_url}")
        print("       run scripts/poc/install.sh first, or check `docker compose ps`")
        return 2
    print(f"  {PASS} gate is up")
    print()

    failures = 0
    for case in CASES:
        page_url = f"{TEST_BASE_URL_INTERNAL}{case.path}"
        print(f"{INFO} {case.name}")
        print(f"      url       : {page_url}")
        print(f"      expecting : {' or '.join(sorted(case.expected_action_set))} ({case.expected_signal})")

        result = evaluate(gate_url, api_key, page_url, depth=depth, tenant=tenant)
        if not isinstance(result, dict):
            print(f"      {FAIL} non-JSON response: {result}")
            failures += 1
            print()
            continue

        decision = (result.get("decision") or {}).get("action", "")
        reason = (result.get("decision") or {}).get("reason", "")
        scores = result.get("scores") or {}
        elapsed = result.get("elapsed_ms")

        print(f"      action    : {decision}")
        print(f"      reason    : {reason}")
        print(f"      scores    : {fmt_scores(scores)}")
        if elapsed is not None:
            print(f"      latency   : {elapsed} ms")

        if decision in case.expected_action_set:
            print(f"      result    : {PASS}")
        else:
            print(f"      result    : {FAIL} — got {decision!r}, expected one of {sorted(case.expected_action_set)}")
            failures += 1
        print()

    total = len(CASES)
    passed = total - failures
    print(f"{INFO} summary: {passed}/{total} passed")
    if failures == 0:
        print(f"  {PASS} URL Trust Gate PoC demo succeeded")
        return 0
    print(f"  {FAIL} URL Trust Gate PoC demo had {failures} failure(s)")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate-url", default=os.environ.get("URL_TRUST_GATE_URL", GATE_URL_DEFAULT))
    p.add_argument("--depth", default="standard", choices=["fast", "standard", "deep"])
    p.add_argument("--tenant", default="poc")
    args = p.parse_args(argv)
    return run(args.gate_url, args.depth, args.tenant)


if __name__ == "__main__":
    raise SystemExit(main())
