#!/usr/bin/env python3
"""Build a plaintext or PQC-wrapped x-api-key header value for scripts/clients."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate x-api-key header value")
    parser.add_argument("service_url")
    parser.add_argument("secret")
    args = parser.parse_args()

    if not args.secret:
        print("", end="")
        return 0

    sys.path.insert(0, str(_repo_root() / "libs" / "cyberarmor-core"))
    from cyberarmor_core.crypto import build_pqc_auth_header

    pqc_enabled = _bool_env("CYBERARMOR_PQC_AUTH_ENABLED", False)
    if not pqc_enabled:
        print(args.secret, end="")
        return 0

    strict = _bool_env("CYBERARMOR_PQC_OUTBOUND_STRICT", False)
    try:
        value = build_pqc_auth_header(args.service_url, args.secret, strict=strict)
    except Exception:
        if strict:
            raise
        value = args.secret
    print(value, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
