"""CyberArmor SDK configuration.

Environment variable prefix: CYBERARMOR_
"""
from __future__ import annotations

import os
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Read an environment variable with an optional default.
    """
    value = os.environ.get(key)
    if value is not None:
        return value
    return default


def _env_int(key: str, default: int = 0) -> int:
    raw = _env(key, str(default))
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = _env(key, "true" if default else "false")
    return (raw or "").lower() in ("1", "true", "yes", "on")


def _env_list(key: str, default: Optional[List[str]] = None) -> List[str]:
    raw = _env(key)
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return default or []


def _redeem_bootstrap_token(
    bootstrap_token: str,
    *,
    package_key: str,
    control_plane_url: str,
    subject_type: str,
    subject_name: Optional[str] = None,
) -> dict:
    payload = {
        "bootstrap_token": bootstrap_token,
        "package_key": package_key,
        "subject_type": subject_type,
    }
    if subject_name:
        payload["subject_name"] = subject_name
    request = urllib.request.Request(
        f"{control_plane_url.rstrip('/')}/bootstrap/redeem",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ValueError(f"Bootstrap redeem failed ({exc.code}): {body[:400]}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Bootstrap redeem failed: {exc.reason}") from exc


@dataclass
class CyberArmorConfig:
    """
    Full SDK configuration.

    All fields have sensible defaults and can be overridden via environment
    variables or by passing keyword arguments to the constructor.

    Environment variable mapping
    ----------------------------
    api_key              -> CYBERARMOR_API_KEY
    api_url              -> CYBERARMOR_API_URL
    tenant_id            -> CYBERARMOR_TENANT_ID
    agent_id             -> CYBERARMOR_AGENT_ID
    environment          -> CYBERARMOR_ENVIRONMENT
    timeout_seconds      -> CYBERARMOR_TIMEOUT_SECONDS
    max_retries          -> CYBERARMOR_MAX_RETRIES
    audit_enabled        -> CYBERARMOR_AUDIT_ENABLED
    audit_batch_size     -> CYBERARMOR_AUDIT_BATCH_SIZE
    audit_flush_interval -> CYBERARMOR_AUDIT_FLUSH_INTERVAL
    dlp_enabled          -> CYBERARMOR_DLP_ENABLED
    injection_detection  -> CYBERARMOR_INJECTION_DETECTION
    local_policy_path    -> CYBERARMOR_LOCAL_POLICY_PATH
    signing_key          -> CYBERARMOR_SIGNING_KEY
    verify_ssl           -> CYBERARMOR_VERIFY_SSL
    log_level            -> CYBERARMOR_LOG_LEVEL
    allowed_models       -> CYBERARMOR_ALLOWED_MODELS     (comma-separated)
    blocked_models       -> CYBERARMOR_BLOCKED_MODELS     (comma-separated)
    """

    # Core authentication
    api_key: Optional[str] = None
    api_url: str = "https://api.cyberarmor.ai/v1"
    control_plane_url: Optional[str] = None
    tenant_id: Optional[str] = None
    agent_id: Optional[str] = None
    bootstrap_token: Optional[str] = None

    # Runtime environment tag
    environment: str = "production"

    # HTTP client settings
    timeout_seconds: float = 10.0
    max_retries: int = 3

    # Audit / event pipeline
    audit_enabled: bool = True
    audit_batch_size: int = 50
    audit_flush_interval: float = 5.0   # seconds

    # In-process security features
    dlp_enabled: bool = True
    injection_detection: bool = True

    # Optional path to a local policy JSON file (offline mode)
    local_policy_path: Optional[str] = None

    # Event signing key (base64-encoded Ed25519 private key or HMAC secret)
    signing_key: Optional[str] = None

    # TLS verification
    verify_ssl: bool = True

    # Logging
    log_level: str = "WARNING"

    # Model allow/block lists (empty = unrestricted)
    allowed_models: List[str] = field(default_factory=list)
    blocked_models: List[str] = field(default_factory=list)

    # Token cache TTL (seconds)
    token_ttl: int = 3600

    # Maximum delegation chain depth (0 = unlimited)
    max_delegation_depth: int = 0

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "CyberArmorConfig":
        """
        Build a CyberArmorConfig entirely from environment variables.

        Reads CYBERARMOR_* environment variables.
        """
        return cls(
            api_key=_env("CYBERARMOR_API_KEY"),
            api_url=_env(
                "CYBERARMOR_API_URL",
                "https://api.cyberarmor.ai/v1",
            ),  # type: ignore[arg-type]
            control_plane_url=_env("CYBERARMOR_CONTROL_PLANE_URL"),
            tenant_id=_env("CYBERARMOR_TENANT_ID"),
            agent_id=_env("CYBERARMOR_AGENT_ID"),
            bootstrap_token=_env("CYBERARMOR_BOOTSTRAP_TOKEN"),
            environment=_env(
                "CYBERARMOR_ENVIRONMENT", "production"
            ),  # type: ignore[arg-type]
            timeout_seconds=float(
                _env("CYBERARMOR_TIMEOUT_SECONDS", "10") or "10"
            ),
            max_retries=_env_int("CYBERARMOR_MAX_RETRIES", 3),
            audit_enabled=_env_bool("CYBERARMOR_AUDIT_ENABLED", True),
            audit_batch_size=_env_int("CYBERARMOR_AUDIT_BATCH_SIZE", 50),
            audit_flush_interval=float(
                _env("CYBERARMOR_AUDIT_FLUSH_INTERVAL", default="5") or "5"
            ),
            dlp_enabled=_env_bool("CYBERARMOR_DLP_ENABLED", True),
            injection_detection=_env_bool("CYBERARMOR_INJECTION_DETECTION", True),
            local_policy_path=_env("CYBERARMOR_LOCAL_POLICY_PATH"),
            signing_key=_env("CYBERARMOR_SIGNING_KEY"),
            verify_ssl=_env_bool("CYBERARMOR_VERIFY_SSL", True),
            log_level=_env("CYBERARMOR_LOG_LEVEL", default="WARNING") or "WARNING",
            allowed_models=_env_list("CYBERARMOR_ALLOWED_MODELS"),
            blocked_models=_env_list("CYBERARMOR_BLOCKED_MODELS"),
            token_ttl=_env_int("CYBERARMOR_TOKEN_TTL", 3600),
            max_delegation_depth=_env_int("CYBERARMOR_MAX_DELEGATION_DEPTH", 0),
        )._apply_bootstrap_if_needed()

    def _apply_bootstrap_if_needed(self) -> "CyberArmorConfig":
        if self.api_key or not self.bootstrap_token:
            return self
        control_plane_url = self.control_plane_url or self.api_url.rsplit("/v1", 1)[0]
        redeemed = _redeem_bootstrap_token(
            self.bootstrap_token,
            package_key="sdk-python",
            control_plane_url=control_plane_url,
            subject_type="sdk_client",
            subject_name=self.agent_id or "python-sdk",
        )
        runtime_env = redeemed.get("runtime_env", {})
        self.api_key = runtime_env.get("CYBERARMOR_API_KEY") or redeemed.get("service_api_key")
        self.tenant_id = runtime_env.get("CYBERARMOR_TENANT_ID") or redeemed.get("tenant_id") or self.tenant_id
        self.control_plane_url = redeemed.get("control_plane_url") or control_plane_url
        self.api_url = self.control_plane_url.rstrip("/") + "/v1"
        self.agent_id = runtime_env.get("CYBERARMOR_AGENT_ID") or redeemed.get("subject_id") or self.agent_id
        return self

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise ValueError for obviously invalid configuration."""
        if not self.api_key and not self.local_policy_path:
            raise ValueError(
                "CyberArmorConfig requires either 'api_key' or 'local_policy_path'. "
                "Set CYBERARMOR_API_KEY or CYBERARMOR_LOCAL_POLICY_PATH."
            )
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0.")
        if self.audit_batch_size < 1:
            raise ValueError("audit_batch_size must be >= 1.")

    def __repr__(self) -> str:
        masked = f"{'*' * 8}{self.api_key[-4:]}" if self.api_key else "None"
        return (
            f"CyberArmorConfig("
            f"api_url={self.api_url!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"agent_id={self.agent_id!r}, "
            f"environment={self.environment!r}, "
            f"api_key={masked!r})"
        )
