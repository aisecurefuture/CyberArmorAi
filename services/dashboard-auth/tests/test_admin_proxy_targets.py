from __future__ import annotations

import importlib
import sys
from pathlib import Path


SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))


def load_dashboard_auth_main(monkeypatch):
    monkeypatch.setenv("DASHBOARD_AUTH_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ADMIN_DASHBOARD_SESSION_SECRET", "test-session-secret")
    for name in ("main", "db", "models", "totp"):
        sys.modules.pop(name, None)
    return importlib.import_module("main")


def test_build_admin_proxy_targets_accepts_url_aliases(monkeypatch):
    monkeypatch.setenv("POLICY_URL", "http://policy-alias:18001")
    monkeypatch.setenv("DETECTION_URL", "http://detection-alias:18002")
    monkeypatch.setenv("RESPONSE_URL", "http://response-alias:18003")
    monkeypatch.setenv("IDENTITY_URL", "http://identity-alias:18004")
    monkeypatch.setenv("SIEM_CONNECTOR_URL", "http://siem-alias:18005")
    monkeypatch.setenv("RUNTIME_URL", "http://runtime-alias:18000")

    module = load_dashboard_auth_main(monkeypatch)
    targets = module._build_admin_proxy_targets()

    assert targets["policy"].url == "http://policy-alias:18001"
    assert targets["detection"].url == "http://detection-alias:18002"
    assert targets["response"].url == "http://response-alias:18003"
    assert targets["identity"].url == "http://identity-alias:18004"
    assert targets["siem"].url == "http://siem-alias:18005"
    assert targets["runtime"].url == "http://runtime-alias:18000"


def test_build_admin_proxy_targets_includes_extended_dashboard_services(monkeypatch):
    module = load_dashboard_auth_main(monkeypatch)
    targets = module._build_admin_proxy_targets()

    assert "runtime" in targets
    assert "url-trust-gate" in targets
    assert "integration-control" in targets
    assert "secrets-service" in targets
    assert targets["url-trust-gate"].dashboard_metadata()["proxyBase"] == "/admin-api/url-trust-gate"
