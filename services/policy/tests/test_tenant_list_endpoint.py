"""Tests for the GET /policies flat query endpoint.

The URL Trust Gate's TenantListClient calls:

    GET /policies?tenant_id=<t>&scope=url-trust-gate

The policy service previously only exposed ``GET /policies/{tenant_id}``,
which requires the tenant_id in the URL path.  This test suite verifies
the flat-query variant returns the correct subset of policies and is
compatible with the ``_merge()`` logic in tenant_lists.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: ensure we can import the FastAPI app without a live database.
# We use the SQLite in-memory backend that the policy service already
# supports via DATABASE_URL env var.
# ---------------------------------------------------------------------------

import os

# Point at a transient in-memory SQLite DB so no real Postgres is needed.
os.environ.setdefault("DATABASE_URL", "sqlite:///file:policy_test_tenant_list?mode=memory&cache=shared&uri=true")
os.environ.setdefault("POLICY_API_SECRET", "test-secret-policy")
os.environ.setdefault("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "true")
os.environ.setdefault("OPA_ENABLED", "false")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Stub cyberarmor_core before importing main
import types

for mod_name in ("cyberarmor_core", "cyberarmor_core.crypto"):
    if mod_name not in sys.modules:
        stub = types.ModuleType(mod_name)
        stub.get_public_key_info = lambda *a, **kw: {}  # type: ignore[attr-defined]
        stub.verify_shared_secret = lambda *a, **kw: True  # type: ignore[attr-defined]
        sys.modules[mod_name] = stub

try:
    import main as policy_main  # noqa: PLC0415
    from fastapi.testclient import TestClient
    import db as policy_db  # noqa: PLC0415
    _SKIP = False
except Exception as exc:
    _SKIP = True
    _SKIP_REASON = str(exc)


@pytest.fixture(scope="module")
def client():
    if _SKIP:
        pytest.skip(f"policy main.py import failed: {_SKIP_REASON}")
    # Create tables directly — the startup hook calls wait_for_db() which
    # polls with exponential back-off and can fail when no Postgres is
    # configured.  Since db.py already supports SQLite we bypass the hook
    # and create tables ourselves.
    from models import Base  # noqa: PLC0415
    Base.metadata.create_all(bind=policy_db.engine)
    with TestClient(policy_main.app, raise_server_exceptions=True) as c:
        yield c


_HEADERS = {"x-api-key": "test-secret-policy"}


def _make_policy(client, *, name: str, tenant_id: str, scope: str, rules: Dict[str, Any], enabled: bool = True):
    resp = client.post(
        "/policies",
        json={
            "name": name,
            "tenant_id": tenant_id,
            "scope": scope,
            "rules": rules,
            "action": "allow",
            "enabled": enabled,
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_list_policies_flat_returns_empty_when_none(client):
    resp = client.get("/policies", params={"tenant_id": "no-such-tenant"}, headers=_HEADERS)
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_policies_flat_scope_filter(client):
    """Only policies with scope=url-trust-gate should come back for that filter."""
    tenant = "tenant-scope-filter"
    _make_policy(
        client,
        name="utg-list-policy",
        tenant_id=tenant,
        scope="url-trust-gate",
        rules={
            "allow_domains": ["safe.example.com"],
            "block_domains": ["evil.example.com"],
        },
    )
    _make_policy(
        client,
        name="general-policy",
        tenant_id=tenant,
        scope="general",
        rules={"block_domains": ["other.example.com"]},
    )

    # Filtered to url-trust-gate only.
    resp = client.get(
        "/policies",
        params={"tenant_id": tenant, "scope": "url-trust-gate"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["scope"] == "url-trust-gate"
    rules = data[0]["rules"]
    assert "allow_domains" in rules
    assert "safe.example.com" in rules["allow_domains"]


def test_list_policies_flat_no_scope_filter_returns_all(client):
    tenant = "tenant-no-scope"
    _make_policy(client, name="p1", tenant_id=tenant, scope="url-trust-gate", rules={})
    _make_policy(client, name="p2", tenant_id=tenant, scope="general", rules={})

    resp = client.get("/policies", params={"tenant_id": tenant}, headers=_HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_list_policies_flat_excludes_disabled(client):
    """enabled_only=true must exclude disabled policies."""
    tenant = "tenant-enabled-only"
    _make_policy(client, name="active", tenant_id=tenant, scope="url-trust-gate", rules={})
    _make_policy(
        client,
        name="inactive",
        tenant_id=tenant,
        scope="url-trust-gate",
        rules={},
        enabled=False,
    )

    resp = client.get(
        "/policies",
        params={"tenant_id": tenant, "enabled_only": "true"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json()]
    assert "active" in names
    assert "inactive" not in names


def test_list_policies_flat_rules_shape_compatible_with_tenant_list_merge(client):
    """The response must be consumable by TenantListClient._merge().

    _merge() iterates each policy, reads rules.allow_domains /
    rules.block_domains / rules.allow_urls / rules.block_urls.  Verify
    the response has the right shape.
    """
    tenant = "tenant-merge-compat"
    _make_policy(
        client,
        name="merge-test",
        tenant_id=tenant,
        scope="url-trust-gate",
        rules={
            "allow_domains": ["allowed.example.com"],
            "block_domains": ["blocked.example.com"],
            "allow_urls": ["https://ok.example.com/path"],
            "block_urls": ["https://bad.example.com/*"],
        },
    )

    resp = client.get(
        "/policies",
        params={"tenant_id": tenant, "scope": "url-trust-gate"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    policies = resp.json()
    assert len(policies) == 1
    rules = policies[0]["rules"]
    assert rules.get("allow_domains") == ["allowed.example.com"]
    assert rules.get("block_domains") == ["blocked.example.com"]
    assert rules.get("allow_urls") == ["https://ok.example.com/path"]
    assert rules.get("block_urls") == ["https://bad.example.com/*"]


def test_list_policies_flat_requires_tenant_id(client):
    """Omitting tenant_id must return 422 (query param required)."""
    resp = client.get("/policies", headers=_HEADERS)
    assert resp.status_code == 422


def test_list_policies_flat_requires_tenant_id_param(client):
    """The tenant_id query param is required — omitting it yields 422."""
    # This is enforced by FastAPI's Query(...) annotation and does not
    # depend on the auth layer being live.
    resp = client.get("/policies", headers=_HEADERS)
    assert resp.status_code == 422


def test_list_policies_flat_scope_is_optional_param(client):
    """Passing no scope filter should not cause a 422 — scope is Optional."""
    resp = client.get("/policies", params={"tenant_id": "scope-optional"}, headers=_HEADERS)
    assert resp.status_code == 200
