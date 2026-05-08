"""Tests for openai_url_trust_gate.py

All gate HTTP calls are mocked so these tests run offline.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from cyberarmor.frameworks.openai_url_trust_gate import (
    GateConfig,
    GatedToolCall,
    URLBlockedByTrustGate,
    _extract_urls,
    _looks_like_url,
    _redact_urls,
    gate_tool_calls,
    gate_tool_calls_async,
    guard_response,
    _extract_tool_calls,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CFG = GateConfig(
    gate_url="https://gate.example/evaluate",
    api_key="test-key",
    tenant_id="test-tenant",
)


def _make_tool_call(name: str, arguments: dict, call_id: str = "call_1") -> MagicMock:
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


def _make_response(tool_calls: list) -> MagicMock:
    msg = MagicMock()
    msg.tool_calls = tool_calls
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    return resp


def _allow_verdict(url: str = "") -> dict:
    return {"decision": {"action": "allow", "reason": "clean"}, "evidence_id": "ev1"}


def _block_verdict(url: str = "") -> dict:
    return {"decision": {"action": "block", "reason": "malicious"}, "evidence_id": "ev2"}


def _redact_verdict(url: str = "") -> dict:
    return {"decision": {"action": "redact", "reason": "suspicious"}, "evidence_id": "ev3"}


def _warn_verdict(url: str = "") -> dict:
    return {"decision": {"action": "warn", "reason": "low confidence"}, "evidence_id": "ev4"}


# ---------------------------------------------------------------------------
# Unit: URL helpers
# ---------------------------------------------------------------------------


class TestLooksLikeUrl:
    def test_http(self):
        assert _looks_like_url("http://example.com") is True

    def test_https(self):
        assert _looks_like_url("https://example.com/path?q=1") is True

    def test_no_scheme(self):
        assert _looks_like_url("example.com") is False

    def test_ftp(self):
        assert _looks_like_url("ftp://files.example.com") is False

    def test_empty(self):
        assert _looks_like_url("") is False

    def test_too_long(self):
        assert _looks_like_url("https://x.com/" + "a" * 4090) is False


class TestExtractUrls:
    def test_flat_dict(self):
        urls = _extract_urls({"url": "https://evil.com", "other": "plain"})
        assert urls == ["https://evil.com"]

    def test_nested_dict(self):
        urls = _extract_urls({"a": {"b": "https://nested.com/path"}})
        assert "https://nested.com/path" in urls

    def test_list_values(self):
        urls = _extract_urls({"urls": ["https://a.com", "https://b.com"]})
        assert set(urls) == {"https://a.com", "https://b.com"}

    def test_no_urls(self):
        assert _extract_urls({"name": "test", "count": 3}) == []

    def test_mixed_types(self):
        urls = _extract_urls({"a": 1, "b": None, "c": "https://ok.com"})
        assert urls == ["https://ok.com"]


class TestRedactUrls:
    def test_replaces_blocked_url(self):
        obj = {"url": "https://evil.com"}
        result = _redact_urls(obj, {"https://evil.com"})
        assert result["url"] == "[URL redacted by CyberArmor Trust Gate]"

    def test_leaves_safe_url(self):
        obj = {"url": "https://safe.com"}
        result = _redact_urls(obj, {"https://evil.com"})
        assert result["url"] == "https://safe.com"

    def test_nested(self):
        obj = {"a": {"url": "https://evil.com"}}
        result = _redact_urls(obj, {"https://evil.com"})
        assert result["a"]["url"] == "[URL redacted by CyberArmor Trust Gate]"

    def test_list(self):
        obj = ["https://evil.com", "https://safe.com"]
        result = _redact_urls(obj, {"https://evil.com"})
        assert result[0] == "[URL redacted by CyberArmor Trust Gate]"
        assert result[1] == "https://safe.com"


# ---------------------------------------------------------------------------
# gate_tool_calls — sync
# ---------------------------------------------------------------------------


class TestGateToolCallsSync:
    def test_allow_verdict_passes_through(self):
        tc = _make_tool_call("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            results = gate_tool_calls([tc], cfg=CFG)
        assert len(results) == 1
        assert results[0].safe_arguments["url"] == "https://example.com"
        assert results[0].urls_found == ["https://example.com"]
        assert results[0].warnings == []

    def test_block_verdict_raises(self):
        tc = _make_tool_call("fetch_page", {"url": "https://evil.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate) as exc_info:
                gate_tool_calls([tc], cfg=CFG)
        assert "https://evil.com" in str(exc_info.value)

    def test_isolate_verdict_raises(self):
        tc = _make_tool_call("fetch_page", {"url": "https://evil.com"})
        verdict = {"decision": {"action": "isolate", "reason": "suspect"}, "evidence_id": "ev9"}
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=verdict,
        ):
            with pytest.raises(URLBlockedByTrustGate):
                gate_tool_calls([tc], cfg=CFG)

    def test_redact_verdict_replaces_url(self):
        tc = _make_tool_call("fetch_page", {"url": "https://suspicious.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_redact_verdict(),
        ):
            results = gate_tool_calls([tc], cfg=CFG)
        assert results[0].safe_arguments["url"] == "[URL redacted by CyberArmor Trust Gate]"
        assert len(results[0].warnings) == 1

    def test_warn_verdict_adds_warning(self):
        tc = _make_tool_call("fetch_page", {"url": "https://warn.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_warn_verdict(),
        ):
            results = gate_tool_calls([tc], cfg=CFG)
        assert results[0].safe_arguments["url"] == "https://warn.com"
        assert len(results[0].warnings) == 1
        assert "warn.com" in results[0].warnings[0]

    def test_no_urls_in_args(self):
        tc = _make_tool_call("echo", {"message": "hello"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
        ) as mock_eval:
            results = gate_tool_calls([tc], cfg=CFG)
        mock_eval.assert_not_called()
        assert results[0].urls_found == []

    def test_invalid_json_args_handled(self):
        tc = MagicMock()
        tc.id = "bad_call"
        tc.function.name = "broken"
        tc.function.arguments = "{not valid json"
        with patch("cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate"):
            results = gate_tool_calls([tc], cfg=CFG)
        assert results[0].urls_found == []

    def test_gate_unreachable_fail_open(self):
        tc = _make_tool_call("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=None,
        ):
            results = gate_tool_calls([tc], cfg=CFG)
        # fail-open: should not raise
        assert results[0].verdict is None

    def test_multiple_tool_calls(self):
        tc1 = _make_tool_call("fetch", {"url": "https://a.com"}, "c1")
        tc2 = _make_tool_call("fetch", {"url": "https://b.com"}, "c2")
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            results = gate_tool_calls([tc1, tc2], cfg=CFG)
        assert len(results) == 2

    def test_evidence_id_on_block(self):
        tc = _make_tool_call("fetch_page", {"url": "https://evil.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate) as exc_info:
                gate_tool_calls([tc], cfg=CFG)
        assert exc_info.value.evidence_id == "ev2"


# ---------------------------------------------------------------------------
# gate_tool_calls — async
# ---------------------------------------------------------------------------


class TestGateToolCallsAsync:
    @pytest.mark.asyncio
    async def test_allow_async(self):
        tc = _make_tool_call("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate_async",
            return_value=_allow_verdict(),
        ):
            results = await gate_tool_calls_async([tc], cfg=CFG)
        assert results[0].safe_arguments["url"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_block_async_raises(self):
        tc = _make_tool_call("fetch_page", {"url": "https://evil.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate_async",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate):
                await gate_tool_calls_async([tc], cfg=CFG)

    @pytest.mark.asyncio
    async def test_redact_async(self):
        tc = _make_tool_call("fetch_page", {"url": "https://suspicious.com"})
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate_async",
            return_value=_redact_verdict(),
        ):
            results = await gate_tool_calls_async([tc], cfg=CFG)
        assert results[0].safe_arguments["url"] == "[URL redacted by CyberArmor Trust Gate]"


# ---------------------------------------------------------------------------
# guard_response
# ---------------------------------------------------------------------------


class TestGuardResponse:
    def test_passes_through_no_tool_calls(self):
        resp = MagicMock()
        resp.choices = [MagicMock()]
        resp.choices[0].message.tool_calls = None
        result = guard_response(resp, cfg=CFG)
        assert result is resp

    def test_passes_through_allow(self):
        tc = _make_tool_call("fetch", {"url": "https://safe.com"})
        resp = _make_response([tc])
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            result = guard_response(resp, cfg=CFG)
        assert result is resp

    def test_raises_on_block(self):
        tc = _make_tool_call("fetch", {"url": "https://evil.com"})
        resp = _make_response([tc])
        with patch(
            "cyberarmor.frameworks.openai_url_trust_gate._Client.evaluate",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate):
                guard_response(resp, cfg=CFG)

    def test_extract_tool_calls_empty(self):
        resp = MagicMock()
        resp.choices = []
        assert _extract_tool_calls(resp) == []
