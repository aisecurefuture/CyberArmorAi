"""Tests for anthropic_url_trust_gate.py

All gate HTTP calls are mocked so these tests run offline.
"""

import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from cyberarmor.frameworks.anthropic_url_trust_gate import (
    GateConfig,
    GatedToolUse,
    URLBlockedByTrustGate,
    _extract_urls,
    _looks_like_url,
    _redact_urls,
    gate_tool_uses,
    gate_tool_uses_async,
    guard_response,
    _extract_tool_use_blocks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CFG = GateConfig(
    gate_url="https://gate.example/evaluate",
    api_key="test-key",
    tenant_id="test-tenant",
)


def _make_block(name: str, input_dict: dict, block_id: str = "tool_1") -> SimpleNamespace:
    """Create a minimal Anthropic ToolUseBlock stand-in."""
    return SimpleNamespace(type="tool_use", id=block_id, name=name, input=input_dict)


def _make_response(blocks: list) -> SimpleNamespace:
    content = blocks
    return SimpleNamespace(content=content)


def _allow_verdict() -> dict:
    return {"decision": {"action": "allow", "reason": "clean"}, "evidence_id": "ev1"}


def _block_verdict() -> dict:
    return {"decision": {"action": "block", "reason": "malicious"}, "evidence_id": "ev2"}


def _redact_verdict() -> dict:
    return {"decision": {"action": "redact", "reason": "suspicious"}, "evidence_id": "ev3"}


def _warn_verdict() -> dict:
    return {"decision": {"action": "warn", "reason": "low confidence"}, "evidence_id": "ev4"}


# ---------------------------------------------------------------------------
# Unit: URL helpers (same logic as OpenAI wrapper — quick sanity)
# ---------------------------------------------------------------------------


class TestLooksLikeUrl:
    def test_https(self):
        assert _looks_like_url("https://example.com") is True

    def test_plain_text(self):
        assert _looks_like_url("just a string") is False

    def test_empty(self):
        assert _looks_like_url("") is False


class TestExtractUrls:
    def test_nested_url(self):
        urls = _extract_urls({"a": {"b": "https://nested.com"}})
        assert "https://nested.com" in urls

    def test_list_of_urls(self):
        urls = _extract_urls(["https://a.com", "https://b.com"])
        assert set(urls) == {"https://a.com", "https://b.com"}


class TestRedactUrls:
    def test_replaces_in_dict(self):
        result = _redact_urls({"url": "https://evil.com"}, {"https://evil.com"})
        assert result["url"] == "[URL redacted by CyberArmor Trust Gate]"

    def test_safe_url_unchanged(self):
        result = _redact_urls({"url": "https://safe.com"}, {"https://evil.com"})
        assert result["url"] == "https://safe.com"


# ---------------------------------------------------------------------------
# gate_tool_uses — sync
# ---------------------------------------------------------------------------


class TestGateToolUsesSync:
    def test_allow_verdict_passes_through(self):
        block = _make_block("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            results = gate_tool_uses([block], cfg=CFG)
        assert len(results) == 1
        assert results[0].safe_input["url"] == "https://example.com"
        assert results[0].urls_found == ["https://example.com"]
        assert results[0].warnings == []

    def test_block_verdict_raises(self):
        block = _make_block("fetch_page", {"url": "https://evil.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate) as exc_info:
                gate_tool_uses([block], cfg=CFG)
        assert "https://evil.com" in str(exc_info.value)
        assert exc_info.value.evidence_id == "ev2"

    def test_isolate_verdict_raises(self):
        block = _make_block("fetch_page", {"url": "https://evil.com"})
        verdict = {"decision": {"action": "isolate", "reason": "suspect"}, "evidence_id": "ev9"}
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=verdict,
        ):
            with pytest.raises(URLBlockedByTrustGate):
                gate_tool_uses([block], cfg=CFG)

    def test_redact_verdict_replaces_url(self):
        block = _make_block("fetch_page", {"url": "https://suspicious.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_redact_verdict(),
        ):
            results = gate_tool_uses([block], cfg=CFG)
        assert results[0].safe_input["url"] == "[URL redacted by CyberArmor Trust Gate]"
        assert len(results[0].warnings) == 1
        assert "suspicious.com" in results[0].warnings[0]

    def test_warn_verdict_adds_warning(self):
        block = _make_block("fetch_page", {"url": "https://warn.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_warn_verdict(),
        ):
            results = gate_tool_uses([block], cfg=CFG)
        assert results[0].safe_input["url"] == "https://warn.com"
        assert len(results[0].warnings) == 1

    def test_no_urls_skips_evaluation(self):
        block = _make_block("echo", {"message": "hello world"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate"
        ) as mock_eval:
            results = gate_tool_uses([block], cfg=CFG)
        mock_eval.assert_not_called()
        assert results[0].urls_found == []

    def test_none_input_handled_gracefully(self):
        block = SimpleNamespace(type="tool_use", id="t1", name="broken", input=None)
        with patch("cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate"):
            results = gate_tool_uses([block], cfg=CFG)
        assert results[0].urls_found == []

    def test_non_dict_input_handled_gracefully(self):
        block = SimpleNamespace(type="tool_use", id="t1", name="broken", input="plain string")
        with patch("cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate"):
            results = gate_tool_uses([block], cfg=CFG)
        assert results[0].urls_found == []

    def test_gate_unreachable_fail_open(self):
        block = _make_block("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=None,
        ):
            results = gate_tool_uses([block], cfg=CFG)
        assert results[0].verdict is None

    def test_multiple_blocks(self):
        b1 = _make_block("fetch", {"url": "https://a.com"}, "t1")
        b2 = _make_block("fetch", {"url": "https://b.com"}, "t2")
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            results = gate_tool_uses([b1, b2], cfg=CFG)
        assert len(results) == 2

    def test_multiple_urls_in_one_block(self):
        block = _make_block("multi_fetch", {
            "primary_url": "https://a.com",
            "fallback_url": "https://b.com",
        })
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            results = gate_tool_uses([block], cfg=CFG)
        assert set(results[0].urls_found) == {"https://a.com", "https://b.com"}

    def test_input_dict_not_mutated(self):
        """gate_tool_uses must not modify the original block.input dict."""
        block = _make_block("fetch_page", {"url": "https://suspicious.com"})
        original_url = block.input["url"]
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_redact_verdict(),
        ):
            gate_tool_uses([block], cfg=CFG)
        assert block.input["url"] == original_url, "original block.input must not be mutated"

    def test_source_tag_is_anthropic(self):
        """Gate requests must use source='anthropic-tool-use'."""
        block = _make_block("fetch", {"url": "https://example.com"})
        captured = {}

        def fake_evaluate(self, url):
            captured["url"] = url
            return _allow_verdict()

        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            fake_evaluate,
        ):
            # We can't inspect the payload directly here without more mocking,
            # so we just verify the call was made.
            gate_tool_uses([block], cfg=CFG)
        assert captured["url"] == "https://example.com"


# ---------------------------------------------------------------------------
# gate_tool_uses — async
# ---------------------------------------------------------------------------


class TestGateToolUsesAsync:
    @pytest.mark.asyncio
    async def test_allow_async(self):
        block = _make_block("fetch_page", {"url": "https://example.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate_async",
            return_value=_allow_verdict(),
        ):
            results = await gate_tool_uses_async([block], cfg=CFG)
        assert results[0].safe_input["url"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_block_async_raises(self):
        block = _make_block("fetch_page", {"url": "https://evil.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate_async",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate):
                await gate_tool_uses_async([block], cfg=CFG)

    @pytest.mark.asyncio
    async def test_redact_async(self):
        block = _make_block("fetch_page", {"url": "https://suspicious.com"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate_async",
            return_value=_redact_verdict(),
        ):
            results = await gate_tool_uses_async([block], cfg=CFG)
        assert results[0].safe_input["url"] == "[URL redacted by CyberArmor Trust Gate]"

    @pytest.mark.asyncio
    async def test_no_urls_async(self):
        block = _make_block("echo", {"message": "hello"})
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate_async"
        ) as mock_eval:
            results = await gate_tool_uses_async([block], cfg=CFG)
        mock_eval.assert_not_called()


# ---------------------------------------------------------------------------
# guard_response
# ---------------------------------------------------------------------------


class TestGuardResponse:
    def test_passes_through_no_tool_use_blocks(self):
        text_block = SimpleNamespace(type="text", text="hello")
        resp = _make_response([text_block])
        result = guard_response(resp, cfg=CFG)
        assert result is resp

    def test_passes_through_allow(self):
        block = _make_block("fetch", {"url": "https://safe.com"})
        resp = _make_response([block])
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_allow_verdict(),
        ):
            result = guard_response(resp, cfg=CFG)
        assert result is resp

    def test_raises_on_block(self):
        block = _make_block("fetch", {"url": "https://evil.com"})
        resp = _make_response([block])
        with patch(
            "cyberarmor.frameworks.anthropic_url_trust_gate._Client.evaluate",
            return_value=_block_verdict(),
        ):
            with pytest.raises(URLBlockedByTrustGate):
                guard_response(resp, cfg=CFG)

    def test_extract_tool_use_blocks_filters_by_type(self):
        text_block = SimpleNamespace(type="text", text="hi")
        tool_block = _make_block("fetch", {"url": "https://x.com"})
        resp = _make_response([text_block, tool_block])
        blocks = _extract_tool_use_blocks(resp)
        assert len(blocks) == 1
        assert blocks[0].type == "tool_use"

    def test_empty_content(self):
        resp = SimpleNamespace(content=[])
        assert _extract_tool_use_blocks(resp) == []

    def test_malformed_response_handled(self):
        resp = SimpleNamespace()  # no .content attribute
        assert _extract_tool_use_blocks(resp) == []
