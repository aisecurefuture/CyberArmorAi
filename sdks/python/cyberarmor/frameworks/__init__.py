"""CyberArmor framework integrations."""

from .langchain import CyberArmorCallbackHandler
from .llamaindex import CyberArmorInstrumentation
from .vercel_ai import CyberArmorVercelAI
from .openai_url_trust_gate import (
    GateConfig as OpenAIGateConfig,
    GatedToolCall,
    URLBlockedByTrustGate as OpenAIURLBlockedByTrustGate,
    gate_tool_calls,
    gate_tool_calls_async,
    guard_response as openai_guard_response,
    guard_response_async as openai_guard_response_async,
)
from .anthropic_url_trust_gate import (
    GateConfig as AnthropicGateConfig,
    GatedToolUse,
    URLBlockedByTrustGate as AnthropicURLBlockedByTrustGate,
    gate_tool_uses,
    gate_tool_uses_async,
    guard_response as anthropic_guard_response,
    guard_response_async as anthropic_guard_response_async,
)

__all__ = [
    # LangChain
    "CyberArmorCallbackHandler",
    # LlamaIndex
    "CyberArmorInstrumentation",
    # Vercel AI
    "CyberArmorVercelAI",
    # OpenAI tool-use URL Trust Gate
    "OpenAIGateConfig",
    "GatedToolCall",
    "OpenAIURLBlockedByTrustGate",
    "gate_tool_calls",
    "gate_tool_calls_async",
    "openai_guard_response",
    "openai_guard_response_async",
    # Anthropic tool-use URL Trust Gate
    "AnthropicGateConfig",
    "GatedToolUse",
    "AnthropicURLBlockedByTrustGate",
    "gate_tool_uses",
    "gate_tool_uses_async",
    "anthropic_guard_response",
    "anthropic_guard_response_async",
]
