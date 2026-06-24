"""
Optional AI-assisted planning for the VectorGuard Web Agent.

The deterministic planner remains the default and the project works without any
API keys. This subpackage provides the *interface* for an optional LLM planner
whose output is strictly validated against known template IDs and known
endpoints, and which falls back to the deterministic planner on any problem.

The LLM only plans. It never sends requests and never invents endpoints,
evidence, or unsupported tests.
"""

from __future__ import annotations

__all__ = [
    "LLMPlanValidationError",
    "LLMUnavailableError",
    "FALLBACK_MESSAGE",
    "get_llm_client",
    "plan_with_llm",
]

from .llm_planner import (
    FALLBACK_MESSAGE,
    LLMUnavailableError,
    get_llm_client,
    plan_with_llm,
)
from .schemas import LLMPlanValidationError
