"""
Deterministic executor: the only thing that actually touches the target.

It sends the running conversation, measures the response (tokens, latency, size),
and enforces this milestone's safety contract:

- TALK-ONLY: only chat messages are sent. No tool calls, no state-changing
  requests, no corpus writes exist on this path at all.
- Input guard: refuses to send an absurdly large conversation, so the agent
  cannot be turned into a load generator against the target.

Token usage is read from the provider's ``usage`` block when present (OpenAI-like
responses include it) and otherwise estimated, so the unbounded-consumption
oracle has a signal on any backend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vectorguard.targets.base import BaseTarget, TargetResponse


class SafetyError(RuntimeError):
    """Raised when an action would violate the executor's safety tier."""


# Generous ceiling on what we will ever send in one conversation (chars).
_MAX_CONVERSATION_CHARS = 200_000


def _estimate_tokens(text: str) -> int:
    # ~4 chars/token is the usual rough rule for English text.
    return max(1, len(text or "") // 4)


def _usage_from_raw(raw: dict[str, Any]) -> dict[str, int | None]:
    usage = raw.get("usage") if isinstance(raw, dict) else None
    if not isinstance(usage, dict):
        return {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None}
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
    }


class Executor:
    """Sends conversations to the target and returns ``(response, meta)``."""

    def __init__(
        self,
        target: "BaseTarget",
        *,
        safety_tier: str = "observe",
        max_conversation_chars: int = _MAX_CONVERSATION_CHARS,
    ) -> None:
        if safety_tier != "observe":
            # Future tiers ("sandbox"/"live") will gate tool execution and state
            # changes. This milestone is talk-only by construction.
            raise SafetyError(
                f"safety_tier {safety_tier!r} not supported in talk-only milestone"
            )
        self._target = target
        self._safety_tier = safety_tier
        self._max_conversation_chars = max_conversation_chars

    def send(
        self, conversation: list[dict[str, str]]
    ) -> tuple["TargetResponse", dict[str, Any]]:
        total_chars = sum(len(turn.get("content") or "") for turn in conversation)
        if total_chars > self._max_conversation_chars:
            raise SafetyError(
                f"conversation too large to send ({total_chars} chars); refusing "
                "to act as a load generator"
            )

        response = self._target.send_messages(conversation)

        usage = _usage_from_raw(getattr(response, "raw", {}) or {})
        char_len = len(response.text or "")
        completion_tokens = usage["completion_tokens"]
        if completion_tokens is None:
            completion_tokens = _estimate_tokens(response.text)

        meta: dict[str, Any] = {
            "char_len": char_len,
            "latency_ms": round(float(getattr(response, "latency_ms", 0.0)), 2),
            "status_code": getattr(response, "status_code", None),
            "prompt_tokens": usage["prompt_tokens"],
            "completion_tokens": completion_tokens,
            "total_tokens": usage["total_tokens"],
            "tokens_estimated": usage["completion_tokens"] is None,
        }
        return response, meta
