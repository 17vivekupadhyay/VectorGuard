"""
Real OpenAI-compatible LLM client for the VectorGuard Web Agent.

This is the optional model behind the planner and report summary. It reuses the
core ``OpenAILikeTarget`` chat client, so it adds no new dependencies and works
with any OpenAI-compatible endpoint via ``VG_WEBAGENT_LLM_BASE_URL``.

Key-free by default: if no API key is configured, ``build_llm_client_from_env``
returns ``None`` and callers fall back to the deterministic pipeline. Transport
or parse failures are surfaced as :class:`LLMUnavailableError` so the same
fallback path is used.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from ...targets.openai_like import OpenAILikeTarget
from .llm_planner import LLMUnavailableError

# repo root: agent -> webagent -> vectorguard -> <root>
_ROOT = Path(__file__).resolve().parents[3]

_SYSTEM_PROMPT = (
    "You are a careful, defensive AppSec assistant for VectorGuard Web Agent. "
    "Follow the user's instructions exactly. Use only the information provided in "
    "the prompt. Do not invent endpoints, evidence, or findings."
)


def _load_env() -> None:
    """Best-effort load of a local .env so API keys are picked up."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    env_path = _ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)


def _resolve_api_key() -> str | None:
    return (
        os.environ.get("VG_WEBAGENT_LLM_API_KEY")
        or os.environ.get("VG_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )


class OpenAICompatibleClient:
    """Adapts ``OpenAILikeTarget`` to the agent's ``complete(prompt) -> str``."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        max_tokens: int = 1200,
        timeout: float = 90.0,
    ) -> None:
        self._target = OpenAILikeTarget(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout=timeout,
            system_prompt=_SYSTEM_PROMPT,
            max_tokens=max_tokens,
        )

    def complete(self, prompt: str) -> str:
        try:
            response = self._target.send_messages(
                [{"role": "user", "content": prompt}]
            )
        except (httpx.HTTPError, ValueError) as error:
            raise LLMUnavailableError(
                f"LLM request failed ({error}); falling back to deterministic."
            )
        return response.text


def build_llm_client_from_env() -> OpenAICompatibleClient | None:
    """
    Build a client from environment variables, or ``None`` if unconfigured.

    Recognized variables:
      - VG_WEBAGENT_LLM_API_KEY / VG_API_KEY / OPENAI_API_KEY  (required)
      - VG_WEBAGENT_LLM_BASE_URL  (default: https://api.openai.com/v1)
      - VG_WEBAGENT_LLM_MODEL     (default: gpt-4o-mini)
      - VG_WEBAGENT_LLM_MAX_TOKENS (default: 1200)
    """
    _load_env()

    api_key = _resolve_api_key()
    if not api_key:
        return None

    base_url = os.environ.get(
        "VG_WEBAGENT_LLM_BASE_URL", "https://api.openai.com/v1"
    )
    model = os.environ.get("VG_WEBAGENT_LLM_MODEL", "gpt-4o-mini")
    try:
        max_tokens = int(os.environ.get("VG_WEBAGENT_LLM_MAX_TOKENS", "1200"))
    except ValueError:
        max_tokens = 1200

    return OpenAICompatibleClient(
        base_url=base_url,
        api_key=api_key,
        model=model,
        max_tokens=max_tokens,
    )
