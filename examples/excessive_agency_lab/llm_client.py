"""
Minimal, provider-agnostic LLM client for the red-team operator.

Talks to any OpenAI-compatible /chat/completions endpoint over httpx (already a
VectorGuard dependency), so it works with:

  * OpenAI            LLM_BASE_URL=https://api.openai.com/v1  LLM_MODEL=gpt-4o-mini  LLM_API_KEY=sk-...
  * A free local model (no key), e.g. Ollama:
                      LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=llama3.1
  * LM Studio / vLLM / any OpenAI-compatible server.

If no endpoint is configured (or a call fails), the operator falls back to the
deterministic tactic ladder, so the lab always runs key-free.
"""

from __future__ import annotations

import os

import httpx


class LLMUnavailable(RuntimeError):
    """Raised when the LLM cannot be reached or returns an unusable response."""


class LLMClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        *,
        timeout: float = 60.0,
        temperature: float = 0.9,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature

    def chat(self, system: str, user: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                json=body,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as error:
            raise LLMUnavailable(str(error)) from error

    def describe(self) -> str:
        return f"{self.model} @ {self.base_url}"

    @classmethod
    def from_env(cls) -> LLMClient | None:
        """Build a client from env, or return None if not configured."""
        base = os.environ.get("LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
        model = os.environ.get("LLM_MODEL") or os.environ.get("OPENAI_MODEL")
        key = (
            os.environ.get("LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("VG_API_KEY")
        )
        if not base or not model:
            return None
        return cls(base, model, key)
