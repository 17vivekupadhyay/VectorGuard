"""
Provider-agnostic LLM client for the black-box operator (httpx, OpenAI-compatible).

Configure via env (any OpenAI-compatible /chat/completions endpoint):

  * OpenAI : LLM_BASE_URL=https://api.openai.com/v1  LLM_MODEL=gpt-4o-mini  LLM_API_KEY=sk-...
  * Local  : LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=llama3.1     (Ollama, no key)

If unconfigured or a call fails, the operator falls back to the deterministic
payload battery, so the agent always runs.
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
        temperature: float = 1.0,
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
            resp = httpx.post(f"{self.base_url}/chat/completions", json=body,
                              headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as error:
            raise LLMUnavailable(str(error)) from error

    def describe(self) -> str:
        return f"{self.model} @ {self.base_url}"

    @classmethod
    def from_env(cls) -> LLMClient | None:
        base = os.environ.get("LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
        model = os.environ.get("LLM_MODEL") or os.environ.get("OPENAI_MODEL")
        key = (os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
               or os.environ.get("VG_API_KEY"))
        if not base or not model:
            return None
        return cls(base, model, key)
