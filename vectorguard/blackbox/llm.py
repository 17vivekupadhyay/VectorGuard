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
        seed: int | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        # Reproducibility: with temperature=0 (and, where the provider honors it,
        # a fixed seed) repeated runs produce the same payloads — required for a
        # stable eval. Defaults keep the attacker varied; set via from_env.
        self.seed = seed

    def chat(self, system: str, user: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body: dict = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self.seed is not None:
            body["seed"] = self.seed
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
        # LLM_TEMPERATURE / LLM_SEED make runs reproducible for eval; both default
        # to the varied-attacker behavior when unset or unparseable.
        temperature = 1.0
        raw_temp = os.environ.get("LLM_TEMPERATURE")
        if raw_temp is not None:
            try:
                temperature = float(raw_temp)
            except ValueError:
                pass
        seed: int | None = None
        raw_seed = os.environ.get("LLM_SEED")
        if raw_seed is not None:
            try:
                seed = int(raw_seed)
            except ValueError:
                pass
        return cls(base, model, key, temperature=temperature, seed=seed)
