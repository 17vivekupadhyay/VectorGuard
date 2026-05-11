from __future__ import annotations

import time
from typing import Any

import httpx

from .base import BaseTarget, TargetResponse


class OpenAILikeTarget(BaseTarget):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: float = 90.0,
        system_prompt: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.system_prompt = system_prompt

    def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _extract_text(self, data: dict[str, Any]) -> str:
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(f"Unexpected response shape: {data}") from exc

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
            return "\n".join(parts).strip()

        return str(content)

    def send_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        full_messages: list[dict[str, str]] = []

        if self.system_prompt:
            full_messages.append({"role": "system", "content": self.system_prompt})

        full_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": full_messages,
            "temperature": 0,
            "max_tokens": 300,
        }

        url = f"{self.base_url}/chat/completions"

        start = time.perf_counter()
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                url,
                headers=self._build_headers(),
                json=payload,
            )
        latency_ms = (time.perf_counter() - start) * 1000

        response.raise_for_status()
        data = response.json()
        text = self._extract_text(data)

        transcript = full_messages + [{"role": "assistant", "content": text}]

        return TargetResponse(
            text=text,
            status_code=response.status_code,
            latency_ms=latency_ms,
            raw=data,
            transcript=transcript,
        )