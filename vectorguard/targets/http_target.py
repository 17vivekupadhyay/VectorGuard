from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import httpx

from .base import BaseTarget, TargetResponse

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


class HTTPAppTarget(BaseTarget):
    """
    Generic HTTP target for testing real chatbot/RAG app endpoints.

    Example config:

    target:
      type: http
      url: "http://localhost:8000/chat"
      method: POST
      headers:
        Content-Type: "application/json"
        Authorization: "Bearer {{env.APP_API_KEY}}"
      body_template:
        message: "{{prompt}}"
      response_path: "answer"
    """

    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: dict[str, Any] | None = None,
        body_template: dict[str, Any] | None = None,
        response_path: str | None = None,
        timeout: float = 90.0,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.body_template = body_template or {"message": "{{prompt}}"}
        self.response_path = response_path
        self.timeout = timeout

    def send_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        prompt = self._messages_to_prompt(messages)
        last_user_message = self._last_user_message(messages)

        context = {
            "prompt": prompt,
            "last_user_message": last_user_message,
            "messages": messages,
            "messages_json": json.dumps(messages),
        }

        headers = self._render_template(self.headers, context)
        body = self._render_template(self.body_template, context)

        start = time.perf_counter()

        with httpx.Client(timeout=self.timeout) as client:
            response = client.request(
                method=self.method,
                url=self.url,
                headers=headers,
                json=body if self.method in {"POST", "PUT", "PATCH"} else None,
                params=body if self.method == "GET" else None,
            )

        latency_ms = (time.perf_counter() - start) * 1000
        response.raise_for_status()

        raw = self._parse_response(response)
        text = self._extract_text(raw, response)

        transcript = messages + [{"role": "assistant", "content": text}]

        return TargetResponse(
            text=text,
            status_code=response.status_code,
            latency_ms=latency_ms,
            raw=raw if isinstance(raw, dict) else {"raw": raw},
            transcript=transcript,
        )

    def _messages_to_prompt(self, messages: list[dict[str, str]]) -> str:
        return "\n\n".join(
            f"{message.get('role', 'user')}: {message.get('content', '')}"
            for message in messages
        )

    def _last_user_message(self, messages: list[dict[str, str]]) -> str:
        for message in reversed(messages):
            if message.get("role") == "user":
                return message.get("content", "")
        return messages[-1].get("content", "") if messages else ""

    def _parse_response(self, response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "")

        if "application/json" in content_type:
            return response.json()

        try:
            return response.json()
        except ValueError:
            return response.text

    def _extract_text(self, raw: Any, response: httpx.Response) -> str:
        if self.response_path:
            value = self._get_by_path(raw, self.response_path)
            return str(value)

        if isinstance(raw, str):
            return raw

        if isinstance(raw, dict):
            for path in [
                "answer",
                "response",
                "text",
                "message",
                "output",
                "content",
                "data.answer",
                "choices.0.message.content",
            ]:
                try:
                    value = self._get_by_path(raw, path)
                    if value is not None:
                        return str(value)
                except (KeyError, IndexError, TypeError):
                    continue

        return response.text

    def _get_by_path(self, data: Any, path: str) -> Any:
        current = data

        for part in path.split("."):
            if isinstance(current, list):
                current = current[int(part)]
            elif isinstance(current, dict):
                if part not in current:
                    raise KeyError(f"Missing response path: {path}")
                current = current[part]
            else:
                raise TypeError(f"Cannot access path '{path}' in non-container value")

        return current

    def _render_template(self, value: Any, context: dict[str, Any]) -> Any:
        if isinstance(value, str):
            return self._render_string(value, context)

        if isinstance(value, list):
            return [self._render_template(item, context) for item in value]

        if isinstance(value, dict):
            return {
                key: self._render_template(item, context)
                for key, item in value.items()
            }

        return value

    def _render_string(self, value: str, context: dict[str, Any]) -> Any:
        exact_match = PLACEHOLDER_RE.fullmatch(value)

        if exact_match:
            return self._resolve_placeholder(exact_match.group(1), context)

        def replacer(match: re.Match[str]) -> str:
            resolved = self._resolve_placeholder(match.group(1), context)
            return str(resolved)

        return PLACEHOLDER_RE.sub(replacer, value)

    def _resolve_placeholder(self, key: str, context: dict[str, Any]) -> Any:
        if key.startswith("env."):
            env_key = key.removeprefix("env.")
            return os.environ.get(env_key, "")

        if key in context:
            return context[key]

        raise KeyError(f"Unknown HTTP target placeholder: {key}")