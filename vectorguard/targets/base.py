from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetResponse:
    text: str
    status_code: int
    latency_ms: float
    raw: dict[str, Any] = field(default_factory=dict)
    transcript: list[dict[str, str]] = field(default_factory=list)


class BaseTarget(ABC):
    @abstractmethod
    def send_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        """Send a conversation to a target and return a normalized response."""
        raise NotImplementedError

    def send_prompt(self, prompt: str) -> TargetResponse:
        return self.send_messages([{"role": "user", "content": prompt}])