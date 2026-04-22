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


class BaseTarget(ABC):
    @abstractmethod
    def send_prompt(self, prompt: str) -> TargetResponse:
        """Send one prompt to a target and return a normalized response."""
        raise NotImplementedError