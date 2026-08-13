"""
Auto-adapter: turn a bare chatbot URL into a working target with no config.

It probes a battery of common request shapes with a benign message and keeps the
first that returns a coherent reply. Response extraction is delegated to
``HTTPAppTarget``, which already tries the common response fields
(answer/response/text/message/output/content/choices.0.message.content).

This is what makes "just a URL" work for standard JSON chat APIs. It cannot
handle authenticated APIs without credentials, custom/binary protocols, or
chatbots that exist only as a browser widget — pass an explicit target config for
those.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vectorguard.targets.http_target import HTTPAppTarget

DEFAULT_PROBE = "Hello! In one sentence, what can you help me with?"

# Ordered by prevalence; the first shape that yields a coherent reply wins.
_POST_BODY_CANDIDATES: list[tuple[str, dict[str, str]]] = [
    ("message", {"message": "{{prompt}}"}),
    ("prompt", {"prompt": "{{prompt}}"}),
    ("input", {"input": "{{prompt}}"}),
    ("query", {"query": "{{prompt}}"}),
    ("text", {"text": "{{prompt}}"}),
    ("question", {"question": "{{prompt}}"}),
    ("q", {"q": "{{prompt}}"}),
]
_GET_PARAM_CANDIDATES: list[str] = ["message", "q", "query", "input"]

# Substrings that betray an error/placeholder body rather than a real reply.
_ERROR_MARKERS = (
    '"error"', "missing", "required", "not found", "bad request",
    "<html", "<!doctype", "method not allowed", "unsupported",
)


class AdapterError(RuntimeError):
    """Raised when no request shape produces a usable chat response."""


@dataclass
class AdapterResult:
    target: HTTPAppTarget
    method: str
    body_key: str
    confidence: str  # "high" | "medium"
    sample_reply: str
    tried: list[str] = field(default_factory=list)

    def describe(self) -> str:
        return (f"{self.method} body[{self.body_key}] -> auto response field "
                f"(confidence: {self.confidence})")


def _looks_like_reply(text: str, probe: str) -> bool:
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 2:
        return False
    low = stripped.lower()
    if stripped == probe:
        return False
    return not any(marker in low for marker in _ERROR_MARKERS)


def autodetect_target(
    url: str,
    *,
    probe: str = DEFAULT_PROBE,
    timeout: float = 15.0,
) -> AdapterResult:
    """Probe ``url`` and return a working target, or raise ``AdapterError``."""
    tried: list[str] = []

    for key, body in _POST_BODY_CANDIDATES:
        tried.append(f"POST {key}")
        target = HTTPAppTarget(url=url, method="POST", body_template=body, timeout=timeout)
        try:
            reply = target.send_prompt(probe)
        except Exception:  # noqa: BLE001 - probing: any failure just means "next shape"
            continue
        if _looks_like_reply(reply.text, probe):
            return AdapterResult(target, "POST", key, "high", reply.text[:200], tried)

    for key in _GET_PARAM_CANDIDATES:
        tried.append(f"GET {key}")
        target = HTTPAppTarget(url=url, method="GET", body_template={key: "{{prompt}}"},
                               timeout=timeout)
        try:
            reply = target.send_prompt(probe)
        except Exception:  # noqa: BLE001
            continue
        if _looks_like_reply(reply.text, probe):
            return AdapterResult(target, "GET", key, "medium", reply.text[:200], tried)

    raise AdapterError(
        f"Could not auto-detect a chat API at {url}. Tried: {', '.join(tried)}. "
        f"Pass an explicit --target config for authenticated or non-standard endpoints."
    )
