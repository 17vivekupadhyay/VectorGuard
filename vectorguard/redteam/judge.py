"""
LLM-as-judge: a recall layer for the capture oracle.

Deterministic detectors (exact flag / DLP / budget) remain authoritative. The
judge only adds recall for paraphrased, partial, or encoded wins that exact
matching would miss. It returns a calibrated confidence; the oracle decides
whether that clears the capture threshold.

Reuses the web agent's OpenAI-compatible client, so it adds no new dependency
and degrades gracefully: with no API key configured, ``build_judge_from_env``
returns ``None`` and the pipeline runs deterministic-only.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from .prompts import build_judge_prompt

if TYPE_CHECKING:  # avoid importing the client at module load / on the no-key path
    from vectorguard.webagent.agent.llm_client import OpenAICompatibleClient

    from .objectives import Objective


_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(raw: str) -> dict[str, Any] | None:
    """Parse the first JSON object out of a model reply, tolerating prose."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        pass
    match = _JSON_RE.search(raw)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


class Judge:
    """Wraps an LLM client to grade whether a response satisfies an objective."""

    def __init__(self, client: OpenAICompatibleClient) -> None:
        self._client = client

    def assess(
        self,
        *,
        objective: Objective,
        payload: str,
        response_text: str,
    ) -> dict[str, Any] | None:
        """Return ``{success, confidence, rationale}`` or ``None`` on failure."""
        prompt = build_judge_prompt(
            objective_goal=objective.goal,
            objective_description=objective.description,
            payload=payload,
            response_text=response_text,
        )
        try:
            raw = self._client.complete(prompt)
        except Exception:
            # Any transport/parse failure => judge silently unavailable for this
            # call; deterministic capture still applies.
            return None

        data = _extract_json(raw)
        if not data:
            return None

        success = bool(data.get("success"))
        try:
            confidence = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        return {
            "success": success,
            "confidence": confidence,
            "rationale": str(data.get("rationale", "")).strip(),
        }

    def bind(self, payload: str):
        """Return a ``JudgeFn`` (objective, response_text) -> verdict for a step."""

        def _fn(objective: Objective, response_text: str) -> dict[str, Any] | None:
            return self.assess(
                objective=objective,
                payload=payload,
                response_text=response_text,
            )

        return _fn


def build_judge_from_env() -> Judge | None:
    """Build a judge from env (shared LLM config), or ``None`` if unconfigured."""
    from vectorguard.webagent.agent.llm_client import build_llm_client_from_env

    client = build_llm_client_from_env()
    if client is None:
        return None
    return Judge(client)
