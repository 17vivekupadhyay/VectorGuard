"""
Optional LLM planner interface for the VectorGuard Web Agent.

No LLM client is wired into the web agent in this phase, so ``get_llm_client``
returns ``None`` and ``plan_with_llm`` raises :class:`LLMUnavailableError`,
prompting the CLI to fall back to the deterministic planner. The project works
without any API keys.

The interface is intentionally small and mockable: a "client" is any object with
a ``complete(prompt: str) -> str`` method returning JSON text. Output is parsed
and strictly validated before use.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from ..loader import load_web_test
from ..planner import PORTSWIGGER_DIR, TEMPLATE_FILES
from ..scope import validate_scope
from .prompts import build_planner_prompt
from .schemas import LLMPlanValidationError, validate_llm_plan

FALLBACK_MESSAGE = "LLM planner unavailable; falling back to deterministic planner."


class LLMUnavailableError(RuntimeError):
    """Raised when no LLM client is configured for the web agent."""


class LLMClient(Protocol):
    """Minimal client interface: returns JSON text for a prompt."""

    def complete(self, prompt: str) -> str:  # pragma: no cover - interface only
        ...


def build_template_catalog(
    templates_dir: Path = PORTSWIGGER_DIR,
) -> dict[str, dict[str, Any]]:
    """Build template metadata used to constrain and validate LLM output."""
    catalog: dict[str, dict[str, Any]] = {}
    for template_id, filename in TEMPLATE_FILES.items():
        path = templates_dir / filename
        test = load_web_test(path)
        method = test.request.method.upper()
        catalog[template_id] = {
            "template_path": str(path),
            "owasp": test.owasp,
            "method": method,
            "requires_state_changing": test.requires_state_changing,
            "executable_now": method == "GET" and not test.requires_state_changing,
        }
    return catalog


def get_llm_client() -> LLMClient | None:
    """
    Return an LLM client for planning, or ``None`` if none is configured.

    The web agent does not wire a real client in this phase, so this returns
    ``None`` and callers fall back to the deterministic planner. A future
    integration can return a client implementing ``complete(prompt)``.
    """
    return None


def plan_with_llm(
    config: dict[str, Any],
    *,
    client: LLMClient | None = None,
    templates_dir: Path = PORTSWIGGER_DIR,
) -> dict[str, Any]:
    """
    Produce a plan using an LLM client.

    Raises :class:`LLMUnavailableError` when no client is configured, and
    :class:`LLMPlanValidationError` when the client's output is invalid.
    """
    if client is None:
        raise LLMUnavailableError(FALLBACK_MESSAGE)

    target = config.get("target")
    scope = config.get("scope") or []
    validate_scope(str(target), list(scope))

    known_endpoints = [str(e) for e in (config.get("known_endpoints") or [])]
    cookies = [str(c) for c in (config.get("cookies") or [])]
    catalog = build_template_catalog(templates_dir)

    prompt = build_planner_prompt(
        target=str(target),
        scope=list(scope),
        description=config.get("description", ""),
        known_endpoints=known_endpoints,
        cookies=cookies,
        template_catalog=catalog,
    )

    raw = client.complete(prompt)
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise LLMPlanValidationError(f"LLM output was not valid JSON: {error}")

    validated = validate_llm_plan(
        data,
        known_endpoints=known_endpoints,
        templates=catalog,
    )

    return {
        "target": str(target),
        "scope": list(scope),
        "description": config.get("description", ""),
        **validated,
    }
