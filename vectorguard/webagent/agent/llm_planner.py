"""
Optional LLM planner interface for the VectorGuard Web Agent.

``get_llm_client`` builds a real OpenAI-compatible client from environment
variables when an API key is configured, and returns ``None`` otherwise so the
CLI falls back to the deterministic planner. The project still works without any
API keys.

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
    Return an LLM client, or ``None`` if none is configured.

    Builds a real OpenAI-compatible client from environment variables when an
    API key is present; otherwise returns ``None`` so callers fall back to the
    deterministic pipeline. The import is local to avoid a module import cycle.
    """
    from .llm_client import build_llm_client_from_env

    return build_llm_client_from_env()


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
    description = config.get("description", "")
    catalog = build_template_catalog(templates_dir)

    # Ground the plan in retrieved OWASP/PortSwigger guidance for this surface.
    guidance = _retrieve_surface_guidance(
        description=description,
        known_endpoints=known_endpoints,
        cookies=cookies,
    )

    prompt = build_planner_prompt(
        target=str(target),
        scope=list(scope),
        description=description,
        known_endpoints=known_endpoints,
        cookies=cookies,
        template_catalog=catalog,
        guidance=guidance,
    )

    raw = client.complete(prompt)
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise LLMPlanValidationError(f"LLM output was not valid JSON: {error}") from error

    validated = validate_llm_plan(
        data,
        known_endpoints=known_endpoints,
        templates=catalog,
    )

    return {
        "target": str(target),
        "scope": list(scope),
        "description": description,
        **validated,
    }


def _retrieve_surface_guidance(
    *,
    description: str,
    known_endpoints: list[str],
    cookies: list[str],
) -> str:
    """
    Retrieve OWASP/PortSwigger guidance relevant to the surface.

    Best-effort: any retrieval problem yields an empty guidance block so the
    planner still works without the knowledge layer.
    """
    try:
        from .knowledge import build_guidance_block, retrieve_guidance

        query = " ".join([description, *known_endpoints, *cookies]).strip()
        if not query:
            return ""
        return build_guidance_block(retrieve_guidance(query, top_k=5))
    except Exception:
        return ""
