"""
The VectorGuard Web Agent loop: observe -> decide -> act, with hard caps.

This is what makes it an agent rather than a fixed pipeline. Each step:
  1. observe: summarize what has been found so far,
  2. decide: an LLM (or deterministic fallback) picks the next check from a
     constrained candidate list, or stops,
  3. act: the deterministic GET runner executes the chosen check and detectors
     judge the response.

Safety is unchanged and enforced on every action:
- bounded iterations (max_steps), no repeated checks,
- the model may only pick from real (template, endpoint) candidates - it can
  never invent endpoints or run anything destructive,
- scope and GET-only execution are re-validated by the runner,
- every decision and its evidence are recorded in an audit trace.

Retrieved guidance is untrusted reference text used to justify a choice; it is
never turned into an executed action.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from vectorguard.config.loader import load_yaml_file

from ..detectors import evaluate_detectors, validate_detector_specs
from ..evidence import save_evidence
from ..findings import build_finding
from ..generator import _apply_overrides
from ..loader import validate_web_test
from ..planner import (
    PORTSWIGGER_DIR,
    TEMPLATE_FILES,
    _select_templates,
    build_plan,
)
from ..runner import RunnerError, run_get_test
from ..scope import ScopeError, validate_scope
from .discovery import extract_links, fetch_seed
from .knowledge import build_guidance_block, retrieve_guidance
from .llm_planner import LLMClient, LLMUnavailableError, build_template_catalog
from .prompts import build_agent_decision_prompt

DEFAULT_MAX_STEPS = 6
DEFAULT_MAX_DISCOVERED = 5


def _build_candidates(
    config: dict[str, Any],
    templates_dir: Path,
) -> list[dict[str, Any]]:
    """Concrete, executable (GET) candidates: (template_id, owasp, WebTest)."""
    plan = build_plan(config, templates_dir=templates_dir)
    known_endpoints = [str(e) for e in (config.get("known_endpoints") or [])]

    candidates: list[dict[str, Any]] = []
    for entry in plan["selected_tests"]:
        data = load_yaml_file(entry["template_path"])
        _apply_overrides(entry["template_id"], data, known_endpoints)
        test = validate_web_test(data, where=entry["template_id"])
        candidates.append(
            {
                "template_id": entry["template_id"],
                "owasp": entry["owasp"],
                "test": test,
                "key": (entry["template_id"], test.request.path),
                "discovered": False,
            }
        )
    return candidates


def _candidate_from_endpoint(
    template_id: str,
    endpoint: str,
    templates_dir: Path,
    owasp: str,
) -> dict[str, Any]:
    """Build a concrete candidate binding a template to a discovered endpoint."""
    data = load_yaml_file(templates_dir / TEMPLATE_FILES[template_id])
    _apply_overrides(template_id, data, [endpoint])
    test = validate_web_test(data, where=template_id)
    return {
        "template_id": template_id,
        "owasp": owasp,
        "test": test,
        "key": (template_id, test.request.path),
        "discovered": True,
    }


def _discover_candidates(
    body_text: str,
    *,
    base_url: str,
    templates_dir: Path,
    catalog: dict[str, dict[str, Any]],
    candidates: list[dict[str, Any]],
    existing_keys: set[tuple[str, str]],
    discovered_paths: list[str],
    max_discovered: int,
) -> None:
    """
    Harvest same-origin links and add new executable candidates, in place.

    Bounded by ``max_discovered``. Only executable (GET) templates whose rules
    match the discovered path are added.
    """
    for path in extract_links(body_text, base_url=base_url):
        if len(discovered_paths) >= max_discovered:
            return
        if path in discovered_paths:
            continue
        discovered_paths.append(path)

        for template_id in _select_templates([path], []):
            meta = catalog.get(template_id)
            if not meta or not meta["executable_now"]:
                continue
            candidate = _candidate_from_endpoint(
                template_id, path, templates_dir, meta["owasp"]
            )
            if candidate["key"] in existing_keys:
                continue
            existing_keys.add(candidate["key"])
            candidates.append(candidate)


def _summarize(raw_results: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    if not raw_results:
        return "No checks have been run yet."

    lines = [
        f"{r['test_id']}: {r['request']['method']} {r['request']['path']} "
        f"-> status {r['response']['status_code']}, "
        f"length {r['response']['body_length']}"
        for r in raw_results
    ]
    lines.append(f"Findings so far: {[f['id'] for f in findings] or 'none'}")
    return "\n".join(lines)


def _guidance_query(remaining: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    parts = [c["owasp"] for c in remaining] + [c["template_id"] for c in remaining]
    if findings:
        parts.append(str(findings[-1].get("category", "")))
    return " ".join(parts)


def _decide(
    client: LLMClient | None,
    *,
    state_summary: str,
    remaining: list[dict[str, Any]],
    guidance: str,
) -> dict[str, Any]:
    """
    Decide the next action. Deterministic fallback picks the first remaining
    candidate. The LLM may only pick a remaining template_id or stop; anything
    else falls back to the first remaining candidate.
    """
    if client is None:
        return {
            "action": "run",
            "template_id": remaining[0]["template_id"],
            "reason": "deterministic sequential selection",
            "source": "deterministic",
        }

    candidate_view = [
        {
            "template_id": c["template_id"],
            "owasp": c["owasp"],
            "path": c["test"].request.path,
        }
        for c in remaining
    ]
    prompt = build_agent_decision_prompt(
        state_summary=state_summary,
        candidates=candidate_view,
        guidance=guidance,
    )

    try:
        raw = client.complete(prompt)
        data = json.loads(raw)
    except (LLMUnavailableError, TypeError, ValueError):
        return {
            "action": "run",
            "template_id": remaining[0]["template_id"],
            "reason": "fallback after LLM error",
            "source": "fallback",
        }

    if isinstance(data, dict) and data.get("action") == "stop":
        return {
            "action": "stop",
            "reason": str(data.get("reason", "model chose to stop")),
            "source": "llm",
        }

    template_id = data.get("template_id") if isinstance(data, dict) else None
    if any(c["template_id"] == template_id for c in remaining):
        return {
            "action": "run",
            "template_id": template_id,
            "reason": str(data.get("reason", "model selection")),
            "source": "llm",
        }

    return {
        "action": "run",
        "template_id": remaining[0]["template_id"],
        "reason": "fallback: model returned an invalid choice",
        "source": "fallback",
    }


def run_agent(
    config: dict[str, Any],
    *,
    out_dir: str | Path,
    client: LLMClient | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    discover: bool = False,
    max_discovered: int = DEFAULT_MAX_DISCOVERED,
    templates_dir: Path = PORTSWIGGER_DIR,
) -> dict[str, Any]:
    """
    Run the bounded agent loop and return aggregated results + an audit trace.

    Returns ``{trace, raw_results, detector_payloads, findings}``.
    """
    target = str(config.get("target") or "")
    scope = [str(s) for s in (config.get("scope") or [])]
    validate_scope(target, scope)  # ScopeError if target/scope invalid

    candidates = _build_candidates(config, templates_dir)
    strategy = "llm" if client is not None else "deterministic"

    catalog = build_template_catalog(templates_dir)
    existing_keys: set[tuple[str, str]] = {c["key"] for c in candidates}
    discovered_paths: list[str] = []

    # Seed discovery: one GET of the site root to harvest same-origin links.
    if discover:
        _discover_candidates(
            fetch_seed(target, scope),
            base_url=target,
            templates_dir=templates_dir,
            catalog=catalog,
            candidates=candidates,
            existing_keys=existing_keys,
            discovered_paths=discovered_paths,
            max_discovered=max_discovered,
        )

    executed: set[tuple[str, str]] = set()
    raw_results: list[dict[str, Any]] = []
    detector_payloads: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    stopped_reason = "completed all candidate checks"

    for step in range(1, max_steps + 1):
        remaining = [c for c in candidates if c["key"] not in executed]
        if not remaining:
            stopped_reason = "no remaining candidate checks"
            break

        guidance = build_guidance_block(
            retrieve_guidance(_guidance_query(remaining, findings), top_k=3)
        )
        decision = _decide(
            client,
            state_summary=_summarize(raw_results, findings),
            remaining=remaining,
            guidance=guidance,
        )

        if decision["action"] == "stop":
            stopped_reason = decision["reason"]
            steps.append({"step": step, "decision": decision})
            break

        chosen = next(c for c in remaining if c["template_id"] == decision["template_id"])
        test = chosen["test"]
        executed.add(chosen["key"])

        # Safety preflight before any request (defensive; templates are known).
        validate_detector_specs(test.detectors)

        try:
            raw_result, body_text = run_get_test(test=test, target=target, scope=scope)
        except (RunnerError, ScopeError, httpx.HTTPError) as error:
            steps.append({"step": step, "decision": decision, "error": str(error)})
            continue

        evidence_files = save_evidence(out_dir, raw_result, body_text)
        raw_result["evidence"] = evidence_files

        detector_results = evaluate_detectors(
            test.detectors,
            body_text=body_text,
            status_code=raw_result["response"]["status_code"],
            body_length=raw_result["response"]["body_length"],
        )
        finding = build_finding(
            test=test,
            raw_result=raw_result,
            detector_results=detector_results,
        )

        raw_results.append(raw_result)
        detector_payloads.append(
            {"test_id": test.id, "detector_results": detector_results}
        )
        if finding:
            findings.append(finding)

        # Harvest links from this response to expand the candidate set.
        if discover:
            _discover_candidates(
                body_text,
                base_url=target,
                templates_dir=templates_dir,
                catalog=catalog,
                candidates=candidates,
                existing_keys=existing_keys,
                discovered_paths=discovered_paths,
                max_discovered=max_discovered,
            )

        steps.append(
            {
                "step": step,
                "decision": decision,
                "action": {
                    "template_id": test.id,
                    "method": test.request.method,
                    "path": test.request.path,
                    "url": raw_result["request"]["url"],
                    "discovered": chosen["discovered"],
                },
                "result": {
                    "status_code": raw_result["response"]["status_code"],
                    "body_length": raw_result["response"]["body_length"],
                    "suspicious_detectors": [
                        d["detector"] for d in detector_results if d["suspicious"]
                    ],
                },
                "finding_id": finding["id"] if finding else None,
            }
        )

    trace = {
        "target": target,
        "scope": scope,
        "strategy": strategy,
        "max_steps": max_steps,
        "discovery_enabled": discover,
        "discovered_endpoints": discovered_paths,
        "steps_taken": len([s for s in steps if "action" in s]),
        "stopped_reason": stopped_reason,
        "steps": steps,
    }

    return {
        "trace": trace,
        "raw_results": raw_results,
        "detector_payloads": detector_payloads,
        "findings": findings,
    }
