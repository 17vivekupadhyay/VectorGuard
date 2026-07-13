"""Shared helpers for web agent commands."""

from __future__ import annotations

from pathlib import Path

from ..agent.report_agent import (
    AISummaryUnavailableError,
    FALLBACK_SUMMARY_MESSAGE,
    generate_ai_summary,
    load_scan_artifacts,
    placeholder_summary_markdown,
    save_agent_summary,
)
from ..agent import get_llm_client
from ..loader import WebTestValidationError, load_web_test
from ..models import WebTest


def load_web_test_or_report(tests_path: str) -> WebTest | None:
    """Load and validate a web test, printing a helpful error on failure."""
    try:
        return load_web_test(tests_path)
    except FileNotFoundError as error:
        print(f"Error: {error}")
    except WebTestValidationError as error:
        print(f"Error: invalid web test - {error}")
    except ValueError as error:
        # Raised by the shared YAML loader (e.g. duplicate keys, non-mapping).
        print(f"Error: could not parse YAML - {error}")
    return None


def maybe_write_ai_summary(out_path: Path) -> None:
    """
    Write agent_summary.md when --ai-summary is requested.

    Never fails the caller: on a missing scan or an unavailable LLM client it
    prints a helpful message and writes a placeholder summary instead.
    """
    try:
        artifacts = load_scan_artifacts(out_path)
    except FileNotFoundError as error:
        print(f"AI summary skipped: {error}")
        return

    try:
        text = generate_ai_summary(artifacts, client=get_llm_client())
        summary_path = save_agent_summary(out_path, text)
        print(f"\nAI summary written:\n  {summary_path}")
    except AISummaryUnavailableError:
        print(f"\n{FALLBACK_SUMMARY_MESSAGE}")
        summary_path = save_agent_summary(out_path, placeholder_summary_markdown(artifacts))
        print(f"Wrote placeholder summary:\n  {summary_path}")


def print_web_test_summary(test: WebTest) -> None:
    """Print a formatted summary of a web test's key attributes."""
    print(f"  id:       {test.id}")
    print(f"  name:     {test.name}")
    print(f"  category: {test.category}")
    print(f"  owasp:    {test.owasp}")
    print(f"  severity: {test.severity}")
    print(f"  safe:     {test.safe}")
    print(f"  requires_state_changing: {test.requires_state_changing}")
    print(f"  request:  {test.request.method} {test.request.path}")
    print(f"  detectors: {', '.join(d.type for d in test.detectors)}")


def print_scan_summary(options, out_path: Path, host: str) -> None:
    """Print a formatted summary of scan options and configuration."""
    safety_mode = "safe" if options.safe_mode else "unsafe"

    print("VectorGuard Web Agent - scan")
    print(f"  Target:        {options.target}")
    print(f"  Target host:   {host or '(could not parse)'}")
    print(f"  Scope:         {', '.join(options.scope)}")
    print(f"  In scope:      True (enforced)")
    print(f"  Tests:         {options.tests or '(none provided)'}")
    print(f"  Output dir:    {out_path}")
    print(f"  Safety mode:   {safety_mode}")
    print(f"  State-changing allowed: {options.allow_state_changing}")
    print(f"  Blocked methods (default): DELETE, PUT, PATCH")
