"""
Seed library: the existing 23 YAML tests become starting payloads and few-shot
knowledge for the attacker, retrieved by objective category.

The seeds are NOT the test list - the operator adapts and escalates beyond them.
They give the attacker a realistic starting point and examples of what a good
payload looks like for each OWASP category.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vectorguard.config.loader import load_yaml_file

# Map test-suite categories onto red-team objective ids.
_CATEGORY_TO_OBJECTIVE: dict[str, str] = {
    "prompt_injection": "prompt_injection_obey",
    "rag_injection": "prompt_injection_obey",
    "authority_spoofing": "prompt_injection_obey",
    "system_prompt_leakage": "system_prompt_leak",
    "prompt_leakage": "system_prompt_leak",
    "sensitive_data_disclosure": "credential_exfil",
    "sensitive_information_disclosure": "credential_exfil",
    "indirect_leakage": "credential_exfil",
    "unbounded_consumption": "unbounded_consumption",
}


def _seed_text(test: dict[str, Any]) -> str:
    """Extract a representative payload string from a test case."""
    if "prompt" in test and isinstance(test["prompt"], str):
        return test["prompt"].strip()
    if "steps" in test and isinstance(test["steps"], list):
        return "\n".join(
            str(step.get("content", "")).strip()
            for step in test["steps"]
            if isinstance(step, dict)
        ).strip()
    return ""


def load_seeds(seeds_dir: str | Path) -> list[dict[str, Any]]:
    """Load every test case under ``seeds_dir`` as a seed record.

    Best-effort: malformed or unrelated YAML files are skipped so the agent
    still runs with whatever seeds are available (including none).
    """
    root = Path(seeds_dir)
    seeds: list[dict[str, Any]] = []

    if not root.exists():
        return seeds

    files = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
    for path in files:
        try:
            data = load_yaml_file(path)
        except (ValueError, FileNotFoundError):
            continue

        tests = data.get("tests")
        if not isinstance(tests, list):
            continue

        for test in tests:
            if not isinstance(test, dict):
                continue
            text = _seed_text(test)
            if not text:
                continue
            category = str(test.get("category", "unknown"))
            seeds.append(
                {
                    "name": test.get("name", "seed"),
                    "category": category,
                    "objective": _CATEGORY_TO_OBJECTIVE.get(category),
                    "owasp_id": test.get("owasp_id"),
                    "text": text,
                }
            )

    return seeds


def seeds_for_objective(
    seeds: list[dict[str, Any]],
    objective_id: str,
    *,
    k: int = 4,
) -> list[dict[str, Any]]:
    """Return up to ``k`` seeds whose category maps to this objective."""
    matched = [seed for seed in seeds if seed.get("objective") == objective_id]
    return matched[:k]
