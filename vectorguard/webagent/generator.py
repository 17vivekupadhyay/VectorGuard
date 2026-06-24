"""
Test generation for the VectorGuard Web Agent.

Reads a target config, builds the deterministic plan, and renders concrete YAML
test files: executable GET tests under ``generated_tests/`` and gated
state-changing tests under ``generated_tests/gated/``.

Generation only writes files. It never sends HTTP requests and never modifies
the original templates. Generated tests remain valid for the ``validate``
command.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import yaml

from vectorguard.config.loader import load_yaml_file

from .planner import PORTSWIGGER_DIR, build_plan, save_plan


def _endpoint_path_and_params(endpoint: str) -> tuple[str, dict[str, str]]:
    """Split a known endpoint into a path and a safe SQLi probe param map.

    Each query parameter value is replaced with a single quote to surface a
    database error (no value extraction).
    """
    parts = urlsplit(endpoint)
    path = parts.path or endpoint
    params = {key: "'" for key in parse_qs(parts.query)}
    return path, params


def _find_endpoint(endpoints: list[str], needle: str) -> str | None:
    for endpoint in endpoints:
        if needle in endpoint:
            return endpoint
    return None


def _apply_overrides(
    template_id: str,
    data: dict[str, Any],
    known_endpoints: list[str],
) -> None:
    """Override request path/params for GET templates from known endpoints."""
    request = data.setdefault("request", {})

    if template_id == "access_control_forced_browsing_admin":
        endpoint = _find_endpoint(known_endpoints, "/admin")
        if endpoint:
            path, _ = _endpoint_path_and_params(endpoint)
            request["path"] = path

    elif template_id == "injection_sqli_basic_error_probe":
        endpoint = _find_endpoint(known_endpoints, "?")
        if endpoint:
            path, params = _endpoint_path_and_params(endpoint)
            request["path"] = path
            if params:
                request["params"] = params

    elif template_id == "jwt_cookie_shape_check":
        endpoint = _find_endpoint(known_endpoints, "my-account")
        if endpoint:
            path, _ = _endpoint_path_and_params(endpoint)
            request["path"] = path


def _write_generated(
    entry: dict[str, Any],
    dest_dir: Path,
    *,
    prefix: str,
    known_endpoints: list[str],
    config_path: str,
) -> str:
    """Render one generated YAML test file and return its path."""
    template_id = entry["template_id"]
    data = load_yaml_file(entry["template_path"])

    if entry.get("executable_now"):
        _apply_overrides(template_id, data, known_endpoints)

    # Append generation provenance (ignored by the validator's required-field
    # checks, kept for traceability).
    data["generated"] = {
        "generated_from": entry["template_path"],
        "reason": entry["reason"],
        "executable_now": entry["executable_now"],
        "target_config": config_path,
    }

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"{prefix}{template_id}.yaml"
    with dest_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)

    return str(dest_path)


def generate_tests(
    config: dict[str, Any],
    *,
    config_path: str,
    out_dir: str | Path,
    templates_dir: Path = PORTSWIGGER_DIR,
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """
    Build the plan and write generated YAML tests.

    Returns ``(plan, written)`` where ``written`` has ``executable`` and
    ``gated`` lists of file paths.
    """
    plan = build_plan(config, templates_dir=templates_dir)
    known_endpoints = [str(e) for e in (config.get("known_endpoints") or [])]

    out_path = Path(out_dir)
    generated_dir = out_path / "generated_tests"
    gated_dir = generated_dir / "gated"

    save_plan(out_path, plan)

    written: dict[str, list[str]] = {"executable": [], "gated": []}

    for entry in plan["selected_tests"]:
        written["executable"].append(
            _write_generated(
                entry,
                generated_dir,
                prefix="generated_",
                known_endpoints=known_endpoints,
                config_path=config_path,
            )
        )

    for entry in plan["gated_tests"]:
        written["gated"].append(
            _write_generated(
                entry,
                gated_dir,
                prefix="gated_",
                known_endpoints=known_endpoints,
                config_path=config_path,
            )
        )

    return plan, written
