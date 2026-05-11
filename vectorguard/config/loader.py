from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Expected top-level mapping/object in config file: {file_path}")

    return data


def get_by_path(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"Missing placeholder path: {path}")
        current = current[part]
    return current


def resolve_string(template: str, context: dict[str, Any]) -> str:
    def replacer(match: re.Match[str]) -> str:
        key = match.group(1)
        value = get_by_path(context, key)
        return str(value)

    return PLACEHOLDER_RE.sub(replacer, template)


def resolve_placeholders(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return resolve_string(value, context)

    if isinstance(value, list):
        return [resolve_placeholders(item, context) for item in value]

    if isinstance(value, dict):
        return {k: resolve_placeholders(v, context) for k, v in value.items()}

    return value