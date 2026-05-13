from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_mapping_no_duplicates(
    loader: yaml.Loader,
    node: yaml.Node,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)

        if key in mapping:
            raise ValueError(f"Duplicate YAML key found: {key}")

        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value

    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping_no_duplicates,
)


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.load(f, Loader=UniqueKeyLoader)

    if not isinstance(data, dict):
        raise ValueError(f"Expected top-level mapping/object in YAML file: {file_path}")

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