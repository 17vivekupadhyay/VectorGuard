"""Shared YAML loader: duplicate-key rejection + placeholder resolution."""

from __future__ import annotations

import pytest

from vectorguard.config.loader import load_yaml_file, resolve_string


def test_duplicate_keys_rejected(tmp_path):
    path = tmp_path / "dup.yaml"
    path.write_text("a: 1\na: 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_yaml_file(path)


def test_loads_valid_mapping(tmp_path):
    path = tmp_path / "ok.yaml"
    path.write_text("a: 1\nb:\n  c: 2\n", encoding="utf-8")
    data = load_yaml_file(path)
    assert data["a"] == 1
    assert data["b"]["c"] == 2


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_yaml_file(tmp_path / "nope.yaml")


def test_resolve_string_substitutes_dotted_path():
    ctx = {"protected": {"secret_token": "CANARY"}}
    assert resolve_string("token={{protected.secret_token}}", ctx) == "token=CANARY"


def test_resolve_string_missing_placeholder_raises():
    with pytest.raises(KeyError):
        resolve_string("{{protected.missing}}", {"protected": {}})
