"""
Configuration helpers for the VectorGuard Web Agent.

Phase 3 builds :class:`ScanOptions` from parsed CLI arguments. A later phase adds
target-config YAML loading (target, scope, known_endpoints, cookies) for the
deterministic planner; that will reuse ``vectorguard.config.loader.load_yaml_file``
rather than re-implementing YAML parsing.
"""

from __future__ import annotations

from .models import ScanOptions
from .scope import normalize_scope


def build_scan_options(
    *,
    target: str | None,
    scope: str | list[str] | None,
    out_dir: str,
    tests: str | None = None,
    safe_mode: bool = True,
    allow_state_changing: bool = False,
) -> ScanOptions:
    """
    Build normalized :class:`ScanOptions` from CLI inputs.

    Presence of ``target`` and ``scope`` is validated here so every entry point
    fails early and consistently with a clear message.
    """
    if not target:
        raise ValueError("A target is required. Pass --target <url>.")

    if isinstance(scope, str):
        scope = [scope]

    normalized_scope = normalize_scope(scope)
    if not normalized_scope:
        raise ValueError("A scope is required. Pass --scope <host> for every scan.")

    return ScanOptions(
        target=target,
        scope=normalized_scope,
        out_dir=out_dir,
        tests=tests,
        safe_mode=safe_mode,
        allow_state_changing=allow_state_changing,
    )
