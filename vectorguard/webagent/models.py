"""
Typed models for the VectorGuard Web Agent.

Phase 3 introduces the minimal shapes used by the skeleton CLI. Later phases
expand these (detector configs, evidence, findings) without changing the public
names introduced here.

Safety constants live here so scope/runner logic in later phases share a single
source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# HTTP methods that are always blocked (destructive), regardless of flags.
DESTRUCTIVE_METHODS: frozenset[str] = frozenset({"DELETE", "PUT", "PATCH"})

# HTTP methods that are safe / read-only by default.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# State-changing methods allowed only when --allow-state-changing is passed.
STATE_CHANGING_METHODS: frozenset[str] = frozenset({"POST"})


@dataclass
class ScanOptions:
    """
    Normalized inputs for a Web Agent scan, as parsed from the CLI.

    Phase 3 only stores and echoes these; no requests are made.
    """

    target: str
    scope: list[str]
    out_dir: str
    tests: str | None = None
    safe_mode: bool = True
    allow_state_changing: bool = False
    extra: dict[str, object] = field(default_factory=dict)
