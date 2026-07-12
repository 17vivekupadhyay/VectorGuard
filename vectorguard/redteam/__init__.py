"""
VectorGuard autonomous LLM red-team agent.

An LLM-driven attacker that reasons about a target chatbot, generates and adapts
its own attack payloads, and pursues OWASP-LLM objectives until a deterministic
oracle confirms it holds proof of exploitation - or the per-objective budget is
exhausted.

Design contract (from CLAUDE.md): the LLM *plans and generates* attacks;
deterministic Python *executes* them and *judges* capture. The LLM never
declares a win - the capture oracle does, by holding actual proof (a planted
flag, a DLP match, or a measured budget breach).

This milestone is talk-only: the operator may only send chat messages. There is
no tool execution, no state change, and no corpus write. Hard response caps are
enforced by the executor.
"""

from __future__ import annotations

from .analyst import Analyst, Assessment
from .campaign import run_campaign
from .episode import run_episode
from .objectives import (
    DEFAULT_INJECTION_CANARY,
    DEFAULT_PLANTED_SECRET,
    DEFAULT_SYSTEM_MARKER,
    CaptureResult,
    Objective,
    ObjectiveConfig,
    build_objectives,
)
from .operator import Operator
from .judge import Judge, build_judge_from_env

__all__ = [
    "run_campaign",
    "run_episode",
    "Operator",
    "Analyst",
    "Assessment",
    "Judge",
    "build_judge_from_env",
    "Objective",
    "ObjectiveConfig",
    "CaptureResult",
    "build_objectives",
    "DEFAULT_SYSTEM_MARKER",
    "DEFAULT_PLANTED_SECRET",
    "DEFAULT_INJECTION_CANARY",
]
