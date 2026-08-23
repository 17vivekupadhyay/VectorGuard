"""
VectorGuard Black-Box Agent.

A point-and-shoot, authorized black-box tester for chatbot endpoints. Given just
a URL (and a required ``--scope``), it auto-detects the chat API shape, then runs
the autonomous LLM-security battery — prompt injection, unbounded consumption,
sensitive-data disclosure, system-prompt leakage — using detection that needs no
target instrumentation:

- prompt injection: an injected canary the agent controls (deterministic proof)
- unbounded consumption: measured response size / latency
- sensitive disclosure: DLP / entropy on responses
- system-prompt leakage: heuristic phrasing (reported as "needs review")

It is defensive and authorization-first: the target host must match ``--scope``,
it is talk-only (chat messages, no tools/state changes), and it redacts secrets
in reports.
"""

from __future__ import annotations

from .adapter import AdapterError, AdapterResult, autodetect_target
from .campaign import BlackBoxResult, run_blackbox
from .oracle import Finding

__all__ = [
    "autodetect_target",
    "AdapterResult",
    "AdapterError",
    "run_blackbox",
    "BlackBoxResult",
    "Finding",
]
