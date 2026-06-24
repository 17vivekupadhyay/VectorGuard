"""
VectorGuard Web Agent.

A defensive, authorized OWASP-style web application security testing layer.

This package is additive and isolated from the LLM/RAG core. It maps known web
surfaces to safe, PortSwigger-inspired checks, runs scoped HTTP tests, captures
evidence, and generates remediation reports.

Phase 3 status: skeleton only. The CLI parses arguments, validates target/scope,
creates the output directory, and prints a dry-run summary. No HTTP requests are
sent.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
