"""
Scope and host validation for the VectorGuard Web Agent.

This is the authoritative scope safety layer. Before any request is ever made
(Phase 6 and later), the target host must match the explicit ``--scope``
allowlist. ``localhost`` and ``127.0.0.1`` are allowed only when they are
explicitly scoped; nothing is auto-allowed.

No HTTP requests are made here. These are pure functions so they can be reasoned
about and verified directly from the CLI.
"""

from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target host is missing, unparseable, or out of scope."""


def normalize_host(host: str | None) -> str:
    """Lowercase and strip a host string."""
    if not host:
        return ""
    return host.strip().lower()


def extract_host(target: str) -> str:
    """
    Extract the host (without port) from a target URL.

    Examples:
        http://localhost:5000      -> "localhost"
        http://127.0.0.1:8080/path -> "127.0.0.1"
        localhost:5000             -> "localhost"
    """
    if not target:
        return ""

    candidate = target if "://" in target else f"http://{target}"
    return normalize_host(urlparse(candidate).hostname)


def normalize_scope_entry(entry: str) -> str:
    """
    Normalize a single scope entry to a bare host.

    Accepts bare hosts ("localhost"), host:port, or full URLs and reduces each
    to a lowercase host so scope matching is consistent with target parsing.
    """
    entry = (entry or "").strip()
    if not entry:
        return ""

    if "://" in entry:
        return extract_host(entry)

    # host:port or bare host
    return extract_host(entry)


def normalize_scope(scope: list[str] | None) -> list[str]:
    """Normalize a list of scope entries to bare hosts, dropping blanks."""
    if not scope:
        return []

    normalized: list[str] = []
    for entry in scope:
        host = normalize_scope_entry(entry)
        if host and host not in normalized:
            normalized.append(host)
    return normalized


def is_in_scope(target: str, scope: list[str]) -> bool:
    """
    Return True when the target host exactly matches a normalized scope entry.

    Loopback hosts (localhost, 127.0.0.1) are NOT treated as interchangeable:
    each must be listed explicitly to be in scope.
    """
    host = extract_host(target)
    if not host:
        return False
    return host in normalize_scope(scope)


def validate_scope(target: str, scope: list[str]) -> str:
    """
    Enforce the scope allowlist for a target.

    Returns the normalized in-scope host on success. Raises :class:`ScopeError`
    when the scope is empty, the host cannot be parsed, or the host is not in
    the allowlist.
    """
    normalized_scope = normalize_scope(scope)
    if not normalized_scope:
        raise ScopeError("A scope is required. Pass --scope <host> for every scan.")

    host = extract_host(target)
    if not host:
        raise ScopeError(f"Could not parse a host from target: {target!r}")

    if host not in normalized_scope:
        raise ScopeError(
            f"Target host {host!r} is out of scope. "
            f"Allowed hosts: {', '.join(normalized_scope)}."
        )

    return host
