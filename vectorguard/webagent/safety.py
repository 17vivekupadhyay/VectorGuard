"""
HTTP method safety for the VectorGuard Web Agent.

This is the authoritative method safety gate. It is enforced before any request
is made (Phase 6 and later). The policy:

- Safe (read-only) methods are always allowed: GET, HEAD, OPTIONS.
- POST is state-changing and blocked unless ``--allow-state-changing`` is passed.
- DELETE, PUT, PATCH are destructive and always blocked in the MVP, even with
  ``--allow-state-changing``. Support may be added explicitly in a later phase.
- Unknown methods are blocked.

No HTTP requests are made here; these are pure validation functions.
"""

from __future__ import annotations

from .models import DESTRUCTIVE_METHODS, SAFE_METHODS, STATE_CHANGING_METHODS


class MethodSafetyError(ValueError):
    """Raised when an HTTP method is not permitted by the safety policy."""


def normalize_method(method: str | None) -> str:
    """Uppercase and strip an HTTP method string."""
    if not method:
        return ""
    return method.strip().upper()


def is_method_allowed(method: str, *, allow_state_changing: bool = False) -> bool:
    """Boolean form of :func:`validate_method` for advisory checks."""
    normalized = normalize_method(method)

    if normalized in SAFE_METHODS:
        return True
    if normalized in STATE_CHANGING_METHODS:
        return allow_state_changing
    return False


def validate_method(method: str, *, allow_state_changing: bool = False) -> str:
    """
    Enforce the method safety policy.

    Returns the normalized method on success. Raises :class:`MethodSafetyError`
    for state-changing methods without ``--allow-state-changing``, for
    destructive methods (always), and for unknown methods.
    """
    normalized = normalize_method(method)

    if not normalized:
        raise MethodSafetyError("No HTTP method provided.")

    if normalized in SAFE_METHODS:
        return normalized

    if normalized in DESTRUCTIVE_METHODS:
        raise MethodSafetyError(
            f"Method {normalized} is destructive and is always blocked in the MVP "
            f"(blocked even with --allow-state-changing)."
        )

    if normalized in STATE_CHANGING_METHODS:
        if allow_state_changing:
            return normalized
        raise MethodSafetyError(
            f"Method {normalized} is state-changing and is blocked by default. "
            f"Pass --allow-state-changing to permit it."
        )

    raise MethodSafetyError(f"Method {normalized} is not a recognized safe method.")
