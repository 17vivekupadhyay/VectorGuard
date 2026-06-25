"""
Bounded, safe endpoint discovery for the VectorGuard Web Agent.

This is NOT a crawler. Discovery only harvests same-origin links that already
appear in response bodies the agent fetched (a single seed GET of the site root,
plus the responses of checks it actually ran). It never recursively fetches
discovered pages just to find more links, so it cannot fan out.

Every discovered endpoint is still subject to the full safety model: same-origin
only, scope re-validated before any request, GET-only, and a hard cap on how many
new endpoints are added. Off by default.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from ..scope import ScopeError, validate_scope

_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SKIP_PREFIXES = ("#", "mailto:", "javascript:", "tel:", "data:")

SEED_TIMEOUT_SECONDS = 10.0


def extract_links(body_text: str, *, base_url: str) -> list[str]:
    """
    Extract same-origin link paths (path[?query]) from an HTML body.

    Only absolute links to the same host and root-relative ("/...") links are
    returned. Off-site, fragment, and scheme links (mailto:, javascript:, ...)
    are dropped.
    """
    if not body_text:
        return []

    base_host = (urlsplit(base_url).hostname or "").lower()
    found: list[str] = []
    seen: set[str] = set()

    for raw in _LINK_RE.findall(body_text):
        link = raw.strip()
        if not link or link.lower().startswith(_SKIP_PREFIXES):
            continue

        if "://" in link:
            parts = urlsplit(link)
            if (parts.hostname or "").lower() != base_host:
                continue
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
        elif link.startswith("/"):
            path = link
        else:
            # Skip bare relative links to avoid ambiguous joins.
            continue

        if path not in seen:
            seen.add(path)
            found.append(path)

    return found


def fetch_seed(
    target: str,
    scope: list[str],
    *,
    timeout: float = SEED_TIMEOUT_SECONDS,
) -> str:
    """
    Fetch the site root once to seed discovery. Returns body text, or "" on any
    problem. Scope is re-validated and redirects are not followed.
    """
    url = target.rstrip("/") + "/"
    try:
        validate_scope(url, scope)
    except ScopeError:
        return ""

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.get(url)
        return response.text
    except httpx.HTTPError:
        return ""
