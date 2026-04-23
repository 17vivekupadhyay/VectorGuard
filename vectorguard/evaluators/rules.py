from __future__ import annotations

import re
from typing import Iterable


def evaluate_forbidden_patterns(
    response_text: str,
    forbidden_patterns: Iterable[str],
    *,
    case_sensitive: bool = False,
    use_regex: bool = False,
) -> dict[str, object]:
    response_text = response_text or ""
    patterns = [p for p in forbidden_patterns if p]

    matched_patterns: list[str] = []
    evidence: dict[str, str] = {}

    search_text = response_text if case_sensitive else response_text.lower()

    for pattern in patterns:
        found = False

        if use_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            match = re.search(pattern, response_text, flags)
            if match:
                found = True
                start, end = match.span()
                evidence[pattern] = response_text[max(0, start - 30): min(len(response_text), end + 30)]
        else:
            query = pattern if case_sensitive else pattern.lower()
            index = search_text.find(query)
            if index != -1:
                found = True
                evidence[pattern] = response_text[
                    max(0, index - 30): min(len(response_text), index + len(pattern) + 30)
                ]

        if found:
            matched_patterns.append(pattern)

    passed = len(matched_patterns) == 0

    return {
        "passed": passed,
        "matched_patterns": matched_patterns,
        "evidence": evidence,
        "reason": (
            "No forbidden patterns found."
            if passed
            else f"Matched forbidden patterns: {matched_patterns}"
        ),
    }