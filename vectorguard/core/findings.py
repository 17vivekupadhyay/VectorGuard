from __future__ import annotations

from typing import Any

CATEGORY_FINDINGS: dict[str, dict[str, str]] = {
        "rag_injection": {
        "title": "RAG prompt injection protection failed",
        "description": (
            "The model appears to have followed instructions embedded inside retrieved "
            "or untrusted context instead of treating that context as data."
        ),
        "recommendation": (
            "Separate trusted instructions from retrieved content, wrap retrieved chunks "
            "as untrusted data, filter retrieved documents for injection patterns, and "
            "add explicit source-boundary checks before generation."
        ),
    },
    "sensitive_information_disclosure": {
        "title": "Sensitive information disclosure detected",
        "description": (
            "The model disclosed or appeared to disclose private, protected, or forbidden information."
        ),
        "recommendation": (
            "Remove secrets from prompts and retrieval context, restrict runtime access, "
            "and add data-loss prevention checks on model outputs."
        ),
    },
    "system_prompt_leakage": {
        "title": "System prompt or internal policy leakage detected",
        "description": (
            "The model appears to reveal hidden instructions, role rules, internal policy names, "
            "or prompt template details."
        ),
        "recommendation": (
            "Do not store secrets or sensitive operational details in model-visible prompts. "
            "Move critical controls server-side and add output filtering for internal markers."
        ),
    },
    "unbounded_consumption": {
        "title": "Unbounded consumption risk detected",
        "description": (
            "The model appears vulnerable to requests that trigger excessive output, cost, "
            "latency, or resource usage."
        ),
        "recommendation": (
            "Enforce max token limits, request size limits, rate limits, timeouts, and batching controls."
        ),
    },
    "prompt_injection": {
        "title": "Prompt injection protection failed",
        "description": (
            "The model appears vulnerable to instructions that attempt to override "
            "the intended system or developer policy."
        ),
        "recommendation": (
            "Strengthen instruction hierarchy, avoid storing secrets in prompts, "
            "add server-side output filtering, and test multi-turn override attempts."
        ),
    },
    "prompt_leakage": {
        "title": "System prompt or hidden instruction leakage detected",
        "description": (
            "The model appears to reveal hidden instructions, policy text, or internal configuration."
        ),
        "recommendation": (
            "Do not place sensitive instructions or secrets in model-visible context. "
            "Move sensitive controls server-side and filter outputs for known internal markers."
        ),
    },
    "sensitive_data_disclosure": {
        "title": "Sensitive data disclosure detected",
        "description": (
            "The model disclosed content matching sensitive or forbidden data patterns."
        ),
        "recommendation": (
            "Remove secrets from prompts and retrieval context, apply data-loss prevention checks, "
            "and restrict what the model can access at runtime."
        ),
    },
    "indirect_leakage": {
        "title": "Indirect leakage detected",
        "description": (
            "The model appears to reveal protected information through indirect, transformed, "
            "encoded, summarized, or reformatted output."
        ),
        "recommendation": (
            "Test encoded, translated, summarized, and reformatted exfiltration paths. "
            "Add semantic leakage detection beyond exact string matching."
        ),
    },
    "authority_spoofing": {
        "title": "Authority spoofing attack succeeded",
        "description": (
            "The model appears to comply with a request that impersonates an administrator, "
            "auditor, developer, or trusted internal role."
        ),
        "recommendation": (
            "Require authorization checks outside the model. The model should not trust role claims "
            "made inside user messages."
        ),
    },
}


DEFAULT_FINDING = {
    "title": "LLM security test failed",
    "description": (
        "The model response violated one or more configured VectorGuard security expectations."
    ),
    "recommendation": (
        "Review the failed detector evidence, strengthen application-level safeguards, "
        "and add regression tests for this behavior."
    ),
}


def collect_evidence(result: dict[str, Any]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}

    if result.get("leak_matches"):
        evidence["leak_matches"] = result["leak_matches"]

    if result.get("leak_evidence"):
        evidence["leak_evidence"] = result["leak_evidence"]

    if result.get("refusal_signals"):
        evidence["refusal_signals"] = result["refusal_signals"]

    if result.get("refusal_evidence"):
        evidence["refusal_evidence"] = result["refusal_evidence"]

    if result.get("other_matches"):
        evidence["other_matches"] = result["other_matches"]

    if result.get("other_evidence"):
        evidence["other_evidence"] = result["other_evidence"]

    return evidence


def build_finding(result: dict[str, Any]) -> dict[str, Any] | None:
    if result.get("passed"):
        return None

    category = str(result.get("category", "unknown"))
    template = CATEGORY_FINDINGS.get(category, DEFAULT_FINDING)

    return {
        "title": template["title"],
        "description": template["description"],
        "recommendation": template["recommendation"],
        "category": category,
        "owasp_id": result.get("owasp_id", "unmapped"),
        "severity": result.get("severity", "unknown"),
        "risk_score": result.get("risk_score", 0.0),
        "evidence": collect_evidence(result),
    }