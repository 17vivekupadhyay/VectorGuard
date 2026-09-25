from __future__ import annotations

from vectorguard.redteam.intelligence import (
    assessment_to_dict,
    build_assessment,
    render_assessment_markdown,
)


def _ep(oid, owasp, sev, captured, tactics, winning_idx=None, intel=None):
    steps = []
    for i, t in enumerate(tactics):
        cap = bool(captured and winning_idx is not None and i == winning_idx)
        steps.append({"tactic": t, "capture": {"captured": cap}})
    return {
        "objective_id": oid,
        "owasp_id": owasp,
        "severity": sev,
        "title": oid.replace("_", " "),
        "captured": captured,
        "steps_taken": len(tactics),
        "stopped_reason": "objective captured" if captured else "exhausted step budget",
        "evidence": "verified capture" if captured else "",
        "capture_method": "deterministic" if captured else "none",
        "proof": "FLAG-123" if captured else "",
        "captured_intel": intel or [],
        "steps": steps,
    }


def test_posture_from_most_severe_capture():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct", "base64_encoding"], 1),
        _ep("unbounded_consumption", "LLM10:2025", "medium", False, ["direct"]),
    ]
    a = build_assessment(eps)
    assert a.posture == "high"
    assert a.captured == 1 and a.total == 2


def test_no_capture_is_not_a_clean_bill():
    a = build_assessment([_ep("credential_exfil", "LLM02:2025", "high", False, ["direct"])])
    assert a.posture == "no-exploits-confirmed"
    assert "not proof" in a.headline.lower()


def test_insight_carries_narrative_root_cause_and_fixes():
    a = build_assessment([
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct", "base64_encoding"], 1)
    ])
    ins = a.insights[0]
    assert ins.captured and ins.winning_tactic == "base64_encoding"
    assert "base64_encoding" in ins.attack_narrative
    assert ins.root_cause and ins.business_impact
    assert len(ins.remediation) >= 2  # curated fixes present


def test_attack_chain_detected_for_known_pair():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct"], 0),
        _ep("credential_exfil", "LLM02:2025", "critical", True, ["direct"], 0),
    ]
    a = build_assessment(eps)
    assert len(a.chains) == 1
    assert set(a.chains[0].objectives) == {"credential_exfil", "system_prompt_leak"}
    # posture escalates to the most severe captured finding
    assert a.posture == "critical"


def test_no_chain_when_only_one_of_pair_captured():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct"], 0),
        _ep("credential_exfil", "LLM02:2025", "critical", False, ["direct"]),
    ]
    assert build_assessment(eps).chains == []


def test_tactic_effectiveness_ranks_capturing_tactics():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct", "base64_encoding"], 1),
        _ep("prompt_injection_obey", "LLM01:2025", "high", False, ["direct"]),
    ]
    a = build_assessment(eps)
    top = a.tactic_stats[0]
    assert top.tactic == "base64_encoding" and top.captures == 1
    direct = next(s for s in a.tactic_stats if s.tactic == "direct")
    assert direct.attempts == 2 and direct.captures == 0 and direct.rate == 0.0


def test_intel_is_deduped_across_objectives():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct"], 0, intel=["MARKER-1", "KEY-9"]),
        _ep("credential_exfil", "LLM02:2025", "critical", True, ["direct"], 0, intel=["KEY-9", "SSN-7"]),
    ]
    a = build_assessment(eps)
    assert a.intel_gathered == ["MARKER-1", "KEY-9", "SSN-7"]


def test_render_markdown_has_analyst_sections():
    eps = [
        _ep("system_prompt_leak", "LLM07:2025", "high", True, ["direct", "base64_encoding"], 1),
        _ep("credential_exfil", "LLM02:2025", "critical", True, ["direct"], 0),
    ]
    md = render_assessment_markdown(build_assessment(eps))
    assert "## Executive summary" in md
    assert "## Findings & remediation" in md
    assert "**Remediation:**" in md
    assert "Attack chains" in md
    assert "Tactic effectiveness" in md


def test_playbook_impact_is_clean_prose_not_a_tuple():
    # guards against a stray trailing comma turning an impact string into a 1-tuple
    from vectorguard.redteam.intelligence import _PLAYBOOK
    for oid, entry in _PLAYBOOK.items():
        impact = entry["business_impact"]
        assert isinstance(impact, str), f"{oid} business_impact is not a str"
        assert not impact.startswith("("), f"{oid} business_impact rendered as a tuple"


def test_assessment_to_dict_includes_tactic_rate():
    a = build_assessment([_ep("system_prompt_leak", "LLM07:2025", "high", True, ["base64_encoding"], 0)])
    d = assessment_to_dict(a)
    assert d["posture"] == "high"
    assert d["tactic_stats"][0]["rate"] == 1.0
