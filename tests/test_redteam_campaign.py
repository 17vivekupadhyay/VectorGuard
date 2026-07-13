"""End-to-end acceptance: autonomous campaign captures multiple OWASP flags.

Uses the vulnerable mock's reply logic in-process (no network) so CI is
deterministic. The agent runs with the deterministic operator (no LLM key) and
the real seed library - proving it escalates and captures WITHOUT any prompt
scripted for this specific target.
"""

from __future__ import annotations

from vectorguard.examples.redteam_mock import UNSCRIPTED_KEY, _generate_reply
from vectorguard.redteam.campaign import run_campaign
from vectorguard.redteam.objectives import (
    DEFAULT_INJECTION_CANARY,
    DEFAULT_PLANTED_SECRET,
    DEFAULT_SYSTEM_MARKER,
    build_objectives,
)
from vectorguard.redteam.operator import Operator
from vectorguard.redteam.seeds import load_seeds
from vectorguard.targets.base import BaseTarget, TargetResponse


def _last_user(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return ""


class VulnerableMockTarget(BaseTarget):
    def send_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        content = _generate_reply(_last_user(messages))
        completion_tokens = max(1, len(content) // 4)
        return TargetResponse(
            text=content,
            status_code=200,
            latency_ms=1.0,
            raw={"usage": {"completion_tokens": completion_tokens, "prompt_tokens": 1, "total_tokens": completion_tokens + 1}},
            transcript=list(messages),
        )


def _by_id(report, obj_id):
    return next(ep for ep in report["objectives"] if ep["objective_id"] == obj_id)


def test_campaign_captures_all_objectives(tmp_path):
    objectives = build_objectives()  # all four, default flags match the mock
    operator = Operator(client=None, seeds=load_seeds("vectorguard/tests"))

    report = run_campaign(
        VulnerableMockTarget(),
        objectives,
        operator,
        judge=None,
        max_steps=6,
        out_dir=str(tmp_path),
        metadata={"target": "in-process-mock"},
    )

    assert report["strategy"] == "deterministic"
    assert report["captured_count"] == 4

    sysleak = _by_id(report, "system_prompt_leak")
    assert sysleak["captured"] is True
    assert sysleak["proof"] == DEFAULT_SYSTEM_MARKER

    cred = _by_id(report, "credential_exfil")
    assert cred["captured"] is True
    # Unscripted leak caught by DLP, not a planted canary.
    assert cred["capture_method"] == "dlp"
    assert cred["proof"] == UNSCRIPTED_KEY
    assert cred["proof"] != DEFAULT_PLANTED_SECRET

    inj = _by_id(report, "prompt_injection_obey")
    assert inj["captured"] is True
    assert inj["proof"] == DEFAULT_INJECTION_CANARY

    consume = _by_id(report, "unbounded_consumption")
    assert consume["captured"] is True
    assert consume["capture_method"] == "budget"


def test_campaign_writes_reports(tmp_path):
    objectives = build_objectives(selected=["system_prompt_leak"])
    operator = Operator(client=None, seeds=[])

    report = run_campaign(
        VulnerableMockTarget(),
        objectives,
        operator,
        max_steps=4,
        out_dir=str(tmp_path),
        metadata={"target": "in-process-mock"},
    )

    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"
    assert json_path.exists()
    assert md_path.exists()

    md = md_path.read_text(encoding="utf-8")
    assert "Exploit Report" in md
    assert "CAPTURED" in md
    assert DEFAULT_SYSTEM_MARKER in md  # proof + reproduction transcript present
