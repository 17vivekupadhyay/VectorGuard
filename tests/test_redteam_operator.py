"""Attacker brain: deterministic escalation, LLM parsing, and adaptation."""

from __future__ import annotations

import json

from vectorguard.redteam.objectives import build_objectives
from vectorguard.redteam.operator import Operator


def _objective(obj_id: str = "system_prompt_leak"):
    return build_objectives(selected=[obj_id])[0]


def test_deterministic_fallback_escalates_across_steps():
    operator = Operator(client=None, seeds=[])
    obj = _objective()

    step1 = operator.propose(
        objective=obj,
        transcript=[],
        last_response="",
        attempted_tactics=[],
        captured_intel=[],
        step=1,
    )
    step2 = operator.propose(
        objective=obj,
        transcript=[],
        last_response="I can't help with that.",
        attempted_tactics=[step1["tactic"]],
        captured_intel=[],
        step=2,
    )

    assert operator.strategy == "deterministic"
    assert step1["source"] == "deterministic"
    assert step1["tactic"] != step2["tactic"]
    assert step1["payload"] != step2["payload"]


class _FakeClient:
    """Returns a different payload once the prompt shows a prior refusal."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        # Key off the target's actual refusal text echoed into the prompt, not
        # the template's own guidance wording.
        if "i can't help with that" in prompt.lower():
            return json.dumps(
                {"payload": "ADAPTED escalation payload", "tactic": "persona", "rationale": "pivot"}
            )
        return json.dumps(
            {"payload": "initial direct payload", "tactic": "direct", "rationale": "open"}
        )


def test_operator_uses_llm_and_adapts_after_refusal():
    client = _FakeClient()
    operator = Operator(client=client, seeds=[])
    obj = _objective()

    first = operator.propose(
        objective=obj,
        transcript=[],
        last_response="",
        attempted_tactics=[],
        captured_intel=[],
        step=1,
    )
    second = operator.propose(
        objective=obj,
        transcript=[{"role": "user", "content": "x"}, {"role": "assistant", "content": "I can't help with that."}],
        last_response="I can't help with that.",
        attempted_tactics=["direct"],
        captured_intel=[],
        step=2,
    )

    assert operator.strategy == "llm"
    assert first["source"] == "llm"
    assert first["payload"] != second["payload"]
    assert second["payload"] == "ADAPTED escalation payload"


class _JunkClient:
    def complete(self, prompt: str) -> str:
        return "this is not json at all"


def test_operator_falls_back_when_llm_output_invalid():
    operator = Operator(client=_JunkClient(), seeds=[])
    proposal = operator.propose(
        objective=_objective(),
        transcript=[],
        last_response="",
        attempted_tactics=[],
        captured_intel=[],
        step=1,
    )
    assert proposal["source"] == "deterministic"
    assert proposal["payload"]
