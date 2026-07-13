"""Episode control flow: stop on capture, stop on no-progress."""

from __future__ import annotations

from vectorguard.examples.redteam_mock import _generate_reply
from vectorguard.redteam.episode import run_episode
from vectorguard.redteam.objectives import DEFAULT_SYSTEM_MARKER, build_objectives
from vectorguard.redteam.operator import Operator
from vectorguard.targets.base import BaseTarget, TargetResponse


def _last_user(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return ""


class MockTarget(BaseTarget):
    """In-process target reusing the vulnerable mock's reply logic."""

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


class RefusingTarget(BaseTarget):
    def send_messages(self, messages: list[dict[str, str]]) -> TargetResponse:
        return TargetResponse(
            text="I'm sorry, I can't help with that request.",
            status_code=200,
            latency_ms=1.0,
        )


def _objective(obj_id: str = "system_prompt_leak"):
    return build_objectives(selected=[obj_id])[0]


def test_episode_escalates_then_captures():
    # No seeds => the direct rung has no escalation cue and is refused; the
    # persona rung (step 2) carries a cue and the mock leaks the marker.
    operator = Operator(client=None, seeds=[])
    episode = run_episode(MockTarget(), _objective(), operator, max_steps=5)

    assert episode["captured"] is True
    assert episode["steps_taken"] == 2
    assert episode["proof"] == DEFAULT_SYSTEM_MARKER
    assert episode["capture_method"] == "deterministic"
    # 2 user turns + 2 assistant turns recorded as the reproduction transcript.
    assert len(episode["transcript"]) == 4
    assert episode["stopped_reason"] == "objective captured"


def test_episode_stops_on_no_progress():
    operator = Operator(client=None, seeds=[])
    episode = run_episode(
        RefusingTarget(),
        _objective(),
        operator,
        max_steps=10,
        no_progress_limit=2,
    )

    assert episode["captured"] is False
    assert episode["steps_taken"] == 2
    assert "no progress" in episode["stopped_reason"]
