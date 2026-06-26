"""Agent loop decision logic (observe -> decide), without network."""

from __future__ import annotations

from types import SimpleNamespace

from vectorguard.webagent.agent.agent_loop import _decide

REMAINING = [
    {"template_id": "a", "owasp": "O1", "test": SimpleNamespace(request=SimpleNamespace(path="/a"))},
    {"template_id": "b", "owasp": "O2", "test": SimpleNamespace(request=SimpleNamespace(path="/b"))},
]


class MockClient:
    def __init__(self, payload):
        self.payload = payload

    def complete(self, prompt):
        return self.payload


def test_deterministic_picks_first_remaining():
    d = _decide(None, state_summary="s", remaining=REMAINING, guidance="")
    assert d["action"] == "run"
    assert d["template_id"] == "a"
    assert d["source"] == "deterministic"


def test_llm_valid_choice_is_used():
    client = MockClient('{"action":"run","template_id":"b","reason":"because"}')
    d = _decide(client, state_summary="s", remaining=REMAINING, guidance="")
    assert d["template_id"] == "b"
    assert d["source"] == "llm"


def test_llm_stop_is_respected():
    client = MockClient('{"action":"stop","reason":"done"}')
    d = _decide(client, state_summary="s", remaining=REMAINING, guidance="")
    assert d["action"] == "stop"


def test_llm_invalid_choice_falls_back():
    client = MockClient('{"action":"run","template_id":"made_up","reason":"x"}')
    d = _decide(client, state_summary="s", remaining=REMAINING, guidance="")
    assert d["action"] == "run"
    assert d["template_id"] == "a"  # fell back to first remaining
    assert d["source"] == "fallback"


def test_llm_garbage_output_falls_back():
    client = MockClient("not json at all")
    d = _decide(client, state_summary="s", remaining=REMAINING, guidance="")
    assert d["source"] == "fallback"
    assert d["template_id"] == "a"
