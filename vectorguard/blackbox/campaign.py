"""
Black-box campaign orchestrator.

Ties the auto-adapter, the payload batteries, and the black-box oracle into one
autonomous run against a chatbot URL. Enforces the authorization gate: the target
host must be inside ``--scope``.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from vectorguard.targets.base import BaseTarget

from . import oracle, probes
from .adapter import AdapterResult, autodetect_target
from .operator import BatteryOperator
from .oracle import Baseline, Finding, make_baseline


class ScopeError(RuntimeError):
    """Raised when the target host is not inside the authorized scope."""


def host_in_scope(url: str, scope: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    for allowed in scope:
        a = allowed.strip().lower()
        if host == a or host.endswith("." + a):
            return True
    return False


def default_canary() -> str:
    # RAG_PWNED_<digits> so it also trips the bundled vulnerable mock; the exact
    # token is arbitrary — any agent-controlled value works.
    return "RAG_PWNED_" + "".join(random.choices(string.digits, k=6))


@dataclass
class BlackBoxResult:
    url: str
    adapter: str
    objectives: list[str]
    findings: list[Finding] = field(default_factory=list)
    baseline_excerpt: str = ""

    @property
    def captured(self) -> list[Finding]:
        return [f for f in self.findings if f.captured]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "adapter": self.adapter,
            "objectives": self.objectives,
            "captured_count": len(self.captured),
            "findings": [f.to_dict() for f in self.findings],
            "baseline_excerpt": self.baseline_excerpt,
        }


def run_blackbox(
    *,
    url: str,
    scope: list[str],
    target: BaseTarget | None = None,
    adapter_note: str = "explicit target config",
    objectives: list[str] | None = None,
    canary: str | None = None,
    operator: Any | None = None,
    max_steps: int = 5,
    max_turns: int = 1,
    max_chars: int = 6000,
    max_latency_ms: float = 25000.0,
    verbose: bool = True,
    _printer: Any = None,
) -> BlackBoxResult:
    if not scope:
        raise ScopeError("An authorization scope is required (--scope).")
    if not host_in_scope(url, scope):
        host = urlparse(url).hostname
        raise ScopeError(
            f"Target host {host!r} is not inside scope {scope}. Refusing to run."
        )

    objectives = objectives or list(probes.OBJECTIVES)
    canary = canary or default_canary()
    operator = operator or BatteryOperator()
    say = _printer or (print if verbose else (lambda *_a, **_k: None))

    # --- auto-adapt (unless an explicit target was supplied) ---
    if target is None:
        result: AdapterResult = autodetect_target(url)
        target = result.target
        adapter_note = result.describe()
        say(f"[adapter] {adapter_note}")
        say(f"[adapter] sample reply: {result.sample_reply[:120]!r}")

    # --- benign baseline for differential checks ---
    probe_resp = target.send_prompt("Hello! What can you do?")
    baseline: Baseline = make_baseline(probe_resp.text, probe_resp.latency_ms)

    run = BlackBoxResult(url=url, adapter=adapter_note, objectives=objectives,
                         baseline_excerpt=probe_resp.text[:160])

    mode = "multi-turn" if max_turns > 1 else "single-shot"
    say(f"[mode    ] {mode} · operator={getattr(operator, 'name', 'battery')}")

    for objective in objectives:
        say(f"\n=== objective: {objective} ===")
        if max_turns > 1:
            finding = _run_multiturn_objective(
                target, objective, canary, baseline, operator,
                max_turns=max_turns, max_chars=max_chars, max_latency_ms=max_latency_ms,
                say=say,
            )
        else:
            finding = _run_objective(
                target, objective, canary, baseline, operator,
                max_steps=max_steps, max_chars=max_chars, max_latency_ms=max_latency_ms,
                say=say,
            )
        run.findings.append(finding)

    return run


def _run_multiturn_objective(
    target: BaseTarget, objective: str, canary: str, baseline: Baseline, operator: Any,
    *, max_turns: int, max_chars: int, max_latency_ms: float, say: Any,
) -> Finding:
    """Hold one evolving conversation: prime a premise over turns, then strike."""
    conversation: list[dict[str, str]] = []
    last_user = ""
    for turn in range(1, max_turns + 1):
        user_msg = operator.propose_turn(objective, canary, conversation)
        if user_msg is None:
            break
        last_user = user_msg
        conversation.append({"role": "user", "content": user_msg})
        resp = target.send_messages(conversation)
        text = resp.text or ""
        conversation.append({"role": "assistant", "content": text})
        finding = _detect(objective, user_msg, text, resp.latency_ms, baseline,
                          canary=canary, max_chars=max_chars, max_latency_ms=max_latency_ms)
        say(f"[turn {turn:>2}] user: {user_msg.splitlines()[0][:60]}")
        say(f"          bot : {text.splitlines()[0][:60]}")
        if finding is not None:
            finding.turns = turn
            say(f"[FINDING ] {finding.confidence.upper()} at turn {turn} — {finding.evidence}")
            return finding
    return Finding(objective, _owasp(objective), False, "none", "none",
                   last_user, f"no signal across {max_turns} turns", turns=max_turns)


def _run_objective(
    target: BaseTarget, objective: str, canary: str, baseline: Baseline, operator: Any,
    *, max_steps: int, max_chars: int, max_latency_ms: float, say: Any,
) -> Finding:
    operator.reset()
    history: list[dict[str, Any]] = []
    last_payload = ""
    for _step in range(max_steps):
        payload = operator.propose(objective, canary, history)
        if payload is None:
            break
        last_payload = payload
        resp = target.send_prompt(payload)
        text = resp.text or ""
        finding = _detect(objective, payload, text, resp.latency_ms, baseline,
                          canary=canary, max_chars=max_chars, max_latency_ms=max_latency_ms)
        history.append({"payload": payload, "response": text,
                        "captured": bool(finding and finding.captured)})
        say(f"[probe   ] {payload.splitlines()[0][:70]}")
        if finding is not None:
            say(f"[FINDING ] {finding.confidence.upper()} ({finding.method}) — "
                f"{finding.evidence}")
            return finding
        say("[ok      ] no signal; adapting")
    return Finding(objective, _owasp(objective), False, "none", "none",
                   last_payload, "no signal across probes")


def _detect(objective, payload, text, latency_ms, baseline, *, canary, max_chars,
            max_latency_ms) -> Finding | None:
    if objective == "injection":
        return oracle.check_injection(payload, text, canary)
    if objective == "consumption":
        return oracle.check_consumption(payload, text, latency_ms, baseline,
                                        max_chars=max_chars, max_latency_ms=max_latency_ms)
    if objective == "disclosure":
        return oracle.check_disclosure(payload, text, baseline)
    if objective == "system_prompt":
        return oracle.check_system_prompt(payload, text, baseline)
    return None


def _owasp(objective: str) -> str:
    return {
        "injection": "LLM01:2025",
        "consumption": "LLM10:2025",
        "disclosure": "LLM02:2025",
        "system_prompt": "LLM07:2025",
    }.get(objective, "unmapped")
