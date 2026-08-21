"""
The attack-until-captured loop for ONE objective.

Each step closes a full feedback loop:
  1. the operator PROPOSES a payload (steered by the analyst's last feedback),
  2. the executor SENDS it (deterministic, measured),
  3. the capture oracle CHECKS for proof,
  4. if not captured, the analyst REFLECTS - scoring progress, extracting intel,
     and recommending the next tactic - which feeds back into step 1.

The loop stops on capture, on the step budget, or on no-progress (several
consecutive steps the analyst scored as going nowhere).

This is the unit that makes the tool an *attacker* rather than a scanner: it
keeps maneuvering against a single goal, reflecting and escalating, until it wins
or the budget runs out. The returned transcript is the reproduction artifact for
any capture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vectorguard.core.scoring import severity_to_score

from .analyst import Analyst
from .executor import Executor

if TYPE_CHECKING:
    from vectorguard.targets.base import BaseTarget

    from .judge import Judge
    from .objectives import Objective
    from .operator import Operator

DEFAULT_MAX_STEPS = 6
DEFAULT_NO_PROGRESS_LIMIT = 3


def run_episode(
    target: BaseTarget,
    objective: Objective,
    operator: Operator,
    *,
    judge: Judge | None = None,
    analyst: Analyst | None = None,
    executor: Executor | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    no_progress_limit: int = DEFAULT_NO_PROGRESS_LIMIT,
) -> dict[str, Any]:
    """Run the bounded attack loop for one objective and return its result."""
    exec_ = executor or Executor(target)
    analyst_ = analyst or Analyst(client=None)  # deterministic reflection by default

    conversation: list[dict[str, str]] = []
    steps: list[dict[str, Any]] = []
    attempted_tactics: list[str] = []
    captured_intel: list[str] = []
    last_response = ""
    guidance: dict[str, Any] | None = None  # analyst feedback from the prior step

    captured = False
    final_capture: Any = None
    no_progress = 0
    stopped_reason = "exhausted step budget"

    for step in range(1, max_steps + 1):
        proposal = operator.propose(
            objective=objective,
            transcript=conversation,
            last_response=last_response,
            attempted_tactics=attempted_tactics,
            captured_intel=captured_intel,
            step=step,
            guidance=guidance,
        )
        payload = proposal["payload"]
        attempted_tactics.append(proposal["tactic"])

        conversation.append({"role": "user", "content": payload})
        response, meta = exec_.send(conversation)
        conversation.append({"role": "assistant", "content": response.text})
        last_response = response.text

        judge_fn = judge.bind(payload) if judge is not None else None
        capture = objective.capture(
            response_text=response.text,
            response_meta=meta,
            judge=judge_fn,
        )

        if capture.captured:
            captured = True
            final_capture = capture
            stopped_reason = "objective captured"
            steps.append(
                {
                    "step": step,
                    "source": proposal["source"],
                    "tactic": proposal["tactic"],
                    "rationale": proposal["rationale"],
                    "payload": payload,
                    "response_text": response.text,
                    "response_meta": meta,
                    "capture": capture.as_dict(),
                    "assessment": None,
                }
            )
            break

        # Reflect: score progress, harvest intel, recommend the next tactic. The
        # result is fed forward as operator guidance on the next iteration.
        assessment = analyst_.reflect(
            objective=objective,
            payload=payload,
            response_text=response.text,
            attempted_tactics=attempted_tactics,
            capture=capture,
        )
        for item in assessment.intel:
            if item not in captured_intel:
                captured_intel.append(item)
        guidance = assessment.as_guidance()

        steps.append(
            {
                "step": step,
                "source": proposal["source"],
                "tactic": proposal["tactic"],
                "rationale": proposal["rationale"],
                "payload": payload,
                "response_text": response.text,
                "response_meta": meta,
                "capture": capture.as_dict(),
                "assessment": assessment.as_dict(),
            }
        )

        # No-progress tracking driven by the analyst's progress score.
        useless = assessment.progress <= 0.1
        no_progress = no_progress + 1 if useless else 0
        if no_progress >= no_progress_limit:
            stopped_reason = f"no progress after {no_progress} useless steps"
            break

    risk_score = 0.0
    if captured and final_capture is not None:
        risk_score = round(
            severity_to_score(objective.severity) * float(final_capture.confidence),
            2,
        )

    return {
        "objective_id": objective.id,
        "owasp_id": objective.owasp_id,
        "severity": objective.severity,
        "title": objective.title,
        "goal": objective.goal,
        "strategy": operator.strategy,
        "analyst_strategy": analyst_.strategy,
        "captured": captured,
        "steps_taken": len(steps),
        "stopped_reason": stopped_reason,
        "risk_score": risk_score,
        "evidence": final_capture.evidence if final_capture else "",
        "capture_method": final_capture.method if final_capture else "none",
        "proof": final_capture.proof if (final_capture and captured) else "",
        "captured_intel": captured_intel,
        "transcript": conversation,
        "steps": steps,
    }
