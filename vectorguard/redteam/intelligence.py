"""
The intelligence layer: turn raw campaign captures into an analyst-grade
assessment.

A capture on its own ("system_prompt_leak, confidence 1.0") is a *signal*. A
security team needs the *meaning*: how it was compromised, the root cause, the
business impact, what to fix, and — the part a single-objective scanner misses —
how findings **chain** into a larger attack. This module produces that from the
campaign's episode data, deterministically (no LLM required), so the deliverable
reads like a pentest report rather than a log.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# --- severity ordering, reused for posture -------------------------------------
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 2}


# --- the analyst playbook: curated root-cause / impact / fix per objective ------
# This is expert knowledge encoded as data, not model-generated prose — every
# line is defensible and consistent run to run.
_PLAYBOOK: dict[str, dict[str, Any]] = {
    "system_prompt_leak": {
        "root_cause": (
            "The system prompt is treated as a secret but shares the same context "
            "window as attacker-influenced input, so the model can be steered into "
            "reproducing it verbatim."
        ),
        "business_impact": (
            "Exposes hidden instructions, guardrail logic, and any secrets or "
            "internal policy embedded in the prompt — a blueprint an attacker uses "
            "to reliably bypass every downstream control."
        ),
        "remediation": [
            "Move secrets and sensitive business logic out of the model-visible "
            "prompt into server-side code the model cannot read.",
            "Add an output filter that blocks responses containing known "
            "system-prompt markers or sentinel strings.",
            "Design controls to survive prompt disclosure — assume the system "
            "prompt is attacker-visible.",
        ],
    },
    "credential_exfil": {
        "root_cause": (
            "Secret-shaped material (API keys, tokens, connection strings) is "
            "reachable in the model's context or tools, and no egress filter "
            "inspects the output for it."
        ),
        "business_impact": (
            "Leaked credentials let an attacker pivot directly into connected "
            "systems — databases, third-party APIs, internal services — turning a "
            "chat bug into a full breach."
        ),
        "remediation": [
            "Never place live credentials in prompts or model-accessible context; "
            "use short-lived, scoped tokens fetched server-side.",
            "Run every response through DLP/egress detection for secret shapes "
            "before it reaches the user.",
            "Rotate any credential the model can see and scope it to least "
            "privilege.",
        ],
    },
    "prompt_injection_obey": {
        "root_cause": (
            "The model does not distinguish trusted developer instructions from "
            "untrusted user (or retrieved) content, so an embedded instruction is "
            "followed as if it were policy."
        ),
        "business_impact": (
            "An attacker — or a poisoned document the model retrieves — can "
            "override intended behaviour: change outputs, trigger actions, or "
            "smuggle instructions to downstream systems."
        ),
        "remediation": [
            "Separate trusted instructions from untrusted content with explicit "
            "delimiters and a strong instruction hierarchy.",
            "Treat retrieved / user content as data, never as commands; wrap it as "
            "quoted, untrusted input.",
            "Add an injection-pattern filter on inputs and validate outputs before "
            "acting on them.",
        ],
    },
    "unbounded_consumption": {
        "root_cause": (
            "There is no ceiling on output size, generation time, or per-request "
            "cost, so a crafted prompt can force expensive, runaway generation."
        ),
        "business_impact": (
            "Denial-of-wallet / denial-of-service: a cheap request can burn large "
            "token/compute cost or exhaust capacity, degrading the service for "
            "everyone."
        ),
        "remediation": [
            "Enforce hard max-output-token and timeout limits on every request.",
            "Apply per-user rate and cost limits with early-stopping.",
            "Reject or truncate prompts that request unbounded repetition or "
            "enumeration.",
        ],
    },
}

# --- known escalation chains: a captured pair that compounds into a bigger risk -
_CHAINS: list[dict[str, Any]] = [
    {
        "pair": {"system_prompt_leak", "credential_exfil"},
        "description": (
            "System-prompt disclosure → credential exfiltration: the leaked prompt "
            "revealed the structure and naming an attacker then used to extract "
            "credentials — a full recon-to-loot chain, not two isolated bugs."
        ),
    },
    {
        "pair": {"system_prompt_leak", "prompt_injection_obey"},
        "description": (
            "System-prompt disclosure → reliable injection: seeing the hidden "
            "instructions let the attacker craft an override that defeats the "
            "model's own guardrails on demand."
        ),
    },
    {
        "pair": {"credential_exfil", "prompt_injection_obey"},
        "description": (
            "Injection → credential exfiltration: an injected instruction was the "
            "delivery mechanism that made the model surface secret material."
        ),
    },
]


@dataclass
class Insight:
    objective_id: str
    title: str
    owasp_id: str
    severity: str
    captured: bool
    winning_tactic: str | None
    steps_to_capture: int | None
    attack_narrative: str
    root_cause: str
    business_impact: str
    remediation: list[str]


@dataclass
class AttackChain:
    objectives: list[str]
    description: str


@dataclass
class TacticStat:
    tactic: str
    attempts: int
    captures: int

    @property
    def rate(self) -> float:
        return round(self.captures / self.attempts, 2) if self.attempts else 0.0


@dataclass
class SecurityAssessment:
    posture: str
    headline: str
    captured: int
    total: int
    insights: list[Insight] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    tactic_stats: list[TacticStat] = field(default_factory=list)
    intel_gathered: list[str] = field(default_factory=list)


# --- helpers -------------------------------------------------------------------
def _winning_tactic(episode: dict[str, Any]) -> str | None:
    for step in episode.get("steps", []):
        if step.get("capture", {}).get("captured"):
            return step.get("tactic")
    return None


def _tactics_tried(episode: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for step in episode.get("steps", []):
        t = step.get("tactic")
        if t and t not in seen:
            seen.append(t)
    return seen


def _narrative(episode: dict[str, Any]) -> str:
    tried = _tactics_tried(episode)
    steps = episode.get("steps_taken", 0)
    if episode.get("captured"):
        win = _winning_tactic(episode) or "an adaptive payload"
        path = " → ".join(tried) if tried else "escalation"
        return (
            f"Compromised in {steps} step(s). The attacker escalated through "
            f"[{path}]; the '{win}' tactic succeeded. Proof obtained via "
            f"{episode.get('capture_method', 'deterministic verification')}: "
            f"{episode.get('evidence', '').strip() or 'a verified capture'}."
        )
    path = ", ".join(tried) if tried else "the tactic ladder"
    return (
        f"Withstood {steps} attempt(s) across {path}; the run stopped because "
        f"{episode.get('stopped_reason', 'the budget was exhausted')}. Note: no "
        f"capture within budget is not proof of safety — only that these tactics "
        f"did not land in the allotted steps."
    )


def _headline(posture: str, captured: int, total: int) -> str:
    if captured == 0:
        return (
            f"No exploits were confirmed across {total} objective(s) in the "
            f"allotted budget. This is a signal, not a clean bill of health — "
            f"absence of a capture is not proof of a secure system."
        )
    words = {"critical": "critical", "high": "serious", "medium": "moderate",
             "low": "minor"}.get(posture, "notable")
    return (
        f"{captured} of {total} objectives were compromised with hard proof, "
        f"indicating a {words} security posture. Each confirmed exploit is a "
        f"failed defense with a reproduction transcript and a concrete fix below."
    )


# --- the public builder --------------------------------------------------------
def build_assessment(episodes: list[dict[str, Any]]) -> SecurityAssessment:
    insights: list[Insight] = []
    captured_ids: set[str] = set()

    for ep in episodes:
        oid = ep["objective_id"]
        book = _PLAYBOOK.get(oid, {})
        if ep.get("captured"):
            captured_ids.add(oid)
        insights.append(
            Insight(
                objective_id=oid,
                title=ep.get("title", oid),
                owasp_id=ep.get("owasp_id", "unmapped"),
                severity=ep.get("severity", "unknown"),
                captured=bool(ep.get("captured")),
                winning_tactic=_winning_tactic(ep),
                steps_to_capture=ep.get("steps_taken") if ep.get("captured") else None,
                attack_narrative=_narrative(ep),
                root_cause=book.get("root_cause", "Root cause not catalogued for this objective."),
                business_impact=str(book.get("business_impact", "Impact not catalogued.")),
                remediation=list(book.get("remediation", [])),
            )
        )

    # posture from the most severe *captured* finding
    captured_sevs = [i.severity for i in insights if i.captured]
    if captured_sevs:
        posture = max(captured_sevs, key=lambda s: _SEV_RANK.get(s, 2))
    else:
        posture = "no-exploits-confirmed"

    # chains: any known escalation pair fully captured
    chains: list[AttackChain] = [
        AttackChain(objectives=sorted(c["pair"]), description=c["description"])
        for c in _CHAINS
        if c["pair"].issubset(captured_ids)
    ]

    # tactic effectiveness across the whole campaign
    attempts: dict[str, int] = {}
    caps: dict[str, int] = {}
    for ep in episodes:
        for step in ep.get("steps", []):
            t = step.get("tactic")
            if not t:
                continue
            attempts[t] = attempts.get(t, 0) + 1
            if step.get("capture", {}).get("captured"):
                caps[t] = caps.get(t, 0) + 1
    tactic_stats = sorted(
        (TacticStat(t, attempts[t], caps.get(t, 0)) for t in attempts),
        key=lambda s: (s.captures, s.attempts),
        reverse=True,
    )

    # intel harvested across the campaign (deduped, order-preserving)
    intel: list[str] = []
    for ep in episodes:
        for item in ep.get("captured_intel", []):
            if item not in intel:
                intel.append(item)

    captured = sum(1 for i in insights if i.captured)
    return SecurityAssessment(
        posture=posture,
        headline=_headline(posture, captured, len(insights)),
        captured=captured,
        total=len(insights),
        insights=insights,
        chains=chains,
        tactic_stats=tactic_stats,
        intel_gathered=intel,
    )


def assessment_to_dict(a: SecurityAssessment) -> dict[str, Any]:
    d = asdict(a)
    # attach derived rate for tactic stats (asdict drops the property)
    for raw, obj in zip(d["tactic_stats"], a.tactic_stats, strict=False):
        raw["rate"] = obj.rate
    return d


def render_assessment_markdown(a: SecurityAssessment) -> str:
    out: list[str] = []
    out.append("## Executive summary\n")
    out.append(f"**Security posture: `{a.posture}`** — {a.headline}\n")

    if a.chains:
        out.append("### Attack chains (compounded risk)\n")
        for c in a.chains:
            out.append(f"- **{' + '.join(c.objectives)}** — {c.description}")
        out.append("")

    captured_insights = [i for i in a.insights if i.captured]
    if captured_insights:
        out.append("## Findings & remediation\n")
        for i in captured_insights:
            out.append(f"### {i.title} — `{i.severity}` ({i.owasp_id})\n")
            out.append(f"- **What happened:** {i.attack_narrative}")
            out.append(f"- **Root cause:** {i.root_cause}")
            out.append(f"- **Business impact:** {i.business_impact}")
            if i.remediation:
                out.append("- **Remediation:**")
                for fix in i.remediation:
                    out.append(f"  - {fix}")
            out.append("")

    if a.tactic_stats:
        out.append("## Tactic effectiveness (against this target)\n")
        out.append("| Tactic | Attempts | Captures | Hit rate |")
        out.append("|---|---|---|---|")
        for s in a.tactic_stats:
            out.append(f"| {s.tactic} | {s.attempts} | {s.captures} | {s.rate} |")
        out.append("")

    if a.intel_gathered:
        out.append("## Reconnaissance harvested\n")
        out.append(
            "Fragments the agent extracted and chained across objectives "
            f"({len(a.intel_gathered)} item(s)): "
            + ", ".join(f"`{x}`" for x in a.intel_gathered[:12])
            + ("…" if len(a.intel_gathered) > 12 else "")
        )
        out.append("")

    return "\n".join(out)
