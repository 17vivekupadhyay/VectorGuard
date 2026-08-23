# Agentic Red-Team Lab — Excessive Agency (LLM06:2025)

> ⚠️ **Lab framework. Sandbox-bound by construction.**
> This is the one part of VectorGuard that crosses from *talk-only* into *taking
> an action*. It is fenced so it can only ever act against owned, in-process,
> inert sandbox agents — never a real system.

A small but full-featured **agentic red-team framework**: an adaptive attacker
that drives tool-using agents into invoking privileged/destructive tools, proves
it with **proof-of-effect**, and writes remediation reports. It reuses
VectorGuard's loop — **operator → executor → oracle → analyst** — but the capture
oracle checks the target's **tool-call ledger** instead of its words.

## Why it's safe to run fully autonomously

| Guardrail | Effect |
|-----------|--------|
| In-process sandbox targets | No network; `run_campaign` is type-bound to `AgentTarget` — it can't be pointed at a URL |
| Inert mock tools | `delete_account`, `export_user_data`, … only *record* being called; every ledger entry is `executed: False` |
| Attestation | The CLI requires `--i-own-this-sandbox`; `run_campaign` requires `authorized_lab=True` |
| Bounded | Hard `--max-steps` budget per objective |
| Offline / key-free | Deterministic operator — reproducible |

## What makes it a real red-team tool

It ships **four target profiles**, each with a *different* authorization flaw, so
the attacker has to adapt rather than replay one payload:

| Profile | Flaw | Falls to |
|---------|------|----------|
| `naive-auth` | trusts authority words in the message | `authority_spoof` |
| `indirect-injection` | trusts instructions inside retrieved `<document>` content | `indirect_retrieval` |
| `schema-confusion` | trusts anything shaped like a structured tool call | `schema_confusion` |
| `hardened` | binds authorization to a verified session | **resists all** |

## Two attacker brains (`--operator`)

| Operator | What it does | Needs |
|----------|--------------|-------|
| `deterministic` (default) | Climbs a fixed tactic ladder (plain → social → authority-spoof → injection-override → indirect-retrieval → schema-confusion); the analyst reads each refusal to jump to the hinted category | nothing — key-free, reproducible |
| `llm` | A real LLM reads the running transcript and *crafts & adapts* each payload; degrades to `deterministic` if no model is configured or a call fails | an OpenAI-compatible endpoint |

The deterministic operator exploits `naive-auth` in **2 steps** by reacting to an
"authorization required" refusal. The LLM operator does the same *by reasoning* —
it generates a first attempt, sees the refusal in the transcript, and adapts.

**Configuring the LLM operator** (any OpenAI-compatible endpoint):

```bash
# free + local (no key) via Ollama:
export LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=llama3.1

# or OpenAI:
export LLM_BASE_URL=https://api.openai.com/v1  LLM_MODEL=gpt-4o-mini  LLM_API_KEY=sk-...
```

## Run it

```bash
cd examples/excessive_agency_lab

# quick single-target demo (deterministic)
python3 autonomous_exploiter.py

# full framework — all profiles, all objectives, with reports
python3 cli.py --target all --i-own-this-sandbox --out reports/agent_rt

# LLM-driven attacker (falls back to deterministic if no model configured)
python3 cli.py --target all --operator llm --i-own-this-sandbox

# one profile / specific objectives
python3 cli.py --target schema-confusion --objectives delete_account,export_user_data \
  --victim carol --i-own-this-sandbox

# verify the framework works end-to-end (deterministic + LLM paths)
python3 selftest.py
```

Objectives: `delete_account`, `export_user_data`, `reset_password`,
`escalate_privileges` (or `all`).

## Output

`--out` writes, per target profile:

```
<out>/<profile>/
  campaign.json   full result: per-objective capture, winning tactic, proof, transcript
  report.md       human-readable exploit report + summary matrix + remediation
```

Every capture's proof carries `executed: False` — the exploit is real, the effect
is inert.

## Files

| File | Role |
|------|------|
| `mock_tools.py` | Inert tools + append-only `ToolLedger` (the proof surface) |
| `targets.py` | `AgentTarget` base + 4 sandbox profiles (the systems under test) |
| `tactics.py` | The escalating tactic library (deterministic operator) |
| `objectives.py` | Concrete win conditions |
| `operators.py` | `DeterministicOperator` + `LLMOperator` (+ analyst) behind one interface |
| `llm_client.py` | Provider-agnostic OpenAI-compatible LLM client (httpx) |
| `engine.py` | Executor + capture oracle + campaign loop + safety gates |
| `report.py` | JSON + Markdown exploit reports |
| `cli.py` | Command-line entry point |
| `selftest.py` | End-to-end verification (15 checks) |
| `autonomous_exploiter.py` | Thin single-target demo wrapper |

## The lesson (remediation)

Every flaw here is the same root cause: **authorization derived from untrusted
input** (message text, retrieved content, or structured syntax). Fix it by
enforcing authorization **server-side, bound to a verified session**, treating all
model-visible input as untrusted, and requiring human confirmation for
destructive tools — exactly what `hardened` does.

## Relationship to the rest of VectorGuard

This framework is intentionally **not** wired into the `vectorguard-redteam` CLI,
which keeps its talk-only guarantee. It lives here, clearly labeled, so the line
between "the defensive tool you ship" and "the action-taking lab" stays explicit.
