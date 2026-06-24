# CLAUDE.md

Guidance for working in the VectorGuard repository.

## Project Purpose

VectorGuard is a **defensive** security testing toolkit. Its original focus is
LLM/RAG/AI-agent security (prompt injection, RAG poisoning, sensitive-data
disclosure, system-prompt leakage, unbounded consumption), mapped to the OWASP
LLM Top 10.

This repository is being extended with **VectorGuard Web Agent**, an
AI-assisted, authorized OWASP-style web application security testing layer. It
behaves like a junior AppSec analyst: it maps known web surfaces to safe,
PortSwigger-inspired checks, runs scoped HTTP tests, captures evidence, and
generates remediation reports.

> VectorGuard Web Agent is a defensive, authorized OWASP-style web application
> security testing layer. It maps known web surfaces to safe PortSwigger-inspired
> checks, executes scoped HTTP tests, captures evidence, and generates
> remediation reports. It is designed for local labs, owned applications, and
> explicitly authorized security testing. Findings are signals for review, not
> proof of complete security.

## Defensive-Use Restrictions

VectorGuard is for defensive testing of systems you own or are explicitly
authorized to test (local labs, owned apps, PortSwigger-style practice targets).

Hard rules for the Web Agent:

- Only scan targets explicitly provided by the user.
- Require `--scope` for every scan; the target host must match the scope.
- Default to **safe mode** and dry-run / safe `GET`-only checks.
- Block destructive HTTP methods by default: `DELETE`, `PUT`, `PATCH`.
- Block state-changing `POST` requests unless `--allow-state-changing` is passed.
- Never run against random public targets.
- Never bypass authentication or authorization outside authorized lab/local targets.
- Save evidence locally but redact secrets, cookies, and `Authorization` headers
  in reports.
- Never commit real API keys, cookies, tokens, or secrets.

The agent/LLM may **plan and explain**. Deterministic Python code **executes**
requests and **evaluates** evidence. The LLM never invents endpoints, evidence,
or destructive tests.

## Current Architecture Summary

VectorGuard is a dependency-light Python package run via `python -m`. There is
no packaging/entry-point config; "tests" today are CI integration smoke tests
that boot a Flask mock and assert exit codes.

Core LLM/RAG pipeline (do not break):

```
YAML suite -> run_suite -> target.send_messages -> evaluate_response -> scoring -> findings -> reports
```

Key modules:

- `vectorguard/cli.py` — argparse CLI, `main() -> int`, colored summary.
- `vectorguard/config/loader.py` — `load_yaml_file` (rejects duplicate keys) and
  `{{placeholder}}` resolution. **Reuse for all YAML loading.**
- `vectorguard/runner/run_suite.py` — load/validate tests, run, build result dicts.
- `vectorguard/evaluators/detectors.py` — `DETECTOR_REGISTRY` + `evaluate_response`
  (required vs advisory detectors).
- `vectorguard/core/scoring.py` — severity weights x confidence = risk score.
- `vectorguard/core/findings.py` — category -> finding template.
- `vectorguard/reports/` — `build_summary`, `save_json_report`, `save_markdown_report`.
- `vectorguard/targets/` — `BaseTarget`, `OpenAILikeTarget`, `HTTPAppTarget` (httpx).
- `vectorguard/rag_scan.py` — separate `__main__` entry point that composes the
  core pipeline. This is the precedent the Web Agent follows.

Dependencies: `httpx`, `pyyaml`, `python-dotenv`, `flask`.

### Web Agent package

The Web Agent is **additive and isolated** under `vectorguard/webagent/`. It has
its own HTTP request/evidence shape (method/path/headers/params; status/headers/
body/length/timing), so it does **not** use `BaseTarget.send_messages`. It
**reuses** cross-cutting infrastructure: `load_yaml_file`, severity scoring math,
`build_summary`, and `save_json_report`.

```
vectorguard/webagent/
  __init__.py
  cli.py      # subcommands: plan / validate / scan / report
  config.py   # target-config model (target, scope, known_endpoints, cookies)
  scope.py    # host extraction + allowlist + method-safety gate
  models.py   # typed dataclasses for web tests, requests, detectors, findings
```

Web test templates live under `vectorguard/web_tests/` (with PortSwigger-core
templates under `vectorguard/web_tests/portswigger_core/`). Web scan output goes
under `reports/<run>/` (evidence, raw_results.json, findings.json, report.md).

## Coding Rules

- Work phase by phase; keep commits small and reviewable.
- Do not edit unrelated files. Do not break existing CLI commands.
- Reuse existing VectorGuard patterns (argparse + `main() -> int`, plain-dict
  payloads, registry dicts, `load_yaml_file`).
- Avoid adding unnecessary dependencies; prefer `httpx` (already present).
- Use `from __future__ import annotations` and type hints, matching the codebase.
- Run after each phase: `python -m compileall vectorguard`.
- Never commit secrets, real cookies, tokens, or API keys.

## Web Agent MVP Scope

Phased build. Each phase is a small commit.

1. Repo understanding and plan.
2. `CLAUDE.md` (this file).
3. Web Agent skeleton: package + dry-run CLI (`plan`, `validate`, `scan`,
   `report`). No HTTP yet.
4. Scope and safety validation (+ unit tests).
5. YAML web test format + loader + `validate`.
6. Safe HTTP runner (GET first) + evidence capture + redaction.
7. Detector system (`status_code`, `body_contains_any`, `body_not_contains_any`,
   `response_length_gt`, `response_length_delta_gt`, `error_keywords`).
8. `findings.json` + `report.md`.
9. PortSwigger-core templates.
10. Deterministic planner -> `plan.json`.
11. Test generation from plan.
12. Optional LLM planner (`--planner llm`), deterministic remains default.
13. Optional AI report summary (`--ai-summary`).
14. Local intentionally-vulnerable demo app.
15. Documentation.

## What NOT to Build

- A full autonomous pentesting tool.
- A public internet scanner.
- Brute force / password spraying / account-takeover automation.
- Exploit chaining or destructive testing.
- Stealth / evasion features.
- Malware-related functionality.
- Browser automation in the MVP.
- A Burp Suite replacement.
- Full crawling in the first version.

## Test Commands

LLM/RAG core (existing — must keep working):

```bash
python -m compileall vectorguard
python -m vectorguard.cli --help
```

Web Agent (current skeleton):

```bash
python -m vectorguard.webagent.cli --help

python -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 \
  --scope localhost \
  --tests vectorguard/web_tests/example_admin_check.yaml \
  --out reports/web_scan_test
```
