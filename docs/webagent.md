# VectorGuard Web Agent

> VectorGuard Web Agent is a defensive, authorized OWASP-style web application
> security testing layer. It maps known web surfaces to safe PortSwigger-inspired
> checks, executes scoped HTTP tests, captures evidence, and generates
> remediation reports. It is designed for local labs, owned applications, and
> explicitly authorized security testing. Findings are signals for review, not
> proof of complete security.

## 1. What it is

- A **defensive, authorized** OWASP-style web application security testing layer.
- Inspired by [PortSwigger Web Security Academy](https://portswigger.net/web-security)
  labs and mapped to the [OWASP Top 10 (2021)](https://owasp.org/Top10/2021/).
- It behaves like a junior AppSec analyst: it maps known surfaces to safe checks,
  runs scoped HTTP requests, captures evidence, and writes remediation reports.
- Pipeline:
  **planner → generated tests → scoped scanner → evidence → detectors → findings → report**.

The agent **plans and explains**; deterministic Python code **executes** requests
and **evaluates** evidence. The agent never invents endpoints, evidence, or
destructive tests.

## 2. What it is not

- Not a full autonomous hacking/pentesting tool.
- Not a public internet scanner.
- Not a Burp Suite replacement.
- No crawling yet.
- No POST execution yet (state-changing templates validate but are gated).
- No real LLM provider integration yet (planner/report agent are stub/fallback).
- No RAG knowledge layer yet.

## 3. Safety model

- Requires an explicit `--scope` for every scan.
- Blocks out-of-scope targets before any request is sent.
- **GET-only** runner today; non-GET tests fail cleanly.
- Blocks state-changing `POST` by default (allowed only with
  `--allow-state-changing`, which the GET-only runner still won't execute).
- Always blocks destructive methods: `PUT`, `PATCH`, `DELETE`.
- Redacts sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`,
  `X-API-Key`, `API-Key`) in saved evidence and reports.
- Intended for local labs, owned applications, and explicitly authorized targets
  only.

## 4. Architecture / pipeline

```
target_config.yaml
  ↓
deterministic or LLM-fallback planner
  ↓
plan.json
  ↓
generated YAML tests
  ↓
safe scoped GET runner
  ↓
evidence/
  ↓
detector_results.json
  ↓
findings.json
  ↓
report.md
  ↓
optional agent_summary.md
```

The Web Agent is additive and isolated under `vectorguard/webagent/`. It reuses
cross-cutting VectorGuard infrastructure (`load_yaml_file`, severity scoring,
JSON report writing) but has its own HTTP request/evidence shape.

## 5. Supported MVP checks

| Template | OWASP | Method | Status |
|----------|-------|--------|--------|
| `access_control_forced_browsing_admin` | A01 Broken Access Control | GET | Executable |
| `injection_sqli_basic_error_probe` | A03 Injection | GET | Executable |
| `jwt_cookie_shape_check` | A01 / A07 | GET | Executable (informational) |
| `auth_username_enumeration` | A07 Auth Failures | POST | Gated (validates, does not run) |
| `csrf_missing_token_check` | A01 / CSRF | POST | Gated (validates, does not run) |

Templates live under `vectorguard/web_tests/portswigger_core/`.

## 6. Quickstart demo

A local, intentionally-vulnerable demo app lives in
[`examples/web_demo_app/`](../examples/web_demo_app/).

Terminal 1 — start the demo app:

```bash
python3 examples/web_demo_app/app.py
```

Terminal 2 — plan, generate tests, and scan:

```bash
python3 -m vectorguard.webagent.cli plan \
  --config examples/web_demo_app/webagent_target.yaml \
  --out reports/demo_plan

python3 -m vectorguard.webagent.cli generate-tests \
  --config examples/web_demo_app/webagent_target.yaml \
  --out reports/demo_generated

python3 -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 --scope localhost \
  --tests reports/demo_generated/generated_tests/generated_access_control_forced_browsing_admin.yaml \
  --out reports/demo_admin --ai-summary

python3 -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 --scope localhost \
  --tests reports/demo_generated/generated_tests/generated_injection_sqli_basic_error_probe.yaml \
  --out reports/demo_sqli --ai-summary
```

## 7. macOS note

On macOS, **AirPlay Receiver** may already use port 5000. If requests to
`localhost:5000` look wrong, either disable AirPlay Receiver in
**System Settings → General → AirDrop & Handoff**, or run the app on another port
and update the target config accordingly.

## 8. Output files

Each scan writes to its `--out` directory:

- `evidence/` — per-test request metadata (`<id>_request.json`) and response body
  (`<id>_response.txt`)
- `raw_results.json` — request/response metadata (status, redacted headers, body
  length, elapsed ms, body sha256)
- `detector_results.json` — structured detector signals
- `findings.json` — higher-level findings (empty when nothing is suspicious)
- `report.md` — deterministic Markdown report
- `agent_summary.md` — only when `--ai-summary` is used (placeholder without an
  LLM client)

## 9. How to add a new YAML test template

Create a YAML file (for example under `vectorguard/web_tests/`) with these fields:

```yaml
id: my_check                 # required, unique string
name: My check               # required string
category: access_control     # required string
owasp: A01-Broken-Access-Control  # required string
severity: high               # one of: info, low, medium, high, critical
safe: true                   # boolean (optional, default true)
requires_state_changing: false  # boolean (optional, default false)

request:
  method: GET                # required (GET runs today; POST validates but is gated)
  path: /admin               # required, must start with "/"
  headers: {}                # optional dict
  params: {}                 # optional dict

detectors:                   # non-empty list; each needs a "type"
  - type: status_code
    suspicious_if: 200
  - type: body_contains_any
    keywords: [Admin, administrator]

remediation:                 # optional list of strings
  - Enforce server-side authorization on admin routes.
```

Supported detector types: `status_code`, `body_contains_any`,
`body_not_contains_any`, `response_length_gt`, `response_length_delta_gt`,
`error_keywords`.

Validate it:

```bash
python3 -m vectorguard.webagent.cli validate --tests path/to/my_check.yaml
```

## 10. Current limitations

- No crawler / endpoint discovery.
- No browser automation.
- No POST execution (state-changing templates are gated).
- No active JWT tampering (JWT check is informational only).
- No brute force / password spraying / account-takeover automation.
- The LLM planner and report agent are stub/fallback unless a client is wired in.
- No RAG knowledge layer yet.

## 11. Roadmap

- RAG knowledge layer over OWASP, PortSwigger notes, and lab writeups.
- Real LLM client integration for the planner and report agent.
- Browser/form discovery.
- Multi-user access-control testing.
- Safe POST support for local labs.
- CI mode for local demo apps.
- Import/coverage summary from a PortSwigger lab repo.

## 12. Portfolio positioning

This module demonstrates an AI-assisted AppSec pipeline: planner, generator,
scanner, detector, and report agent. The agent plans and explains while
deterministic code executes scoped requests and evaluates evidence, keeping the
system safe, reproducible, and auditable.
