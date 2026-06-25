# Building VectorGuard Web Agent — Claude Code Session

**Author:** Vivek Upadhyay
**Tool:** Claude Code (Opus 4.8)
**Project:** [VectorGuard](https://github.com/17vivekupadhyay/VectorGuard) — a defensive security testing toolkit
**Branch:** `feature/web-agent`

## What this session is

A phased, commit-by-commit build of **VectorGuard Web Agent**: a new defensive,
authorized, OWASP-style web application security testing layer added to an
existing LLM/RAG security toolkit. The work was done as 15 reviewable phases.
The guiding rule throughout:

> The agent **plans and explains**. Deterministic Python code **executes**
> requests and **evaluates** evidence. The LLM never invents endpoints, evidence,
> or destructive tests.

Hard safety constraints enforced in code, not just docs: explicit `--scope`
required, out-of-scope targets blocked before any request, GET-only runner,
`POST` blocked by default, `PUT`/`PATCH`/`DELETE` always blocked, sensitive
headers redacted, local/authorized targets only.

---

## Final result

Ten commits on `feature/web-agent`, smallest-reviewable-unit style:

```
(docs)  Add VectorGuard Web Agent documentation              ← Phase 15 (pending approval at session end)
2e57371 Add local intentionally-vulnerable web agent demo app   ← Phase 14
04806e0 Add optional AI report summary for web agent            ← Phase 13
060d077 Add optional LLM-assisted web agent planner             ← Phase 12
46a9ac9 Add web agent test generation from plan                 ← Phase 11
e70ee71 Add deterministic web agent planner                     ← Phase 10
f0d9dbe Add PortSwigger-core web security templates             ← Phase 9
8b58116 Add web agent findings and Markdown report generation   ← Phase 8
5dbe759 Add web agent HTTP runner, evidence capture, and detectors  ← Phase 6+7
74bf2bd Add web agent YAML test validation                      ← Phase 5
69feffe Add web agent skeleton and safety guards                ← Phase 3+4
```

Final package layout:

```
vectorguard/webagent/
  __init__.py
  cli.py          # subcommands: plan / generate-tests / validate / scan / check / report
  config.py       # ScanOptions builder + scope normalization
  scope.py        # host extraction + allowlist + ScopeError
  safety.py       # HTTP method safety gate + MethodSafetyError
  models.py       # dataclasses: ScanOptions, RequestSpec, DetectorSpec, WebTest
  loader.py       # web test YAML loader + typed validation
  runner.py       # safe GET runner + evidence shape
  evidence.py     # redaction + evidence/raw_results/detector_results writers
  detectors.py    # 6 detector types + registry + preflight validation
  findings.py     # detector results -> findings (reuses core severity scoring)
  report.py       # deterministic Markdown report
  planner.py      # deterministic planner -> plan.json
  generator.py    # plan -> concrete YAML tests
  agent/
    __init__.py
    llm_planner.py   # optional LLM planner (stub/fallback, mockable client)
    schemas.py       # strict validation of LLM plan output
    prompts.py       # structured-data-only prompt builder
    report_agent.py  # optional AI report summary (stub/fallback)

vectorguard/web_tests/portswigger_core/
  access_control_forced_browsing_admin.yaml   # A01, GET, executable
  injection_sqli_basic_error_probe.yaml       # A03, GET, executable
  jwt_cookie_shape_check.yaml                 # A01/A07, GET, informational
  auth_username_enumeration.yaml              # A07, POST, gated
  csrf_missing_token_check.yaml               # A01/CSRF, POST, gated

examples/web_demo_app/    # local intentionally-vulnerable Flask demo + target config
docs/webagent.md          # full guide
```

---

## Phase 1 — Repo understanding and implementation plan

**Prompt (abridged):** Analyze the existing VectorGuard architecture; identify
how CLI, YAML loading, detectors, reports, storage, and runners work; produce an
implementation plan; do not edit files yet.

**What I did:** Read the codebase and mapped its pipeline:

```
YAML suite → run_suite → target.send_messages → evaluate_response → scoring → findings → reports
```

Key finding: the project is dependency-light (`httpx`, `pyyaml`, `python-dotenv`,
`flask`), run via `python -m`, with **no pytest** — "tests" are CI integration
smoke tests that boot a Flask mock and assert exit codes. The strongest
precedent for the Web Agent was `vectorguard/rag_scan.py`: a *separate* `__main__`
module that **composes** the core pipeline rather than modifying it.

**Decision:** The Web Agent would be **additive and isolated** under
`vectorguard/webagent/`, reusing cross-cutting infra (`load_yaml_file`, severity
scoring, `build_summary`, `save_json_report`) but with its own HTTP
request/evidence shape — because the LLM core sends `messages[]` and evaluates
`response.text`, whereas the Web Agent sends HTTP requests and evaluates
status/headers/body/length/timing. Forcing `BaseTarget.send_messages` would
distort both.

Recommended first increment: Phase 2 (`CLAUDE.md`) + Phase 3 (skeleton) together.

---

## Phase 2 + 3 — `CLAUDE.md` and the skeleton CLI

**Constraints:** No HTTP, no crawling, no LLM, no pytest, no CI changes, don't
touch existing LLM/RAG scanner.

**Delivered:**
- `CLAUDE.md` — project purpose, defensive-use restrictions, architecture
  summary, coding rules, MVP scope, "what not to build", test commands.
- `vectorguard/webagent/` package with `__init__.py`, `cli.py`, `config.py`,
  `scope.py`, `models.py`.
- argparse CLI with subcommands `plan` / `validate` / `scan` / `report`, all
  dry-run. `scan` parses `--target`/`--scope`/`--tests`/`--out`, validates
  presence, creates the output dir, prints a dry-run summary, **sends zero HTTP
  requests**.
- `vectorguard/web_tests/example_admin_check.yaml` placeholder.
- Added `reports/` to `.gitignore`.

**Verified:** `python3 -m compileall vectorguard` OK; `--help` lists subcommands;
dry-run `scan` against `localhost` creates the dir and sends nothing; missing
`--scope` is rejected with exit code 2.

---

## Phase 4 — Scope and safety validation

**Delivered:**
- `scope.py`: `ScopeError`, `normalize_host`, `extract_host`, `normalize_scope`,
  and authoritative `validate_scope` (deny-by-default; `localhost`/`127.0.0.1`
  allowed only when explicitly scoped, not auto-equivalent).
- `safety.py`: `MethodSafetyError`, `validate_method`, `is_method_allowed`.
  Policy: `GET`/`HEAD`/`OPTIONS` allowed; `POST` blocked unless
  `--allow-state-changing`; `DELETE`/`PUT`/`PATCH` **always** blocked (even with
  the flag).
- `scan` now enforces scope (blocks out-of-scope, exit 2); new `check` command
  to verify scope + method safety without sending anything.

**Verified (8 scenarios):** localhost allowed, 127.0.0.1 allowed, out-of-scope
blocked, DELETE blocked by default, DELETE still blocked with flag, POST blocked
by default, POST allowed with flag, PUT blocked with flag.

**Committed:** `69feffe Add web agent skeleton and safety guards` (one checkpoint
covering Phases 3+4).

---

## Phase 5 — YAML web test loading and validation

**Delivered:**
- `loader.py` — reuses `vectorguard.config.loader.load_yaml_file` (duplicate-key
  rejection, top-level-mapping enforcement) and adds `validate_web_test`,
  `load_web_test`, `WebTestValidationError`.
- `models.py` — `SEVERITY_LEVELS`, dataclasses `RequestSpec`, `DetectorSpec`,
  `WebTest`.
- `validate` and `scan` both load + validate the YAML first.

**Validation rules:** required non-empty strings for `id`/`name`/`category`/
`owasp`; `severity ∈ {info,low,medium,high,critical}`; `safe`/
`requires_state_changing` booleans (optional, type-checked); `request.method`
required; `request.path` must start with `/`; `headers`/`params` dicts if
present; `detectors` non-empty list each with a `type`; `remediation` list of
strings.

**Verified:** valid file prints a summary and exits 0; an intentionally invalid
example produced a helpful error:

```
Error: invalid web test - web test examples/webagent/invalid_admin_check.yaml
'invalid_admin_check': 'severity' must be one of [critical, high, info, low, medium]
(got 'extreme').
```

**Committed:** `74bf2bd Add web agent YAML test validation`.

---

## Phase 6 — Safe GET HTTP runner + evidence capture

**Delivered:**
- `runner.py` — `run_get_test`: builds the URL from `--target` + `path`,
  **re-validates scope against the resolved URL before sending**, bounded
  timeout, `follow_redirects=False`, returns structured raw result. Rejects
  non-GET with `RunnerError`.
- `evidence.py` — `redact_headers` (Authorization, Cookie, Set-Cookie,
  X-API-Key, API-Key → `[REDACTED]`), `save_evidence`
  (`evidence/<id>_request.json`, `<id>_response.txt`), `save_raw_results`.
- `scan` executes the GET and saves evidence.

**Verified:** real GET scan against a local server → status 200, evidence saved;
`raw_results.json` captured status/headers/body_length/elapsed_ms/body_sha256
with `Set-Cookie` redacted; out-of-scope blocked before any request; POST cleanly
rejected.

---

## Phase 7 — Detector system

**Delivered:** `detectors.py` with six detectors, each emitting
`{detector, suspicious, confidence, matched, explanation}`:

| Detector | Suspicious when | Confidence |
|----------|-----------------|------------|
| `status_code` | status ∈ `suspicious_if` | high |
| `body_contains_any` | any keyword present | medium |
| `body_not_contains_any` | none of the keywords present | low |
| `response_length_gt` | length > `value` | low |
| `response_length_delta_gt` | `|len − baseline| > value` (graceful no-baseline) | medium |
| `error_keywords` | any error/stack-trace marker present | high |

Unknown types raise a helpful `WebDetectorError`. `scan` evaluates detectors and
writes `detector_results.json`.

**Safety improvement (requested before commit):** added `validate_detector_specs`
preflight so an **unknown detector type fails before any HTTP request is sent** —
proven via a server hit-log showing zero requests for the bad-detector scan.

**Committed:** `5dbe759 Add web agent HTTP runner, evidence capture, and detectors`
(combined Phase 6+7, since the changes were interleaved in `cli.py`/`evidence.py`).

---

## Phase 8 — Findings and Markdown report

**Delivered:**
- `findings.py` — converts a test + raw result + detector results into a finding,
  **only** when ≥1 detector is suspicious; confidence = highest among suspicious
  detectors; reuses `vectorguard.core.scoring.severity_to_score` for a
  `risk_score`.
- `report.py` — deterministic Markdown with metadata, target, scope, safety mode,
  test run, findings summary, detailed findings, evidence files, remediation,
  retest command, and a defensive-use disclaimer.
- `scan` writes `findings.json` + `report.md`; `report` regenerates `report.md`
  from a saved scan directory.

**Verified:** admin scan → 1 finding (high, confidence high, risk 8.0), full
artifact set; clean 404 scan → `"findings": []` and report says "No findings".

**Committed:** `8b58116 Add web agent findings and Markdown report generation`.

---

## Phase 9 — PortSwigger-core templates

**Delivered five safe, conservative templates** under
`vectorguard/web_tests/portswigger_core/`:

| Template | OWASP | Method | Executable now? |
|----------|-------|--------|-----------------|
| access_control_forced_browsing_admin | A01 | GET `/admin` | ✅ runs |
| injection_sqli_basic_error_probe | A03 | GET `/filter?category='` | ✅ runs |
| jwt_cookie_shape_check | A01/A07 | GET `/my-account` | ✅ runs (informational) |
| csrf_missing_token_check | A01/CSRF | POST | ⛔ gated |
| auth_username_enumeration | A07 | POST | ⛔ gated |

The SQLi probe uses a single `'` — error-surfacing only, no extraction/blind
techniques. Auth template is a single controlled attempt (no brute force). JWT
template only flags the `eyJ` token shape (no tampering).

**Verified:** all five validate; GET templates run and find issues; POST
templates are gated two layers deep (method safety, then GET-only runner).

**Committed:** `f0d9dbe Add PortSwigger-core web security templates`.

---

## Phase 10 — Deterministic planner

**Delivered:**
- `planner.py` — `load_target_config`, `build_plan`, `save_plan`, `PlannerError`.
  Reads a target config (target, scope, known_endpoints, cookies), validates
  target+scope, applies endpoint/cookie rules, and loads each template to derive
  `executable_now` so the plan never drifts from the YAML.
- `examples/webagent/target_config.yaml`.
- `plan --config … --out …` writes `plan.json` (no HTTP).

**Rules:** `/admin` → forced-browsing; query params → SQLi probe; `login` → auth
(gated); `change-email`/`change-password`/`update`/`account` → CSRF (gated);
`my-account` or cookies present → JWT review.

**Verified:** the example config → 3 selected (executable GET), 2 gated (POST),
0 skipped; out-of-scope config rejected with no HTTP.

**Committed:** `e70ee71 Add deterministic web agent planner`.

---

## Phase 11 — Test generation from plan

**Delivered:** `generator.py` — builds the plan and renders concrete YAML:
executable GET tests → `generated_tests/`, gated POST tests →
`generated_tests/gated/`. Per-endpoint overrides for GET templates (e.g.
`/filter?category=Gifts` → path `/filter`, params `{category: "'"}`); appends a
`generated:` provenance block (`generated_from`, `reason`, `executable_now`,
`target_config`). Originals never mutated. New `generate-tests` CLI command.

**Verified:** exact output structure from spec; all 5 generated tests validate;
a generated GET test round-trips through `scan` and produces a finding; original
templates untouched.

**Committed:** `46a9ac9 Add web agent test generation from plan`.

---

## Phase 12 — Optional LLM-assisted planner (safe interface)

**Delivered:** `agent/` subpackage —
- `schemas.py` — `validate_llm_plan` enforces: template IDs must exist, endpoints
  must exist in `known_endpoints`, `executable_now` must match real template
  metadata, state-changing templates must be gated.
- `prompts.py` — builds a prompt from **structured surface data only** (no raw
  HTML).
- `llm_planner.py` — `get_llm_client()` returns `None` (no client wired this
  phase), `plan_with_llm`, `LLMUnavailableError`, `FALLBACK_MESSAGE`.
- `plan --planner deterministic|llm` (default deterministic). LLM mode falls back
  to deterministic on unavailability **or** invalid output.

**Verified (mock client, no real API):** valid output accepted; invented template
ID rejected; gated template placed in `selected_tests` rejected; invented
endpoint rejected. `--planner llm` with no key prints exactly *"LLM planner
unavailable; falling back to deterministic planner."* and writes a plan identical
to deterministic. Works without any API keys.

**Committed:** `060d077 Add optional LLM-assisted web agent planner`.

---

## Phase 13 — Optional AI report summary

**Delivered:** `agent/report_agent.py` — `--ai-summary` on `scan` and `report`.
Uses **only** `findings.json` / `detector_results.json` / `raw_results.json` /
`plan.json` as evidence. Without an LLM it never fails the scan: prints *"AI
summary unavailable; deterministic report.md was still generated."* and writes a
placeholder `agent_summary.md`. With a (mock) client it produces all eight
sections (Executive summary, OWASP mapping, Findings explained, Technical
evidence, Risk and impact, Remediation, Retest plan, Limitations).

**Verified:** scan without the flag still works (no summary file); fallback path
clean; zero findings → placeholder says "No suspicious findings were detected";
mock client produces all sections and the prompt carried only provided evidence.

**Committed:** `04806e0 Add optional AI report summary for web agent`.

---

## Phase 14 — Local intentionally-vulnerable demo app

**Delivered:** `examples/web_demo_app/` — `app.py` (Flask, binds `127.0.0.1:5000`,
fake-vulnerable responses), `README.md` (clearly marked intentionally vulnerable,
local-only, do-not-deploy), `webagent_target.yaml`.

Routes: `/admin` (fake admin, "delete user"), `/filter?category=Gifts` (normal),
`/filter?category='` (HTTP 500 with `SQL syntax` error), `/my-account` (JWT-shaped
token).

**Verified end-to-end** (ran the app on 5001 to dodge a macOS AirPlay :5000
conflict): plan → 3 selected/1 gated/1 skipped; generate-tests → 3+1 YAML; admin
scan → finding (high); SQLi scan → finding (high, status 500 + SQL error
markers). A README note documents the macOS AirPlay Receiver port-5000 conflict.

**Committed:** `2e57371 Add local intentionally-vulnerable web agent demo app`.

Sample SQLi report excerpt:

```
## Detailed Findings
### SQL injection basic error probe
- OWASP: A03-Injection
- Severity: high
- Confidence: high
- Endpoint: GET /filter
- Status code: 500
- Matched evidence: [500, 'SQL syntax', 'you have an error in your SQL']

**Suspicious detectors**
- status_code (confidence=high): Response status 500 matched suspicious_if [500].
- error_keywords (confidence=high): Response body contained error marker(s): [...].
```

---

## Phase 15 — Documentation

**Delivered:** `docs/webagent.md` (12 sections: what it is / is not, safety model,
architecture pipeline, supported MVP checks, quickstart demo, macOS note, output
files, how to add a YAML template, current limitations, roadmap, portfolio
positioning) and a "VectorGuard Web Agent" section in the root `README.md`
linking to it. Docs-only; no scanner behavior changed; kept accurate to what
exists today (GET-only, gated POST, stub LLM, no RAG).

---

## Engineering notes / themes

- **Phase-by-phase, smallest reviewable commits.** Every phase ended with
  `python -m compileall vectorguard` and concrete verification before any commit,
  and I never committed without explicit approval.
- **Safety enforced in code.** Scope is re-validated against the *resolved* URL
  inside the runner; unknown detector types fail *before* sending; redaction
  happens at evidence-build time; the GET-only runner is a second gate behind
  method safety.
- **Honest reporting.** When `git commit` once reported "nothing to commit"
  because the tree was already committed, I surfaced that the co-author trailer
  was missing rather than claiming success. When the demo app hit the macOS
  AirPlay :5000 conflict, I diagnosed it via `lsof`, proved the app itself was
  correct from its log, and ran verification on an alternate port instead of
  faking a green result.
- **Reuse over reinvention.** The Web Agent reuses the existing YAML loader,
  severity scoring, and report conventions; it never touches the LLM/RAG core.
- **Deterministic core, optional AI.** The planner and report summary default to
  deterministic and work with no API keys; the LLM is an optional, strictly
  validated, mockable interface that can only choose among known templates and
  known endpoints — it can never invent endpoints, evidence, or destructive
  tests.

---

_Generated from a Claude Code session. VectorGuard Web Agent is a defensive
testing aid; findings are signals for review, not proof of complete security._
