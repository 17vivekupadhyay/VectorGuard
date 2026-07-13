# VectorGuard Repository Structure

A quick reference for navigating the codebase. VectorGuard has three testing tiers, each with its own module tree.

## Top-Level Entry Points

```
python -m vectorguard.cli              # YAML-based LLM/RAG security tests (Phase 1-2)
python -m vectorguard.redteam.cli      # Autonomous red-team agent (Phase 3)
python -m vectorguard.webagent.cli     # OWASP web application security testing (Phase 4+)
```

---

## Module Guide by Feature

### 1. YAML LLM/RAG Tests (`vectorguard/`)

**Purpose:** Run declarative YAML attack suites against LLM/RAG systems.

| Module | Purpose |
|--------|---------|
| `cli.py` | Main entry: load YAML suite, orchestrate pipeline |
| `config/loader.py` | YAML loading, `{{placeholder}}` substitution |
| `core/scoring.py` | Severity → risk score conversion |
| `core/findings.py` | Category → finding template mapping |
| `evaluators/detectors.py` | Pattern matching (contains, refusal, normalization) |
| `runner/run_suite.py` | Load tests, validate, execute pipeline |
| `targets/` | Target interfaces: `OpenAILikeTarget`, `HTTPAppTarget` |
| `reports/` | Build and save JSON/Markdown reports |

**Pipeline:** Load YAML → validate → send to target → evaluate response → score → findings → reports

---

### 2. Autonomous Red-Team Agent (`vectorguard/redteam/`)

**Purpose:** AI-driven attack orchestration: plan → execute → judge → reflect → escalate.

| Module | Purpose |
|--------|---------|
| `cli.py` | Single `attack` subcommand; parse args, dispatch to campaign |
| `campaign.py` | Orchestrate attack phases (reconnaissance, escalation, analysis) |
| `operator.py` | LLM payload generator (talk-only, no execution) |
| `executor.py` | Deterministic request sender (enforces safe-by-default) |
| `judge.py` | LLM judge: did the attack succeed? |
| `analyst.py` | Reflect on results, recommend next tactics |
| `objectives.py` | Attack objectives (prompt injection, data exfil, etc.) |
| `prompts.py` | Templates for operator/judge/analyst LLM calls |
| `seeds.py` | Payload seed tactics (jailbreak templates, etc.) |

**Loop:** Operator → Executor → Judge → Analyst → escalate tactics

---

### 3. Web Agent (`vectorguard/webagent/`)

**Purpose:** Bounded OWASP-style security testing: safe-by-default, GET-only by default.

#### Commands (each in its own module under `commands/`)

| Command | File | Purpose |
|---------|------|---------|
| `plan` | `commands/plan.py` | Map target endpoints to test templates (dry-run) |
| `generate-tests` | `commands/generate.py` | Build YAML test files from plan |
| `agent` | `commands/agent.py` | Run observe-decide-act loop over a target |
| `validate` | `commands/validate.py` | Validate YAML web test (dry-run) |
| `scan` | `commands/scan.py` | Send a single safe GET, capture evidence |
| `check` | `commands/check.py` | Verify scope/method safety (dry-run) |
| `report` | `commands/report.py` | Render report from previous scan (dry-run) |

#### Core Modules

| Module | Purpose |
|--------|---------|
| `cli.py` | Parser + dispatcher (routes subcommands) |
| `commands/shared.py` | Shared helpers: `load_web_test_or_report`, print utilities |
| `config.py` | Target configuration model |
| `scope.py` | Host allowlist validation |
| `safety.py` | HTTP method safety (DELETE, PUT blocked by default) |
| `models.py` | Dataclasses for tests, requests, detectors, findings |
| `loader.py` | YAML web test loader |
| `detectors.py` | HTTP response analyzers (status, body, length, error keywords) |
| `findings.py` | Assemble findings from detector results |
| `evidence.py` | Save raw responses, sanitize secrets |
| `runner.py` | Safe HTTP request executor |
| `planner.py` | Generate test plan from target config |
| `generator.py` | Build test files from plan |
| `agent/agent_loop.py` | Observe-decide-act orchestration |
| `agent/llm_client.py` | LLM client (Claude via environment) |
| `agent/report_agent.py` | AI summary generation |
| `report.py` | Build Markdown reports |

**Pipeline:** Config → Planner → Generator → Scan/Agent → Detector → Findings → Report

---

## Key Patterns

### Configuration Loading

All YAML loading goes through **one place**:
```python
from vectorguard.config.loader import load_yaml_file
config = load_yaml_file(path)  # Validates, rejects duplicates, resolves {{placeholders}}
```

### Scoring and Findings

Severity → risk score conversion is centralized:
```python
from vectorguard.core.scoring import severity_to_score
score = severity_to_score("high")  # Returns numeric score
```

Finding templates (category descriptions, recommendations):
```python
from vectorguard.core.findings import CATEGORY_FINDINGS
template = CATEGORY_FINDINGS.get("rag_injection")
```

---

## Testing

- **Unit tests:** `tests/test_*.py` (YAML suite, redteam, web agent)
- **Integration smoke tests:** CI runs Flask mock target, exercises CLI exit codes
- **Demo app:** `examples/rag_chatbot_app.py` (Flask app with intentional vulnerabilities)

---

## Output Conventions

All tools save to:

```
reports/
  <run-id>/
    raw_results.json        # Detector output (what was triggered)
    findings.json           # Assembled findings (categories, evidence, risk scores)
    report.md               # Human-readable Markdown
    evidence/
      <test-id>/
        request.txt         # HTTP request (redacted)
        response.txt        # HTTP response (redacted)
```

**Redaction rules:**
- `Authorization` headers removed
- Cookies removed
- Secrets tagged in config are masked in evidence files

---

## Common Tasks

### Add a new YAML detector
1. Edit `vectorguard/evaluators/detectors.py`
2. Add pattern logic to `DETECTOR_REGISTRY`
3. Test: `python -m pytest tests/test_detectors.py`

### Add a new web detector
1. Edit `vectorguard/webagent/detectors.py`
2. Add to `evaluate_detectors()` dispatcher
3. Test: `python -m pytest tests/test_webagent_detectors.py`

### Add a new CLI command (web agent)
1. Create `vectorguard/webagent/commands/<name>.py` with `cmd_<name>(args)` function
2. Add to `commands/__init__.py` exports
3. Register in `cli.py`'s `build_parser()` subparser

### Run a scan
```bash
python -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 \
  --scope localhost \
  --tests vectorguard/web_tests/example.yaml \
  --out reports/my_scan
```

---

## Philosophy

**VectorGuard is defensive and bounded:**
- Only scans targets you own or explicitly authorize
- Default to safe-by-default (GET-only, dry-run when possible)
- Requires `--scope` on every command
- Blocks destructive methods by default
- Never commits secrets or real credentials

**Code organization:**
- Minimal dependencies (`httpx`, `pyyaml`, `flask`, `python-dotenv`)
- Plain Python: no ORM, no heavy frameworks
- Reusable patterns: registry dicts, validation layers, evidence redaction
- One YAML loader, one scoring function, one report builder
