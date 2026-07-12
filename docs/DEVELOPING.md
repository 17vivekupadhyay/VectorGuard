# VectorGuard Developer Guide

This guide covers setting up a development environment, understanding the codebase, and contributing to VectorGuard.

---

## Table of Contents

1. [Setup](#setup)
2. [Project Structure](#project-structure)
3. [Core Concepts](#core-concepts)
4. [Common Workflows](#common-workflows)
5. [Testing](#testing)
6. [Debugging](#debugging)
7. [Adding Features](#adding-features)
8. [Architecture Deep Dive](#architecture-deep-dive)

---

## Setup

### Prerequisites

- Python 3.9+
- pip
- git

### Local Development Install

```bash
# Clone the repo
git clone https://github.com/17vivekupadhyay/VectorGuard.git
cd VectorGuard

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode (editable)
pip install -e .

# Verify installation
python -m compileall vectorguard
python -m vectorguard.cli --help
```

### Environment Setup

```bash
# Copy example .env
cp .env.example .env

# Edit with your API key
export VG_API_KEY=your_key_here
```

### Verify the Build

```bash
# Test YAML suites
python3 -m vectorguard.cli \
  --target vectorguard/examples/demo_target.yaml \
  --tests vectorguard/tests/rag_injection.yaml \
  --verbose

# Test autonomous agent
python3 -m vectorguard.redteam.cli attack \
  --target vectorguard/examples/redteam_target.yaml \
  --scope 127.0.0.1 \
  --objectives system_prompt_leak \
  --max-steps 2

# Test web agent
python3 -m vectorguard.webagent.cli plan \
  --target http://localhost:5000 \
  --scope localhost
```

---

## Project Structure

```
vectorguard/
├── cli.py                          # Main YAML suite CLI
├── rag_scan.py                     # Local RAG scan CLI
│
├── config/
│   └── loader.py                   # YAML loading + {{placeholder}} resolution
│
├── core/
│   ├── scoring.py                  # Risk scoring (severity × confidence)
│   └── findings.py                 # Finding templates + OWASP mapping
│
├── evaluators/
│   └── detectors.py                # Detector registry + evaluation logic
│
├── runner/
│   └── run_suite.py                # Test loading + execution loop
│
├── targets/
│   ├── __init__.py                 # BaseTarget interface
│   ├── openai_like.py              # OpenAI-compatible chat endpoints
│   └── http.py                     # Generic HTTP chatbot adapter
│
├── reports/
│   ├── json_report.py              # JSON output
│   ├── markdown.py                 # Markdown output
│   └── summary.py                  # Summary aggregation
│
├── rag.py                          # RAG utilities (load, chunk, retrieve)
│
├── redteam/                        # Autonomous red-team agent
│   ├── cli.py                      # Red-team CLI
│   ├── operator.py                 # Payload generator (brain)
│   ├── analyst.py                  # Response analyzer (reflection)
│   ├── objectives.py               # Objectives + oracle (proof capture)
│   ├── episode.py                  # Single objective loop
│   ├── campaign.py                 # Multi-objective orchestration
│   ├── judge.py                    # LLM-as-judge (optional)
│   ├── seeds.py                    # Attack seed/hint database
│   ├── executor.py                 # HTTP request execution
│   └── prompts.py                  # LLM prompt templates
│
├── webagent/                       # Web application agent
│   ├── cli.py                      # Web agent CLI
│   ├── config.py                   # Target config model
│   ├── scope.py                    # Scope validation + method gating
│   └── models.py                   # Typed request/response models
│
├── web_tests/                      # Web test templates
│   └── portswigger_core/           # PortSwigger-inspired checks
│
├── tests/                          # YAML attack suites
│   ├── rag_injection.yaml
│   ├── prompt_injection.yaml
│   └── ...
│
└── storage/                        # Generated reports (gitignored)
```

---

## Core Concepts

### 1. The Config Loader

**File:** `vectorguard/config/loader.py`

Handles YAML loading with placeholder resolution:

```python
from vectorguard.config.loader import load_yaml_file

config = load_yaml_file("vectorguard/examples/demo_target.yaml")
# Resolves {{env.VG_API_KEY}}, {{protected.secret}}, etc.
```

**Use this for:**
- Loading target configs
- Loading test suites
- Loading web configs
- Any YAML with `{{placeholder}}` syntax

**Don't:**
- Use `yaml.load()` directly (no placeholder support)
- Bypass the loader (reuse matters)

---

### 2. Detector Registry

**File:** `vectorguard/evaluators/detectors.py`

Pattern-based evaluation of model responses:

```python
from vectorguard.evaluators.detectors import evaluate_response

result = evaluate_response(
    response_text="The password is secret123",
    detectors=[
        {
            "type": "contains",
            "patterns": ["secret123"],
            "required": True,
        }
    ]
)

# result["passed"] = False (forbidden pattern found)
# result["detector_results"] = [...]
```

**Detector types:**
- `contains` — Forbidden string match (required by default)
- `regex` — Regex pattern match (required by default)
- `refusal` — Expected refusal language (advisory by default)
- `expected_contains` — Expected strings (required by default)
- `max_output_chars` — Output length check (required by default)

**To add a new detector:**
1. Implement `evaluate_<type>()` function
2. Register in `DETECTOR_REGISTRY` dict
3. Add tests in `tests/test_detectors.py`

---

### 3. Scoring Pipeline

**File:** `vectorguard/core/scoring.py`

Risk calculation: `severity × confidence = risk_score`

```python
from vectorguard.core.scoring import calculate_risk_score

risk = calculate_risk_score(
    severity="high",      # high, medium, low
    confidence=0.9,       # 0.0 to 1.0
)
# risk = 8.0 (for high) or 5.0 (for medium), etc.
```

**Severity levels:**
- `high` → 8.0
- `medium` → 5.0
- `low` → 2.0
- `info` → 1.0

**Confidence:**
- 1.0 → Deterministic proof (exact match, DLP)
- 0.85 → DLP hit (pattern-based)
- 0.6-0.8 → LLM-as-judge, heuristic signal
- 0.0 → No signal

---

### 4. Targets (Send Requests)

**Base class:** `vectorguard/targets/__init__.py`

```python
from vectorguard.targets import BaseTarget

class CustomTarget(BaseTarget):
    def send_messages(self, messages: list[dict]) -> str:
        # messages = [{"role": "user", "content": "..."}, ...]
        # Return model response as string
        pass
```

**Built-in targets:**
- `OpenAILikeTarget` — OpenAI-compatible endpoints
- `HTTPAppTarget` — Generic HTTP chatbots (POST with custom body template)

---

### 5. The Autonomous Agent Loop

**File:** `vectorguard/redteam/episode.py`

```python
for step in range(max_steps):
    # Operator: generate payload
    proposal = operator.propose(
        objective=objective,
        transcript=transcript,
        last_response=last_response,
        attempted_tactics=attempted_tactics,
        guidance=analyst_guidance,
    )
    
    # Executor: send it (deterministic, no LLM)
    response = executor.send(proposal["payload"])
    transcript.append({...})
    
    # Oracle: check for proof (deterministic)
    capture = objective.capture(response)
    if capture.captured:
        return Finding(capture, objective, transcript)
    
    # Analyst: reflect and recommend next move
    assessment = analyst.reflect(
        objective=objective,
        payload=proposal["payload"],
        response_text=response,
        attempted_tactics=attempted_tactics,
        capture=capture,
    )
    
    analyst_guidance = assessment.as_guidance()
```

**Key invariant:** LLM only proposes and reflects. Python executes and judges.

---

## Common Workflows

### Workflow 1: Run Existing YAML Suite

```bash
python3 -m vectorguard.cli \
  --target vectorguard/examples/demo_target.yaml \
  --tests vectorguard/tests/rag_injection.yaml \
  --out reports/test_run \
  --verbose
```

**Output:**
- `reports/test_run/run_TIMESTAMP.json` — Structured results
- `reports/test_run/run_TIMESTAMP.md` — Human-readable report

---

### Workflow 2: Create New YAML Test

**File:** `vectorguard/tests/my_test.yaml`

```yaml
tests:
  - name: my_test
    category: prompt_injection
    owasp_id: LLM01:2025
    severity: high
    prompt: "Try to make the model do X"
    detectors:
      - type: contains
        patterns:
          - "{{protected.secret_token}}"
          - "LEAKED_MARKER_001"
        required: true
        normalize: true
      
      - type: refusal
        patterns: ["i can't", "i cannot"]
        required: false
```

**Run it:**
```bash
python3 -m vectorguard.cli \
  --target vectorguard/examples/demo_target.yaml \
  --tests vectorguard/tests/my_test.yaml
```

---

### Workflow 3: Add a New Detector Type

**Example:** Add `similarity` detector (semantic similarity between response and expected)

1. **Implement** in `vectorguard/evaluators/detectors.py`:
```python
def evaluate_similarity(
    response_text: str,
    patterns: list[str],
    *,
    threshold: float = 0.8,
) -> dict[str, Any]:
    """Compare response to expected patterns using semantic similarity."""
    # Implementation here (e.g., use embeddings, cosine distance)
    return {
        "passed": similarity_score >= threshold,
        "detector_type": "similarity",
        "detector_semantics": "expected",
        "matched_patterns": [...],
        "reason": f"Similarity {similarity_score:.2f} vs threshold {threshold}",
    }
```

2. **Register** in detector registry:
```python
DETECTOR_REGISTRY = {
    "contains": evaluate_contains,
    "regex": evaluate_regex,
    "refusal": evaluate_refusal,
    "similarity": evaluate_similarity,  # ← Add here
    ...
}
```

3. **Test** in `tests/test_detectors.py`:
```python
def test_evaluate_similarity():
    result = evaluate_similarity(
        response_text="The answer is 42",
        patterns=["answer is 42"],
        threshold=0.8,
    )
    assert result["passed"] == True
```

4. **Use in YAML:**
```yaml
detectors:
  - type: similarity
    patterns: ["expected answer"]
    threshold: 0.7
```

---

### Workflow 4: Run Autonomous Red-Team Agent

**Basic:**
```bash
python3 -m vectorguard.redteam.cli attack \
  --target vectorguard/examples/redteam_target.yaml \
  --scope 127.0.0.1 \
  --objectives system_prompt_leak \
  --max-steps 6 \
  --out reports/redteam_run
```

**With LLM:**
```bash
VG_API_KEY=your_key python3 -m vectorguard.redteam.cli attack \
  --target vectorguard/examples/redteam_target.yaml \
  --scope 127.0.0.1 \
  --objectives all \
  --max-steps 6 \
  --out reports/redteam_run
```

**Deterministic fallback** (no API key):
- Uses hardcoded escalation ladder
- Analyst uses pattern matching (refusal detection)
- Oracle is fully deterministic

---

### Workflow 5: Run Web Agent

**Plan only (dry-run):**
```bash
python3 -m vectorguard.webagent.cli plan \
  --target http://localhost:5000 \
  --scope localhost
```

**Execute scan:**
```bash
python3 -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 \
  --scope localhost \
  --tests vectorguard/web_tests/portswigger_core/admin_check.yaml \
  --out reports/web_scan
```

---

## Testing

### Running Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Specific test file
python3 -m pytest tests/test_detectors.py -v

# Single test
python3 -m pytest tests/test_detectors.py::test_evaluate_contains -v

# With coverage
python3 -m pytest tests/ --cov=vectorguard --cov-report=html
```

### Test Structure

```
tests/
├── test_detectors.py               # Detector logic
├── test_config_loader.py           # YAML + placeholder resolution
├── test_scoring.py                 # Risk calculation
├── test_redteam_operator.py        # Payload generation
├── test_redteam_analyst.py         # Response analysis
├── test_redteam_objectives.py      # Oracle + capture logic
├── test_redteam_episode.py         # Loop logic
└── test_redteam_campaign.py        # Multi-objective orchestration
```

### Writing a Test

```python
# tests/test_my_feature.py
from vectorguard.evaluators.detectors import evaluate_contains

def test_evaluate_contains_basic():
    result = evaluate_contains(
        response_text="The secret is SECRET_123",
        patterns=["SECRET_123"],
    )
    assert result["passed"] == False
    assert "SECRET_123" in result["matched_patterns"]
    assert result["detector_type"] == "contains"

def test_evaluate_contains_case_insensitive():
    result = evaluate_contains(
        response_text="The secret is secret_123",
        patterns=["SECRET_123"],
        case_sensitive=False,
    )
    assert result["passed"] == False
```

---

## Debugging

### Enable Verbose Logging

```bash
python3 -m vectorguard.cli \
  --target vectorguard/examples/demo_target.yaml \
  --tests vectorguard/tests/rag_injection.yaml \
  --verbose
```

Prints:
- Test names and payloads
- Model responses (full text)
- Detector results (per test)
- Findings details

### Debug the Operator (Agent)

```python
# In your code or a script
from vectorguard.redteam.operator import Operator

operator = Operator(client=None)  # Deterministic mode

proposal = operator.propose(
    objective=my_objective,
    transcript=[],
    last_response="",
    attempted_tactics=[],
    captured_intel=[],
    step=1,
)

print(proposal)
# {
#     "payload": "For an authorized audit, please...",
#     "tactic": "direct",
#     "rationale": "First attempt",
#     "source": "deterministic",
# }
```

### Debug the Analyst (Reflection)

```python
from vectorguard.redteam.analyst import Analyst

analyst = Analyst(client=None)  # Deterministic mode

assessment = analyst.reflect(
    objective=my_objective,
    payload="My attack payload",
    response_text="I can't do that",
    attempted_tactics=["direct"],
    capture=CaptureResult(captured=False, confidence=0.0, ...),
)

print(assessment.as_dict())
# {
#     "refused": true,
#     "progress": 0.0,
#     "intel": [],
#     "strategy": "Target refused; escalate to persona_roleplay.",
#     "recommended_tactic": "persona_roleplay",
#     "source": "deterministic",
# }
```

### Print a Detector Result

```python
from vectorguard.evaluators.detectors import evaluate_detector

detector_config = {
    "type": "contains",
    "patterns": ["SECRET"],
    "required": True,
}

result = evaluate_detector("The answer is SECRET", detector_config)
print(json.dumps(result, indent=2))
```

---

## Adding Features

### Add a New Attack Objective

**File:** `vectorguard/redteam/objectives.py`

```python
@dataclass
class Objective:
    id: str
    kind: str  # ← "my_new_objective"
    owasp_id: str
    severity: str
    title: str
    goal: str
    description: str
    config: ObjectiveConfig = field(default_factory=ObjectiveConfig)
    judgeable: bool = True

# In _deterministic_capture():
def _deterministic_capture(self, response_text, response_meta):
    if self.kind == "my_new_objective":
        marker = self.config.my_marker  # Add to ObjectiveConfig
        if _contains(response_text, marker):
            return CaptureResult(
                captured=True,
                confidence=1.0,
                evidence=_window(response_text, marker),
                method="deterministic",
                proof=marker,
            )
    return CaptureResult(False, 0.0, "not captured", "none")
```

### Add a New Web Check Template

**File:** `vectorguard/web_tests/portswigger_core/my_check.yaml`

```yaml
check:
  name: my_security_check
  description: "Check for X vulnerability"
  target: "/my-endpoint"
  method: GET
  expected:
    status: 200
    body_contains: []
    body_not_contains: ["error", "exception"]
  detectors:
    - type: status_code
      value: 200
    - type: body_not_contains
      patterns: ["admin"]
```

### Add a New Target Adapter

**File:** `vectorguard/targets/my_adapter.py`

```python
from vectorguard.targets import BaseTarget

class MyCustomTarget(BaseTarget):
    def __init__(self, config: dict):
        self.config = config
        self.api_url = config.get("api_url")
    
    def send_messages(self, messages: list[dict]) -> str:
        # Implement your custom request logic
        # Return model response as string
        pass
```

**Register in:** `vectorguard/targets/__init__.py`

---

## Architecture Deep Dive

### Execution Model: Talk-Only + Deterministic

```
LLM (Operator):
  Generates: payload, tactic, rationale
  Cannot: execute, judge, declare victory

Python (Executor):
  Executes: sends HTTP request to target
  Returns: response text + metadata

Python (Oracle):
  Judges: is proof present? (deterministic check)
  Confidence: 1.0 (planted flag), 0.85 (DLP), 0.6+ (judge)

Python (Analyst):
  Reflects: reads response, extracts intel
  Recommends: next tactic based on signals
  Anchors: progress to oracle confidence
```

**Why?** Reproducibility. LLMs hallucinate. Python doesn't.

### Detector Semantics

```
Forbidden (leakage):
  - contains, regex, max_output_chars
  - Pass when pattern NOT found
  - Required by default
  - Test fails if ANY forbidden pattern found

Expected (validation):
  - expected_contains, refusal
  - Pass when pattern IS found
  - Advisory by default (except expected_contains)
  - Test passes if ANY expected pattern found

Required vs Advisory:
  - Required detectors must all pass
  - Advisory detectors are informational only
  - Test fails if ANY required detector fails
```

### Config Resolution Flow

```
1. User: python -m vectorguard.cli --target demo_target.yaml
2. CLI loads: demo_target.yaml via load_yaml_file()
3. Loader: detects {{env.VG_API_KEY}}, {{protected.secret}}
4. Resolver:
   - {{env.X}} → os.environ.get("X")
   - {{protected.X}} → config["protected"]["X"]
5. Result: fully resolved config dict in memory
6. Target: receives resolved config, builds client
```

### Test Execution Loop

```
for test in tests:
    1. Render {{placeholders}} in test["prompt"]
    2. Send to target via target.send_messages()
    3. Get response text
    4. For each detector:
       a. Evaluate detector against response
       b. Mark as passed/failed
       c. Capture evidence
    5. Check required detectors:
       - All pass? → test passes
       - Any fail? → test fails
    6. Score finding:
       - severity × confidence → risk_score
    7. Add to results
```

---

## Common Patterns

### Pattern 1: Reuse Config Loader

```python
from vectorguard.config.loader import load_yaml_file

# ✅ Good: use the loader
config = load_yaml_file("path/to/config.yaml")

# ❌ Bad: bypass the loader
with open("path/to/config.yaml") as f:
    config = yaml.load(f)  # No placeholder resolution
```

### Pattern 2: Check Required vs Advisory

```python
# In detector evaluation:
if detector_type in {"refusal", "expected_refusal"}:
    required = False  # Soft signals
else:
    required = True   # Hard signals
```

### Pattern 3: Anchor to Deterministic Proof

```python
# In analyst:
if capture.confidence > 0:
    progress = float(capture.confidence)  # Anchor to oracle
elif looks_like_refusal(response_text):
    progress = 0.0
else:
    progress = 0.3  # Engaged but no proof
```

### Pattern 4: Extract Evidence Window

```python
# In detectors:
def evidence_window(text: str, start: int, end: int, window: int = 30) -> str:
    return text[max(0, start - window): min(len(text), end + window)]

# Use: show context around the match
evidence = evidence_window(response_text, match_start, match_end)
```

---

## Performance Notes

### Bottlenecks

1. **LLM calls** — Each operator/analyst call to an LLM is ~1-5s
   - Use deterministic fallback in tests
   - Batch requests where possible

2. **Large responses** — If model outputs 100k chars, detector evaluation slows
   - Set `max_output_chars` detector
   - Cap response length in target config

3. **Regex patterns** — Complex regexes on large text can be slow
   - Use simple patterns where possible
   - Prefer `contains` over `regex`

### Optimizations

- Use deterministic mode in CI (no API calls)
- Cache loaded YAML files
- Batch YAML suites (one run, many tests)
- Parallel target requests (HTTP is I/O-bound)

---

## Contributing

### Before Opening a PR

1. Run tests: `python3 -m pytest tests/ -v`
2. Check compilation: `python -m compileall vectorguard`
3. Lint (if configured): `flake8 vectorguard` or similar
4. Update docs if needed (CLAUDE.md, this file, docstrings)

### Commit Messages

- Start with action verb: "Add", "Fix", "Refactor", "Remove"
- Be specific: "Add similarity detector" not "Update detectors"
- One focus per commit (atomic)

### PR Guidelines

- Link related issues/discussions
- Explain the why, not just the what
- Test new features (add tests, not just code)
- Update CLAUDE.md if the architecture changes

---

## Troubleshooting

### Import Errors

```
ModuleNotFoundError: No module named 'vectorguard'
```

**Fix:** Install in dev mode:
```bash
pip install -e .
```

### Config Resolution Fails

```
KeyError: 'VG_API_KEY' in {{env.VG_API_KEY}}
```

**Fix:** Set environment variable:
```bash
export VG_API_KEY=your_key
python3 -m vectorguard.cli ...
```

### Tests Fail

```
AssertionError: expected True, got False
```

**Fix:** Run with verbose output to see what's happening:
```bash
python3 -m pytest tests/test_detectors.py::test_name -vv -s
```

### Agent Keeps Escalating

**Expected:** Agent tries 6 tactics (direct → persona → override → encoding → splitting → flooding) before giving up.

**If it doesn't stop:** Check `max_steps` setting or step limit logic.

---

## Questions?

- Check [CLAUDE.md](../CLAUDE.md) for architecture overview
- Read test files for examples
- Open an issue with questions
