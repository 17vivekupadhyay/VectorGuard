# VectorGuard Web Agent — Local Demo App

⚠️ **Intentionally vulnerable. Local-only. Do not deploy publicly.**

This is a tiny Flask app for demonstrating VectorGuard Web Agent end-to-end
against a known, owned, local target. Its "vulnerabilities" are faked responses
(no real database, no real authentication) so the scanner's safe GET checks have
something to detect. It binds to `127.0.0.1` only.

## Routes

| Route | Behavior |
|-------|----------|
| `GET /` | Homepage with links to the routes below |
| `GET /admin` | Fake admin panel ("Admin Panel", "delete user") — missing access control |
| `GET /filter?category=Gifts` | Normal product listing |
| `GET /filter?category='` | Fake SQL error (`SQL syntax`) with HTTP 500 |
| `GET /my-account` | Account page exposing a fake JWT-shaped token |

## Run it

Terminal 1 — start the demo app:

```bash
python3 examples/web_demo_app/app.py
```

> On macOS, AirPlay Receiver may already use port 5000. If requests to
> localhost:5000 look wrong, either disable AirPlay Receiver in System Settings →
> General → AirDrop & Handoff, or run the app on another port and update the
> target config accordingly.

Terminal 2 — plan, generate tests, and scan:

```bash
# Map the known endpoints to safe templates
python3 -m vectorguard.webagent.cli plan \
  --config examples/web_demo_app/webagent_target.yaml \
  --out reports/demo_plan

# Generate concrete YAML tests from the plan
python3 -m vectorguard.webagent.cli generate-tests \
  --config examples/web_demo_app/webagent_target.yaml \
  --out reports/demo_generated

# Run the access-control check (GET /admin)
python3 -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 --scope localhost \
  --tests reports/demo_generated/generated_tests/generated_access_control_forced_browsing_admin.yaml \
  --out reports/demo_admin --ai-summary

# Run the safe SQL error probe (GET /filter?category=')
python3 -m vectorguard.webagent.cli scan \
  --target http://localhost:5000 --scope localhost \
  --tests reports/demo_generated/generated_tests/generated_injection_sqli_basic_error_probe.yaml \
  --out reports/demo_sqli --ai-summary
```

Each scan writes `evidence/`, `raw_results.json`, `detector_results.json`,
`findings.json`, and `report.md` (plus `agent_summary.md` with `--ai-summary`).

## Reminder

VectorGuard Web Agent is a defensive testing aid. Findings are signals for human
review, not proof of complete security. Only run it against local labs, owned
applications, or explicitly authorized targets.
