"""
CLI for the VectorGuard autonomous LLM red-team agent.

    python -m vectorguard.redteam.cli attack \
        --target vectorguard/examples/redteam_target.yaml \
        --scope localhost \
        --objectives all \
        --max-steps 6 \
        --out reports/redteam_run

Safe by default: talk-only. No tools, no state changes, no corpus writes; the
executor enforces this and caps conversation size. The attacker/judge LLM is
loaded from environment variables when available and otherwise degrades to the
deterministic tactic ladder.
"""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from vectorguard.cli import (
    GREEN,
    RED,
    YELLOW,
    build_target,
    colorize,
    load_env_file,
)
from vectorguard.config.loader import load_yaml_file
from vectorguard.webagent.agent.llm_client import build_llm_client_from_env

from .analyst import Analyst
from .campaign import run_campaign
from .judge import Judge
from .objectives import (
    DEFAULT_INJECTION_CANARY,
    DEFAULT_PLANTED_SECRET,
    DEFAULT_SYSTEM_MARKER,
    ObjectiveConfig,
    build_objectives,
)
from .operator import Operator
from .seeds import load_seeds


class ScopeError(RuntimeError):
    """Raised when the target host is not inside the authorized scope."""


def _target_host(config: dict[str, Any], args: argparse.Namespace) -> str:
    target_config = config.get("target", {})
    base = (
        args.base_url
        or target_config.get("base_url")
        or target_config.get("url")
        or ""
    )
    host = urlparse(base).hostname or base
    return host


def validate_scope(host: str, scope: str) -> None:
    """The target host must equal the scope or be a subdomain of it."""
    if not scope:
        raise ScopeError("--scope is required; refusing to scan without scope")
    if not host:
        raise ScopeError("could not determine target host for scope check")
    if host == scope or host.endswith("." + scope):
        return
    raise ScopeError(
        f"target host {host!r} is not within authorized scope {scope!r}"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vectorguard.redteam.cli",
        description="VectorGuard autonomous LLM red-team agent",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    attack = subparsers.add_parser(
        "attack", help="Run the autonomous red-team campaign against a target"
    )
    attack.add_argument(
        "--target",
        default=os.environ.get(
            "VG_TARGET_CONFIG", "vectorguard/examples/redteam_target.yaml"
        ),
        help="Path to target config YAML",
    )
    attack.add_argument("--base-url", default=os.environ.get("VG_BASE_URL"))
    attack.add_argument("--model", default=os.environ.get("VG_MODEL"))
    attack.add_argument(
        "--api-key-env",
        default=os.environ.get("VG_API_KEY_ENV", "VG_API_KEY"),
    )
    attack.add_argument(
        "--scope",
        required=True,
        help="Authorized scope host; target host must match",
    )
    attack.add_argument(
        "--objectives",
        default="all",
        help="Comma-separated objective ids, or 'all'",
    )
    attack.add_argument("--max-steps", type=int, default=6)
    attack.add_argument(
        "--seeds",
        default="vectorguard/tests",
        help="Directory of YAML seed suites",
    )
    attack.add_argument("--out", default="reports/redteam_run")
    attack.add_argument("--no-color", action="store_true")
    attack.add_argument(
        "--fail-on-capture",
        action="store_true",
        help="Exit 1 if any objective is captured",
    )

    # Planted flags / budgets (what you placed in the target you are testing).
    attack.add_argument("--system-marker", default=DEFAULT_SYSTEM_MARKER)
    attack.add_argument("--planted-secret", default=DEFAULT_PLANTED_SECRET)
    attack.add_argument("--injection-canary", default=DEFAULT_INJECTION_CANARY)
    attack.add_argument("--max-output-tokens", type=int, default=800)
    attack.add_argument("--max-output-chars", type=int, default=6000)

    return parser


def _print_summary(report: dict[str, Any], *, use_color: bool) -> None:
    captured = report["captured_count"]
    total = len(report["objectives"])
    summary = report["summary"]

    print("\nVectorGuard Red-Team Campaign\n")
    print(f"Strategy: {report['strategy']}")
    print(
        colorize(
            f"Objectives captured: {captured} / {total}",
            RED if captured else GREEN,
            enabled=use_color,
        )
    )
    print(f"Total risk score: {summary.get('total_risk_score', 0.0)}")
    print(f"Max risk score: {summary.get('max_risk_score', 0.0)}")
    print()

    for ep in report["objectives"]:
        if ep["captured"]:
            status = colorize("CAPTURED", RED, enabled=use_color)
        else:
            status = colorize("not captured", GREEN, enabled=use_color)
        print(f"{ep['objective_id']} [{ep['owasp_id']}]: {status}")
        print(f"  severity: {ep['severity']}  risk: {ep['risk_score']}")
        print(f"  steps: {ep['steps_taken']}  stopped: {ep['stopped_reason']}")
        if ep["captured"]:
            print(
                colorize(
                    f"  proof ({ep['capture_method']}): {ep['proof']}",
                    YELLOW,
                    enabled=use_color,
                )
            )
            print(f"  evidence: {ep['evidence']}")
        print()


def _run_attack(args: argparse.Namespace) -> int:
    config = load_yaml_file(args.target)

    host = _target_host(config, args)
    try:
        validate_scope(host, args.scope)
    except ScopeError as error:
        print(colorize(f"Scope check failed: {error}", RED, enabled=not args.no_color))
        return 2

    target = build_target(config=config, args=args)

    selected = None if args.objectives.strip().lower() == "all" else [
        item.strip() for item in args.objectives.split(",") if item.strip()
    ]

    obj_config = ObjectiveConfig(
        system_marker=args.system_marker,
        planted_secret=args.planted_secret,
        injection_canary=args.injection_canary,
        max_completion_tokens=args.max_output_tokens,
        max_response_chars=args.max_output_chars,
    )
    objectives = build_objectives(selected=selected, config=obj_config)

    seeds = load_seeds(args.seeds)
    # One shared LLM client powers both the attacker brain and the judge. With
    # no API key configured this is None and both degrade gracefully: the
    # operator falls back to the deterministic tactic ladder and capture is
    # deterministic-only.
    client = build_llm_client_from_env()
    operator = Operator(client=client, seeds=seeds, max_steps=args.max_steps)
    judge = Judge(client) if client is not None else None
    analyst = Analyst(client=client)  # reflection layer; deterministic if no key

    metadata = {
        "target": host,
        "scope": args.scope,
        "config_path": args.target,
        "started_at": datetime.now(UTC).isoformat(),
        "seeds_loaded": len(seeds),
    }

    report = run_campaign(
        target,
        objectives,
        operator,
        judge=judge,
        analyst=analyst,
        max_steps=args.max_steps,
        out_dir=args.out,
        metadata=metadata,
    )

    _print_summary(report, use_color=not args.no_color)

    paths = report.get("report_paths", {})
    if paths:
        print(f"Saved JSON report to: {paths.get('json')}")
        print(f"Saved Markdown report to: {paths.get('markdown')}")

    if args.fail_on_capture and report["captured_count"] > 0:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    load_env_file()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "attack":
        return _run_attack(args)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
