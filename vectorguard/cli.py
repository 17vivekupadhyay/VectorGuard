from __future__ import annotations

import argparse
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vectorguard.config.loader import load_yaml_file, resolve_string
from vectorguard.reports.json_report import save_json_report
from vectorguard.reports.markdown import save_markdown_report
from vectorguard.reports.summary import build_summary
from vectorguard.runner.run_suite import run_suite
from vectorguard.targets.openai_like import OpenAILikeTarget
from vectorguard.targets.http_target import HTTPAppTarget

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


ROOT = Path(__file__).resolve().parents[1]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def load_env_file() -> None:
    """
    Load .env automatically if python-dotenv is installed.

    Install with:
        pip install python-dotenv
    """
    if load_dotenv is None:
        return

    env_path = ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run VectorGuard LLM/RAG security tests"
    )

    parser.add_argument(
        "--target",
        default=os.environ.get(
            "VG_TARGET_CONFIG",
            "vectorguard/examples/demo_target.yaml",
        ),
        help="Path to target config YAML",
    )

    parser.add_argument(
        "--tests",
        default=os.environ.get(
            "VG_TEST_FILE",
            "vectorguard/tests/prompt_injection.yaml",
        ),
        help="Path to VectorGuard test suite YAML",
    )

    parser.add_argument(
        "--out",
        default=os.environ.get("VG_OUTPUT_DIR", "vectorguard/storage"),
        help="Directory for generated JSON/Markdown reports",
    )

    parser.add_argument(
        "--base-url",
        default=os.environ.get("VG_BASE_URL"),
        help="Override target base URL",
    )

    parser.add_argument(
        "--model",
        default=os.environ.get("VG_MODEL"),
        help="Override target model",
    )

    parser.add_argument(
        "--api-key-env",
        default=os.environ.get("VG_API_KEY_ENV", "VG_API_KEY"),
        help="Environment variable containing API key",
    )

    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 1 if any tests fail",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extra finding details for failed tests",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output",
    )

    return parser.parse_args()


def colorize(text: str, color: str, *, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{color}{text}{RESET}"


def status_text(passed: bool, *, color: bool = True) -> str:
    if passed:
        return colorize("PASSED", GREEN, enabled=color)
    return colorize("FAILED", RED, enabled=color)


def display_reason(result: dict[str, Any]) -> str:
    """
    Hide advisory detector noise on passing tests.

    Example:
      [required] No forbidden patterns found.; [advisory] Missing expected refusal patterns...

    becomes:
      [required] No forbidden patterns found.
    """
    reason = str(result.get("reason", ""))

    if result.get("passed"):
        parts = [
            part
            for part in reason.split("; ")
            if not part.startswith("[advisory]")
        ]
        return "; ".join(parts) if parts else reason

    return reason


def print_colored_summary(
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    *,
    use_color: bool = True,
    verbose: bool = False,
) -> None:
    print("\nVectorGuard Results\n")
    print(f"Total: {summary.get('total', 0)}")
    print(colorize(f"Passed: {summary.get('passed', 0)}", GREEN, enabled=use_color))
    print(colorize(f"Failed: {summary.get('failed', 0)}", RED, enabled=use_color))
    print(f"Pass rate: {summary.get('pass_rate', 0.0)}%")
    print(f"Total risk score: {summary.get('total_risk_score', 0.0)}")
    print(f"Max risk score: {summary.get('max_risk_score', 0.0)}")
    print()

    for result in results:
        passed = bool(result.get("passed", False))
        status = status_text(passed, color=use_color)

        print(f"{result.get('name', 'unknown_test')}: {status}")
        print(f"  category: {result.get('category', 'unknown')}")
        print(f"  owasp_id: {result.get('owasp_id', 'unmapped')}")
        print(f"  severity: {result.get('severity', 'unknown')}")
        print(f"  detector: {result.get('detector_type', 'unknown')}")
        print(f"  risk_score: {result.get('risk_score', 0.0)}")
        print(f"  reason: {display_reason(result)}")

        if verbose and not passed:
            finding = result.get("finding")
            if finding:
                print(f"  finding: {finding.get('title', 'unknown finding')}")
                print(f"  recommendation: {finding.get('recommendation', '')}")

            leak_matches = result.get("leak_matches", [])
            if leak_matches:
                print(f"  leak_matches: {leak_matches}")

            other_matches = result.get("other_matches", [])
            if other_matches:
                print(f"  other_matches: {other_matches}")

        print()


def get_api_key(args: argparse.Namespace, target_config: dict[str, Any]) -> str:
    api_key_env = (
        args.api_key_env
        or target_config.get("api_key_env")
        or "VG_API_KEY"
    )

    api_key = (
        os.environ.get(api_key_env)
        or os.environ.get("VG_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )

    if not api_key:
        raise RuntimeError(
            "Missing API key.\n\n"
            "Set one of these in your shell or .env file:\n"
            "  VG_API_KEY=your_key_here\n"
            "  OPENAI_API_KEY=your_key_here\n\n"
            "Then run:\n"
            "  python3 -m vectorguard.cli --target vectorguard/examples/demo_target.yaml "
            "--tests vectorguard/tests/rag_injection.yaml"
        )

    return api_key


def build_system_prompt(config: dict[str, Any]) -> str | None:
    system_prompt_template = config.get("system_prompt")

    if not system_prompt_template:
        return None

    return resolve_string(str(system_prompt_template), config)


def build_target(
    *,
    config: dict[str, Any],
    args: argparse.Namespace,
) -> BaseTarget:
    if "target" not in config:
        raise ValueError("Target config is missing required top-level key: target")

    target_config = config["target"]

    if not isinstance(target_config, dict):
        raise ValueError("target must be a YAML object/mapping")

    target_type = target_config.get("type", "openai_like")

    if target_type == "openai_like":
        base_url = args.base_url or target_config.get("base_url")
        model = args.model or target_config.get("model")

        if not base_url:
            raise ValueError("Target config is missing target.base_url")

        if not model:
            raise ValueError("Target config is missing target.model")

        api_key = get_api_key(args, target_config)
        system_prompt = build_system_prompt(config)

        timeout = float(target_config.get("timeout", 90.0))
        max_tokens = int(target_config.get("max_tokens", 300))

        return OpenAILikeTarget(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout=timeout,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
        )

    if target_type == "http":
        url = target_config.get("url")

        if not url:
            raise ValueError("HTTP target config is missing target.url")

        return HTTPAppTarget(
            url=url,
            method=target_config.get("method", "POST"),
            headers=target_config.get("headers", {"Content-Type": "application/json"}),
            body_template=target_config.get("body_template", {"message": "{{prompt}}"}),
            response_path=target_config.get("response_path"),
            timeout=float(target_config.get("timeout", 90.0)),
        )

    raise ValueError(f"Unsupported target type: {target_type}")


def build_metadata(
    *,
    run_id: str,
    config_path: str,
    test_file: str,
    config: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    target_config = config.get("target", {})

    return {
        "run_id": run_id,
        "suite_name": Path(test_file).name,
        "target_type": target_config.get("type", "openai_like"),
        "base_url": args.base_url or target_config.get("base_url", "unknown"),
        "model": args.model or target_config.get("model", "unknown"),
        "config_path": config_path,
        "test_file": test_file,
    }


def main() -> int:
    load_env_file()

    args = parse_args()

    config_path = args.target
    test_file = args.tests
    output_dir = args.out

    config = load_yaml_file(config_path)
    target = build_target(config=config, args=args)

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]

    metadata = build_metadata(
        run_id=run_id,
        config_path=config_path,
        test_file=test_file,
        config=config,
        args=args,
    )

    results = run_suite(
        target=target,
        test_file=test_file,
        context=config,
    )

    summary = build_summary(results)

    json_report_path = save_json_report(
        results=results,
        summary=summary,
        metadata=metadata,
        output_dir=output_dir,
    )

    markdown_report_path = save_markdown_report(
        results=results,
        summary=summary,
        metadata=metadata,
        output_dir=output_dir,
        suite_name=f"VectorGuard Report - {Path(test_file).name}",
    )

    print_colored_summary(
        summary=summary,
        results=results,
        use_color=not args.no_color,
        verbose=args.verbose,
    )

    print(f"Saved JSON report to: {json_report_path}")
    print(f"Saved Markdown report to: {markdown_report_path}")

    if args.fail_on_findings and summary.get("failed", 0) > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())