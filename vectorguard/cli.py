from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from vectorguard.reports.json_report import save_json_report
from vectorguard.reports.markdown import save_markdown_report
from vectorguard.reports.summary import build_summary
from vectorguard.runner.run_suite import run_suite
from vectorguard.targets.openai_like import OpenAILikeTarget
from vectorguard.config.loader import load_yaml_file, resolve_string

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def color_status(passed: bool) -> str:
    return f"{GREEN}PASSED{RESET}" if passed else f"{RED}FAILED{RESET}"


def print_colored_summary(summary: dict, results: list[dict]) -> None:
    print("\nVectorGuard Results\n")
    print(f"Total: {summary['total']}")
    print(f"{GREEN}Passed: {summary['passed']}{RESET}")
    print(f"{RED}Failed: {summary['failed']}{RESET}")
    print(f"Pass rate: {summary['pass_rate']}%")
    print()

    for result in results:
        status = color_status(result.get("passed", False))
        print(f"{result['name']}: {status}")
        print(f"  category: {result['category']}")
        print(f"  severity: {result['severity']}")
        print(f"  detector: {result['detector_type']}")
        print(f"  reason: {result['reason']}")
        print()


def main() -> None:
    config_path = os.environ.get(
        "VG_TARGET_CONFIG",
        "vectorguard/examples/demo_target.yaml",
    )
    config = load_yaml_file(config_path)

    target_config = config["target"]
    base_url = os.environ.get("VG_BASE_URL", target_config["base_url"])
    api_key = os.environ["VG_API_KEY"]
    model = os.environ.get("VG_MODEL", target_config["model"])
    test_file = os.environ.get("VG_TEST_FILE", "vectorguard/tests/prompt_injection.yaml")

    system_prompt = resolve_string(config["system_prompt"], config)

    target = OpenAILikeTarget(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
    )

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]

    metadata = {
        "run_id": run_id,
        "suite_name": Path(test_file).name,
        "target_type": target_config.get("type", "unknown"),
        "base_url": base_url,
        "model": model,
        "config_path": config_path,
    }

    results = run_suite(target, test_file, context=config)
    summary = build_summary(results)

    json_report_path = save_json_report(
        results=results,
        summary=summary,
        metadata=metadata,
    )

    markdown_report_path = save_markdown_report(
        results=results,
        summary=summary,
        metadata=metadata,
        suite_name=f"VectorGuard Report - {Path(test_file).name}",
    )

    print_colored_summary(summary, results)
    print(f"Saved JSON report to: {json_report_path}")
    print(f"Saved Markdown report to: {markdown_report_path}")
    
if __name__ == "__main__":
    main()