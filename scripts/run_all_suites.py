from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_DIR = ROOT / "vectorguard" / "tests"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all VectorGuard YAML suites")
    parser.add_argument(
        "--target",
        default="vectorguard/examples/demo_target.yaml",
        help="Target config YAML",
    )
    parser.add_argument(
        "--test-dir",
        default=str(DEFAULT_TEST_DIR),
        help="Directory containing YAML test suites",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 if any suite has findings",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    test_dir = Path(args.test_dir)

    suites = sorted(
        path for path in test_dir.glob("*.yaml")
        if not path.name.startswith("_")
    )

    if not suites:
        print(f"No YAML suites found in {test_dir}")
        return 1

    suites_with_findings_or_errors = 0

    for suite in suites:
        print("=" * 80)
        print(f"Running suite: {suite.name}")
        print("=" * 80)

        cmd = [
            sys.executable,
            "-m",
            "vectorguard.cli",
            "--target",
            args.target,
            "--tests",
            str(suite),
        ]

        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
        )

        if completed.returncode != 0:
            suites_with_findings_or_errors += 1

    print("=" * 80)
    print("VectorGuard suite run complete")
    print(f"Suites run: {len(suites)}")
    print(f"Suites with findings/errors: {suites_with_findings_or_errors}")

    if args.fail_on_findings and suites_with_findings_or_errors > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())