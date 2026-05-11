from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUITE = ROOT / "vectorguard/tests/rag_injection.yaml"
TMP_DIR = ROOT / "vectorguard/tests/.tmp_rag_single"
TARGET_CONFIG = os.getenv("VG_TARGET_CONFIG", "./my_target.yaml")


def main() -> int:
    if not SOURCE_SUITE.exists():
        print(f"Missing suite: {SOURCE_SUITE}")
        return 1

    TMP_DIR.mkdir(parents=True, exist_ok=True)

    data = yaml.safe_load(SOURCE_SUITE.read_text(encoding="utf-8"))
    tests = data.get("tests", [])

    if not tests:
        print("No tests found.")
        return 1

    print(f"Loaded {len(tests)} RAG tests from {SOURCE_SUITE}")
    print()

    passed = 0
    failed = 0
    crashed = 0

    for index, test in enumerate(tests, start=1):
        name = test.get("name", f"test_{index}")
        tmp_file = TMP_DIR / f"{index:02d}_{name}.yaml"

        tmp_file.write_text(
            yaml.safe_dump({"tests": [test]}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

        print("=" * 80)
        print(f"[{index}/{len(tests)}] Running {name}")
        print("=" * 80)

        env = os.environ.copy()
        env["VG_TARGET_CONFIG"] = TARGET_CONFIG
        env["VG_TEST_FILE"] = str(tmp_file)

        try:
            completed = subprocess.run(
                [sys.executable, "-m", "vectorguard.cli"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=140,
            )
        except subprocess.TimeoutExpired:
            crashed += 1
            print(f"CRASHED/TIMEOUT: {name}")
            print()
            continue

        output = completed.stdout + "\n" + completed.stderr
        print(output)

        if completed.returncode != 0:
            crashed += 1
            print(f"CRASHED: {name}")
        elif "Failed: 0" in output:
            passed += 1
            print(f"PASSED: {name}")
        else:
            failed += 1
            print(f"FAILED: {name}")

        print()

    print("=" * 80)
    print("RAG ONE-BY-ONE SUMMARY")
    print("=" * 80)
    print(f"Passed:  {passed}")
    print(f"Failed:  {failed}")
    print(f"Crashed: {crashed}")
    print(f"Total:   {len(tests)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
