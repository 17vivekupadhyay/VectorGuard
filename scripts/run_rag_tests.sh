#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -z "${VG_API_KEY:-}" ] && [ -n "${OPENAI_API_KEY:-}" ]; then
  export VG_API_KEY="$OPENAI_API_KEY"
fi

if [ -z "${VG_API_KEY:-}" ]; then
  echo "Missing VG_API_KEY or OPENAI_API_KEY"
  echo "Run: export VG_API_KEY='your_key_here'"
  exit 1
fi

TARGET_CONFIG="${VG_TARGET_CONFIG:-./my_target.yaml}"
TEST_FILE="./vectorguard/tests/rag_injection.yaml"

echo "Running VectorGuard RAG injection tests"
echo "Target config: $TARGET_CONFIG"
echo "Test file: $TEST_FILE"
echo

python3 -m vectorguard.cli \
  --target "$TARGET_CONFIG" \
  --tests "$TEST_FILE"
