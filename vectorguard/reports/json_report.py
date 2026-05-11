from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def save_json_report(
    results: list[dict[str, Any]],
    summary: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    output_dir: str = "vectorguard/storage",
) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_path = Path(output_dir) / f"run_{timestamp}.json"

    payload: dict[str, Any] = {"results": results}
    if summary is not None:
        payload["summary"] = summary
    if metadata is not None:
        payload["metadata"] = metadata

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return str(output_path)