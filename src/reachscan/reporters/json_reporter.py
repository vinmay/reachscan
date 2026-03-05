from typing import Any, Dict
import json
from reachscan.schema import build_v1_report


def json_report(results: Dict[str, Any]) -> str:
    """Return a pretty-printed JSON string for the scanner results (v1 schema)."""
    return json.dumps(build_v1_report(results), indent=2, ensure_ascii=False)


def write_json_report(results: Dict[str, Any], path: str) -> None:
    """Write the JSON report to the given filesystem path.

    Creates parent directories if necessary.
    """
    import os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json_report(results))
