from typing import Any, Dict
import json
from datetime import datetime

def json_report(results: Dict[str, Any]) -> str:
    """
    Return a pretty-printed JSON string for the scanner results.
    Adds a generated_at timestamp to the top-level object.
    """
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report": results
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)

def write_json_report(results: Dict[str, Any], path: str) -> None:
    """
    Write the JSON report to the given filesystem path.
    Creates parent directories if necessary.
    """
    import os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json_report(results))