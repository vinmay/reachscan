"""
Scanner orchestration. Uses the detector registry to run all registered detectors
over Python files under a given path and returns a normalized report object.
"""

from pathlib import Path
from typing import Dict, Any, List
from agent_scan.detectors.registry import get_detectors, call_detector
from agent_scan.detectors.base import CapabilityFinding
import os

def _gather_py_files(path: Path) -> List[Path]:
    """Return list of .py files under path (or single file if path is file)."""
    path = Path(path)
    if path.is_file() and path.suffix == ".py":
        return [path]
    # exclude typical virtualenv and hidden directories
    def is_excluded(p: Path) -> bool:
        parts = {p_.lower() for p_ in p.parts}
        # quick exclusions
        if "site-packages" in parts or ".venv" in parts or "venv" in parts or "__pycache__" in parts:
            return True
        return False

    files = [p for p in path.rglob("*.py") if not is_excluded(p)]
    return files

def _normalize_finding(f: CapabilityFinding) -> Dict[str, Any]:
    """Convert a CapabilityFinding to a serializable dict."""
    # Attempt common conversions, be resilient to both dataclass and simple objects
    if hasattr(f, "as_dict") and callable(getattr(f, "as_dict")):
        return f.as_dict()
    # fallback to attribute access
    return {
        "capability": getattr(f, "capability", None),
        "evidence": getattr(f, "evidence", None),
        "file": getattr(f, "file", None),
        "lineno": getattr(f, "lineno", None),
        "confidence": getattr(f, "confidence", None),
    }

def scan_path(path: Path, ruleset: str = "core") -> Dict[str, Any]:
    """
    Run all registered detectors over the given path and return a structured report.

    Returns a dict like:
    {
      "target": str(path),
      "num_files_scanned": N,
      "findings": [
         {"detector": "shell_exec", "finding": { ... }},
         ...
      ],
      "capabilities": ["EXECUTE", "READ"],
      "possible_impacts": [...],
    }
    """
    path = Path(path)
    py_files = _gather_py_files(path)

    # load detectors from registry
    detectors = get_detectors()

    findings: List[Dict[str, Any]] = []

    # run detectors over files
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8")
        except Exception:
            # skip files we can't read
            continue

        for name, detector in detectors.items():
            # detectors may choose to ignore ruleset; we pass ruleset if needed later
            raw = call_detector(detector, str(p), src)
            # call_detector returns list[CapabilityFinding] or empty list on error
            for f in raw:
                # f expected to be CapabilityFinding (or similar)
                normalized = _normalize_finding(f)
                findings.append({"detector": name, "finding": normalized})

    # aggregate capabilities
    capability_keys = sorted({entry["finding"]["capability"] for entry in findings if entry["finding"].get("capability")})

    # derive simple possible impacts (v1)
    possible_impacts = []
    if "EXECUTE" in capability_keys:
        possible_impacts.append("Commands could be executed on the host machine.")
    if "READ" in capability_keys and "SEND" in capability_keys:
        possible_impacts.append("Local files could be read and transmitted externally (data exfiltration risk).")
    if "SECRETS" in capability_keys and "SEND" in capability_keys:
        possible_impacts.append("Credentials or secrets could be transmitted externally.")
    if not possible_impacts:
        possible_impacts.append("No high-confidence risky capability chains detected by phase-1 checks.")

    report = {
        "target": str(path),
        "num_files_scanned": len(py_files),
        "findings": findings,
        "capabilities": capability_keys,
        "possible_impacts": possible_impacts,
    }
    return report