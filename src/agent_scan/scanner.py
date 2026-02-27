"""
Scanner orchestration. Uses the detector registry to run all registered detectors
over Python files under a given path and returns a normalized report object.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from agent_scan.detectors.registry import get_detectors, call_detector
from agent_scan.detectors.base import CapabilityFinding
from agent_scan.analysis.finding_enrichment import enrich_finding
from agent_scan.analysis.impact import analyze_combined_capabilities
from agent_scan.source_loader import ProgressCallback
from agent_scan.source_loader import resolve_target
from agent_scan import detectors  # noqa: F401 - ensures detector modules register themselves

# Directory name components that universally indicate non-agent-runtime paths.
# Any .py file whose absolute path contains one of these as a directory part is excluded.
_EXCLUDED_DIR_PARTS = frozenset({
    # virtualenv / cache (original)
    "site-packages", ".venv", "venv", "__pycache__",
    # CI / version-control infrastructure
    ".git", ".github",
    # test directories
    "tests", "test",
    # benchmark infrastructure
    "benchmark", "benchmarks",
})


def _gather_py_files(path: Path) -> List[Path]:
    """Return list of .py files under path (or single file if path is file).

    Files are excluded when any directory component of their path matches a
    known non-agent-runtime name (CI scripts, test dirs, benchmark dirs) or
    when the filename follows a test-file naming convention (test_*.py /
    *_test.py).
    """
    path = Path(path)
    if path.is_file() and path.suffix == ".py":
        return [path]

    def is_excluded(p: Path) -> bool:
        parts = {part.lower() for part in p.parts}
        if parts & _EXCLUDED_DIR_PARTS:
            return True
        name = p.name.lower()
        if name.startswith("test_") or name.endswith("_test.py"):
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

def scan_path(
    path: Path,
    ruleset: str = "core",
    progress_callback: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
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
      "risks": [...],
    }
    """
    path = Path(path)
    py_files = _gather_py_files(path)

    # load detectors from registry
    detectors = get_detectors()

    findings: List[Dict[str, Any]] = []

    total_files = len(py_files)
    if progress_callback:
        progress_callback("analysis_scan", 0, f"0/{total_files} files")

    # run detectors over files
    for idx, p in enumerate(py_files, start=1):
        try:
            src = p.read_text(encoding="utf-8")
        except Exception:
            # skip files we can't read
            if progress_callback:
                pct = int((idx / total_files) * 100) if total_files else 100
                progress_callback("analysis_scan", pct, f"{idx}/{total_files} files")
            continue

        for name, detector in detectors.items():
            # detectors may choose to ignore ruleset; we pass ruleset if needed later
            raw = call_detector(detector, str(p), src)
            # call_detector returns list[CapabilityFinding] or empty list on error
            for f in raw:
                # f expected to be CapabilityFinding (or similar)
                normalized = _normalize_finding(f)
                enriched = enrich_finding(normalized)
                findings.append({"detector": name, "finding": enriched})

        if progress_callback:
            pct = int((idx / total_files) * 100) if total_files else 100
            progress_callback("analysis_scan", pct, f"{idx}/{total_files} files")

    if progress_callback and total_files == 0:
        progress_callback("analysis_scan", 100, "0/0 files")

    # aggregate capabilities
    capability_keys = sorted({entry["finding"]["capability"] for entry in findings if entry["finding"].get("capability")})
    risks = analyze_combined_capabilities([entry["finding"] for entry in findings])

    report = {
        "target": str(path),
        "num_files_scanned": len(py_files),
        "findings": findings,
        "capabilities": capability_keys,
        "risks": risks,
    }
    return report


def scan_target(
    target: str | Path,
    ruleset: str = "core",
    progress_callback: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    """
    Scan a local path, GitHub URL, or MCP endpoint target.
    """
    with resolve_target(target, progress_callback=progress_callback) as resolved:
        report = scan_path(resolved.local_path, ruleset=ruleset, progress_callback=progress_callback)
        report["target"] = resolved.display_target
        report["source_type"] = resolved.source_type
        return report
