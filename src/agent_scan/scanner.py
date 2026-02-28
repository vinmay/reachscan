"""
Scanner orchestration. Uses the detector registry to run all registered detectors
over Python files under a given path and returns a normalized report object.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from agent_scan.detectors.registry import get_detectors, call_detector
from agent_scan.detectors.base import CapabilityFinding
from agent_scan.analysis.finding_enrichment import enrich_finding
from agent_scan.analysis.impact import analyze_combined_capabilities
from agent_scan.source_loader import ProgressCallback
from agent_scan.source_loader import resolve_target
from agent_scan.ts_entry_points import scan_ts_files, TSEntryPoint
from agent_scan.py_entry_points import scan_py_files, EntryPoint as PyEntryPoint
from agent_scan import detectors  # noqa: F401 - ensures detector modules register themselves


def make_finding_id(
    detector: str, file: str, lineno: int, root: Path, evidence: str = ""
) -> tuple[str, str]:
    """
    Return (finding_id, finding_ref) for a capability finding.

    finding_id  — 12-char SHA-1 hex digest of the canonical ref string.
                  Compact, stable, safe to use as a dict key or in JSON arrays.
                  This is what EntryPoint.reachable_findings stores.

    finding_ref — human-readable "{detector}:{relative_file}:{lineno}:{evidence}".
                  Shown in the text reporter; not used for cross-referencing.
                  Evidence is included so two findings at the same line with
                  different evidence (e.g. network detector emitting once per
                  call site) produce distinct, readable refs.
    """
    try:
        relative = str(Path(file).relative_to(root))
    except ValueError:
        relative = file
    ref = f"{detector}:{relative}:{lineno}:{evidence}" if evidence else f"{detector}:{relative}:{lineno}"
    digest = hashlib.sha1(ref.encode()).hexdigest()[:12]
    return digest, ref

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

# Extension → human-readable language name for the "unsupported language" notice.
_EXT_TO_LANGUAGE = {
    ".go":    "Go",
    ".rs":    "Rust",
    ".rb":    "Ruby",
    ".java":  "Java",
    ".kt":    "Kotlin",
    ".kts":   "Kotlin",
    ".scala": "Scala",
    ".cs":    "C#",
    ".cpp":   "C++",
    ".cc":    "C++",
    ".cxx":   "C++",
    ".c":     "C",
    ".swift": "Swift",
    ".php":   "PHP",
    ".r":     "R",
    ".jl":    "Julia",
    ".lua":   "Lua",
    ".ex":    "Elixir",
    ".exs":   "Elixir",
    ".erl":   "Erlang",
    ".hs":    "Haskell",
    ".clj":   "Clojure",
    ".dart":  "Dart",
    ".zig":   "Zig",
    ".pl":    "Perl",
    ".sh":    "Shell",
}

# Directory parts to skip when counting languages (noise/deps/generated).
_LANG_EXCLUDED_DIR_PARTS = frozenset({
    "node_modules", "vendor", "third_party", "third-party",
    "site-packages", ".venv", "venv", "__pycache__",
    ".git", ".github", "dist", "build", "out", "target",
    "coverage", ".next", ".nuxt",
})


def _detect_other_languages(path: Path) -> List[Dict[str, Any]]:
    """
    Walk path and count source files by language for unsupported languages.
    Returns a list of {"language": str, "count": int} sorted by count descending.
    Only called when no Python files were found, so Python itself is excluded.
    """
    if path.is_file():
        return []

    counts: Dict[str, int] = {}
    for p in path.rglob("*"):
        if not p.is_file():
            continue
        parts = {part.lower() for part in p.parts}
        if parts & _LANG_EXCLUDED_DIR_PARTS:
            continue
        lang = _EXT_TO_LANGUAGE.get(p.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    return sorted(
        [{"language": lang, "count": cnt} for lang, cnt in counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )


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
                finding_id, finding_ref = make_finding_id(
                    name,
                    enriched.get("file", ""),
                    enriched.get("lineno", 0),
                    path,
                    enriched.get("evidence", ""),
                )
                enriched["finding_id"] = finding_id    # compact hash — used by reachability
                enriched["finding_ref"] = finding_ref  # human-readable — used by reporter
                findings.append({"detector": name, "finding": enriched})

        if progress_callback:
            pct = int((idx / total_files) * 100) if total_files else 100
            progress_callback("analysis_scan", pct, f"{idx}/{total_files} files")

    if progress_callback and total_files == 0:
        progress_callback("analysis_scan", 100, "0/0 files")

    # aggregate capabilities
    capability_keys = sorted({entry["finding"]["capability"] for entry in findings if entry["finding"].get("capability")})
    risks = analyze_combined_capabilities([entry["finding"] for entry in findings])

    # TypeScript/JavaScript entry point detection
    ts_entry_points = scan_ts_files(path)

    # Python entry point detection
    py_entry_points = scan_py_files(path)

    # Language detection — only when no Python files found, to explain the gap
    other_languages = _detect_other_languages(path) if not py_files else []

    report = {
        "target": str(path),
        "num_files_scanned": len(py_files),
        "findings": findings,
        "capabilities": capability_keys,
        "risks": risks,
        "ts_entry_points": [ep.as_dict() for ep in ts_entry_points],
        "py_entry_points": [ep.as_dict() for ep in py_entry_points],
        "other_languages": other_languages,
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
