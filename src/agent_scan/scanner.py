from pathlib import Path
from typing import List, Dict, Any
import os

try:
    from agent_scan.detectors.shell_exec import scan_path as shell_scan_path
except Exception:
    def shell_scan_path(path: Path):
        return []

def _gather_py_files(path: Path):
    if path.is_file() and path.suffix == ".py":
        return [path]
    files = list(path.rglob("*.py"))
    return files

def scan_path(path: Path, ruleset: str = "core") -> Dict[str, Any]:
    """
    Run the core detectors over the given path.
    Returns a structured dict (human-readable + machine friendly).
    """
    path = Path(path)
    py_files = _gather_py_files(path)

    findings = []
    for p in py_files:
        try:
            hits = shell_scan_path(p)
        except TypeError:
            try:
                content = p.read_text(encoding="utf-8")
            except Exception:
                continue
            from agent_scan.detectors.shell_exec import detect_in_code
            hits = detect_in_code(content)
        if hits:
            findings.append({"path": str(p), "hits": hits})

    capabilities = set()
    for f in findings:
        for (_, ev) in f["hits"]:
            ev_l = ev.lower()
            if "exec" in ev_l or "popen" in ev_l or "system" in ev_l or "run(" in ev_l:
                capabilities.add("Execute shell commands")

    possible_impacts = []
    if "Execute shell commands" in capabilities:
        possible_impacts.append("Commands could be executed on the host machine.")
    if not possible_impacts:
        possible_impacts.append("No high-confidence risky capabilities detected (phase-1 checks).")

    return {
        "target": str(path),
        "num_files_scanned": len(py_files),
        "findings": findings,
        "capabilities": sorted(list(capabilities)),
        "possible_impacts": possible_impacts,
    }