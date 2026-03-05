"""Stable v1 JSON schema for reachscan reports."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError
from typing import Any, Dict


def _get_tool_version() -> str:
    try:
        return version("reachscan")
    except PackageNotFoundError:
        return "unknown"


_VALID_RISK_LEVELS = {"high", "medium", "low", "info"}

_STATIC_ANALYSIS_NOTE = (
    "This report reflects code patterns. "
    "It does not prove runtime behavior or exploitability."
)


def normalize_finding(finding: dict) -> dict:
    """Enforce schema constraints on a finding dict.

    Returns a new dict with normalized values; all other fields are passed through.
    """
    result = dict(finding)

    # risk_level → lowercase; unknown values default to "medium"
    risk = result.get("risk_level")
    if isinstance(risk, str):
        risk = risk.lower()
        if risk not in _VALID_RISK_LEVELS:
            risk = "medium"
        result["risk_level"] = risk
    elif risk is not None:
        result["risk_level"] = "medium"

    # confidence → float, clamped to [0.0, 1.0]
    conf = result.get("confidence")
    if conf is not None:
        try:
            conf = float(conf)
            conf = max(0.0, min(1.0, conf))
        except (TypeError, ValueError):
            conf = None
        result["confidence"] = conf

    # lineno → int or None
    lineno = result.get("lineno")
    if lineno is not None:
        try:
            result["lineno"] = int(lineno)
        except (TypeError, ValueError):
            result["lineno"] = None

    return result


def build_v1_report(results: Dict[str, Any]) -> Dict[str, Any]:
    """Convert scanner output dict to a flat v1 schema dict."""
    py_entry_points = results.get("py_entry_points", [])
    ts_entry_points = results.get("ts_entry_points", [])
    entry_points_detected = len(py_entry_points) + len(ts_entry_points)

    normalized_findings = [
        {"detector": item.get("detector"), "finding": normalize_finding(item.get("finding", {}))}
        for item in results.get("findings", [])
    ]

    report: Dict[str, Any] = {
        "schema_version": "1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reachscan_version": _get_tool_version(),
        "target": results.get("target", ""),
        "source_type": results.get("source_type", "local"),
        "resolved_version": results.get("resolved_version"),
        "num_files_scanned": results.get("num_files_scanned", 0),
        "num_ts_files_scanned": results.get("num_ts_files_scanned", 0),
        "entry_points_detected": entry_points_detected,
        "py_entry_points": py_entry_points,
        "ts_entry_points": ts_entry_points,
        "capabilities": results.get("capabilities", []),
        "risks": results.get("risks", []),
        "findings": normalized_findings,
        "other_languages": results.get("other_languages", []),
        "static_analysis_note": _STATIC_ANALYSIS_NOTE,
    }
    return report
