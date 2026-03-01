"""Tests for the stable v1 JSON schema (schema.py)."""
from datetime import datetime, timezone

import pytest

from agent_scan.schema import normalize_finding, build_v1_report


# ---------------------------------------------------------------------------
# normalize_finding
# ---------------------------------------------------------------------------

def test_normalize_finding_risk_level_lowercased():
    result = normalize_finding({"risk_level": "HIGH"})
    assert result["risk_level"] == "high"


def test_normalize_finding_risk_level_unknown_defaults_to_medium():
    result = normalize_finding({"risk_level": "critical"})
    assert result["risk_level"] == "medium"


def test_normalize_finding_risk_level_valid_values_preserved():
    for level in ("high", "medium", "low", "info"):
        assert normalize_finding({"risk_level": level})["risk_level"] == level


def test_normalize_finding_risk_level_non_string_defaults_to_medium():
    result = normalize_finding({"risk_level": 42})
    assert result["risk_level"] == "medium"


def test_normalize_finding_confidence_clamped_above():
    result = normalize_finding({"confidence": 1.5})
    assert result["confidence"] == 1.0


def test_normalize_finding_confidence_clamped_below():
    result = normalize_finding({"confidence": -0.1})
    assert result["confidence"] == 0.0


def test_normalize_finding_confidence_normal_value():
    result = normalize_finding({"confidence": 0.85})
    assert abs(result["confidence"] - 0.85) < 1e-9


def test_normalize_finding_confidence_string_converted():
    result = normalize_finding({"confidence": "0.7"})
    assert abs(result["confidence"] - 0.7) < 1e-9


def test_normalize_finding_lineno_converted_to_int():
    result = normalize_finding({"lineno": "42"})
    assert result["lineno"] == 42
    assert isinstance(result["lineno"], int)


def test_normalize_finding_lineno_invalid_becomes_none():
    result = normalize_finding({"lineno": "abc"})
    assert result["lineno"] is None


def test_normalize_finding_lineno_none_stays_none():
    result = normalize_finding({"lineno": None})
    assert result["lineno"] is None


def test_normalize_finding_other_fields_passed_through():
    finding = {"capability": "EXECUTE", "evidence": "subprocess.run()", "extra": "preserved"}
    result = normalize_finding(finding)
    assert result["capability"] == "EXECUTE"
    assert result["evidence"] == "subprocess.run()"
    assert result["extra"] == "preserved"


# ---------------------------------------------------------------------------
# build_v1_report
# ---------------------------------------------------------------------------

def _make_results(**kwargs):
    base = {
        "target": ".",
        "source_type": "local",
        "num_files_scanned": 5,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "py_entry_points": [],
        "ts_entry_points": [],
        "other_languages": [],
    }
    base.update(kwargs)
    return base


def test_build_v1_report_required_top_level_keys():
    report = build_v1_report(_make_results())
    required = {
        "schema_version", "generated_at", "agent_scan_version",
        "target", "source_type", "resolved_version",
        "num_files_scanned", "entry_points_detected",
        "py_entry_points", "ts_entry_points",
        "capabilities", "risks", "findings",
        "other_languages", "static_analysis_note",
    }
    assert required <= set(report.keys())


def test_build_v1_report_schema_version():
    report = build_v1_report(_make_results())
    assert report["schema_version"] == "1"


def test_build_v1_report_generated_at_is_valid_utc_iso8601():
    report = build_v1_report(_make_results())
    ts = report["generated_at"]
    assert ts.endswith("Z"), f"Expected UTC 'Z' suffix, got: {ts}"
    # Should parse without error
    parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert parsed.year >= 2024


def test_build_v1_report_entry_points_detected_sum():
    results = _make_results(
        py_entry_points=[{"name": "tool_a"}, {"name": "tool_b"}],
        ts_entry_points=[{"name": "ts_tool"}],
    )
    report = build_v1_report(results)
    assert report["entry_points_detected"] == 3


def test_build_v1_report_entry_points_detected_zero():
    report = build_v1_report(_make_results())
    assert report["entry_points_detected"] == 0


def test_build_v1_report_normalizes_nested_findings():
    results = _make_results(findings=[
        {"detector": "shell_exec", "finding": {"risk_level": "HIGH", "confidence": 2.0, "lineno": "10"}}
    ])
    report = build_v1_report(results)
    f = report["findings"][0]["finding"]
    assert f["risk_level"] == "high"
    assert f["confidence"] == 1.0
    assert f["lineno"] == 10


def test_build_v1_report_no_report_wrapper():
    report = build_v1_report(_make_results())
    assert "report" not in report


def test_build_v1_report_resolved_version_included_when_present():
    results = _make_results()
    results["resolved_version"] = "1.2.3"
    report = build_v1_report(results)
    assert report["resolved_version"] == "1.2.3"


def test_build_v1_report_resolved_version_none_when_absent():
    report = build_v1_report(_make_results())
    assert report["resolved_version"] is None


def test_build_v1_report_static_analysis_note_present():
    report = build_v1_report(_make_results())
    assert "static_analysis_note" in report
    assert len(report["static_analysis_note"]) > 10
