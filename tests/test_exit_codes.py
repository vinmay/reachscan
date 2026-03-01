"""Tests for CLI exit code contract and --severity flag."""
import pytest

from agent_scan.cli import main, _compute_exit_code


# ---------------------------------------------------------------------------
# _compute_exit_code unit tests
# ---------------------------------------------------------------------------

def _make_results(findings=None):
    return {"findings": findings or []}


def _finding(reachability="reachable", risk_level="high"):
    return {"detector": "shell_exec", "finding": {"reachability": reachability, "risk_level": risk_level}}


def test_exit_0_no_findings():
    assert _compute_exit_code(_make_results(), "high") == 0


def test_exit_1_reachable_high_severity_high():
    results = _make_results([_finding("reachable", "high")])
    assert _compute_exit_code(results, "high") == 1


def test_exit_0_reachable_medium_severity_high():
    results = _make_results([_finding("reachable", "medium")])
    assert _compute_exit_code(results, "high") == 0


def test_exit_1_reachable_medium_severity_medium():
    results = _make_results([_finding("reachable", "medium")])
    assert _compute_exit_code(results, "medium") == 1


def test_exit_1_reachable_high_severity_medium():
    results = _make_results([_finding("reachable", "high")])
    assert _compute_exit_code(results, "medium") == 1


def test_exit_0_severity_none_with_reachable_high():
    results = _make_results([_finding("reachable", "high")])
    assert _compute_exit_code(results, "none") == 0


def test_exit_0_unreachable_findings_severity_high():
    results = _make_results([_finding("unreachable", "high")])
    assert _compute_exit_code(results, "high") == 0


def test_exit_0_module_level_findings_severity_medium():
    results = _make_results([_finding("module_level", "high")])
    assert _compute_exit_code(results, "medium") == 0


# ---------------------------------------------------------------------------
# main() integration tests via monkeypatch
# ---------------------------------------------------------------------------

def _stub_results(findings=None):
    return {
        "target": ".",
        "source_type": "local",
        "num_files_scanned": 0,
        "findings": findings or [],
        "capabilities": [],
        "risks": [],
        "py_entry_points": [],
        "ts_entry_points": [],
        "other_languages": [],
    }


def test_main_exits_0_no_findings(monkeypatch, capsys):
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results())
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "high"])
    assert exc.value.code == 0


def test_main_exits_1_reachable_high_finding(monkeypatch, capsys):
    findings = [_finding("reachable", "high")]
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results(findings))
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "high"])
    assert exc.value.code == 1


def test_main_exits_0_reachable_medium_severity_high(monkeypatch, capsys):
    findings = [_finding("reachable", "medium")]
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results(findings))
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "high"])
    assert exc.value.code == 0


def test_main_exits_1_reachable_medium_severity_medium(monkeypatch, capsys):
    findings = [_finding("reachable", "medium")]
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results(findings))
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "medium"])
    assert exc.value.code == 1


def test_main_exits_0_severity_none_with_high_finding(monkeypatch, capsys):
    findings = [_finding("reachable", "high")]
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results(findings))
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "none"])
    assert exc.value.code == 0


def test_main_exits_2_on_scan_error(monkeypatch, capsys):
    def bad_scan(*a, **kw):
        raise RuntimeError("network timeout")
    monkeypatch.setattr("agent_scan.cli.scan_target", bad_scan)
    with pytest.raises(SystemExit) as exc:
        main(["."])
    assert exc.value.code == 2


def test_main_exits_0_unreachable_findings_only(monkeypatch, capsys):
    findings = [_finding("unreachable", "high"), _finding("module_level", "high")]
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results(findings))
    with pytest.raises(SystemExit) as exc:
        main([".", "--severity", "high"])
    assert exc.value.code == 0


def test_main_json_output_uses_v1_schema(monkeypatch, capsys):
    import json
    monkeypatch.setattr("agent_scan.cli.scan_target", lambda *a, **kw: _stub_results())
    with pytest.raises(SystemExit):
        main([".", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["schema_version"] == "1"
    assert "generated_at" in data
    assert "agent_scan_version" in data
    assert "report" not in data
