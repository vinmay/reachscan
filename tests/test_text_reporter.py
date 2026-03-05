from reachscan.reporters.text_reporter import human_report, _format_path


def test_report_shows_other_languages_when_no_supported_files():
    results = {
        "target": "/tmp/go-mcp-server",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
        "other_languages": [
            {"language": "Go", "count": 146},
            {"language": "Shell", "count": 8},
        ],
    }
    out = human_report(results)
    assert "No Python or TypeScript files were found for analysis." in out
    assert "Go (146 files)" in out
    assert "Shell (8 files)" in out
    assert "reachscan currently supports Python" in out


def test_report_shows_no_files_notice_when_nothing_found():
    results = {
        "target": "/tmp/no-python-project",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
    }
    out = human_report(results)
    assert "No Python or TypeScript files were found for analysis." in out


def test_report_shows_ts_files_without_entry_points_notice():
    results = {
        "target": "/tmp/ts-no-entrypoints",
        "num_files_scanned": 0,
        "num_ts_files_scanned": 24,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
    }
    out = human_report(results)
    assert "TypeScript/JavaScript files scanned: 24" in out
    assert "Found 24 TypeScript/JavaScript files" in out
    assert "No Python or TypeScript files were found for analysis." not in out


def test_report_shows_ts_notice_when_only_ts_found():
    results = {
        "target": "/tmp/ts-only-project",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [
            {"name": "read_file", "file": "src/tools.ts", "lineno": 10, "pattern_type": "mcp_tool", "confidence": 0.95}
        ],
    }
    out = human_report(results)
    assert "TypeScript Entry Points" in out
    assert "read_file" in out
    assert "Full capability analysis requires Python source" in out


# ── Reachability tests ──────────────────────────────────────────────────────

def _make_result(findings, py_entry_points=None):
    return {
        "target": "/tmp/proj",
        "num_files_scanned": 1,
        "findings": findings,
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
        "py_entry_points": py_entry_points or [],
    }


def _make_finding(reachability, capability="EXECUTE", path=None, ep_name=None, truncated=False):
    return {
        "detector": "shell_exec",
        "finding": {
            "reachability": reachability,
            "capability": capability,
            "evidence": "subprocess.run()",
            "file": "/f.py",
            "lineno": 10,
            "risk_level": "high",
            "explanation": "Can exec.",
            "impact": "Bad.",
            "entry_point_name": ep_name,
            "reachability_path": path,
            "reachability_path_truncated": truncated,
        },
    }


def test_reachability_summary_shown():
    findings = [
        _make_finding("reachable"),
        _make_finding("unreachable"),
        _make_finding("unreachable"),
    ]
    out = human_report(_make_result(findings))
    assert "Reachability Summary" in out
    assert "1 reachable" in out
    assert "2 unreachable" in out


def test_reachable_findings_section():
    findings = [_make_finding("reachable", path=["run_shell", "_run_cmd"])]
    out = human_report(_make_result(findings))
    assert "Reachable Findings" in out
    assert "path: run_shell → _run_cmd" in out
    assert "explanation: Can exec." in out
    assert "impact: Bad." in out


def test_other_findings_section_unreachable():
    findings = [_make_finding("unreachable")]
    out = human_report(_make_result(findings))
    assert "Other Findings" in out
    assert "UNREACHABLE" in out
    assert "explanation: Can exec." in out


def test_other_findings_section_unknown():
    findings = [_make_finding("unknown")]
    out = human_report(_make_result(findings))
    assert "Other Findings" in out
    assert "UNKNOWN" in out
    assert "explanation: Can exec." in out


def test_no_entry_points_notice():
    findings = [_make_finding("no_entry_points")]
    out = human_report(_make_result(findings))
    assert "Reachability Summary" not in out
    assert "No Python entry points detected" in out
    assert "subprocess.run()" in out


def test_no_reachable_findings_notice():
    findings = [_make_finding("unreachable")]
    out = human_report(_make_result(findings))
    assert "No findings reachable from the detected entry points." in out


def test_module_level_finding():
    findings = [_make_finding("module_level")]
    out = human_report(_make_result(findings))
    assert "Other Findings" in out
    assert "MODULE_LEVEL" in out
    assert "Executes on import" in out
    assert "explanation: Can exec." in out


def test_module_level_in_summary():
    findings = [
        _make_finding("reachable"),
        _make_finding("module_level"),
        _make_finding("module_level"),
    ]
    out = human_report(_make_result(findings))
    assert "module-level" in out
    assert "2" in out  # 2 module-level findings


def test_py_entry_points_shown_at_top():
    findings = [_make_finding("reachable")]
    result = _make_result(findings, py_entry_points=[
        {"name": "my_tool", "framework": "pydantic_ai", "pattern_type": "decorator",
         "file": "tools.py", "lineno": 10},
    ])
    out = human_report(result)
    ep_pos = out.index("Python Entry Points")
    summary_pos = out.index("Reachability Summary")
    assert ep_pos < summary_pos, "Entry points section must appear before Reachability Summary"
