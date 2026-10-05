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
    assert "TypeScript call paths are not traced yet" in out


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


# ── Combined risks from module-level code ──────────────────────────────────

def _risk_results(states_by_cap, files_by_cap=None):
    files_by_cap = files_by_cap or {}
    findings = []
    for cap, states in states_by_cap.items():
        for i, state in enumerate(states):
            findings.append({
                "detector": "x",
                "finding": {
                    "capability": cap, "evidence": "e()", "lineno": i + 1,
                    "file": files_by_cap.get(cap, [f"{cap.lower()}.ts"] * len(states))[i],
                    "risk_level": "high", "reachability": state,
                    "explanation": "", "impact": "",
                },
            })
    return {
        "target": "/p", "num_files_scanned": 1, "capabilities": list(states_by_cap),
        "risks": [{
            "id": "remote_control", "title": "Remote Control Risk", "severity": "high",
            "why": "w", "capabilities_triggered": sorted(states_by_cap),
        }],
        "findings": findings,
    }


def test_combined_risk_from_module_level_only_is_labeled_with_files():
    results = _risk_results(
        {"EXECUTE": ["module_level", "unknown"], "SEND": ["module_level"]},
        {"EXECUTE": ["scripts/build.ts", "src/a.ts"], "SEND": ["scripts/release.ts"]},
    )
    out = human_report(results)
    assert "from module-level code only" in out
    assert "      - scripts/build.ts" in out
    assert "      - scripts/release.ts" in out
    assert "      - src/a.ts" not in out  # unknown finding, not module-level
    assert "[HIGH] Remote Control Risk" in out  # severity unchanged


def test_combined_risk_with_reachable_capability_not_labeled():
    results = _risk_results({"EXECUTE": ["reachable"], "SEND": ["module_level"]})
    assert "from module-level code only" not in human_report(results)


def test_combined_risk_without_reachability_data_not_labeled():
    results = _risk_results({"EXECUTE": ["no_entry_points"], "SEND": ["no_entry_points"]})
    assert "from module-level code only" not in human_report(results)


def test_module_level_file_list_is_capped():
    files = [f"scripts/s{i:02d}.ts" for i in range(13)]
    results = _risk_results({"EXECUTE": ["module_level"] * 13, "SEND": ["module_level"]},
                            {"EXECUTE": files, "SEND": ["scripts/s00.ts"]})
    out = human_report(results)
    assert "      - scripts/s09.ts" in out
    assert "      - scripts/s10.ts" not in out
    assert "… and 3 more files" in out


def test_combined_risk_mixing_presence_and_module_level_not_labeled():
    """Python presence-counted EXECUTE + TS module_level SEND: not module-level only."""
    results = _risk_results(
        {"EXECUTE": ["no_entry_points"], "SEND": ["module_level"]},
        {"EXECUTE": ["tools.py"], "SEND": ["scripts/release.ts"]},
    )
    assert "from module-level code only" not in human_report(results)
