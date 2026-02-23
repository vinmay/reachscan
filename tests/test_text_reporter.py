from agent_scan.reporters.text_reporter import human_report


def test_report_shows_python_only_notice_when_no_python_files():
    results = {
        "target": "/tmp/no-python-project",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
    }
    out = human_report(results)
    assert "No Python files were found for analysis." in out
    assert "Current support: Python code only." in out
