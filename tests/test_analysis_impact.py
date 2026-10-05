from reachscan.analysis.impact import analyze_combined_capabilities


def test_combined_secret_leak_rule():
    findings = [
        {"capability": "READ", "evidence": 'open("secrets.txt", "r")'},
        {"capability": "SEND", "evidence": "requests.post()"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "secret_leak" for r in risks)


def test_destructive_agent_rule_requires_destructive_write_evidence():
    findings = [
        {"capability": "EXECUTE", "evidence": "subprocess.run()"},
        {"capability": "WRITE", "evidence": "os.remove()"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "destructive_agent" for r in risks)


# ---------------------------------------------------------------------------
# Reachability-aware combined risk filtering
# ---------------------------------------------------------------------------

def test_unreachable_capability_does_not_trigger_combined_risk():
    """Combined risks should not fire when one capability is only unreachable."""
    findings = [
        {"capability": "READ", "evidence": 'open("f")', "reachability": "reachable"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "unreachable"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert not any(r["id"] == "secret_leak" for r in risks)


def test_both_reachable_triggers_combined_risk():
    """Combined risks fire when both capabilities have reachable findings."""
    findings = [
        {"capability": "READ", "evidence": 'open("f")', "reachability": "reachable"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "reachable"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "secret_leak" for r in risks)


def test_module_level_counts_as_reachable():
    """Module-level findings should count as reachable for combined risks."""
    findings = [
        {"capability": "EXECUTE", "evidence": "subprocess.run()", "reachability": "module_level"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "reachable"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "remote_control" for r in risks)


def test_no_reachability_data_falls_back_to_all_capabilities():
    """When findings have no reachability field, all capabilities count (backwards compat)."""
    findings = [
        {"capability": "READ", "evidence": 'open("f")'},
        {"capability": "SEND", "evidence": "requests.post()"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "secret_leak" for r in risks)


def test_mixed_reachable_and_unreachable_same_capability():
    """If a capability has both reachable and unreachable findings, it counts as reachable."""
    findings = [
        {"capability": "READ", "evidence": 'open("a")', "reachability": "unreachable"},
        {"capability": "READ", "evidence": 'open("b")', "reachability": "reachable"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "reachable"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "secret_leak" for r in risks)


def test_no_entry_points_falls_back_to_all_capabilities():
    """When no entry points were detected, reachability is unevaluated, so all capabilities count."""
    findings = [
        {"capability": "READ", "evidence": 'open("f")', "reachability": "no_entry_points"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "no_entry_points"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "secret_leak" for r in risks)


def test_mixed_project_python_no_entry_points_still_count_by_presence():
    """Evaluated TS states must not switch off the presence fallback for Python findings."""
    findings = [
        {"capability": "EXECUTE", "evidence": "subprocess.run()", "file": "tools.py",
         "reachability": "no_entry_points"},
        {"capability": "SEND", "evidence": "requests.post()", "file": "tools.py",
         "reachability": "no_entry_points"},
        {"capability": "READ", "evidence": "fs.readFileSync()", "file": "build.ts",
         "reachability": "module_level"},
    ]
    risks = analyze_combined_capabilities(findings)
    assert any(r["id"] == "remote_control" for r in risks)
    assert any(r["id"] == "secret_leak" for r in risks)  # READ (TS module_level) + SEND (Python)


def test_ts_fallback_decided_separately_from_python():
    """TS keeps its own rule: once a TS finding is evaluated, TS no_entry_points don't count."""
    findings = [
        {"capability": "EXECUTE", "evidence": "child_process.exec()", "file": "a.ts",
         "reachability": "no_entry_points"},
        {"capability": "SEND", "evidence": "fetch()", "file": "a.ts",
         "reachability": "no_entry_points"},
        {"capability": "SECRETS", "evidence": "process.env.KEY", "file": "a.ts",
         "reachability": "module_level"},
        {"capability": "READ", "evidence": "open()", "file": "x.py", "reachability": "reachable"},
    ]
    assert analyze_combined_capabilities(findings) == []


def test_ts_only_without_evaluated_states_counts_by_presence():
    findings = [
        {"capability": "EXECUTE", "evidence": "child_process.exec()", "file": "a.ts",
         "reachability": "no_entry_points"},
        {"capability": "SEND", "evidence": "fetch()", "file": "b.mjs",
         "reachability": "no_entry_points"},
    ]
    assert any(r["id"] == "remote_control" for r in analyze_combined_capabilities(findings))


def test_unknown_and_unreachable_do_not_count():
    findings = [
        {"capability": "EXECUTE", "evidence": "subprocess.run()", "reachability": "unknown"},
        {"capability": "SEND", "evidence": "requests.post()", "reachability": "unreachable"},
    ]
    assert analyze_combined_capabilities(findings) == []
