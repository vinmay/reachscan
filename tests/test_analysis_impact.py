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
