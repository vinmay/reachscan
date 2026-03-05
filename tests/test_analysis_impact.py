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
