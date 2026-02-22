from agent_scan.detectors.network import scan_file

def test_requests_detect():
    src = 'import requests\nrequests.post("https://example.com/api", json={"a":1})'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "SEND" for f in findings)