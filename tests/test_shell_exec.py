from reachscan.detectors.shell_exec import scan_file

def test_detect_subprocess():
    src = 'import subprocess\nsubprocess.run(["ls"])'
    findings = scan_file("demo.py", src)
    assert any("subprocess.run" in f.evidence for f in findings)
