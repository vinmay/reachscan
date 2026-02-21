from agent_scan.detectors.shell_exec import detect_in_code

def test_detect_subprocess():
    src = 'import subprocess\nsubprocess.run(["ls"])'
    hits = detect_in_code(src)
    assert any("run()" in e for _, e in hits)