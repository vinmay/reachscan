from reachscan.detectors.file_access import scan_file

def test_open_read():
    src = 'f = open("secrets.txt", "r")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "READ" for f in findings)

def test_open_write():
    src = 'f = open("out.txt", "w")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "WRITE" for f in findings)