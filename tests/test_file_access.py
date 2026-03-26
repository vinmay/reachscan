from reachscan.detectors.file_access import scan_file

def test_open_read():
    src = 'f = open("secrets.txt", "r")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "READ" for f in findings)

def test_open_write():
    src = 'f = open("out.txt", "w")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "WRITE" for f in findings)


def test_with_open_dedup():
    """'with open(f)' and 'open(f)' at the same line should produce one finding, not two."""
    src = 'with open("data.txt", "rb") as f:\n    data = f.read()\n'
    findings = scan_file("demo.py", src)
    read_findings = [f for f in findings if f.capability == "READ"]
    assert len(read_findings) == 1, f"Expected 1 READ finding, got {len(read_findings)}"


def test_with_open_write_dedup():
    """'with open(f, \"w\")' should also dedup to one WRITE finding."""
    src = 'with open("out.txt", "w") as f:\n    f.write("hello")\n'
    findings = scan_file("demo.py", src)
    write_findings = [f for f in findings if f.capability == "WRITE"]
    assert len(write_findings) == 1, f"Expected 1 WRITE finding, got {len(write_findings)}"