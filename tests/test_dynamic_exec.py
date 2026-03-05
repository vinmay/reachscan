from reachscan.detectors.dynamic_exec import scan_file

def test_eval_exec_compile():
    src = 'x = eval("1+1")\nexec("print(123)")\ncompile("1+1", "<str>", "eval")'
    findings = scan_file("demo.py", src)
    caps = [f.evidence for f in findings]
    assert any("eval" in e for e in caps)
    assert any("exec" in e for e in caps)
    assert any("compile" in e for e in caps)

def test_importlib_dynamic_import():
    src = 'import importlib\nimportlib.import_module("json")'
    findings = scan_file("demo.py", src)
    assert any("importlib.import_module" in f.evidence for f in findings)

def test_runpy_exec():
    src = 'import runpy\nrunpy.run_module("json")'
    findings = scan_file("demo.py", src)
    assert any("runpy.run_module" in f.evidence for f in findings)
