from pathlib import Path

from reachscan.scanner import scan_target


def test_scan_target_local(tmp_path: Path):
    demo = tmp_path / "demo.py"
    demo.write_text("import subprocess\nsubprocess.run(['ls'])", encoding="utf-8")

    report = scan_target(str(demo))
    assert report["source_type"] == "local"
    assert report["target"] == str(demo.resolve())
    assert "EXECUTE" in report["capabilities"]


def test_scan_target_github(monkeypatch, tmp_path: Path):
    events = []

    def fake_clone(url: str, out_dir: Path, progress_callback=None):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "demo.py").write_text("import requests\nrequests.get('https://example.com')", encoding="utf-8")
        if progress_callback:
            progress_callback("github_clone", 100, "Clone complete")
            events.append("called")

    monkeypatch.setattr("reachscan.source_loader._clone_github_repo", fake_clone)

    report = scan_target("https://github.com/example/project", progress_callback=lambda *_: None)
    assert report["source_type"] == "github"
    assert report["target"] == "https://github.com/example/project"
    assert "SEND" in report["capabilities"]
    assert events


def test_scan_target_mcp(monkeypatch):
    def fake_materialize(endpoint: str, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "demo.py").write_text("x = open('data.txt', 'w')", encoding="utf-8")

    monkeypatch.setattr("reachscan.source_loader._materialize_mcp_endpoint", fake_materialize)

    report = scan_target("mcp+https://mcp.example.com")
    assert report["source_type"] == "mcp"
    assert report["target"] == "mcp+https://mcp.example.com"
    assert "WRITE" in report["capabilities"]
