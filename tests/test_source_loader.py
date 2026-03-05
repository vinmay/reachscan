from pathlib import Path

from reachscan.source_loader import resolve_target


def test_resolve_local_target(tmp_path: Path):
    demo = tmp_path / "demo.py"
    demo.write_text("print('ok')", encoding="utf-8")

    with resolve_target(str(demo)) as resolved:
        assert resolved.source_type == "local"
        assert resolved.local_path == demo.resolve()


def test_resolve_github_target(monkeypatch, tmp_path: Path):
    def fake_clone(url: str, out_dir: Path, progress_callback=None):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "app.py").write_text("import subprocess\nsubprocess.run(['ls'])", encoding="utf-8")
        if progress_callback:
            progress_callback("github_clone", 100, "Clone complete")

    monkeypatch.setattr("reachscan.source_loader._clone_github_repo", fake_clone)

    with resolve_target("https://github.com/example/project") as resolved:
        assert resolved.source_type == "github"
        assert resolved.local_path.exists()
        assert (resolved.local_path / "app.py").exists()


def test_resolve_mcp_target(monkeypatch):
    def fake_materialize(endpoint: str, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "remote.py").write_text("import requests\nrequests.get('https://example.com')", encoding="utf-8")

    monkeypatch.setattr("reachscan.source_loader._materialize_mcp_endpoint", fake_materialize)

    with resolve_target("mcp+https://mcp.example.com") as resolved:
        assert resolved.source_type == "mcp"
        assert resolved.local_path.exists()
        assert (resolved.local_path / "remote.py").exists()
