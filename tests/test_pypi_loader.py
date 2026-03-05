"""Tests for PyPI package resolution in source_loader."""
import pytest
from pathlib import Path

from reachscan.source_loader import (
    _is_pypi_target,
    _parse_pypi_target,
    resolve_target,
)


# ---------------------------------------------------------------------------
# _is_pypi_target
# ---------------------------------------------------------------------------

def test_is_pypi_target_bare_name():
    assert _is_pypi_target("pypi:requests") is True

def test_is_pypi_target_versioned():
    assert _is_pypi_target("pypi:requests==2.31.0") is True

def test_is_pypi_target_hyphenated():
    assert _is_pypi_target("pypi:langchain-core") is True

def test_is_pypi_target_underscored():
    assert _is_pypi_target("pypi:langchain_core") is True

def test_is_pypi_target_rejects_bare_name():
    assert _is_pypi_target("requests") is False

def test_is_pypi_target_rejects_absolute_path():
    assert _is_pypi_target("/home/user/proj") is False

def test_is_pypi_target_rejects_relative_path():
    assert _is_pypi_target("./myapp") is False

def test_is_pypi_target_rejects_http_url():
    assert _is_pypi_target("https://github.com/org/repo") is False

def test_is_pypi_target_rejects_mcp():
    assert _is_pypi_target("mcp+https://example.com") is False


# ---------------------------------------------------------------------------
# _parse_pypi_target
# ---------------------------------------------------------------------------

def test_parse_pypi_target_bare():
    name, version = _parse_pypi_target("pypi:requests")
    assert name == "requests"
    assert version is None

def test_parse_pypi_target_versioned():
    name, version = _parse_pypi_target("pypi:requests==2.31.0")
    assert name == "requests"
    assert version == "2.31.0"

def test_parse_pypi_target_hyphenated():
    name, version = _parse_pypi_target("pypi:langchain-core==0.2.1")
    assert name == "langchain-core"
    assert version == "0.2.1"


# ---------------------------------------------------------------------------
# resolve_target — PyPI branch (network mocked)
# ---------------------------------------------------------------------------

def _make_fake_fetch(version="2.31.0"):
    """Return a fake _fetch_pypi_package that writes a stub .py file."""
    def fake_fetch(name, ver, out_dir, progress_callback=None):
        (out_dir / "stub.py").write_text(f"# {name} {version}\n", encoding="utf-8")
        return version
    return fake_fetch


def test_resolve_target_pypi_bare(monkeypatch):
    monkeypatch.setattr(
        "reachscan.source_loader._fetch_pypi_package", _make_fake_fetch("2.31.0")
    )
    with resolve_target("pypi:requests") as resolved:
        assert resolved.source_type == "pypi"
        assert resolved.resolved_version == "2.31.0"
        assert resolved.local_path.exists()
        assert (resolved.local_path / "stub.py").exists()


def test_resolve_target_pypi_versioned(monkeypatch):
    monkeypatch.setattr(
        "reachscan.source_loader._fetch_pypi_package", _make_fake_fetch("2.28.0")
    )
    with resolve_target("pypi:requests==2.28.0") as resolved:
        assert resolved.source_type == "pypi"
        assert resolved.resolved_version == "2.28.0"
        assert resolved.display_target == "pypi:requests==2.28.0"


def test_resolve_target_pypi_not_found(monkeypatch):
    def fake_fetch_error(name, ver, out_dir, progress_callback=None):
        raise RuntimeError(f"PyPI: package '{name}' not found.")

    monkeypatch.setattr(
        "reachscan.source_loader._fetch_pypi_package", fake_fetch_error
    )
    with pytest.raises(RuntimeError, match="not found"):
        with resolve_target("pypi:doesnotexist-package-xyz") as _:
            pass


def test_resolve_target_pypi_tmp_cleaned_up(monkeypatch):
    """Temp directory is removed after the context manager exits."""
    def fake_fetch(name, ver, out_dir, progress_callback=None):
        (out_dir / "stub.py").write_text("x = 1", encoding="utf-8")
        return "1.0.0"

    monkeypatch.setattr("reachscan.source_loader._fetch_pypi_package", fake_fetch)

    with resolve_target("pypi:somepackage") as resolved:
        tmp = resolved.local_path

    assert not tmp.exists()


def test_resolve_target_pypi_progress_callback_called(monkeypatch):
    """progress_callback is forwarded into _fetch_pypi_package."""
    calls = []

    def fake_fetch(name, ver, out_dir, progress_callback=None):
        if progress_callback:
            progress_callback("pypi_download", 0, "start")
            progress_callback("pypi_download", 100, "done")
        (out_dir / "stub.py").write_text("x = 1", encoding="utf-8")
        return "1.0.0"

    monkeypatch.setattr("reachscan.source_loader._fetch_pypi_package", fake_fetch)

    with resolve_target("pypi:somepackage", progress_callback=lambda s, p, d: calls.append(s)) as _:
        pass

    assert "pypi_download" in calls


# ---------------------------------------------------------------------------
# resolved_version surfaces in scan report and text output
# ---------------------------------------------------------------------------

def test_scan_target_sets_resolved_version(monkeypatch, tmp_path):
    """scan_target stamps resolved_version from the PyPI source into the report."""
    from reachscan.scanner import scan_target

    def fake_fetch(name, ver, out_dir, progress_callback=None):
        (out_dir / "agent.py").write_text("import os\nos.getenv('KEY')", encoding="utf-8")
        return "3.0.1"

    monkeypatch.setattr("reachscan.source_loader._fetch_pypi_package", fake_fetch)

    report = scan_target("pypi:somepackage")
    assert report["source_type"] == "pypi"
    assert report["resolved_version"] == "3.0.1"
    assert report["target"] == "pypi:somepackage"


def test_text_report_shows_version(monkeypatch):
    """human_report includes the resolved version in the footer line."""
    from reachscan.reporters.text_reporter import human_report

    results = {
        "target": "requests",
        "source_type": "pypi",
        "resolved_version": "2.31.0",
        "num_files_scanned": 12,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
        "py_entry_points": [],
    }
    out = human_report(results)
    assert "version 2.31.0" in out
    assert "requests" in out


def test_text_report_no_version_for_local(monkeypatch):
    """human_report does not mention version for local/github scans."""
    from reachscan.reporters.text_reporter import human_report

    results = {
        "target": "/tmp/myproject",
        "source_type": "local",
        "num_files_scanned": 5,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
        "py_entry_points": [],
    }
    out = human_report(results)
    assert "version" not in out
