"""Tests for SARIF 2.1.0 output (--sarif)."""
import json
from pathlib import Path

import jsonschema
import pytest

from reachscan.analysis.impact import analyze_combined_capabilities
from reachscan.cli import main
from reachscan.reporters.json_reporter import json_report
from reachscan.reporters.sarif_reporter import COMBINED_RULES, build_sarif
from reachscan.scanner import scan_path

SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)


def _validate(log: dict) -> None:
    jsonschema.validate(log, SCHEMA)


def _write_mcp_project(root: Path) -> Path:
    (root / "server.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from mcp.server.fastmcp import FastMCP",
                "from helpers import fetch",
                "",
                'mcp = FastMCP("x")',
                "",
                "def _run(cmd):",
                "    return subprocess.run(cmd, shell=True)",
                "",
                "@mcp.tool()",
                "def run_cmd(cmd: str) -> str:",
                "    return _run(cmd)",
                "",
                "@mcp.tool()",
                "def get(url: str):",
                "    return fetch(url)",
                "",
                "def unused():",
                '    open("x", "w").write("y")',
            ]
        ),
        encoding="utf-8",
    )
    (root / "helpers.py").write_text(
        "import requests\n\ndef fetch(url):\n    return requests.get(url).text\n",
        encoding="utf-8",
    )
    return root


def _run_cli(capsys, argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code, capsys.readouterr().out


@pytest.fixture
def project(tmp_path):
    return _write_mcp_project(tmp_path)


def _results_by_rule(log):
    out = {}
    for r in log["runs"][0]["results"]:
        out.setdefault(r["ruleId"], []).append(r)
    return out


# ---------------------------------------------------------------------------
# Schema validity and structure
# ---------------------------------------------------------------------------

def test_cli_sarif_validates_against_schema(project, capsys):
    code, out = _run_cli(capsys, [str(project), "--sarif"])
    log = json.loads(out)
    _validate(log)
    assert log["version"] == "2.1.0"
    assert code == 1  # reachable high finding, default --severity high


def test_sarif_include_unreachable_validates_and_adds_findings(project, capsys):
    _, default_out = _run_cli(capsys, [str(project), "--sarif"])
    _, full_out = _run_cli(capsys, [str(project), "--sarif", "--sarif-include-unreachable"])
    default_log, full_log = json.loads(default_out), json.loads(full_out)
    _validate(full_log)

    default_states = {
        r["properties"]["reachability"]
        for r in default_log["runs"][0]["results"]
        if "reachability" in r["properties"]
    }
    full_states = {
        r["properties"]["reachability"]
        for r in full_log["runs"][0]["results"]
        if "reachability" in r["properties"]
    }
    assert "unreachable" not in default_states
    assert "unreachable" in full_states
    assert default_log["runs"][0]["properties"]["omittedFindings"] == 1
    assert full_log["runs"][0]["properties"]["omittedFindings"] == 0


def test_rules_cover_all_capabilities_and_combined_risks(project):
    log = build_sarif(scan_path(project))
    rule_ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]
    for cap in ("EXECUTE", "SEND", "READ", "WRITE", "SECRETS", "DYNAMIC", "AUTONOMY"):
        assert f"reachscan/{cap}" in rule_ids
    for risk_id in COMBINED_RULES:
        assert f"reachscan/combined/{risk_id}" in rule_ids
    for result in log["runs"][0]["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]


def test_combined_rules_match_impact_rule_ids():
    findings = [
        {"capability": c, "evidence": e, "reachability": "reachable"}
        for c, e in [
            ("SEND", "requests.post()"),
            ("WRITE", "os.remove()"),
            ("EXECUTE", "subprocess.run()"),
            ("READ", "open()"),
        ]
    ]
    risk_ids = {r["id"] for r in analyze_combined_capabilities(findings)}
    assert risk_ids == set(COMBINED_RULES)


# ---------------------------------------------------------------------------
# Results: levels, locations, code flows, properties
# ---------------------------------------------------------------------------

def test_reachable_finding_has_code_flow_per_hop(project):
    log = build_sarif(scan_path(project))
    execute = _results_by_rule(log)["reachscan/EXECUTE"][0]
    assert execute["level"] == "error"
    assert execute["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "server.py",
        "uriBaseId": "%SRCROOT%",
    }
    assert execute["locations"][0]["physicalLocation"]["region"]["startLine"] == 8

    steps = execute["codeFlows"][0]["threadFlows"][0]["locations"]
    # run_cmd (entry point) -> _run -> subprocess.run() sink
    assert [s["location"]["physicalLocation"]["region"]["startLine"] for s in steps] == [11, 7, 8]
    assert steps[0]["location"]["message"]["text"] == "LLM entry point run_cmd"
    assert [s["executionOrder"] for s in steps] == [0, 1, 2]

    props = execute["properties"]
    assert props["reachability"] == "reachable"
    assert props["entryPoint"] == "run_cmd"
    assert props["reachabilityPath"] == ["run_cmd", "_run"]
    assert 0.0 <= props["confidence"] <= 1.0
    assert execute["partialFingerprints"]["reachscanFindingId/v1"] == props["findingId"]


def test_cross_file_code_flow_points_at_each_file(project):
    log = build_sarif(scan_path(project))
    send = _results_by_rule(log)["reachscan/SEND"][0]
    steps = send["codeFlows"][0]["threadFlows"][0]["locations"]
    uris = [s["location"]["physicalLocation"]["artifactLocation"]["uri"] for s in steps]
    assert uris == ["server.py", "helpers.py", "helpers.py"]


def _synthetic(findings, risks=None, source_type="github"):
    return {
        "target": "https://github.com/org/repo",
        "source_type": source_type,
        "findings": [{"detector": "shell_exec", "finding": f} for f in findings],
        "risks": risks or [],
        "py_entry_points": [],
        "ts_entry_points": [],
    }


def _f(capability="EXECUTE", risk="high", state="reachable", lineno=3, fid="a1"):
    return {
        "capability": capability,
        "evidence": "x()",
        "file": "pkg/mod.py",
        "lineno": lineno,
        "confidence": 0.9,
        "risk_level": risk,
        "reachability": state,
        "entry_point_name": "tool" if state == "reachable" else None,
        "reachability_path": ["tool"] if state == "reachable" else None,
        "finding_id": fid,
    }


@pytest.mark.parametrize(
    "risk,state,level",
    [
        ("high", "reachable", "error"),
        ("medium", "reachable", "warning"),
        ("low", "reachable", "note"),
        ("high", "module_level", "note"),
        ("high", "unreachable", "note"),
        ("high", "unknown", "note"),
        ("high", "no_entry_points", "note"),
    ],
)
def test_level_mapping(risk, state, level):
    log = build_sarif(_synthetic([_f(risk=risk, state=state)]), include_unreachable=True)
    _validate(log)
    assert log["runs"][0]["results"][0]["level"] == level


def test_default_excludes_non_reachable_states():
    findings = [
        _f(state="reachable", fid="1"),
        _f(state="module_level", fid="2"),
        _f(state="unreachable", fid="3"),
        _f(state="unknown", fid="4"),
        _f(state="no_entry_points", fid="5"),
    ]
    log = build_sarif(_synthetic(findings))
    ids = [r["properties"]["findingId"] for r in log["runs"][0]["results"]]
    assert ids == ["1", "2"]
    assert log["runs"][0]["properties"]["omittedFindings"] == 3


def test_remote_target_uses_relative_uris_without_base_mapping():
    log = build_sarif(_synthetic([_f()]))
    _validate(log)
    run = log["runs"][0]
    assert "originalUriBaseIds" not in run
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "pkg/mod.py", "uriBaseId": "%SRCROOT%"}


def test_missing_lineno_omits_region():
    log = build_sarif(_synthetic([_f(lineno=None)]))
    _validate(log)
    assert "region" not in log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]


def test_combined_risk_anchored_on_contributing_findings():
    findings = [_f("EXECUTE", fid="e"), _f("SEND", lineno=9, fid="s")]
    risk = {
        "id": "remote_control",
        "title": "Remote Control Risk",
        "severity": "high",
        "why": "w",
        "capabilities_triggered": ["EXECUTE", "SEND"],
    }
    log = build_sarif(_synthetic(findings, [risk]))
    _validate(log)
    combined = _results_by_rule(log)["reachscan/combined/remote_control"][0]
    assert combined["level"] == "error"
    assert combined["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert combined["relatedLocations"][0]["physicalLocation"]["region"]["startLine"] == 9


def test_combined_risk_is_note_when_a_capability_is_not_reachable():
    findings = [_f("EXECUTE"), _f("SEND", state="no_entry_points")]
    risk = {
        "id": "remote_control",
        "title": "Remote Control Risk",
        "severity": "high",
        "why": "w",
        "capabilities_triggered": ["EXECUTE", "SEND"],
    }
    log = build_sarif(_synthetic(findings, [risk]))
    combined = _results_by_rule(log)["reachscan/combined/remote_control"][0]
    assert combined["level"] == "note"


# ---------------------------------------------------------------------------
# CLI contract
# ---------------------------------------------------------------------------

def test_json_and_sarif_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as exc:
        main([".", "--json", "--sarif"])
    assert exc.value.code == 2


def test_include_unreachable_requires_sarif(capsys):
    with pytest.raises(SystemExit) as exc:
        main([".", "--sarif-include-unreachable"])
    assert exc.value.code == 2


@pytest.mark.parametrize("severity", ["high", "medium", "none"])
def test_sarif_exit_code_matches_json(project, capsys, severity):
    json_code, _ = _run_cli(capsys, [str(project), "--json", "--severity", severity])
    sarif_code, _ = _run_cli(capsys, [str(project), "--sarif", "--severity", severity])
    assert sarif_code == json_code


def test_json_output_excludes_internal_path_locations(project):
    report = json.loads(json_report(scan_path(project)))
    for item in report["findings"]:
        assert "reachability_path_locations" not in item["finding"]


def test_relativize_paths_covers_hop_locations(tmp_path):
    from reachscan.scanner import _relativize_paths

    report = {
        "findings": [
            {
                "finding": {
                    "file": str(tmp_path / "pkg" / "mod.py"),
                    "reachability_path_locations": [
                        {"function": "tool", "file": str(tmp_path / "pkg" / "mod.py"), "lineno": 1}
                    ],
                }
            }
        ]
    }
    _relativize_paths(report, tmp_path)
    finding = report["findings"][0]["finding"]
    assert finding["file"] == str(Path("pkg") / "mod.py")
    assert finding["reachability_path_locations"][0]["file"] == str(Path("pkg") / "mod.py")
