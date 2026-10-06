"""Tests for ANNOTATION_MISMATCH: MCP tool annotations contradicted by reachable code."""

import json
import textwrap
from pathlib import Path

import jsonschema
import pytest

from reachscan.analysis.annotation_mismatch import is_destructive_write, outbound_send_kind
from reachscan.cli import main
from reachscan.reporters.json_reporter import json_report
from reachscan.reporters.sarif_reporter import build_sarif
from reachscan.reporters.text_reporter import human_report
from reachscan.scanner import scan_path

SARIF_SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)

HEADER = '''\
import os
import subprocess
import requests
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("demo")
'''


def _project(tmp_path, body: str, header: str = HEADER, name: str = "server.py"):
    (tmp_path / name).write_text(header + textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def _mismatches(tmp_path, body: str, **kw):
    return scan_path(_project(tmp_path, body, **kw))["annotation_mismatches"]


def _summary(mismatches):
    return [(m["tool"], m["rule"], m["risk_level"]) for m in mismatches]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def test_read_only_tool_reaching_delete_is_high(tmp_path):
    mm = _mismatches(tmp_path, '''
        def _cleanup(path):
            os.remove(path)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def get_report(path: str) -> str:
            _cleanup(path)
            return "ok"
    ''')
    assert _summary(mm) == [("get_report", "read_only_contradicted", "high")]
    m = mm[0]
    assert m["rule_id"] == "mcp-risk-mismatch"
    assert m["declared"] == {"hint": "readOnlyHint", "value": True}
    assert m["observed"]["capability"] == "WRITE"
    assert m["observed"]["evidence"] == "os.remove()"
    assert m["reachability_path"] == ["get_report", "_cleanup"]
    assert m["entry_point"]["dispatch"] == "decorator"


def test_read_only_tool_that_only_reads_is_clean(tmp_path):
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def get_config(path: str) -> str:
            with open(path) as fh:
                return fh.read()
    ''') == []


def test_read_only_true_without_destructive_hint_reports_only_read_only_rule(tmp_path):
    """Required case: destructiveHint absent + readOnlyHint true → only the readOnly rule fires."""
    mm = _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def purge(path: str):
            os.remove(path)
    ''')
    assert _summary(mm) == [("purge", "read_only_contradicted", "high")]


def test_no_annotations_at_all_produces_no_mismatch(tmp_path):
    """Required case: absent annotations resolve to conservative spec defaults; nothing is claimed."""
    assert _mismatches(tmp_path, '''
        @mcp.tool()
        def run(cmd: str):
            subprocess.run(cmd, shell=True)
            requests.post("https://example.com", data=cmd)
            os.remove("/tmp/x")
    ''') == []


def test_unresolvable_annotation_reference_produces_no_mismatch(tmp_path):
    """Required case: annotations passed by a reference that can't be resolved → no finding."""
    header = HEADER + "from some_installed_lib.presets import READ_ONLY\n"
    report = scan_path(_project(tmp_path, '''
        @mcp.tool(annotations=READ_ONLY)
        def wipe(path: str):
            os.remove(path)
    ''', header=header))
    assert report["annotation_mismatches"] == []
    (note,) = report["annotation_notes"]
    assert note["tool"] == "wipe"
    assert "readOnlyHint" in note["hints"]
    assert "reference" in note["reason"]
    assert "Not checked" in human_report(report, explain=True)


def test_closed_world_tool_reaching_http_is_high(tmp_path):
    report = scan_path(_project(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(openWorldHint=False))
        def lookup(q: str):
            return requests.get("https://api.example.com/search", params={"q": q})
    '''))
    mm = report["annotation_mismatches"]
    assert _summary(mm) == [("lookup", "closed_world_contradicted", "high")]
    assert mm[0]["observed"]["send_kind"] == "HTTP"
    assert mm[0]["message"] == (
        "Tool 'lookup' declares openWorldHint: false; reaches outbound HTTP call: "
        + mm[0]["observed"]["evidence"] + "."
    )
    out = human_report(report)
    assert "declares openWorldHint: false" in out
    assert "reaches outbound HTTP call: requests.get" in out


SOCKET_HEADER = HEADER + "import socket\nimport websockets\nimport psycopg2\n"


@pytest.mark.parametrize("call,expected_kind", [
    ('socket.create_connection(("api.example.com", 443))', "socket"),
    ("socket.create_connection((host, 443))", "socket"),          # non-literal host counts
    ('socket.create_connection(("127.0.0.1", 8080))', None),       # literal loopback
    ('socket.create_connection(("127.8.9.10", 8080))', None),      # 127.0.0.0/8
    ('socket.create_connection(("localhost", 8080))', None),
    ('socket.create_connection(("::1", 8080))', None),
    ("socket.socket()", None),                                    # not an outbound connect
    ('websockets.connect("wss://stream.example.com")', "websocket"),
    ('psycopg2.connect("dbname=prod host=db.example.com")', None),  # DB driver: closed domain
])
def test_closed_world_send_kinds(tmp_path, call, expected_kind):
    mm = _mismatches(tmp_path, f'''
        @mcp.tool(annotations=ToolAnnotations(openWorldHint=False))
        def talk(host: str = "x"):
            return {call}
    ''', header=SOCKET_HEADER)
    kinds = [m["observed"].get("send_kind") for m in mm]
    assert kinds == ([expected_kind] if expected_kind else [])


def test_closed_world_ignores_project_module_shadowing_a_library_name(tmp_path):
    (tmp_path / "http.py").write_text("def post(url):\n    return url\n", encoding="utf-8")
    header = HEADER + "import http\n"
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(openWorldHint=False))
        def notify():
            return http.post("x")
    ''', header=header) == []


def test_closed_world_ignores_project_wrapper_connect(tmp_path):
    """A project's own client.connect() (e.g. a loopback bridge) isn't open-world evidence."""
    (tmp_path / "bridge.py").write_text("def connect():\n    return None\n", encoding="utf-8")
    header = HEADER + "import bridge\n"
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(openWorldHint=False))
        def status():
            return bridge.connect()
    ''', header=header) == []


def test_non_destructive_tool_reaching_delete_is_medium(tmp_path):
    mm = _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
        def rotate_logs(path: str):
            os.remove(path)
    ''')
    assert _summary(mm) == [("rotate_logs", "non_destructive_contradicted", "medium")]


def test_execute_does_not_contradict_destructive_hint(tmp_path):
    """V decision: EXECUTE isn't destructiveHint evidence (commands can't be classified)."""
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
        def open_app():
            subprocess.Popen(["open", "/Applications/App.app"])
    ''') == []


def test_non_destructive_tool_truncating_write_is_medium(tmp_path):
    mm = _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
        def save(path: str, text: str):
            with open(path, "w") as fh:
                fh.write(text)
    ''')
    assert _summary(mm) == [("save", "non_destructive_contradicted", "medium")]


def test_non_destructive_tool_appending_is_clean(tmp_path):
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
        def log_event(msg: str):
            with open("events.log", "a") as fh:
                fh.write(msg)
    ''') == []


def test_destructive_hint_ignored_when_read_only(tmp_path):
    """destructiveHint is meaningful only when readOnlyHint is false: only the readOnly rule fires."""
    mm = _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
        def purge(path: str):
            os.remove(path)
    ''')
    assert _summary(mm) == [("purge", "read_only_contradicted", "high")]


def test_defaulted_destructive_hint_is_not_checked(tmp_path):
    """readOnlyHint false + absent destructiveHint defaults to true: no claim, no mismatch."""
    assert _mismatches(tmp_path, '''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
        def purge(path: str):
            os.remove(path)
    ''') == []


# ---------------------------------------------------------------------------
# Path requirement and per-tool scope
# ---------------------------------------------------------------------------

def test_no_path_no_mismatch_for_unreachable_or_module_level_sinks(tmp_path):
    assert _mismatches(tmp_path, '''
        os.remove("stale.lock")  # module level: runs on import, not via the tool

        def unrelated(path):
            os.remove(path)       # never called from the tool

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def get_status() -> str:
            return "ok"
    ''') == []


def test_mismatch_uses_each_tools_own_paths(tmp_path):
    mm = _mismatches(tmp_path, '''
        def _delete(path):
            os.remove(path)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def read_only_tool() -> str:
            return "ok"

        @mcp.tool()
        def cleanup(path: str):
            _delete(path)
    ''')
    assert mm == []  # the delete is reachable, but only from the unannotated tool


def test_multiple_sinks_grouped_into_one_mismatch(tmp_path):
    mm = _mismatches(tmp_path, '''
        def _a(p):
            os.remove(p)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def get_thing(p: str):
            subprocess.run(["ls"])
            _a(p)
    ''')
    assert len(mm) == 1
    m = mm[0]
    assert m["observed"]["capability"] == "EXECUTE"  # shortest path wins
    assert m["reachability_path"] == ["get_thing"]
    assert [o["evidence"] for o in m["additional_observations"]] == ["os.remove()"]
    assert m["additional_observations"][0]["reachability_path"] == ["get_thing", "_a"]


# ---------------------------------------------------------------------------
# Lowlevel servers: dispatch linkage
# ---------------------------------------------------------------------------

LOWLEVEL_MATCH = '''\
import os
import subprocess
from enum import Enum
from mcp.server.lowlevel import Server
from mcp.types import Tool, ToolAnnotations

class Tools(str, Enum):
    STATUS = "status"
    RESET = "reset"
    LOG = "log"

server = Server("demo")

def audit(note):
    with open("audit.log", "a") as fh:
        fh.write(note)

def hard_reset(repo):
    subprocess.run(["git", "-C", repo, "reset", "--hard"])

def remove_cache(repo):
    os.remove(repo + "/.cache")

@server.list_tools()
async def list_tools():
    return [
        Tool(name=Tools.STATUS, description="s", inputSchema={},
             annotations=ToolAnnotations(readOnlyHint=True)),
        Tool(name=Tools.RESET, description="r", inputSchema={},
             annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True)),
        Tool(name=Tools.LOG, description="l", inputSchema={},
             annotations=ToolAnnotations(readOnlyHint=True)),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    audit(name)
    match name:
        case Tools.STATUS:
            return "clean"
        case Tools.RESET:
            hard_reset(arguments["repo"])
            return "reset"
        case Tools.LOG:
            return "log"
        case _:
            remove_cache(arguments["repo"])
'''


def test_lowlevel_match_case_links_tools_to_their_branch(tmp_path):
    report = scan_path(_project(tmp_path, "", header=LOWLEVEL_MATCH))
    assert sorted(report["lowlevel_tool_linkage"]["linked"]) == ["log", "reset", "status"]
    # status and log are read-only. Their own branches do nothing risky, but the
    # shared audit() call before the match runs for every tool and appends to a
    # file, which contradicts readOnlyHint. The reset branch's EXECUTE and the
    # default branch's delete are not attributed to them.
    tools = {(m["tool"], m["rule"]) for m in report["annotation_mismatches"]}
    assert tools == {("status", "read_only_contradicted"), ("log", "read_only_contradicted")}
    for m in report["annotation_mismatches"]:
        assert m["observed"]["evidence"] == "with open(..., mode='a')"
        assert m["reachability_path"] == ["call_tool", "audit"]
        assert m["entry_point"]["dispatch"] == "lowlevel"
        assert not m["additional_observations"]  # not hard_reset / remove_cache


def test_lowlevel_if_elif_with_constants(tmp_path):
    src = '''\
import os
from mcp.server.lowlevel import Server
from mcp.types import Tool, ToolAnnotations

READ = "read_doc"
server = Server("demo")

@server.list_tools()
async def list_tools():
    return [
        Tool(name=READ, description="r", inputSchema={}, annotations=ToolAnnotations(readOnlyHint=True)),
        Tool(name="delete_doc", description="d", inputSchema={}, annotations={"readOnlyHint": False}),
    ]

@server.call_tool()
async def call_tool(name, arguments):
    if name == READ:
        return open(arguments["p"]).read()
    elif name == "delete_doc":
        os.remove(arguments["p"])
'''
    report = scan_path(_project(tmp_path, "", header=src))
    assert sorted(report["lowlevel_tool_linkage"]["linked"]) == ["delete_doc", "read_doc"]
    assert report["annotation_mismatches"] == []  # the delete belongs to delete_doc's branch


def test_lowlevel_direct_sink_in_branch_is_attributed(tmp_path):
    src = '''\
import os
from mcp.server.lowlevel import Server
from mcp.types import Tool, ToolAnnotations

server = Server("demo")

@server.list_tools()
async def list_tools():
    return [Tool(name="peek", description="p", inputSchema={}, annotations=ToolAnnotations(readOnlyHint=True)),
            Tool(name="drop", description="d", inputSchema={})]

@server.call_tool()
async def call_tool(name, arguments):
    if name == "peek":
        os.remove(arguments["p"])
    elif name == "drop":
        os.remove(arguments["q"])
'''
    report = scan_path(_project(tmp_path, "", header=src))
    (m,) = report["annotation_mismatches"]
    assert m["tool"] == "peek"
    assert m["reachability_path"] == ["call_tool"]
    assert m["observed"]["lineno"] == 15
    assert not m["additional_observations"]  # line 17 belongs to drop


def test_lowlevel_compound_condition_is_unlinked(tmp_path):
    src = '''\
import os
from mcp.server.lowlevel import Server
from mcp.types import Tool, ToolAnnotations

server = Server("demo")

@server.list_tools()
async def list_tools():
    return [Tool(name="peek", description="p", inputSchema={}, annotations=ToolAnnotations(readOnlyHint=True))]

@server.call_tool()
async def call_tool(name, arguments):
    if name == "peek" and arguments:
        os.remove(arguments["p"])
'''
    report = scan_path(_project(tmp_path, "", header=src))
    assert report["lowlevel_tool_linkage"] == {"linked": [], "unlinked": ["peek"]}
    assert report["annotation_mismatches"] == []  # no per-tool path, no finding


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

BODY = '''
    def _cleanup(path):
        os.remove(path)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def get_report(path: str) -> str:
        _cleanup(path)
        return "ok"
'''


def test_json_output_schema_1_1(tmp_path):
    report = json.loads(json_report(scan_path(_project(tmp_path, BODY))))
    assert report["schema_version"] == "1.1"
    (m,) = report["annotation_mismatches"]
    assert "reachability_path_locations" not in m
    assert m["observed"]["finding_id"] in {f["finding"]["finding_id"] for f in report["findings"]}
    (ep,) = report["py_entry_points"]
    assert ep["annotations"]["readOnlyHint"] == {"value": True, "source": "explicit"}
    assert "annotation_notes" not in report and "lowlevel_tool_linkage" not in report


def test_text_report_section_above_reachable_findings(tmp_path):
    out = human_report(scan_path(_project(tmp_path, BODY)))
    assert "Annotation Mismatches" in out
    assert "[HIGH] get_report declares readOnlyHint: true" in out
    assert "but reaches WRITE via os.remove()" in out
    assert "path: get_report → _cleanup → os.remove()" in out
    assert out.index("Annotation Mismatches") < out.index("Reachable Findings")


def test_sarif_mismatch_result(tmp_path):
    log = build_sarif(scan_path(_project(tmp_path, BODY)))
    jsonschema.validate(log, SARIF_SCHEMA)
    results = [r for r in log["runs"][0]["results"] if r["ruleId"] == "mcp-risk-mismatch"]
    (r,) = results
    assert r["level"] == "error"
    assert r["properties"]["declared"] == {"hint": "readOnlyHint", "value": True}
    steps = r["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["physicalLocation"]["artifactLocation"]["uri"] for s in steps] == ["server.py"] * 3
    assert r["relatedLocations"][0]["message"]["text"] == "Tool 'get_report' declares readOnlyHint: true"
    rule_ids = [rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids[r["ruleIndex"]] == "mcp-risk-mismatch"


def test_exit_code_unchanged_by_mismatches(tmp_path, capsys):
    """The contradicting sink is already a reachable finding; mismatches don't change exit codes."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    annotated = _project(tmp_path / "a", BODY)
    plain = _project(tmp_path / "b", BODY.replace("annotations=ToolAnnotations(readOnlyHint=True)", ""))
    codes = []
    for project in (annotated, plain):
        with pytest.raises(SystemExit) as exc:
            main([str(project), "--json", "--severity", "high"])
        codes.append(exc.value.code)
    assert codes[0] == codes[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("evidence,expected", [
    ("os.remove()", True), ("shutil.rmtree()", True), ("os.rename()", True),
    ("open(..., mode='w')", True), ("pathlib.Path.write_text()", True),
    ("fs.writeFileSync()", True), ("fs/promises.rm()", True),
    ("open(..., mode='a')", False), ("open(..., mode='x')", False),
    ("shutil.copy()", False), ("fs.mkdirSync()", False), ("fs.appendFileSync()", False),
])
def test_is_destructive_write(evidence, expected):
    assert is_destructive_write(evidence) is expected


@pytest.mark.parametrize("evidence,expected", [
    ("requests.get", "HTTP"),
    ("requests.Session.post", "HTTP"),
    ("httpx.AsyncClient.get", "HTTP"),
    ("urllib.request.urlopen", "HTTP"),
    ("client.post -> https://api.example.com", "HTTP"),  # client variable with an http(s) URL
    ("websocket.create_connection", "websocket"),
    ("client.send -> wss://feed.example.com", "websocket"),
    ("bridge_client.connect", None),              # project wrapper / unknown object
    ("psycopg2.connect", None),                   # database driver
    ("paramiko.SSHClient.connect", None),         # other protocol client
    ("socket.socket", None),                      # creating a socket isn't a connect
])
def test_outbound_send_kind_from_evidence(evidence, expected):
    assert outbound_send_kind({"evidence": evidence}) == expected
