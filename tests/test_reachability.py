"""Tests for the reachability analysis pass (Step 4)."""

import warnings

import pytest

from agent_scan.call_graph import MODULE_LEVEL
from agent_scan.py_entry_points import (
    EntryPoint,
    FRAMEWORK_LANGCHAIN,
    PATTERN_CLASS_ATTRIBUTE,
    PATTERN_DECORATOR,
)
from agent_scan.reachability import (
    DISPLAY_DEPTH,
    MODULE_LEVEL_STATE,
    NO_ENTRY_POINTS,
    REACHABLE,
    TRAVERSAL_DEPTH,
    UNKNOWN,
    UNREACHABLE,
    _bfs,
    analyze_reachability,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(file: str, lineno: int, finding_id: str = "abc123") -> dict:
    """Minimal enriched finding dict."""
    return {
        "reachability": None,
        "entry_point_name": None,
        "reachability_path": None,
        "reachability_path_truncated": None,
        "file": file,
        "lineno": lineno,
        "finding_id": finding_id,
        "capability": "EXECUTE",
    }


def make_ep(name: str, file: str, lineno: int) -> EntryPoint:
    """Minimal EntryPoint."""
    return EntryPoint(
        name=name,
        file=file,
        lineno=lineno,
        framework=FRAMEWORK_LANGCHAIN,
        pattern_type=PATTERN_DECORATOR,
    )


# ---------------------------------------------------------------------------
# Test 1 — no entry points
# ---------------------------------------------------------------------------

def test_no_entry_points():
    findings = [make_finding("/f.py", 5)]
    analyze_reachability(
        findings,
        py_entry_points=[],
        graph={},
        lineno_index={"/f.py": {0: MODULE_LEVEL, 5: "some_fn"}},
    )
    assert findings[0]["reachability"] == NO_ENTRY_POINTS
    assert findings[0]["entry_point_name"] is None
    assert findings[0]["reachability_path"] is None


# ---------------------------------------------------------------------------
# Test 2 — finding directly inside the entry point function
# ---------------------------------------------------------------------------

def test_finding_directly_in_entry_point():
    FILE = "/project/tools.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool"}}
    graph = {(FILE, "my_tool"): set()}
    findings = [make_finding(FILE, 12)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["entry_point_name"] == "my_tool"
    assert f["reachability_path"] == ["my_tool"]
    assert f["reachability_path_truncated"] is False


# ---------------------------------------------------------------------------
# Test 3 — one hop: entry point → helper → finding
# ---------------------------------------------------------------------------

def test_one_hop_reachable():
    TOOLS = "/project/tools.py"
    HELPER = "/project/helper.py"
    ep = make_ep("my_tool", TOOLS, 10)
    lineno_index = {
        TOOLS: {0: MODULE_LEVEL, 10: "my_tool"},
        HELPER: {0: MODULE_LEVEL, 5: "helper_fn"},
    }
    graph = {
        (TOOLS, "my_tool"): {(HELPER, "helper_fn")},
        (HELPER, "helper_fn"): set(),
    }
    findings = [make_finding(HELPER, 8)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["reachability_path"] == ["my_tool", "helper_fn"]


# ---------------------------------------------------------------------------
# Test 4 — unreachable: entry points exist but finding is disconnected
# ---------------------------------------------------------------------------

def test_unreachable():
    FILE = "/project/tools.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool", 20: "other_fn"}}
    graph = {
        (FILE, "my_tool"): set(),
        (FILE, "other_fn"): set(),
    }
    findings = [make_finding(FILE, 22)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == UNREACHABLE


# ---------------------------------------------------------------------------
# Test 5 — depth limit stops BFS: chain longer than TRAVERSAL_DEPTH
# ---------------------------------------------------------------------------

def test_depth_limit_stops_bfs():
    FILE = "/project/tools.py"
    # Chain fn0 → fn1 → ... → fn{N} where N = TRAVERSAL_DEPTH + 1
    # fn{N} is one hop beyond the BFS depth limit — not reached
    N = TRAVERSAL_DEPTH + 1

    lineno_index = {FILE: {0: MODULE_LEVEL}}
    graph = {}
    for i in range(N + 1):
        lineno_index[FILE][i * 10 + 10] = f"fn{i}"
        graph[(FILE, f"fn{i}")] = {(FILE, f"fn{i + 1}")} if i < N else set()

    ep = make_ep("fn0", FILE, 10)
    findings = [make_finding(FILE, N * 10 + 12)]

    with pytest.warns(UserWarning, match="nodes skipped"):
        analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == UNREACHABLE


# ---------------------------------------------------------------------------
# Test 6 — path exactly at DISPLAY_DEPTH nodes → not truncated
# ---------------------------------------------------------------------------

def test_path_not_truncated():
    FILE = "/project/tools.py"
    # Chain fn0 → ... → fn{N} where N = DISPLAY_DEPTH - 1
    # Path to fn{N} has DISPLAY_DEPTH nodes → not truncated
    N = DISPLAY_DEPTH - 1

    lineno_index = {FILE: {0: MODULE_LEVEL}}
    graph = {}
    for i in range(N + 1):
        lineno_index[FILE][i * 10 + 10] = f"fn{i}"
        graph[(FILE, f"fn{i}")] = {(FILE, f"fn{i + 1}")} if i < N else set()

    ep = make_ep("fn0", FILE, 10)
    findings = [make_finding(FILE, N * 10 + 12)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["reachability_path_truncated"] is False
    assert len(f["reachability_path"]) == DISPLAY_DEPTH


# ---------------------------------------------------------------------------
# Test 7 — path one beyond DISPLAY_DEPTH → truncated
# ---------------------------------------------------------------------------

def test_path_truncated():
    FILE = "/project/tools.py"
    N = DISPLAY_DEPTH  # path to fn{N} has DISPLAY_DEPTH + 1 nodes → truncated

    lineno_index = {FILE: {0: MODULE_LEVEL}}
    graph = {}
    for i in range(N + 1):
        lineno_index[FILE][i * 10 + 10] = f"fn{i}"
        graph[(FILE, f"fn{i}")] = {(FILE, f"fn{i + 1}")} if i < N else set()

    ep = make_ep("fn0", FILE, 10)
    findings = [make_finding(FILE, N * 10 + 12)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["reachability_path_truncated"] is True
    assert len(f["reachability_path"]) == DISPLAY_DEPTH + 1


# ---------------------------------------------------------------------------
# Test 8 — finding at module level → UNKNOWN
# ---------------------------------------------------------------------------

def test_module_level_unknown():
    FILE = "/project/tools.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool"}}
    graph = {(FILE, "my_tool"): set()}
    # lineno 5 is before any function → hits the 0 → MODULE_LEVEL sentinel
    findings = [make_finding(FILE, 5)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == MODULE_LEVEL_STATE


# ---------------------------------------------------------------------------
# Test 9 — finding in file not in lineno_index → UNKNOWN (no crash)
# ---------------------------------------------------------------------------

def test_file_not_in_lineno_index():
    FILE = "/project/tools.py"
    OTHER = "/project/other.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool"}}
    graph = {(FILE, "my_tool"): set()}
    findings = [make_finding(OTHER, 5)]

    with pytest.warns(UserWarning, match="not in lineno index"):
        analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == UNKNOWN


# ---------------------------------------------------------------------------
# Test 10 — ep.reachable_findings is populated for REACHABLE findings
# ---------------------------------------------------------------------------

def test_reachable_findings_on_entry_point():
    FILE = "/project/tools.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool"}}
    graph = {(FILE, "my_tool"): set()}
    findings = [make_finding(FILE, 12, finding_id="abc123")]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == REACHABLE
    assert "abc123" in ep.reachable_findings


# ---------------------------------------------------------------------------
# Test 11 — cycle in graph does not cause infinite loop
# ---------------------------------------------------------------------------

def test_cycle_no_infinite_loop():
    FILE = "/project/tools.py"
    ep = make_ep("fn_a", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "fn_a", 20: "fn_b"}}
    graph = {
        (FILE, "fn_a"): {(FILE, "fn_b")},
        (FILE, "fn_b"): {(FILE, "fn_a")},  # cycle
    }
    findings = [make_finding(FILE, 22)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == REACHABLE


# ---------------------------------------------------------------------------
# Test 12 — two entry points: shorter path wins
# ---------------------------------------------------------------------------

def test_multiple_entry_points_shortest_path_wins():
    FILE = "/project/tools.py"
    # ep1 (ep1_fn) reaches fn_c in 2 hops: ep1_fn → fn_b → fn_c
    # ep2 (ep2_fn) reaches fn_c in 1 hop:  ep2_fn → fn_c
    ep1 = make_ep("ep1_tool", FILE, 10)
    ep2 = make_ep("ep2_tool", FILE, 20)

    lineno_index = {
        FILE: {0: MODULE_LEVEL, 10: "ep1_fn", 20: "ep2_fn", 30: "fn_b", 40: "fn_c"}
    }
    graph = {
        (FILE, "ep1_fn"): {(FILE, "fn_b")},
        (FILE, "ep2_fn"): {(FILE, "fn_c")},
        (FILE, "fn_b"): {(FILE, "fn_c")},
        (FILE, "fn_c"): set(),
    }
    findings = [make_finding(FILE, 42)]

    analyze_reachability(findings, [ep1, ep2], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["entry_point_name"] == "ep2_tool"
    assert len(f["reachability_path"]) == 2  # [ep2_fn, fn_c]


# ---------------------------------------------------------------------------
# Test 13 — two EPs at equal depth: alphabetically first ep.name wins
# ---------------------------------------------------------------------------

def test_multiple_entry_points_deterministic_tiebreaker():
    FILE = "/project/tools.py"
    # Both entry points reach fn_c in 1 hop
    # ep names: "z_tool" vs "a_tool"; "a_tool" < "z_tool" → a_tool wins
    ep_z = make_ep("z_tool", FILE, 10)
    ep_a = make_ep("a_tool", FILE, 20)

    lineno_index = {
        FILE: {0: MODULE_LEVEL, 10: "z_fn", 20: "a_fn", 30: "fn_c"}
    }
    graph = {
        (FILE, "z_fn"): {(FILE, "fn_c")},
        (FILE, "a_fn"): {(FILE, "fn_c")},
        (FILE, "fn_c"): set(),
    }
    findings = [make_finding(FILE, 32)]

    analyze_reachability(findings, [ep_z, ep_a], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["entry_point_name"] == "a_tool"


# ---------------------------------------------------------------------------
# Test 14 — ep.lineno lookup resolves function name from lineno_index
# ---------------------------------------------------------------------------

def test_entry_point_lineno_lookup():
    FILE = "/project/tools.py"
    lineno_index = {FILE: {0: MODULE_LEVEL, 15: "actual_fn"}}
    graph = {(FILE, "actual_fn"): set()}
    # ep.lineno=15 matches "actual_fn" in lineno_index
    ep = make_ep("tool_name", FILE, 15)
    findings = [make_finding(FILE, 17)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == REACHABLE


# ---------------------------------------------------------------------------
# Test 15 — BFS visited cap triggers warning
# ---------------------------------------------------------------------------

def test_bfs_visited_cap_warning():
    FILE = "/project/tools.py"
    # Small graph; visited_cap=2 forces early abort after processing fn0
    graph = {
        (FILE, "fn0"): {(FILE, "fn1"), (FILE, "fn2")},
        (FILE, "fn1"): set(),
        (FILE, "fn2"): set(),
    }
    start = (FILE, "fn0")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        _bfs(start, graph, max_depth=8, visited_cap=2)
        assert any("BFS cap" in str(warning.message) for warning in w)


# ---------------------------------------------------------------------------
# Test 16 — nodes skipped by depth triggers warning in analyze_reachability
# ---------------------------------------------------------------------------

def test_nodes_skipped_by_depth_warning():
    FILE = "/project/tools.py"
    N = TRAVERSAL_DEPTH + 1  # chain one hop beyond the limit

    lineno_index = {FILE: {0: MODULE_LEVEL}}
    graph = {}
    for i in range(N + 1):
        lineno_index[FILE][i * 10 + 10] = f"fn{i}"
        graph[(FILE, f"fn{i}")] = {(FILE, f"fn{i + 1}")} if i < N else set()

    ep = make_ep("fn0", FILE, 10)
    findings: list = []

    with pytest.warns(UserWarning, match="nodes skipped"):
        analyze_reachability(findings, [ep], graph, lineno_index)


# ---------------------------------------------------------------------------
# Test 17 — finding inside nested function (not in graph) → UNKNOWN
# ---------------------------------------------------------------------------

def test_nested_function_finding_gets_unknown():
    FILE = "/project/tools.py"
    ep = make_ep("outer_fn", FILE, 10)

    # lineno_index includes both outer_fn and the nested function "inner"
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "outer_fn", 12: "inner"}}

    # graph only has outer_fn — "inner" is a nested function not in project_functions
    graph = {(FILE, "outer_fn"): set()}

    # finding at lineno 14 → bisect resolves to "inner" (lineno 12)
    findings = [make_finding(FILE, 14)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    # "inner" not in graph → UNKNOWN (not UNREACHABLE)
    assert findings[0]["reachability"] == UNKNOWN


# ---------------------------------------------------------------------------
# Test 18 — parse failure file → UNKNOWN without crash
# ---------------------------------------------------------------------------

def test_parse_failure_file_unknown():
    FILE = "/project/tools.py"
    FAILED = "/project/bad_syntax.py"
    ep = make_ep("my_tool", FILE, 10)
    lineno_index = {FILE: {0: MODULE_LEVEL, 10: "my_tool"}}
    graph = {(FILE, "my_tool"): set()}
    findings = [make_finding(FAILED, 5)]

    with pytest.warns(UserWarning, match="not in lineno index"):
        analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == UNKNOWN


# ---------------------------------------------------------------------------
# Test 19 — class-based EP: lineno is class def line → falls back to _run
# ---------------------------------------------------------------------------

def test_class_based_entry_point_falls_back_to_run_method():
    FILE = "/project/tools.py"
    # Simulate a BaseTool subclass:
    #   line 10: class MyTool(BaseTool):  ← ep.lineno (class def, NOT in lineno_index)
    #   line 12: def __init__(self): ...  ← in lineno_index as "MyTool.__init__"
    #   line 15: def _run(self): ...      ← in lineno_index as "MyTool._run"
    #   line 18: finding (EXECUTE)
    lineno_index = {
        FILE: {0: MODULE_LEVEL, 12: "MyTool.__init__", 15: "MyTool._run"}
    }
    graph = {
        (FILE, "MyTool.__init__"): set(),
        (FILE, "MyTool._run"): set(),
    }
    ep = EntryPoint(
        name="my_tool",
        file=FILE,
        lineno=10,  # class def line — not in lineno_index
        framework=FRAMEWORK_LANGCHAIN,
        pattern_type=PATTERN_CLASS_ATTRIBUTE,
    )
    findings = [make_finding(FILE, 18)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    f = findings[0]
    assert f["reachability"] == REACHABLE
    assert f["entry_point_name"] == "my_tool"
    assert f["reachability_path"] == ["MyTool._run"]


# ---------------------------------------------------------------------------
# Test 20 — class-based EP with no _run: stays skipped (doesn't crash)
# ---------------------------------------------------------------------------

def test_class_based_entry_point_no_run_method_skipped():
    FILE = "/project/tools.py"
    # Class has no _run/_arun/__call__ — fallback returns None → entry point skipped
    lineno_index = {
        FILE: {0: MODULE_LEVEL, 12: "MyTool.__init__", 20: "standalone_fn"}
    }
    graph = {
        (FILE, "MyTool.__init__"): set(),
        (FILE, "standalone_fn"): set(),
    }
    ep = EntryPoint(
        name="my_tool",
        file=FILE,
        lineno=10,
        framework=FRAMEWORK_LANGCHAIN,
        pattern_type=PATTERN_CLASS_ATTRIBUTE,
    )
    # Finding is inside standalone_fn — not reachable from ep (ep was skipped)
    findings = [make_finding(FILE, 22)]

    analyze_reachability(findings, [ep], graph, lineno_index)

    assert findings[0]["reachability"] == UNREACHABLE
