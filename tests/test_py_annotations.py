"""Tests for MCP tool annotation extraction from Python sources."""

import textwrap

from reachscan.py_annotations import DEFAULT, EXPLICIT, UNRESOLVABLE
from reachscan.py_entry_points import detect_py_entry_points

FASTMCP_HEADER = '''\
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("demo")
'''


def _tool(src: str, name: str = "t", header: str = FASTMCP_HEADER):
    eps = detect_py_entry_points("server.py", header + textwrap.dedent(src))
    matches = [ep for ep in eps if ep.name == name]
    assert len(matches) == 1, [ep.name for ep in eps]
    return matches[0]


def _hints(info):
    return {key: (hv.value, hv.source) for key, hv in info.hints().items()}


# ---------------------------------------------------------------------------
# Required cases
# ---------------------------------------------------------------------------

def test_read_only_true_without_destructive_hint():
    """destructiveHint absent + readOnlyHint true → destructive counts as false."""
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def t(): ...
    ''')
    assert ep.annotations.declared
    assert _hints(ep.annotations) == {
        "readOnlyHint": (True, EXPLICIT),
        "destructiveHint": (False, DEFAULT),
        "idempotentHint": (False, DEFAULT),
        "openWorldHint": (True, DEFAULT),
    }


def test_no_annotations_at_all_uses_spec_defaults():
    ep = _tool('''
        @mcp.tool()
        def t(): ...
    ''')
    assert not ep.annotations.declared
    assert not ep.annotations.unresolved_reference
    assert _hints(ep.annotations) == {
        "readOnlyHint": (False, DEFAULT),
        "destructiveHint": (True, DEFAULT),
        "idempotentHint": (False, DEFAULT),
        "openWorldHint": (True, DEFAULT),
    }


def test_unresolvable_reference_makes_every_hint_unresolvable():
    ep = _tool('''
        from .shared import READ_ONLY

        @mcp.tool(annotations=READ_ONLY)
        def t(): ...
    ''')
    assert ep.annotations.declared
    assert ep.annotations.unresolved_reference
    assert all(hv.source == UNRESOLVABLE and hv.value is None
               for hv in ep.annotations.hints().values())


def test_reference_to_function_result_is_unresolvable():
    ep = _tool('''
        def make():
            return ToolAnnotations(readOnlyHint=True)

        ANN = make()

        @mcp.tool(annotations=ANN)
        def t(): ...
    ''')
    assert ep.annotations.unresolved_reference
    assert ep.annotations.read_only.source == UNRESOLVABLE


# ---------------------------------------------------------------------------
# FastMCP forms
# ---------------------------------------------------------------------------

def test_all_hints_explicit():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False,
        ))
        def t(): ...
    ''')
    assert _hints(ep.annotations) == {
        "readOnlyHint": (False, EXPLICIT),
        "destructiveHint": (False, EXPLICIT),
        "idempotentHint": (True, EXPLICIT),
        "openWorldHint": (False, EXPLICIT),
    }


def test_read_only_false_explicit_destructive_defaults_true():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
        def t(): ...
    ''')
    assert ep.annotations.destructive.value is True
    assert ep.annotations.destructive.source == DEFAULT


def test_dict_literal_annotations():
    ep = _tool('''
        @mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == EXPLICIT and ep.annotations.read_only.value is True
    assert ep.annotations.open_world.source == EXPLICIT and ep.annotations.open_world.value is False
    assert ep.annotations.destructive.value is False


def test_module_level_constant_reference_resolves():
    ep = _tool('''
        READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

        @mcp.tool(annotations=READ_ONLY)
        def t(): ...
    ''')
    assert not ep.annotations.unresolved_reference
    assert ep.annotations.read_only.value is True
    assert ep.annotations.open_world.value is False


def test_reassigned_constant_is_unresolvable():
    ep = _tool('''
        ANN = ToolAnnotations(readOnlyHint=True)
        ANN = ToolAnnotations(readOnlyHint=False)

        @mcp.tool(annotations=ANN)
        def t(): ...
    ''')
    assert ep.annotations.unresolved_reference


def test_bool_constant_hint_value_resolves():
    ep = _tool('''
        RO = True

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=RO))
        def t(): ...
    ''')
    assert ep.annotations.read_only.value is True
    assert ep.annotations.read_only.source == EXPLICIT


def test_non_literal_read_only_makes_destructive_unresolvable():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=settings.read_only))
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == UNRESOLVABLE
    assert ep.annotations.destructive.source == UNRESOLVABLE
    assert ep.annotations.open_world.source == DEFAULT  # unrelated hints still default


def test_spread_in_tool_annotations_makes_unlisted_hints_unresolvable():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, **extra))
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == EXPLICIT
    assert ep.annotations.open_world.source == UNRESOLVABLE
    assert ep.annotations.destructive.source == UNRESOLVABLE


def test_spread_in_dict_makes_unlisted_hints_unresolvable():
    ep = _tool('''
        @mcp.tool(annotations={**BASE, "openWorldHint": False})
        def t(): ...
    ''')
    assert ep.annotations.open_world.source == EXPLICIT
    assert ep.annotations.read_only.source == UNRESOLVABLE


def test_kwargs_spread_in_decorator_is_unresolvable():
    ep = _tool('''
        @mcp.tool(**tool_options)
        def t(): ...
    ''')
    assert ep.annotations.unresolved_reference
    assert ep.annotations.read_only.source == UNRESOLVABLE


def test_annotations_none_counts_as_undeclared():
    ep = _tool('''
        @mcp.tool(annotations=None)
        def t(): ...
    ''')
    assert not ep.annotations.declared
    assert ep.annotations.destructive.value is True


def test_hint_set_to_none_counts_as_absent():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=None, openWorldHint=None))
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == DEFAULT
    assert ep.annotations.open_world.source == DEFAULT


def test_bare_decorator_without_parentheses():
    ep = _tool('''
        @mcp.tool
        def t(): ...
    ''')
    assert not ep.annotations.declared


def test_fastmcp_v2_import():
    header = 'from fastmcp import FastMCP\nmcp = FastMCP("x")\n'
    ep = _tool('''
        @mcp.tool(name="t", annotations={"readOnlyHint": True})
        async def run(): ...
    ''', header=header)
    assert ep.annotations.read_only.value is True


def test_title_ignored():
    ep = _tool('''
        @mcp.tool(annotations={"title": "Nice"})
        def t(): ...
    ''')
    assert ep.annotations.declared
    assert ep.annotations.read_only.source == DEFAULT


def test_snake_case_hint_is_unresolvable():
    """read_only_hint is honored by MCP SDK 2.x but silently ignored by 1.x."""
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == UNRESOLVABLE
    assert ep.annotations.destructive.source == UNRESOLVABLE  # depends on readOnlyHint
    assert ep.annotations.open_world.source == DEFAULT


def test_snake_case_dict_key_is_unresolvable():
    ep = _tool('''
        @mcp.tool(annotations={"open_world_hint": False})
        def t(): ...
    ''')
    assert ep.annotations.open_world.source == UNRESOLVABLE


def test_camel_case_wins_when_both_spellings_given():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, read_only_hint=True))
        def t(): ...
    ''')
    assert ep.annotations.read_only.source == EXPLICIT


def test_non_mcp_tool_has_no_annotations():
    header = "from langchain_core.tools import tool\n"
    ep = _tool('''
        @tool
        def t(x: str) -> str:
            return x
    ''', header=header)
    assert ep.annotations is None


def test_annotations_in_json_dict_for_mcp_tools():
    ep = _tool('''
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
        def t(): ...
    ''')
    ann = ep.as_dict()["annotations"]
    assert ann["declared"] is True and ann["unresolved_reference"] is False
    assert ann["readOnlyHint"] == {"value": True, "source": "explicit"}
    assert ann["destructiveHint"] == {"value": False, "source": "default"}
    assert "declared_tools" not in ep.as_dict()


def test_non_mcp_entry_point_dict_has_no_annotation_keys():
    header = "from langchain_core.tools import tool\n"
    ep = _tool('''
        @tool
        def t(x: str) -> str:
            return x
    ''', header=header)
    assert "annotations" not in ep.as_dict()
    assert "declared_tools" not in ep.as_dict()


# ---------------------------------------------------------------------------
# Lowlevel server: types.Tool declarations
# ---------------------------------------------------------------------------

LOWLEVEL = '''\
from mcp import types
from mcp.server.lowlevel import Server

app = Server("demo")

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="read_doc",
            description="Read a doc",
            inputSchema={"type": "object"},
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        types.Tool(name="delete_doc", description="Delete", inputSchema={}),
        types.Tool(name=dynamic_name, description="?", inputSchema={}),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    ...
'''


def test_lowlevel_declared_tools_on_list_tools_entry_point():
    eps = {ep.name: ep for ep in detect_py_entry_points("server.py", LOWLEVEL)}
    tools = {t.name: t for t in eps["list_tools"].declared_tools}
    assert set(tools) == {"read_doc", "delete_doc"}  # dynamic name skipped
    read = tools["read_doc"].annotations
    assert read.read_only.value is True and read.read_only.source == EXPLICIT
    assert read.open_world.value is False
    delete = tools["delete_doc"].annotations
    assert not delete.declared
    assert delete.destructive.value is True and delete.destructive.source == DEFAULT
    assert tools["read_doc"].lineno == 9
    assert eps["call_tool"].declared_tools == []


def test_lowlevel_module_level_tool_list_and_direct_imports():
    src = '''\
from mcp.server.lowlevel import Server
from mcp.types import Tool, ToolAnnotations

RO = ToolAnnotations(readOnlyHint=True)
TOOLS = [
    Tool(name="search", description="s", inputSchema={}, annotations=RO),
    Tool(name="fetch", description="f", inputSchema={}, annotations={"openWorldHint": True}),
]
server = Server("x")

@server.list_tools()
async def handle_list():
    return TOOLS
'''
    eps = {ep.name: ep for ep in detect_py_entry_points("server.py", src)}
    tools = {t.name: t.annotations for t in eps["handle_list"].declared_tools}
    assert tools["search"].read_only.value is True
    assert tools["fetch"].open_world.source == EXPLICIT


def test_lowlevel_tool_from_other_module_ignored():
    src = '''\
from mcp.server.lowlevel import Server
from mylib import Tool

server = Server("x")

@server.list_tools()
async def handle_list():
    return [Tool(name="x", annotations={"readOnlyHint": True})]
'''
    eps = {ep.name: ep for ep in detect_py_entry_points("server.py", src)}
    assert eps["handle_list"].declared_tools == []


def test_lowlevel_tool_with_kwargs_spread_is_unresolvable():
    src = '''\
from mcp import types
from mcp.server.lowlevel import Server

server = Server("x")

@server.list_tools()
async def handle_list():
    return [types.Tool(name="x", description="d", inputSchema={}, **extra)]
'''
    eps = {ep.name: ep for ep in detect_py_entry_points("server.py", src)}
    (tool,) = eps["handle_list"].declared_tools
    assert tool.annotations.unresolved_reference


def test_lowlevel_tool_name_from_enum_member():
    src = '''\
from enum import Enum
from mcp.server import Server
from mcp.types import Tool, ToolAnnotations

class GitTools(str, Enum):
    STATUS = "git_status"
    RESET = "git_reset"

def serve():
    server = Server("mcp-git")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name=GitTools.STATUS, description="s", inputSchema={},
                 annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False)),
            Tool(name=GitTools.RESET, description="r", inputSchema={},
                 annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True)),
            Tool(name=Other.MISSING, description="?", inputSchema={}),
        ]
'''
    eps = {ep.name: ep for ep in detect_py_entry_points("server.py", src)}
    tools = {t.name: t.annotations for t in eps["list_tools"].declared_tools}
    assert set(tools) == {"git_status", "git_reset"}
    assert tools["git_status"].read_only.value is True
    assert tools["git_reset"].destructive.value is True
    assert tools["git_reset"].destructive.source == EXPLICIT


# ---------------------------------------------------------------------------
# Cross-file constants (one hop into project files)
# ---------------------------------------------------------------------------

def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def _scan_tools(root):
    from reachscan.py_entry_points import scan_py_files
    return {ep.name: ep for ep in scan_py_files(root) if ep.annotations is not None}


def test_cross_file_constant_resolves(tmp_path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "annotations.py", """
        from mcp import types as mcp_types
        READ_ONLY = mcp_types.ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    """)
    _write(tmp_path / "pkg" / "server.py", """
        from mcp.server.fastmcp import FastMCP
        from pkg.annotations import READ_ONLY
        mcp = FastMCP("x")

        @mcp.tool(annotations=READ_ONLY)
        def t(): ...
    """)
    ann = _scan_tools(tmp_path)["t"].annotations
    assert not ann.unresolved_reference
    assert ann.read_only.value is True and ann.read_only.source == EXPLICIT
    assert ann.open_world.value is False


def test_cross_file_relative_import_resolves(tmp_path):
    _write(tmp_path / "srv" / "__init__.py", "")
    _write(tmp_path / "srv" / "shared.py", 'MUTATE = {"readOnlyHint": False, "destructiveHint": False}\n')
    _write(tmp_path / "srv" / "tools.py", """
        from mcp.server.fastmcp import FastMCP
        from .shared import MUTATE
        mcp = FastMCP("x")

        @mcp.tool(annotations=MUTATE)
        def t(): ...
    """)
    ann = _scan_tools(tmp_path)["t"].annotations
    assert ann.destructive.value is False and ann.destructive.source == EXPLICIT


def test_cross_file_stops_after_one_hop(tmp_path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "base.py", "from mcp.types import ToolAnnotations\nRO = ToolAnnotations(readOnlyHint=True)\n")
    _write(tmp_path / "pkg" / "mid.py", "from pkg.base import RO\nALIAS = RO\n")
    _write(tmp_path / "pkg" / "server.py", """
        from mcp.server.fastmcp import FastMCP
        from pkg.mid import ALIAS
        mcp = FastMCP("x")

        @mcp.tool(annotations=ALIAS)
        def t(): ...
    """)
    ann = _scan_tools(tmp_path)["t"].annotations
    assert ann.unresolved_reference
    assert ann.read_only.source == UNRESOLVABLE


def test_cross_file_import_from_outside_project_is_unresolvable(tmp_path):
    _write(tmp_path / "server.py", """
        from mcp.server.fastmcp import FastMCP
        from some_installed_lib.presets import READ_ONLY
        mcp = FastMCP("x")

        @mcp.tool(annotations=READ_ONLY)
        def t(): ...
    """)
    ann = _scan_tools(tmp_path)["t"].annotations
    assert ann.unresolved_reference
