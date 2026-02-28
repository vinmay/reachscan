"""Tests for Python entry point detection."""

import pytest
from pathlib import Path
from agent_scan.py_entry_points import (
    detect_py_entry_points,
    scan_py_files,
    _is_excluded_py_file,
    _decorator_key,
    _resolve_framework,
    FRAMEWORK_MCP,
    FRAMEWORK_LANGCHAIN,
    FRAMEWORK_CREWAI,
    FRAMEWORK_PYDANTIC_AI,
    FRAMEWORK_UNKNOWN,
    PATTERN_DECORATOR,
    PATTERN_CLASS_ATTRIBUTE,
)


# ---------------------------------------------------------------------------
# MCP @mcp.tool() — Pattern 1: attribute call
# ---------------------------------------------------------------------------

def test_mcp_tool_decorator_bare():
    content = '''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("server")

@mcp.tool()
async def read_documentation(url: str) -> str:
    """Fetch documentation."""
    return url
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "read_documentation"
    assert r.framework == FRAMEWORK_MCP
    assert r.pattern_type == PATTERN_DECORATOR
    assert r.lineno == 5  # lineno of the def statement, not the decorator


def test_mcp_tool_decorator_explicit_name():
    content = '''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("server")

@mcp.tool(name="run_query", description="Run SQL")
async def run_query(sql: str) -> list:
    return []
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    assert results[0].name == "run_query"
    assert results[0].framework == FRAMEWORK_MCP


def test_mcp_tool_decorator_multiple():
    content = '''\
from mcp.server.fastmcp import FastMCP, Context
mcp = FastMCP("server")

@mcp.tool()
async def tool_one(x: str) -> str:
    return x

@mcp.tool()
async def tool_two(y: str) -> str:
    return y

@mcp.tool(name="explicit_three")
async def tool_three(z: str) -> str:
    return z
'''
    results = detect_py_entry_points("server.py", content)
    names = [r.name for r in results]
    assert names == ["tool_one", "tool_two", "explicit_three"]
    assert all(r.framework == FRAMEWORK_MCP for r in results)


def test_mcp_tool_any_variable_name():
    """Variable before .tool() doesn't have to be named 'mcp'."""
    content = '''\
from mcp.server.fastmcp import FastMCP
server = FastMCP("server")

@server.tool()
async def my_tool() -> str:
    return "ok"
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    assert results[0].name == "my_tool"
    assert results[0].framework == FRAMEWORK_MCP


def test_mcp_tool_imported_from_submodule():
    """mcp object imported from a project-local shared module (common in monorepos)."""
    content = '''\
from awslabs.valkey_mcp_server.common.server import mcp

@mcp.tool()
async def string_set(key: str) -> str:
    return key
'''
    results = detect_py_entry_points("tools/string.py", content)
    assert len(results) == 1
    assert results[0].name == "string_set"
    # Variable name 'mcp' triggers MCP heuristic even without direct mcp import
    assert results[0].framework == FRAMEWORK_MCP


def test_mcp_tool_sync_function():
    """Sync (non-async) functions with @mcp.tool() are also entry points."""
    content = '''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("s")

@mcp.tool()
def get_status() -> str:
    return "ok"
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    assert results[0].name == "get_status"


# ---------------------------------------------------------------------------
# @tool bare / @tool("Name") — Pattern 2 & 3
# ---------------------------------------------------------------------------

def test_langchain_bare_tool():
    content = '''\
from langchain_core.tools import tool

@tool
def web_search(query: str) -> str:
    """Search the web."""
    return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "web_search"
    assert r.framework == FRAMEWORK_LANGCHAIN
    assert r.pattern_type == PATTERN_DECORATOR


def test_crewai_tool_with_name_arg():
    content = '''\
from crewai.tools import tool

@tool("Name of my tool")
def my_tool(question: str) -> str:
    """Tool description."""
    return question
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "Name of my tool"
    assert r.framework == FRAMEWORK_CREWAI


def test_tool_with_name_kwarg():
    content = '''\
from langchain_core.tools import tool

@tool(name="custom_name", description="does something")
def my_func(x: str) -> str:
    return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "custom_name"


def test_tool_framework_prefers_origin_over_flags():
    """When 'tool' is imported from crewai, use crewai even if langchain also imported."""
    content = '''\
from crewai.tools import tool
from langchain_core.tools import BaseTool

@tool("crew_tool")
def my_crew_tool(q: str) -> str:
    return q
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].framework == FRAMEWORK_CREWAI


def test_bare_tool_unknown_framework():
    """@tool with no recognizable import is marked unknown but still detected."""
    content = '''\
from some_custom_framework import tool

@tool
def my_function(x: str) -> str:
    return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "my_function"
    assert results[0].framework == FRAMEWORK_UNKNOWN


# ---------------------------------------------------------------------------
# @agent.tool / @agent.tool_plain — Pattern 4: plain attribute
# ---------------------------------------------------------------------------

def test_pydantic_ai_agent_tool():
    """@agent.tool is detected via the 'tool' pattern.

    Framework resolves to 'langchain_or_crewai' (the ENTRY_POINT_DECORATORS default for 'tool')
    at confidence 0.60 because 'agent' is a local variable, not a direct import — the
    receiver name alone is insufficient to prove pydantic_ai vs LangChain/CrewAI.
    """
    content = '''\
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o")

@agent.tool
def get_weather(ctx: RunContext, city: str) -> str:
    return f"Weather in {city}"
'''
    results = detect_py_entry_points("agent.py", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "get_weather"
    assert r.framework == "langchain_or_crewai"  # 'tool' default; receiver 'agent' not in imports
    assert r.confidence == 0.60
    assert r.pattern_type == PATTERN_DECORATOR


def test_pydantic_ai_tool_plain():
    content = '''\
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
async def web_search(query: str) -> str:
    return query

@agent.tool_plain
def delete_file(path: str) -> str:
    return path
'''
    results = detect_py_entry_points("agent.py", content)
    names = [r.name for r in results]
    assert "web_search" in names
    assert "delete_file" in names
    # 'tool_plain' maps to FRAMEWORK_PYDANTIC_AI in ENTRY_POINT_DECORATORS (confidence 0.60
    # because receiver 'agent' is a local variable, not imported from pydantic_ai directly).
    assert all(r.framework == FRAMEWORK_PYDANTIC_AI for r in results)
    assert all(r.confidence == 0.60 for r in results)


def test_pydantic_ai_mixed_tool_and_tool_plain():
    content = '''\
from pydantic_ai import Agent

agent = Agent("claude-3-5-sonnet")

@agent.tool
def lookup(ctx, q: str) -> str:
    return q

@agent.tool_plain
def calculate(x: int) -> int:
    return x * 2
'''
    results = detect_py_entry_points("agent.py", content)
    assert len(results) == 2


# ---------------------------------------------------------------------------
# class X(BaseTool) — Pattern: class attribute
# ---------------------------------------------------------------------------

def test_base_tool_class_plain_assignment():
    content = '''\
from crewai.tools import BaseTool

class MyCustomTool(BaseTool):
    name: str = "Name of my tool"
    description: str = "Clear description."

    def _run(self, question: str) -> str:
        return question
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "Name of my tool"
    assert r.framework == FRAMEWORK_CREWAI
    assert r.pattern_type == PATTERN_CLASS_ATTRIBUTE
    assert r.lineno == 3


def test_base_tool_class_unannotated_assignment():
    content = '''\
from langchain_core.tools import BaseTool

class SearchTool(BaseTool):
    name = "web_search"
    description = "Searches the web."

    def _run(self, query: str) -> str:
        return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "web_search"
    assert results[0].framework == FRAMEWORK_LANGCHAIN


def test_base_tool_class_no_static_name_skipped():
    """BaseTool subclass where name is dynamic is not emitted."""
    content = '''\
from langchain_core.tools import BaseTool

class DynamicTool(BaseTool):
    description = "Something."

    def __init__(self, tool_name: str):
        self.name = tool_name

    def _run(self, x: str) -> str:
        return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert results == []


def test_base_tool_class_autogen_style():
    """AutoGen BaseTool[Input, Output] pattern."""
    content = '''\
from autogen_core.tools import BaseTool
from pydantic import BaseModel

class ScheduleMeetingTool(BaseTool):
    name = "schedule_meeting"
    description = "Schedule a meeting."

    async def run(self, args, token):
        pass
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "schedule_meeting"


# ---------------------------------------------------------------------------
# No false positives
# ---------------------------------------------------------------------------

def test_no_fp_plain_function():
    content = '''\
def process_data(x: str) -> str:
    return x.upper()

async def fetch_url(url: str) -> bytes:
    return b""
'''
    results = detect_py_entry_points("utils.py", content)
    assert results == []


def test_no_fp_unrelated_decorator():
    content = '''\
import functools

@functools.lru_cache(maxsize=128)
def expensive(x: int) -> int:
    return x * x

@staticmethod
def helper(y: str) -> str:
    return y
'''
    results = detect_py_entry_points("utils.py", content)
    assert results == []


def test_no_fp_class_not_inheriting_base_tool():
    content = '''\
class MyModel:
    name = "my_model"
    description = "A regular class."
'''
    results = detect_py_entry_points("models.py", content)
    assert results == []


def test_no_fp_tool_variable_not_decorator():
    """tool used as a variable, not as a decorator."""
    content = '''\
from langchain_core.tools import tool, BaseTool

my_tool = tool(some_function)  # not a decorator
'''
    results = detect_py_entry_points("tools.py", content)
    assert results == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_no_duplicate_findings():
    """Same function with one tool decorator emits exactly one entry point."""
    content = '''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("s")

@mcp.tool()
async def my_tool() -> str:
    return "ok"
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

def test_test_file_excluded():
    assert _is_excluded_py_file(Path("tests/test_tools.py")) is True
    assert _is_excluded_py_file(Path("src/tools_test.py")) is True
    assert _is_excluded_py_file(Path("src/test_tools.py")) is True


def test_normal_file_not_excluded():
    assert _is_excluded_py_file(Path("src/tools.py")) is False
    assert _is_excluded_py_file(Path("agent/server.py")) is False


def test_venv_excluded():
    assert _is_excluded_py_file(Path(".venv/lib/python3.11/site-packages/mcp/server.py")) is True


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def test_scan_py_files_finds_tools(tmp_path):
    f = tmp_path / "src" / "tools.py"
    f.parent.mkdir(parents=True)
    f.write_text('''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("s")

@mcp.tool()
async def get_data() -> str:
    return "data"

@mcp.tool()
async def set_data(val: str) -> None:
    pass
''')
    results = scan_py_files(tmp_path)
    names = {r.name for r in results}
    assert names == {"get_data", "set_data"}


def test_scan_py_files_skips_tests(tmp_path):
    test_file = tmp_path / "tests" / "test_tools.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text('''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("s")

@mcp.tool()
async def should_not_appear() -> str:
    return "nope"
''')
    src_file = tmp_path / "src" / "tools.py"
    src_file.parent.mkdir(parents=True)
    src_file.write_text('''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("s")

@mcp.tool()
async def real_tool() -> str:
    return "yes"
''')
    results = scan_py_files(tmp_path)
    names = {r.name for r in results}
    assert "real_tool" in names
    assert "should_not_appear" not in names


def test_scan_single_py_file(tmp_path):
    f = tmp_path / "server.py"
    f.write_text('''\
from pydantic_ai import Agent
agent = Agent("gpt-4o")

@agent.tool
def lookup(ctx, q: str) -> str:
    return q
''')
    results = scan_py_files(f)
    assert len(results) == 1
    assert results[0].name == "lookup"


def test_scan_py_files_empty_dir(tmp_path):
    results = scan_py_files(tmp_path)
    assert results == []


# ---------------------------------------------------------------------------
# Confidence levels (0.95 / 0.70 / 0.60)
# ---------------------------------------------------------------------------

def test_confidence_095_known_import():
    """Decorator resolved to a known framework import → confidence 0.95."""
    content = '''\
from langchain_core.tools import tool

@tool
def web_search(query: str) -> str:
    return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.95
    assert results[0].framework == FRAMEWORK_LANGCHAIN


def test_confidence_095_receiver_known_import():
    """@mcp.tool() where 'mcp' is directly imported from mcp.* → 0.95.

    Note: `mcp = FastMCP(...)` (variable assignment) is NOT in the imports dict,
    so the common FastMCP pattern yields 0.60 via the receiver-name hint instead.
    This test uses `import mcp` so the receiver IS a known import.
    """
    content = '''\
import mcp

@mcp.tool()
async def fetch(url: str) -> str:
    return url
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.95
    assert results[0].framework == FRAMEWORK_MCP


def test_confidence_070_import_unknown_module():
    """Decorator found in imports but module not in KNOWN_FRAMEWORK_MODULES → 0.70."""
    content = '''\
from my_custom_sdk.tools import tool

@tool
def my_func(x: str) -> str:
    return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.70
    assert results[0].framework == FRAMEWORK_UNKNOWN


def test_confidence_070_receiver_mcp_hint_with_import():
    """mcp object imported from project-local module (not mcp.*) → 0.70, framework=mcp."""
    content = '''\
from my_project.common.server import mcp

@mcp.tool()
async def list_items() -> list:
    return []
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.70
    assert results[0].framework == FRAMEWORK_MCP


def test_confidence_060_no_import():
    """Decorator name in ENTRY_POINT_DECORATORS but no import at all → 0.60."""
    content = '''\
@tool
def standalone(x: str) -> str:
    return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.60


def test_confidence_060_mcp_receiver_hint_no_import():
    """@mcp.tool() where 'mcp' is never imported → 0.60, framework=mcp (receiver hint)."""
    content = '''\
@mcp.tool()
async def get_data() -> str:
    return "data"
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.60
    assert results[0].framework == FRAMEWORK_MCP


def test_confidence_095_base_class_known_import():
    """BaseTool subclass with import from crewai → confidence 0.95."""
    content = '''\
from crewai.tools import BaseTool

class MyTool(BaseTool):
    name = "my_tool"
    description = "does stuff"

    def _run(self, x: str) -> str:
        return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.95
    assert results[0].framework == FRAMEWORK_CREWAI


def test_confidence_060_base_class_no_import():
    """BaseTool subclass with no import → confidence 0.60."""
    content = '''\
class InlineWorker(BaseTool):
    name = "inline_worker"
    description = "ad-hoc"

    def _run(self, x: str) -> str:
        return x
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].confidence == 0.60


# ---------------------------------------------------------------------------
# _decorator_key internals
# ---------------------------------------------------------------------------

import ast as _ast


def _parse_decorator(src: str):
    """Parse the first decorator from a minimal function definition."""
    wrapped = f"{src}\ndef f(): pass"
    tree = _ast.parse(wrapped)
    func = tree.body[0]
    return func.decorator_list[0]


def test_decorator_key_bare_name():
    node = _parse_decorator("@tool")
    key, receiver = _decorator_key(node)
    assert key == "tool"
    assert receiver is None


def test_decorator_key_bare_call():
    node = _parse_decorator("@tool()")
    key, receiver = _decorator_key(node)
    assert key == "tool"
    assert receiver is None


def test_decorator_key_call_with_arg():
    node = _parse_decorator('@tool("my name")')
    key, receiver = _decorator_key(node)
    assert key == "tool"
    assert receiver is None


def test_decorator_key_attribute_call():
    node = _parse_decorator("@mcp.tool()")
    key, receiver = _decorator_key(node)
    assert key == "tool"
    assert receiver == "mcp"


def test_decorator_key_attribute_bare():
    node = _parse_decorator("@agent.tool")
    key, receiver = _decorator_key(node)
    assert key == "tool"
    assert receiver == "agent"


def test_decorator_key_three_level_skipped():
    """@pytest.mark.tool (three-level) returns (None, None) to avoid false positives."""
    node = _parse_decorator("@pytest.mark.tool")
    key, receiver = _decorator_key(node)
    assert key is None
    assert receiver is None


def test_decorator_key_three_level_call_skipped():
    node = _parse_decorator("@a.b.c()")
    key, receiver = _decorator_key(node)
    assert key is None
    assert receiver is None


# ---------------------------------------------------------------------------
# _resolve_framework internals
# ---------------------------------------------------------------------------

def test_resolve_framework_step1_receiver_known():
    """Step 1: receiver in imports, module known → 0.95."""
    imports = {"mcp": "mcp.server.fastmcp"}
    fw, conf = _resolve_framework("tool", "mcp", imports)
    assert fw == FRAMEWORK_MCP
    assert conf == 0.95


def test_resolve_framework_step2_key_known():
    """Step 2: bare key in imports, module known → 0.95."""
    imports = {"tool": "langchain_core.tools"}
    fw, conf = _resolve_framework("tool", None, imports)
    assert fw == FRAMEWORK_LANGCHAIN
    assert conf == 0.95


def test_resolve_framework_step3_receiver_mcp_hint():
    """Step 3: receiver in imports but module unknown; name is MCP hint → 0.70, mcp."""
    imports = {"mcp": "my_project.server"}
    fw, conf = _resolve_framework("tool", "mcp", imports)
    assert fw == FRAMEWORK_MCP
    assert conf == 0.70


def test_resolve_framework_step4_key_import_unknown_module():
    """Step 4: key in imports, module not in KNOWN_FRAMEWORK_MODULES → 0.70, unknown."""
    imports = {"tool": "my_custom_sdk.tools"}
    fw, conf = _resolve_framework("tool", None, imports)
    assert fw == FRAMEWORK_UNKNOWN
    assert conf == 0.70


def test_resolve_framework_step5_receiver_hint_no_import():
    """Step 5: not imported; receiver name in _MCP_RECEIVER_HINTS → 0.60, mcp."""
    fw, conf = _resolve_framework("tool", "server", {})
    assert fw == FRAMEWORK_MCP
    assert conf == 0.60


def test_resolve_framework_step6_key_in_decorators():
    """Step 6: key in ENTRY_POINT_DECORATORS, no import, no hint → 0.60, dict default."""
    fw, conf = _resolve_framework("function_tool", None, {})
    from agent_scan.py_entry_points import FRAMEWORK_OPENAI_AGENTS
    assert fw == FRAMEWORK_OPENAI_AGENTS
    assert conf == 0.60


def test_resolve_framework_step7_fallback():
    """Step 7: key unknown, no import, no hint → 0.60, FRAMEWORK_UNKNOWN."""
    fw, conf = _resolve_framework("totally_unknown_decorator", "some_obj", {})
    assert fw == FRAMEWORK_UNKNOWN
    assert conf == 0.60
