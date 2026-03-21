"""Tests for Python entry point detection."""

import pytest
from pathlib import Path
from reachscan.py_entry_points import (
    detect_py_entry_points,
    scan_py_files,
    _is_excluded_py_file,
    _decorator_key,
    _resolve_framework,
    FRAMEWORK_MCP,
    FRAMEWORK_LANGCHAIN,
    FRAMEWORK_CREWAI,
    FRAMEWORK_PYDANTIC_AI,
    FRAMEWORK_STRANDS,
    FRAMEWORK_HAYSTACK,
    FRAMEWORK_AGNO,
    FRAMEWORK_METAGPT,
    FRAMEWORK_MARVIN,
    FRAMEWORK_AGENCY_SWARM,
    FRAMEWORK_SMOLAGENTS,
    FRAMEWORK_LLAMAINDEX,
    FRAMEWORK_DSPY,
    FRAMEWORK_GOOGLE_ADK,
    FRAMEWORK_SWARM,
    FRAMEWORK_CAMEL,
    FRAMEWORK_UNKNOWN,
    PATTERN_DECORATOR,
    PATTERN_CLASS_ATTRIBUTE,
    PATTERN_REGISTRATION_CALL,
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

    Framework resolves to pydantic_ai at confidence 0.80 because the file imports
    Agent from pydantic_ai, and 'agent' (lowercase) is inferred to be an instance
    of that class via the title-case lookup in _resolve_framework step 1.5.
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
    assert r.framework == FRAMEWORK_PYDANTIC_AI  # inferred from Agent import via title-case lookup
    assert r.confidence == 0.80
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
    # 'agent' (lowercase) is inferred as an instance of Agent imported from pydantic_ai
    # via the title-case lookup in _resolve_framework step 1.5 → confidence 0.80.
    assert all(r.framework == FRAMEWORK_PYDANTIC_AI for r in results)
    assert all(r.confidence == 0.80 for r in results)


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
# MCP low-level server API: @app.call_tool() / @app.list_tools()
# ---------------------------------------------------------------------------

def test_mcp_lowlevel_call_tool():
    """@app.call_tool() dispatch handler is detected as an MCP entry point."""
    content = '''\
from mcp.server.lowlevel import Server
app = Server(name="markitdown-mcp", version="0.1.0")

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "convert":
        return await convert(arguments["uri"])
    raise ValueError(f"Unknown tool: {name}")
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    ep = results[0]
    assert ep.name == "call_tool"
    assert ep.framework == "mcp"
    assert ep.pattern_type == "decorator"


def test_mcp_lowlevel_list_tools():
    """@app.list_tools() handler is detected as an MCP entry point."""
    content = '''\
from mcp.server.lowlevel import Server
app = Server(name="my-server", version="1.0.0")

@app.list_tools()
async def list_tools():
    return [{"name": "convert", "description": "..."}]
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 1
    ep = results[0]
    assert ep.name == "list_tools"
    assert ep.framework == "mcp"


def test_mcp_lowlevel_both_handlers():
    """Both @app.call_tool() and @app.list_tools() in same file → 2 entry points."""
    content = '''\
from mcp.server.lowlevel import Server
app = Server(name="svc", version="0.1.0")

@app.list_tools()
async def list_tools():
    return []

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    pass
'''
    results = detect_py_entry_points("server.py", content)
    assert len(results) == 2
    names = {ep.name for ep in results}
    assert names == {"list_tools", "call_tool"}


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


def test_no_fp_nested_function_in_method():
    """SDK-internal pattern: @function_tool on a closure inside a method body.

    Mirrors openai-agents Agent.as_tool() which defines:
        @function_tool(name_override=..., description_override=...)
        async def run_agent(context, input): ...
    inside the method body and returns it.  This is an internal SDK
    implementation detail, not a user-defined entry point.
    """
    content = '''\
from agents.tool import function_tool

class Agent:
    def as_tool(self, tool_name=None, tool_description=None):
        @function_tool(name_override=tool_name, description_override=tool_description or "")
        async def run_agent(context, input: str) -> str:
            return ""

        return run_agent
'''
    results = detect_py_entry_points("agent.py", content)
    assert results == [], f"Expected no entry points, got: {results}"


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
    from reachscan.py_entry_points import FRAMEWORK_OPENAI_AGENTS
    assert fw == FRAMEWORK_OPENAI_AGENTS
    assert conf == 0.60


def test_resolve_framework_step7_fallback():
    """Step 7: key unknown, no import, no hint → 0.60, FRAMEWORK_UNKNOWN."""
    fw, conf = _resolve_framework("totally_unknown_decorator", "some_obj", {})
    assert fw == FRAMEWORK_UNKNOWN
    assert conf == 0.60


# ---------------------------------------------------------------------------
# AWS Strands Agents — @tool decorator
# ---------------------------------------------------------------------------

def test_strands_tool_decorator():
    content = '''\
from strands import Agent, tool

@tool
def my_tool(param1: str) -> dict:
    """Tool description."""
    return {"result": param1}
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "my_tool"
    assert results[0].framework == FRAMEWORK_STRANDS
    assert results[0].confidence == 0.95


def test_strands_tool_from_strands_tools():
    content = '''\
from strands_tools import tool

@tool
def search(query: str) -> str:
    """Search."""
    return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].framework == FRAMEWORK_STRANDS
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# Haystack — @tool decorator
# ---------------------------------------------------------------------------

def test_haystack_tool_decorator():
    content = '''\
from haystack.tools import tool

@tool
def weather(city: str) -> str:
    """Get weather for a city."""
    return f"Sunny in {city}"
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "weather"
    assert results[0].framework == FRAMEWORK_HAYSTACK
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# Agno / Phidata — @tool decorator and Toolkit base class
# ---------------------------------------------------------------------------

def test_agno_tool_decorator():
    content = '''\
from agno.tools import tool

@tool
def search(query: str) -> str:
    """Search the web."""
    return "results"
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "search"
    assert results[0].framework == FRAMEWORK_AGNO
    assert results[0].confidence == 0.95


def test_phidata_tool_decorator():
    """Phidata (old name for Agno) resolves to agno framework."""
    content = '''\
from phi.tools import tool

@tool
def calculator(expression: str) -> str:
    """Evaluate expression."""
    return str(eval(expression))
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].framework == FRAMEWORK_AGNO
    assert results[0].confidence == 0.95


def test_agno_toolkit_base_class():
    content = '''\
from agno.tools import Toolkit

class WebSearchToolkit(Toolkit):
    name = "web_search"
    description = "Search the web"

    def _run(self, query: str) -> str:
        return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "web_search"
    assert results[0].framework == FRAMEWORK_AGNO
    assert results[0].pattern_type == PATTERN_CLASS_ATTRIBUTE
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# MetaGPT — @register_tool decorator
# ---------------------------------------------------------------------------

def test_metagpt_register_tool():
    content = '''\
from metagpt.tools.tool_registry import register_tool

@register_tool(tags=["math"])
class Calculator:
    """A calculator tool."""
    name = "calculator"

    def add(self, a: int, b: int) -> int:
        return a + b
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "calculator"
    assert results[0].framework == FRAMEWORK_METAGPT
    assert results[0].confidence == 0.95


def test_metagpt_register_tool_on_function():
    content = '''\
from metagpt.tools.tool_registry import register_tool

@register_tool()
def web_scraper(url: str) -> str:
    """Scrape a web page."""
    return ""
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "web_scraper"
    assert results[0].framework == FRAMEWORK_METAGPT


# ---------------------------------------------------------------------------
# Marvin — @marvin.fn and @ai_model decorators
# ---------------------------------------------------------------------------

def test_marvin_fn_decorator():
    content = '''\
import marvin

@marvin.fn
def sentiment(text: str) -> float:
    """Return sentiment score from -1 to 1."""
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "sentiment"
    assert results[0].framework == FRAMEWORK_MARVIN
    assert results[0].confidence == 0.95


def test_marvin_ai_model_decorator():
    content = '''\
from marvin import ai_model

@ai_model
class Location:
    city: str
    state: str
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "Location"  # class name used when no name attr
    assert results[0].framework == FRAMEWORK_MARVIN
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# Agency Swarm — @function_tool and BaseTool
# ---------------------------------------------------------------------------

def test_agency_swarm_function_tool():
    content = '''\
from agency_swarm import function_tool

@function_tool
def my_tool(param: str) -> str:
    """Tool description."""
    return param
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "my_tool"
    assert results[0].framework == FRAMEWORK_AGENCY_SWARM
    assert results[0].confidence == 0.95


def test_agency_swarm_base_tool():
    content = '''\
from agency_swarm.tools import BaseTool

class FileReader(BaseTool):
    name = "file_reader"
    description = "Reads files"

    def _run(self, path: str) -> str:
        return ""
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "file_reader"
    assert results[0].framework == FRAMEWORK_AGENCY_SWARM
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# smolagents — @tool decorator with module attribution
# ---------------------------------------------------------------------------

def test_smolagents_tool_decorator():
    content = '''\
from smolagents import tool

@tool
def web_search(query: str) -> str:
    """Search the web."""
    return query
'''
    results = detect_py_entry_points("tools.py", content)
    assert len(results) == 1
    assert results[0].name == "web_search"
    assert results[0].framework == FRAMEWORK_SMOLAGENTS
    assert results[0].confidence == 0.95


# ---------------------------------------------------------------------------
# Pattern 3: Factory / Constructor Call Detection
# ---------------------------------------------------------------------------

# --- LlamaIndex ---

class TestLlamaIndexFactory:
    def test_function_tool_from_defaults_fn_kwarg(self):
        content = '''\
from llama_index.core.tools import FunctionTool

def my_search(query: str) -> str:
    return query

tool = FunctionTool.from_defaults(fn=my_search, description="Search")
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        r = results[0]
        assert r.name == "my_search"
        assert r.framework == FRAMEWORK_LLAMAINDEX
        assert r.pattern_type == PATTERN_REGISTRATION_CALL
        assert r.confidence == 0.95
        assert r.lineno == 3  # points to the function def, not the call

    def test_function_tool_from_defaults_positional(self):
        content = '''\
from llama_index.core.tools import FunctionTool

def add(a: int, b: int) -> int:
    return a + b

tool = FunctionTool.from_defaults(add)
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "add"
        assert results[0].framework == FRAMEWORK_LLAMAINDEX

    def test_function_tool_from_defaults_explicit_name(self):
        content = '''\
from llama_index.core.tools import FunctionTool

def my_func():
    pass

tool = FunctionTool.from_defaults(fn=my_func, name="search_tool")
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "search_tool"

    def test_query_engine_tool_with_name(self):
        content = '''\
from llama_index.core.tools import QueryEngineTool

tool = QueryEngineTool.from_defaults(query_engine=engine, name="query_docs")
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "query_docs"
        assert results[0].framework == FRAMEWORK_LLAMAINDEX
        assert results[0].pattern_type == PATTERN_REGISTRATION_CALL

    def test_multiple_tools(self):
        content = '''\
from llama_index.core.tools import FunctionTool

def search(q: str) -> str:
    return q

def summarize(text: str) -> str:
    return text

search_tool = FunctionTool.from_defaults(fn=search)
summarize_tool = FunctionTool.from_defaults(fn=summarize)
'''
        results = detect_py_entry_points("tools.py", content)
        names = [r.name for r in results]
        assert "search" in names
        assert "summarize" in names
        assert len(results) == 2

    def test_no_match_without_import(self):
        """FunctionTool.from_defaults without llama_index import should not match."""
        content = '''\
def my_func():
    pass

tool = FunctionTool.from_defaults(fn=my_func)
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 0


# --- DSPy ---

class TestDSPyFactory:
    def test_dspy_tool_positional(self):
        content = '''\
import dspy

def search(query: str) -> str:
    return query

tool = dspy.Tool(search, name="search")
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        r = results[0]
        assert r.name == "search"
        assert r.framework == FRAMEWORK_DSPY
        assert r.pattern_type == PATTERN_REGISTRATION_CALL
        assert r.confidence == 0.95

    def test_dspy_tool_bare_import(self):
        content = '''\
from dspy import Tool

def my_func():
    pass

tool = Tool(my_func, name="my_tool")
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "my_tool"
        assert results[0].framework == FRAMEWORK_DSPY

    def test_dspy_tool_no_name(self):
        """Without name= kwarg, falls back to function reference name."""
        content = '''\
from dspy import Tool

def calculator(expr: str) -> str:
    return expr

tool = Tool(calculator)
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "calculator"


# --- OpenAI Swarm ---

class TestOpenAISwarmFactory:
    def test_agent_functions_list(self):
        content = '''\
from swarm import Agent

def get_weather(location: str) -> str:
    return "sunny"

def send_email(to: str, body: str) -> str:
    return "sent"

agent = Agent(name="helper", functions=[get_weather, send_email])
'''
        results = detect_py_entry_points("tools.py", content)
        names = [r.name for r in results]
        assert "get_weather" in names
        assert "send_email" in names
        assert len(results) == 2
        for r in results:
            assert r.framework == FRAMEWORK_SWARM
            assert r.pattern_type == PATTERN_REGISTRATION_CALL
            assert r.confidence == 0.95

    def test_agent_functions_single(self):
        content = '''\
from swarm import Agent

def my_tool():
    pass

agent = Agent(functions=[my_tool])
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "my_tool"

    def test_no_match_without_swarm_import(self):
        """Agent(functions=[...]) without swarm import should not match."""
        content = '''\
def my_func():
    pass

agent = Agent(functions=[my_func])
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 0

    def test_lineno_points_to_func_def(self):
        content = '''\
from swarm import Agent

def helper_func():
    pass

agent = Agent(functions=[helper_func])
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].lineno == 3  # function def line, not Agent() call line


# --- Google ADK ---

class TestGoogleADKFactory:
    def test_agent_tools_list(self):
        content = '''\
from google.adk import Agent

def search_web(query: str) -> str:
    return query

def get_time() -> str:
    return "now"

agent = Agent(tools=[search_web, get_time])
'''
        results = detect_py_entry_points("tools.py", content)
        names = [r.name for r in results]
        assert "search_web" in names
        assert "get_time" in names
        assert len(results) == 2
        for r in results:
            assert r.framework == FRAMEWORK_GOOGLE_ADK
            assert r.pattern_type == PATTERN_REGISTRATION_CALL

    def test_google_adk_alt_import(self):
        content = '''\
from google_adk import Agent

def my_tool():
    pass

a = Agent(tools=[my_tool])
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].framework == FRAMEWORK_GOOGLE_ADK

    def test_no_false_positive_pydantic_agent(self):
        """Agent(tools=[...]) from pydantic_ai should NOT match as Google ADK."""
        content = '''\
from pydantic_ai import Agent

def my_tool():
    pass

agent = Agent(tools=[my_tool])
'''
        results = detect_py_entry_points("tools.py", content)
        # Should not produce Pattern 3 results (pydantic_ai Agent is not Google ADK)
        factory_results = [r for r in results if r.pattern_type == PATTERN_REGISTRATION_CALL]
        assert len(factory_results) == 0


# --- CAMEL AI ---

class TestCamelAIFactory:
    def test_function_tool_positional(self):
        content = '''\
from camel.toolkits import FunctionTool

def my_func(x: str) -> str:
    return x

tool = FunctionTool(my_func)
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        r = results[0]
        assert r.name == "my_func"
        assert r.framework == FRAMEWORK_CAMEL
        assert r.pattern_type == PATTERN_REGISTRATION_CALL
        assert r.confidence == 0.95

    def test_multiple_function_tools_in_list(self):
        content = '''\
from camel.toolkits import FunctionTool

def search(q: str) -> str:
    return q

def write(text: str) -> str:
    return text

tools = [FunctionTool(search), FunctionTool(write)]
'''
        results = detect_py_entry_points("tools.py", content)
        names = [r.name for r in results]
        assert "search" in names
        assert "write" in names
        assert len(results) == 2


# --- Edge cases ---

class TestFactoryEdgeCases:
    def test_no_duplicate_with_decorator(self):
        """If a function is both decorated and registered via factory, dedup collapses them."""
        content = '''\
from llama_index.core.tools import FunctionTool
from langchain_core.tools import tool

@tool
def my_search(q: str) -> str:
    return q

t = FunctionTool.from_defaults(fn=my_search)
'''
        results = detect_py_entry_points("tools.py", content)
        # Dedup by (lineno, name) — both point to my_search at line 5
        assert len(results) == 1
        assert results[0].name == "my_search"

    def test_factory_inside_function_not_detected(self):
        """Factory calls inside function bodies should not be detected (module-level only)."""
        content = '''\
from llama_index.core.tools import FunctionTool

def my_func():
    pass

def setup():
    tool = FunctionTool.from_defaults(fn=my_func)
    return tool
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 0

    def test_expr_statement_factory(self):
        """Factory call as bare expression (no assignment)."""
        content = '''\
from dspy import Tool

def my_func():
    pass

Tool(my_func)
'''
        results = detect_py_entry_points("tools.py", content)
        assert len(results) == 1
        assert results[0].name == "my_func"
