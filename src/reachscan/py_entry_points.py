"""
Python agent entry point data model and detector.

Detects functions exposed to LLMs in Python source files using AST analysis.
Detection is data-driven against four structural patterns — framework labels
are metadata for reporting only and do not drive detection logic.

The four patterns (all known frameworks reduce to one of these):

  Pattern 1 — Decorator on a function:
      @tool                  LangChain, CrewAI, smolagents, Strands, Haystack, Agno
      @function_tool         OpenAI Agents, Agency Swarm
      @agent.tool            Pydantic AI
      @mcp.tool()            MCP Python SDK / FastMCP
      @kernel_function()     Semantic Kernel
      @register_for_llm()    AutoGen
      @register_tool()       MetaGPT
      @marvin.fn             Marvin
      @ai_model              Marvin
      @app.call_tool()       MCP lowlevel server API (dispatch handler for all tools)
      @app.list_tools()      MCP lowlevel server API (handler that lists available tools)

  Pattern 2 — Class inheriting from a base tool class:
      class MyTool(BaseTool): name = "..."

  Pattern 3 — Registration call  [planned, not yet implemented]
      StructuredTool.from_function(func=my_func)
      agent.register_tool(my_func)

  Pattern 4 — Dict/schema definition  [planned, not yet implemented]
      tools = [{"name": "read_file", "input_schema": {...}}]

Confidence model:
  0.95 — decorator/class resolved to a known framework import
  0.70 — decorator/class found in imports but source module unknown
  0.60 — decorator/class name matches a known pattern but no import found
           (variable constructed locally, or star-import)

Extensibility:
  Add entries to ENTRY_POINT_DECORATORS or ENTRY_POINT_BASE_CLASSES to
  support new frameworks without changing detection logic. A future
  --entry-point-decorator CLI flag will append to these dicts at runtime.

Known limitations:
  - Factory calls (StructuredTool.from_function, FunctionTool.from_defaults)
    are not detected in v1 — function name not statically available at call site.
  - Dynamic registration (tools in a loop, getattr-based) is not detected.
  - Three-level decorator chains (@pytest.mark.tool) are skipped; only
    simple (@name) and two-level (@obj.name) decorators are matched.
  - Local imports inside functions are not examined.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Framework label constants (metadata only — do not use in detection logic)
# ---------------------------------------------------------------------------

FRAMEWORK_MCP = "mcp"
FRAMEWORK_LANGCHAIN = "langchain"
FRAMEWORK_CREWAI = "crewai"
FRAMEWORK_PYDANTIC_AI = "pydantic_ai"
FRAMEWORK_OPENAI_AGENTS = "openai_agents"
FRAMEWORK_SEMANTIC_KERNEL = "semantic_kernel"
FRAMEWORK_AUTOGEN = "autogen"
FRAMEWORK_STRANDS = "strands"
FRAMEWORK_HAYSTACK = "haystack"
FRAMEWORK_AGNO = "agno"
FRAMEWORK_METAGPT = "metagpt"
FRAMEWORK_MARVIN = "marvin"
FRAMEWORK_AGENCY_SWARM = "agency_swarm"
FRAMEWORK_SMOLAGENTS = "smolagents"
FRAMEWORK_GOOGLE_ADK = "google_adk"
FRAMEWORK_LLAMAINDEX = "llamaindex"
FRAMEWORK_DSPY = "dspy"
FRAMEWORK_CAMEL = "camel"
FRAMEWORK_UNKNOWN = "unknown"

# ---------------------------------------------------------------------------
# Pattern type identifiers
# ---------------------------------------------------------------------------

PATTERN_DECORATOR = "decorator"
PATTERN_CLASS_ATTRIBUTE = "class_attribute"
PATTERN_REGISTRATION_CALL = "registration_call"  # planned

# ---------------------------------------------------------------------------
# Detection tables  (update these to add framework support, not logic)
# ---------------------------------------------------------------------------

# Maps canonical decorator name → default framework label.
# "Canonical name" = the attr part of @obj.name or the bare name for @name.
# The default label is only used when import resolution fails (confidence 0.60).
# Extend this dict to support new frameworks without touching detection code.
ENTRY_POINT_DECORATORS: Dict[str, str] = {
    "tool":             "langchain_or_crewai",   # @tool, @mcp.tool(), @agent.tool
    "tool_plain":       FRAMEWORK_PYDANTIC_AI,   # @agent.tool_plain
    "function_tool":    FRAMEWORK_OPENAI_AGENTS, # @function_tool
    "kernel_function":  FRAMEWORK_SEMANTIC_KERNEL,
    "register_for_llm": FRAMEWORK_AUTOGEN,
    "call_tool":        FRAMEWORK_MCP,           # @app.call_tool()   — MCP lowlevel dispatch handler
    "list_tools":       FRAMEWORK_MCP,           # @app.list_tools()  — MCP lowlevel tool listing
    "register_tool":    FRAMEWORK_METAGPT,       # @register_tool(tags=[...])
    "fn":               FRAMEWORK_MARVIN,        # @marvin.fn
    "ai_model":         FRAMEWORK_MARVIN,        # @marvin.ai_model
}

# Maps base class name → default framework label.
ENTRY_POINT_BASE_CLASSES: Dict[str, str] = {
    "BaseTool":      "langchain_or_crewai",
    "StructuredTool": FRAMEWORK_LANGCHAIN,
    "Toolkit":        FRAMEWORK_AGNO,             # Agno/Phidata toolkit base class
}

# Maps module prefix → canonical framework label.
# Used by import resolution to assign authoritative framework + confidence 0.95.
KNOWN_FRAMEWORK_MODULES: Dict[str, str] = {
    "langchain_core":   FRAMEWORK_LANGCHAIN,
    "langchain":        FRAMEWORK_LANGCHAIN,
    "crewai":           FRAMEWORK_CREWAI,
    "pydantic_ai":      FRAMEWORK_PYDANTIC_AI,
    "mcp":              FRAMEWORK_MCP,
    "fastmcp":          FRAMEWORK_MCP,
    "openai_agents":    FRAMEWORK_OPENAI_AGENTS,
    "agents":           FRAMEWORK_OPENAI_AGENTS,
    "semantic_kernel":  FRAMEWORK_SEMANTIC_KERNEL,
    "autogen_core":     FRAMEWORK_AUTOGEN,
    "autogen":          FRAMEWORK_AUTOGEN,
    "strands":          FRAMEWORK_STRANDS,
    "strands_tools":    FRAMEWORK_STRANDS,
    "haystack":         FRAMEWORK_HAYSTACK,
    "agno":             FRAMEWORK_AGNO,
    "phi":              FRAMEWORK_AGNO,            # Phidata (old name for Agno)
    "phidata":          FRAMEWORK_AGNO,
    "metagpt":          FRAMEWORK_METAGPT,
    "marvin":           FRAMEWORK_MARVIN,
    "agency_swarm":     FRAMEWORK_AGENCY_SWARM,
    "smolagents":       FRAMEWORK_SMOLAGENTS,
    "google.adk":       FRAMEWORK_GOOGLE_ADK,
    "google_adk":       FRAMEWORK_GOOGLE_ADK,
    "llama_index":      FRAMEWORK_LLAMAINDEX,
    "dspy":             FRAMEWORK_DSPY,
    "camel":            FRAMEWORK_CAMEL,
}

# Variable names that strongly suggest a locally-constructed MCP server instance.
# Used as a fallback when the variable was not imported (e.g. mcp = FastMCP("s")).
_MCP_RECEIVER_HINTS: frozenset = frozenset({"mcp", "server", "app", "fastmcp"})

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EntryPoint:
    """
    A single LLM-callable function detected in Python source.

    Fields set at detection time:
        name         — the name the LLM uses to invoke this function
        file         — absolute path to the source file
        lineno       — 1-based line number of the def or class statement
        framework    — framework label (see FRAMEWORK_* constants); metadata only
        pattern_type — one of the PATTERN_* constants above
        confidence   — detection confidence 0.0–1.0 (see module docstring)

    Fields written by reachability analysis (Step 3):
        reachable_findings — list of finding_ids confirmed reachable from
                             this entry point via the intra-project call graph
    """
    name: str
    file: str
    lineno: int
    framework: str
    pattern_type: str
    confidence: float = 1.0
    reachable_findings: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "file": self.file,
            "lineno": self.lineno,
            "framework": self.framework,
            "pattern_type": self.pattern_type,
            "confidence": self.confidence,
            "reachable_findings": self.reachable_findings,
        }


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

_EXCLUDED_PY_DIR_PARTS = frozenset({
    "site-packages", ".venv", "venv", "__pycache__",
    ".git", ".github",
    "tests", "test",
    "benchmark", "benchmarks",
    "node_modules",
})


def _is_excluded_py_file(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    parts = {part.lower() for part in path.parts}
    return bool(parts & _EXCLUDED_PY_DIR_PARTS)


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------

def _infer_receiver_modules(tree: ast.AST, imports: Dict[str, str]) -> Dict[str, str]:
    """
    Scan module-level assignments to infer the source module of local variables.

    Handles patterns like:
        agent = Agent(...)          → {"agent": "pydantic_ai"}
        weather_agent = Agent(...)  → {"weather_agent": "pydantic_ai"}

    where the called class is in `imports`. Only top-level assignments are examined;
    assignments inside functions are skipped (they're too context-dependent to infer).
    """
    inferred: Dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        # Simple assignment: x = Class(...)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            called_name = _call_func_name(node.value)
            if called_name:
                module = imports.get(called_name, "")
                if module:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            inferred[target.id] = module
        # Annotated assignment: x: Type = Class(...)
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.value, ast.Call)
        ):
            called_name = _call_func_name(node.value)
            if called_name:
                module = imports.get(called_name, "")
                if module and isinstance(node.target, ast.Name):
                    inferred[node.target.id] = module
    return inferred


def _call_func_name(call: ast.Call) -> Optional[str]:
    """Return the bare function/class name from a Call node, or None.

    Handles plain calls (Agent(...)), attribute calls (mod.Agent(...)),
    and subscripted generics (Agent[Deps, T](...)).
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.attr
    # Agent[Deps, T](...) — subscript wrapping a Name
    if isinstance(func, ast.Subscript) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _collect_imports(tree: ast.AST) -> Dict[str, str]:
    """
    Return a dict mapping each locally-imported name to its source module.

    Only top-level imports are examined. Local imports inside functions are
    intentionally skipped.

    Examples:
        from langchain_core.tools import tool   → {"tool": "langchain_core.tools"}
        from crewai.tools import BaseTool        → {"BaseTool": "crewai.tools"}
        import mcp                               → {"mcp": "mcp"}
        import mcp.server.fastmcp as mcp_server  → {"mcp_server": "mcp.server.fastmcp"}
    """
    origins: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                origins[local] = node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name.split(".")[0]
                origins[local] = alias.name
    return origins


def _module_to_framework(module: str) -> Optional[str]:
    """Map a full module path to a framework label, or None if unrecognised."""
    for prefix, fw in KNOWN_FRAMEWORK_MODULES.items():
        if module == prefix or module.startswith(prefix + "."):
            return fw
    return None


def _resolve_framework(
    key: str,
    receiver_name: Optional[str],
    imports: Dict[str, str],
    inferred: Optional[Dict[str, str]] = None,
) -> Tuple[str, float]:
    """
    Return (framework_label, confidence) for a detected entry point.

    Resolution order:
      1. receiver in imports and module is known   → 0.95
      2. key (bare name) in imports, module known  → 0.95
      3. receiver in inferred instances, module known → 0.80
         (e.g. weather_agent = Agent(...) where Agent is from pydantic_ai)
      4. receiver in imports, module unknown       → 0.70
         (but if receiver name hints at MCP, label as "mcp" not "unknown_framework")
      5. key in imports, module unknown            → 0.70
      6. receiver name matches _MCP_RECEIVER_HINTS → 0.60, label "mcp"
      7. key in ENTRY_POINT_DECORATORS             → 0.60, dict default label
      8. fallback                                  → 0.60, FRAMEWORK_UNKNOWN
    """
    # Steps 1 & 2: known import resolves receiver or bare name
    for name in filter(None, [receiver_name, key]):
        module = imports.get(name, "")
        if module:
            fw = _module_to_framework(module)
            if fw:
                return fw, 0.95

    # Step 3: receiver is an inferred local instance (e.g. weather_agent = Agent(...))
    if receiver_name and inferred:
        module = inferred.get(receiver_name, "")
        if module:
            fw = _module_to_framework(module)
            if fw:
                return fw, 0.80

    # Steps 4 & 5: import found but module not in known list
    for name in filter(None, [receiver_name, key]):
        module = imports.get(name, "")
        if module:
            # Receiver named "mcp"/"server"/etc. coming from a project-local
            # module (e.g. valkey monorepo shared server) is almost certainly MCP.
            if name and name.lower() in _MCP_RECEIVER_HINTS:
                return FRAMEWORK_MCP, 0.70
            return FRAMEWORK_UNKNOWN, 0.70

    # Step 5: not imported, but receiver name is a strong MCP hint
    if receiver_name and receiver_name.lower() in _MCP_RECEIVER_HINTS:
        return FRAMEWORK_MCP, 0.60

    # Step 6: key in known decorator table
    default_label = ENTRY_POINT_DECORATORS.get(key)
    if default_label:
        return default_label, 0.60

    return FRAMEWORK_UNKNOWN, 0.60


# ---------------------------------------------------------------------------
# Decorator key extraction
# ---------------------------------------------------------------------------

def _decorator_key(
    decorator: ast.expr,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract (canonical_key, receiver_name) from a decorator node.

    canonical_key  — the attribute or bare name that identifies the pattern
    receiver_name  — the variable the method is called on (or None for bare names)

    Only simple (@name) and two-level (@obj.name or @obj.name()) forms are matched.
    Three-level chains (@a.b.c) are returned as (None, None) to avoid false positives.

    Examples:
        @tool            → ("tool", None)
        @tool()          → ("tool", None)
        @tool("Name")    → ("tool", None)
        @mcp.tool()      → ("tool", "mcp")
        @agent.tool      → ("tool", "agent")
        @agent.tool_plain → ("tool_plain", "agent")
        @pytest.mark.tool → (None, None)  — three-level, skipped
    """
    # Unwrap a Call node to get the underlying function expression
    inner = decorator.func if isinstance(decorator, ast.Call) else decorator

    if isinstance(inner, ast.Name):
        return inner.id, None

    if isinstance(inner, ast.Attribute):
        # Only match when the receiver is a simple name (two-level)
        if isinstance(inner.value, ast.Name):
            return inner.attr, inner.value.id
        # Three-level or deeper — skip
        return None, None

    return None, None


# ---------------------------------------------------------------------------
# Pattern 1: decorator check
# ---------------------------------------------------------------------------

def _check_decorator(
    decorator: ast.expr,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    file_path: str,
    imports: Dict[str, str],
    inferred: Optional[Dict[str, str]] = None,
) -> Optional[EntryPoint]:
    """Return an EntryPoint if the decorator matches a known entry point pattern."""
    key, receiver = _decorator_key(decorator)
    if key is None or key not in ENTRY_POINT_DECORATORS:
        return None

    # Extract explicit tool name from decorator args/kwargs if present
    name = func_node.name
    if isinstance(decorator, ast.Call):
        name = _name_from_call(decorator, default=func_node.name)

    # For decorated classes, prefer a static 'name' attribute in the class body
    if isinstance(func_node, ast.ClassDef):
        class_name = _extract_class_name_attr(func_node)
        if class_name:
            name = class_name

    framework, confidence = _resolve_framework(key, receiver, imports, inferred)

    return EntryPoint(
        name=name,
        file=file_path,
        lineno=func_node.lineno,
        framework=framework,
        pattern_type=PATTERN_DECORATOR,
        confidence=confidence,
    )


def _extract_class_name_attr(class_node: ast.ClassDef) -> Optional[str]:
    """Extract a static string 'name' attribute from a class body, or None."""
    for stmt in class_node.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if (
                    isinstance(target, ast.Name) and target.id == "name"
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    return stmt.value.value
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == "name"
            and stmt.value is not None
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            return stmt.value.value
    return None


def _name_from_call(call: ast.Call, default: str) -> str:
    """
    Extract a tool name from a decorator call node.
    Checks positional string arg first, then name= keyword, falls back to default.
    """
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return default


# ---------------------------------------------------------------------------
# Pattern 2: BaseTool subclass check
# ---------------------------------------------------------------------------

def _check_base_tool_class(
    class_node: ast.ClassDef,
    file_path: str,
    imports: Dict[str, str],
) -> Optional[EntryPoint]:
    """
    Return an EntryPoint if the class inherits from a known base tool class
    and has a static string name attribute.
    """
    base_name: Optional[str] = None
    for base in class_node.bases:
        candidate = None
        if isinstance(base, ast.Name):
            candidate = base.id
        elif isinstance(base, ast.Attribute):
            candidate = base.attr
        if candidate and candidate in ENTRY_POINT_BASE_CLASSES:
            base_name = candidate
            break
    if base_name is None:
        return None

    # Scan class body for a static name attribute
    tool_name: Optional[str] = None
    for stmt in class_node.body:
        # name = "literal"
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if (
                    isinstance(target, ast.Name) and target.id == "name"
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                ):
                    tool_name = stmt.value.value
                    break
        # name: str = "literal"
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == "name"
            and stmt.value is not None
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            tool_name = stmt.value.value

        if tool_name is not None:
            break

    if tool_name is None:
        return None

    # Resolve framework from the base class import origin
    module = imports.get(base_name, "")
    fw = _module_to_framework(module) if module else None
    if fw is None:
        fw = ENTRY_POINT_BASE_CLASSES.get(base_name, FRAMEWORK_UNKNOWN)
        confidence = 0.60 if not module else 0.70
    else:
        confidence = 0.95

    return EntryPoint(
        name=tool_name,
        file=file_path,
        lineno=class_node.lineno,
        framework=fw,
        pattern_type=PATTERN_CLASS_ATTRIBUTE,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def _iter_detectable_nodes(parent: ast.AST):
    """
    Yield FunctionDef, AsyncFunctionDef, and ClassDef nodes visible at
    module scope or class body scope.

    Intentionally does NOT recurse into function or method bodies, so
    closures defined inside methods (e.g. SDK-internal helpers like
    ``@function_tool async def run_agent(...)`` inside ``Agent.as_tool()``)
    are invisible to the detector.  Real user-defined tools are always at
    module or class scope, never nested inside other functions.
    """
    for node in ast.iter_child_nodes(parent):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
            # Do NOT recurse: anything inside this function body is skipped
        elif isinstance(node, ast.ClassDef):
            yield node
            yield from _iter_detectable_nodes(node)  # recurse into class body only


def detect_py_entry_points(file_path: str, content: str) -> List[EntryPoint]:
    """
    Scan a single Python file's content for LLM entry points.

    Returns a list of EntryPoint objects, deduplicated by (lineno, name).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError:
        return []

    imports = _collect_imports(tree)
    inferred = _infer_receiver_modules(tree, imports)
    results: List[EntryPoint] = []
    seen: set = set()  # (lineno, name) dedup

    for node in _iter_detectable_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                ep = _check_decorator(decorator, node, file_path, imports, inferred)
                if ep:
                    key = (ep.lineno, ep.name)
                    if key not in seen:
                        seen.add(key)
                        results.append(ep)
                    break  # first matching decorator wins per function

        elif isinstance(node, ast.ClassDef):
            # Check decorators on classes (e.g. @register_tool, @ai_model)
            for decorator in node.decorator_list:
                ep = _check_decorator(decorator, node, file_path, imports, inferred)
                if ep:
                    key = (ep.lineno, ep.name)
                    if key not in seen:
                        seen.add(key)
                        results.append(ep)
                    break
            else:
                # No decorator matched — check base class inheritance
                ep = _check_base_tool_class(node, file_path, imports)
                if ep:
                    key = (ep.lineno, ep.name)
                    if key not in seen:
                        seen.add(key)
                        results.append(ep)

    # Secondary pass: MCP low-level handlers may appear inside factory functions
    # (e.g. `def create_app(): app = Server(...); @app.call_tool() async def call_tool()`).
    # `call_tool` and `list_tools` are MCP-specific enough that using ast.walk
    # for just these two keys doesn't risk false positives from SDK internals.
    _MCP_HANDLER_KEYS = frozenset({"call_tool", "list_tools"})
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                dkey, _ = _decorator_key(decorator)
                if dkey not in _MCP_HANDLER_KEYS:
                    continue
                ep = _check_decorator(decorator, node, file_path, imports, inferred)
                if ep:
                    result_key = (ep.lineno, ep.name)
                    if result_key not in seen:
                        seen.add(result_key)
                        results.append(ep)
                break

    return results


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def scan_py_files(root: Path) -> List[EntryPoint]:
    """
    Walk root and detect Python entry points in all eligible files.

    Skips test files, __pycache__, .venv, and other non-agent-runtime paths.
    """
    root = Path(root)
    results: List[EntryPoint] = []

    if root.is_file():
        if root.suffix == ".py" and not _is_excluded_py_file(root):
            _scan_one_py(root, results)
        return results

    for p in root.rglob("*.py"):
        if not _is_excluded_py_file(p):
            _scan_one_py(p, results)

    return results


def _scan_one_py(path: Path, results: List[EntryPoint]) -> None:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    results.extend(detect_py_entry_points(str(path), content))
