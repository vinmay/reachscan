"""
MCP tool annotation extraction for Python sources.

Reads the ToolAnnotations hints declared on MCP tools:

  - FastMCP:  @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, ...))
              @mcp.tool(annotations={"readOnlyHint": True, ...})
  - lowlevel: types.Tool(name="x", ..., annotations=types.ToolAnnotations(...))
              inside @server.list_tools() handlers or module-level tool lists

Each hint resolves to a value plus where that value came from:
  explicit      — declared with a literal (or a module-level bool constant)
  default       — absent; the MCP spec default applies
  unresolvable  — declared, but not statically knowable (a non-literal value,
                  a **spread, or an annotations object passed by a reference
                  that can't be resolved). Unresolvable hints never produce
                  findings.

Spec defaults (MCP specification, schema version 2026-07-28, ToolAnnotations):
  readOnlyHint     default false
  destructiveHint  default true; meaningful only when readOnlyHint == false
  idempotentHint   default false; meaningful only when readOnlyHint == false
  openWorldHint    default true
So an absent destructiveHint counts as true only when readOnlyHint is false
(explicitly or by default). When readOnlyHint is true it counts as false, and
when readOnlyHint is unresolvable it is unresolvable too.

Hint spelling: the MCP Python SDK 1.x accepts only camelCase fields
(readOnlyHint) and silently ignores snake_case ones (read_only_hint) because
extra fields are allowed; SDK 2.x accepts both. A snake_case hint therefore
means different things depending on the SDK version, so it is unresolvable
unless the camelCase spelling is also given.

Known limitations:
  - References are followed one hop: to a module-level assignment in the same
    file, or (when a project root is given) in the project file it is
    imported from. Function return values and deeper chains are unresolvable.
  - Tools registered with mcp.add_tool(fn, annotations=...) are not detected
    as entry points, so their annotations are not read.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

SPEC_VERSION = "2026-07-28"

EXPLICIT = "explicit"
DEFAULT = "default"
UNRESOLVABLE = "unresolvable"

HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
# snake_case spellings: honored by MCP Python SDK 2.x, ignored by 1.x.
SNAKE_HINT_KEYS = {
    "read_only_hint": "readOnlyHint",
    "destructive_hint": "destructiveHint",
    "idempotent_hint": "idempotentHint",
    "open_world_hint": "openWorldHint",
}


@dataclass
class HintValue:
    value: Optional[bool]   # None when unresolvable
    source: str             # EXPLICIT | DEFAULT | UNRESOLVABLE

    def as_dict(self) -> dict:
        return {"value": self.value, "source": self.source}


@dataclass
class ToolAnnotationInfo:
    """Effective annotation hints for one MCP tool, with spec defaults applied."""
    read_only: HintValue
    destructive: HintValue
    idempotent: HintValue
    open_world: HintValue
    declared: bool                    # an annotations argument was given (and not None)
    unresolved_reference: bool = False  # annotations passed by a reference we couldn't resolve

    def hints(self) -> Dict[str, HintValue]:
        return {
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        }


@dataclass
class DeclaredTool:
    """A lowlevel `types.Tool(...)` declaration found in a list_tools handler or tool list."""
    name: str
    lineno: int
    annotations: ToolAnnotationInfo


# ---------------------------------------------------------------------------
# Module context
# ---------------------------------------------------------------------------

@dataclass
class ModuleContext:
    """Module-level facts used to resolve references within one file."""
    imports: Dict[str, str]
    assignments: Dict[str, ast.expr] = field(default_factory=dict)
    # String class attributes, e.g. enum members: {("GitTools", "STATUS"): "git_status"}
    class_strings: Dict[tuple, str] = field(default_factory=dict)
    # Module-level `from M import N [as L]`: {L: (M, level, N)}
    import_from: Dict[str, Tuple[str, int, str]] = field(default_factory=dict)
    # Resolves an imported name to (expression, defining module's context), or None.
    external: Optional[Callable[[str], Optional[Tuple[ast.expr, "ModuleContext"]]]] = None

    @classmethod
    def from_tree(cls, tree: ast.Module, imports: Dict[str, str]) -> "ModuleContext":
        assignments: Dict[str, ast.expr] = {}
        counts: Dict[str, int] = {}
        for stmt in tree.body:
            targets: List[ast.expr] = []
            value: Optional[ast.expr] = None
            if isinstance(stmt, ast.Assign):
                targets, value = stmt.targets, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                targets, value = [stmt.target], stmt.value
            for target in targets:
                if isinstance(target, ast.Name):
                    counts[target.id] = counts.get(target.id, 0) + 1
                    assignments[target.id] = value
        # A name assigned more than once at module level isn't a reliable constant.
        for name, count in counts.items():
            if count > 1:
                assignments.pop(name, None)
        class_strings: Dict[tuple, str] = {}
        for stmt in tree.body:
            if not isinstance(stmt, ast.ClassDef):
                continue
            for item in stmt.body:
                if (isinstance(item, ast.Assign) and len(item.targets) == 1
                        and isinstance(item.targets[0], ast.Name)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)):
                    class_strings[(stmt.name, item.targets[0].id)] = item.value.value
        import_from: Dict[str, Tuple[str, int, str]] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    import_from[alias.asname or alias.name] = (
                        stmt.module or "", stmt.level, alias.name
                    )
        return cls(imports=imports, assignments=assignments, class_strings=class_strings,
                   import_from=import_from)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

_MISSING = object()


def _callee_name(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_tool_annotations_call(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and _callee_name(node.func) == "ToolAnnotations"


def is_mcp_tool_call(node: ast.expr, ctx: ModuleContext) -> bool:
    """True for Tool(...) calls whose callee resolves to the mcp package (mcp.types.Tool)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "Tool":
        return ctx.imports.get("Tool", "").split(".")[0] == "mcp"
    if isinstance(func, ast.Attribute) and func.attr == "Tool":
        base = func.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name):
            return ctx.imports.get(base.id, "").split(".")[0] == "mcp"
    return False


def _hint_value(node: ast.expr, ctx: ModuleContext):
    """Resolve one hint value: True/False, None (unset), or _MISSING (unresolvable)."""
    if isinstance(node, ast.Constant) and (isinstance(node.value, bool) or node.value is None):
        return node.value
    if isinstance(node, ast.Name):
        ref = ctx.assignments.get(node.id)
        if isinstance(ref, ast.Constant) and isinstance(ref.value, bool):
            return ref.value
    return _MISSING


def _raw_hints(node: ast.expr, ctx: ModuleContext, depth: int = 0):
    """Return (raw hints dict, unresolved_reference) for an annotations expression.

    Raw hint values are True/False, or _MISSING for unresolvable. Keys absent
    from the dict were not declared. Returns (None, False) for `None`.
    """
    if isinstance(node, ast.Constant) and node.value is None:
        return None, False

    if _is_tool_annotations_call(node):
        raw: Dict[str, object] = {}
        spread = False
        snake = set()
        for kw in node.keywords:
            if kw.arg is None:
                spread = True
            elif kw.arg in HINT_KEYS:
                value = _hint_value(kw.value, ctx)
                if value is not None:
                    raw[kw.arg] = value
            elif kw.arg in SNAKE_HINT_KEYS:
                snake.add(SNAKE_HINT_KEYS[kw.arg])
        for key in snake:
            raw.setdefault(key, _MISSING)  # SDK-version-dependent spelling
        if spread or node.args:
            for key in HINT_KEYS:
                raw.setdefault(key, _MISSING)
        return raw, False

    if isinstance(node, ast.Dict):
        raw = {}
        spread = False
        snake_dict_keys = set()
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                spread = True
                continue
            if isinstance(key_node, ast.Constant) and key_node.value in HINT_KEYS:
                value = _hint_value(value_node, ctx)
                if value is not None:
                    raw[key_node.value] = value
            elif isinstance(key_node, ast.Constant) and key_node.value in SNAKE_HINT_KEYS:
                snake_dict_keys.add(SNAKE_HINT_KEYS[key_node.value])
            elif not isinstance(key_node, ast.Constant):
                spread = True  # computed key could name any hint
        for key in snake_dict_keys:
            raw.setdefault(key, _MISSING)  # SDK-version-dependent spelling
        if spread:
            for key in HINT_KEYS:
                raw.setdefault(key, _MISSING)
        return raw, False

    if isinstance(node, ast.Name) and depth == 0:
        ref = ctx.assignments.get(node.id)
        if ref is not None:
            return _raw_hints(ref, ctx, depth + 1)
        if node.id in ctx.import_from and ctx.external is not None:
            resolved = ctx.external(node.id)
            if resolved is not None:
                expr, ext_ctx = resolved
                return _raw_hints(expr, ext_ctx, depth + 1)

    # Anything else: a reference or expression we can't resolve statically.
    return {key: _MISSING for key in HINT_KEYS}, True


def _apply_defaults(raw: Optional[Dict[str, object]], declared: bool,
                    unresolved_reference: bool) -> ToolAnnotationInfo:
    raw = raw or {}

    def resolve(key: str, default: bool) -> HintValue:
        if key not in raw:
            return HintValue(default, DEFAULT)
        value = raw[key]
        if value is _MISSING:
            return HintValue(None, UNRESOLVABLE)
        return HintValue(bool(value), EXPLICIT)

    read_only = resolve("readOnlyHint", False)

    if "destructiveHint" in raw:
        destructive = resolve("destructiveHint", True)
    elif read_only.source == UNRESOLVABLE:
        destructive = HintValue(None, UNRESOLVABLE)
    else:
        # Default true, but only meaningful when readOnlyHint is false.
        destructive = HintValue(not read_only.value, DEFAULT)

    return ToolAnnotationInfo(
        read_only=read_only,
        destructive=destructive,
        idempotent=resolve("idempotentHint", False),
        open_world=resolve("openWorldHint", True),
        declared=declared,
        unresolved_reference=unresolved_reference,
    )


def annotations_from_expr(node: Optional[ast.expr], ctx: ModuleContext) -> ToolAnnotationInfo:
    """Effective annotations for an `annotations=` argument (None means not given)."""
    if node is None:
        return _apply_defaults(None, declared=False, unresolved_reference=False)
    raw, unresolved = _raw_hints(node, ctx)
    if raw is None:
        return _apply_defaults(None, declared=False, unresolved_reference=False)
    return _apply_defaults(raw, declared=True, unresolved_reference=unresolved)


def annotations_from_call(call: ast.Call, ctx: ModuleContext) -> ToolAnnotationInfo:
    """Effective annotations from the `annotations=` keyword of a call, if present.

    A `**kwargs` spread in the call could carry annotations, so it makes every
    hint unresolvable when no explicit `annotations=` keyword is given.
    """
    for kw in call.keywords:
        if kw.arg == "annotations":
            return annotations_from_expr(kw.value, ctx)
    if any(kw.arg is None for kw in call.keywords):
        return _apply_defaults({key: _MISSING for key in HINT_KEYS}, declared=True,
                               unresolved_reference=True)
    return annotations_from_expr(None, ctx)


# ---------------------------------------------------------------------------
# Lowlevel types.Tool declarations
# ---------------------------------------------------------------------------

def _tool_name(call: ast.Call, ctx: ModuleContext) -> Optional[str]:
    for kw in call.keywords:
        if kw.arg == "name":
            value = kw.value
            if isinstance(value, ast.Name):
                value = ctx.assignments.get(value.id, value)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                # Enum or class constant defined in this file: GitTools.STATUS
                return ctx.class_strings.get((value.value.id, value.attr))
            return None
    return None


def declared_tools(nodes: List[ast.AST], ctx: ModuleContext) -> List[DeclaredTool]:
    """Find mcp.types.Tool(...) declarations under the given nodes.

    Tools whose name isn't a string literal, a module-level string constant, or
    a string class attribute in this file (e.g. an enum member) are skipped:
    their annotations can't be tied to a tool.
    """
    results: List[DeclaredTool] = []
    seen = set()
    for root in nodes:
        for node in ast.walk(root):
            if not is_mcp_tool_call(node, ctx):
                continue
            name = _tool_name(node, ctx)
            if name is None or (node.lineno, name) in seen:
                continue
            seen.add((node.lineno, name))
            results.append(DeclaredTool(
                name=name,
                lineno=node.lineno,
                annotations=annotations_from_call(node, ctx),
            ))
    return results


# ---------------------------------------------------------------------------
# Cross-file resolution (one hop into project files)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=512)
def _parse_module_context(path: str) -> Optional[ModuleContext]:
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, ValueError, OSError):
        return None
    from reachscan.py_entry_points import _collect_imports  # local import: avoids a cycle
    return ModuleContext.from_tree(tree, _collect_imports(tree))


def make_external_resolver(root: Path, current_file: Path, ctx: ModuleContext):
    """Build a resolver for names imported into current_file from project files.

    The returned callable maps a local name to (expression, defining module's
    context) when the name is imported with `from M import N` from a file under
    root and N is a single module-level assignment there. The defining
    module's context has no resolver of its own, so resolution stops after one
    hop.
    """
    from reachscan.call_graph import _resolve_module_to_file  # local import: avoids a cycle

    def resolve(local: str):
        module, level, name = ctx.import_from[local]
        target = _resolve_module_to_file(module, root, current_file, level) if module else None
        if target is None:
            return None
        ext_ctx = _parse_module_context(target)
        if ext_ctx is None:
            return None
        expr = ext_ctx.assignments.get(name)
        return (expr, ext_ctx) if expr is not None else None

    return resolve
