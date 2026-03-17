"""
Intra-project call graph data model and construction.

This module defines the type contracts used by the call graph builder and the
reachability analyser, and provides the construction logic (build_call_graph).

Type contracts (used by Step 4 reachability analysis):
  FunctionNode   — (abs_file_path, qualified_name): canonical function identifier
  CallGraph      — adjacency map: FunctionNode → set of called FunctionNodes
  LinenoIndex    — per-file {start_lineno → (qualified_name, end_lineno)}; includes
                   0 → ("<module>", None) sentinel so all findings have a containing
                   "function" context. end_lineno enables scope-aware nested function
                   resolution.
  ImportMap      — per-file {local_name → source_file} for project-local imports
  ReexportMap    — project-wide {exported_name → source_file} from __init__.py

Qualified name conventions (follows __qualname__):
  top-level function : "process_auth"
  class method       : "MyTool._run"
  nested function    : bare name (e.g. "inner"), NOT in project_functions

Construction algorithm — three phases:

  Phase 1 — __init__.py pre-pass:
    Collect one level of relative re-exports from every __init__.py.
    Used so that `from mypkg import process_auth` resolves even when
    process_auth lives in mypkg/utils.py and is re-exported via __init__.py.

  Phase 2 — Per-file analysis:
    For each .py file, parse the AST and:
      a) Collect top-level imports that resolve within the project boundary
         → ImportMap[file][local_name] = source_file
      b) Collect exportable function names (top-level functions + immediate class
         methods — things that can be imported by other project files)
         → project_functions[file] = {qualified_name, ...}

  Phase 3 — Edge extraction:
    _FileVisitor walks each file's AST using NodeVisitor and:
      - Records every function/method start line in LinenoIndex (including nested
        functions; sentinel 0 → "<module>" covers code outside all functions).
      - On each ast.Call, tries to resolve the callee to a project FunctionNode
        using the four-step resolution order below and adds a directed edge.

  Call resolution order (inside _FileVisitor, per call site):
    1. Bare name in same file's project_functions   → (file, name)
    2. Bare name in file's ImportMap                → (source_file, name) if exported
    3. self.attr() in active class context          → (file, ClassName.attr)
    4. obj.attr() where obj is a simple Name in ImportMap
                                                    → (source_file, attr) if exported
    Otherwise: unresolvable → edge dropped silently

Known limitations (v1):
  - Nested functions appear in LinenoIndex but not in project_functions.
    Findings inside them get UNKNOWN reachability (static analysis limitation).
  - Module-level findings get UNKNOWN via the "<module>" sentinel (not in graph).
  - Star imports (from x import *) are not resolved.
  - Type-based method dispatch (obj.method() where obj is not self and is not a
    directly imported module) is not resolved.
  - Dynamic calls (getattr, __import__, etc.) produce no edges.
  - Only top-level module-level imports are examined; imports inside function
    bodies are not tracked.
  - Graph may contain cycles (mutual recursion) — Step 4 BFS must track visited
    nodes to avoid infinite loops.
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

# (abs_file_path, qualified_name) — e.g. ("/abs/path/tools.py", "MyTool._run")
FunctionNode = Tuple[str, str]

# Adjacency map: each FunctionNode → set of FunctionNodes it calls in-project.
CallGraph = Dict[FunctionNode, Set[FunctionNode]]

# Per-file map: start_lineno → (qualified function name, end_lineno or None).
# Sentinel 0 → ("<module>", None) is always present to cover module-level code.
LinenoIndex = Dict[str, Dict[int, Tuple[str, Optional[int]]]]

# Per-file map: local import name → resolved abs source file path.
ImportMap = Dict[str, Dict[str, str]]

# Project-wide map: exported name → source file (from __init__.py pre-pass).
ReexportMap = Dict[str, str]

UNRESOLVABLE = "<unresolvable>"
MODULE_LEVEL = "<module>"   # sentinel: code that lives outside any function


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_call_graph(
    py_files: List[Path],
    root: Path,
) -> Tuple[CallGraph, LinenoIndex, ImportMap]:
    """
    Build the intra-project call graph, lineno index, and import map.

    Args:
        py_files: Pre-filtered list of .py files to analyse (same list used
                  by the scanner for detector runs). Paths are resolved to
                  their canonical absolute form internally.
        root:     Project root directory. Used to enforce the project boundary
                  when resolving import paths.

    Returns a three-tuple (graph, lineno, imp_map):
        graph:   CallGraph — FunctionNode → set of callee FunctionNodes.
                 Every function definition in every file has at least an empty
                 set entry so callers can iterate nodes safely.
        lineno:  LinenoIndex — per-file {start_lineno → (qualified_name, end_lineno)}.
                 Includes nested functions and the 0 → ("<module>", None) sentinel.
        imp_map: ImportMap — per-file {local_name → abs_source_file} for
                 project-local imports resolved at the top-level of each file.
    """
    root = Path(root).resolve()
    files = [Path(f).resolve() for f in py_files]

    # Phase 1: one-level re-export map from __init__.py relative imports
    reexport_map = _build_reexport_map(files, root)

    # Phase 2: per-file import maps and exportable function names
    trees: Dict[str, ast.AST] = {}
    imp_map: ImportMap = {}
    project_functions: Dict[str, Set[str]] = {}  # file → {qualified_name}

    for f in files:
        fstr = str(f)
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(content)
        except Exception:
            continue

        trees[fstr] = tree
        imp_map[fstr] = _collect_file_imports(f, tree, root, reexport_map)
        project_functions[fstr] = _collect_exportable_names(tree)

    # Phase 3: call edge extraction and lineno index construction
    graph: CallGraph = {}
    lineno: LinenoIndex = {}

    for fstr, tree in trees.items():
        visitor = _FileVisitor(
            file=fstr,
            file_imports=imp_map.get(fstr, {}),
            project_functions=project_functions,
        )
        visitor.visit(tree)

        for fn, callees in visitor.graph.items():
            graph.setdefault(fn, set()).update(callees)

        lineno[fstr] = visitor.lineno_index

    return graph, lineno, imp_map


# ---------------------------------------------------------------------------
# Phase 1: __init__.py re-export pre-pass
# ---------------------------------------------------------------------------

def _build_reexport_map(files: List[Path], root: Path) -> ReexportMap:
    """
    Build a project-wide {exported_name → source_file} map.

    Walks every __init__.py in the file list and follows relative imports one
    level deep. Only relative imports (level > 0) are followed; absolute
    imports in __init__.py are ignored (they are third-party or stdlib).
    """
    reexport_map: ReexportMap = {}

    for f in files:
        if f.name != "__init__.py":
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(content)
        except Exception:
            continue

        for node in tree.body:
            if not isinstance(node, ast.ImportFrom) or node.level == 0:
                continue  # only relative imports

            module = node.module or ""

            for alias in node.names:
                if alias.name == "*":
                    continue

                # Determine the module to resolve:
                #   "from .utils import foo" → module="utils", resolve "utils"
                #   "from . import utils"    → module="",      resolve alias.name="utils"
                sub = module if module else alias.name
                source_file = _resolve_module_to_file(sub, root, f, node.level)
                if source_file is None:
                    continue

                exported_name = alias.asname if alias.asname else alias.name
                reexport_map[exported_name] = source_file

    return reexport_map


# ---------------------------------------------------------------------------
# Module → file path resolution
# ---------------------------------------------------------------------------

def _resolve_module_to_file(
    module_str: str,
    root: Path,
    current_file: Path,
    level: int = 0,
) -> Optional[str]:
    """
    Resolve a module specifier to an absolute .py file path within root.

    level=0  absolute: "from mypackage.utils import foo"
    level=1  relative: "from . import foo"  (same package as current_file)
    level=2  relative: "from .. import foo" (parent package)

    Tries candidate.py first, then candidate/__init__.py.
    Returns None if the path does not exist or falls outside root.
    """
    if not module_str:
        return None

    if level > 0:
        base = current_file.parent
        for _ in range(level - 1):
            base = base.parent
    else:
        base = root

    rel = Path(module_str.replace(".", "/"))
    candidate = base / rel

    for path in (candidate.with_suffix(".py"), candidate / "__init__.py"):
        if path.is_file():
            try:
                resolved = path.resolve()
                resolved.relative_to(root)      # verify within project boundary
                return str(resolved)
            except ValueError:
                pass

    return None


# ---------------------------------------------------------------------------
# Phase 2 helpers
# ---------------------------------------------------------------------------

def _collect_file_imports(
    file: Path,
    tree: ast.AST,
    root: Path,
    reexport_map: ReexportMap,
) -> Dict[str, str]:
    """
    Return {local_name: abs_source_file} for top-level imports that resolve
    within the project boundary.

    Only top-level (module-level) import statements are examined; imports
    inside function or class bodies are not tracked.

    For names that resolve to a package __init__.py, the reexport_map is
    checked first so the mapping points to the actual defining file rather
    than the re-exporting __init__.py.
    """
    result: Dict[str, str] = {}

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue

            module = node.module or ""
            level = node.level

            if level > 0 and not module:
                # "from . import name1, name2" — each alias is itself a submodule
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    source_file = _resolve_module_to_file(alias.name, root, file, level)
                    local = alias.asname if alias.asname else alias.name
                    if source_file is not None:
                        result[local] = source_file
            else:
                # "from [dots]module import name1, name2"
                source_file = _resolve_module_to_file(module, root, file, level)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname if alias.asname else alias.name
                    if source_file is not None:
                        # Prefer reexport source (more specific than __init__.py)
                        result[local] = reexport_map.get(local, source_file)
                    elif local in reexport_map:
                        result[local] = reexport_map[local]

        elif isinstance(node, ast.Import):
            for alias in node.names:
                source_file = _resolve_module_to_file(alias.name, root, file, 0)
                if source_file is not None:
                    local = alias.asname if alias.asname else alias.name.split(".")[0]
                    result[local] = source_file

    return result


def _collect_exportable_names(tree: ast.AST) -> Set[str]:
    """
    Return qualified names of functions importable from this file:
      - top-level functions:         "process_auth"
      - immediate class methods:     "MyTool._run"

    Nested functions (defined inside other functions) are excluded — they
    cannot be imported and are handled separately in the lineno index.
    """
    names: Set[str] = set()

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(f"{node.name}.{item.name}")

    return names


# ---------------------------------------------------------------------------
# Phase 3: single-file AST visitor
# ---------------------------------------------------------------------------

class _FileVisitor(ast.NodeVisitor):
    """
    Single-file AST visitor that builds call graph edges and a lineno index.

    Context tracking:
        _class_stack  — names of enclosing ClassDef nodes (innermost last)
        _func_stack   — qualified names of enclosing function/method definitions
        _func_depth   — nesting depth (0 = not inside any function)

    Qualified name convention:
        - Class method at _func_depth==0: "ClassName.method"
        - All other functions (top-level or nested): bare "name"

    Outputs:
        graph        — {FunctionNode: set(FunctionNode)} — edges from this file
        lineno_index — {start_lineno: (qualified_name, end_lineno)}; sentinel 0 → ("<module>", None)
    """

    def __init__(
        self,
        file: str,
        file_imports: Dict[str, str],             # local_name → source_file
        project_functions: Dict[str, Set[str]],   # source_file → {qualified_name}
    ) -> None:
        self._file = file
        self._file_imports = file_imports
        self._project_functions = project_functions

        self._class_stack: List[str] = []
        self._func_stack: List[str] = []
        self._func_depth: int = 0

        self.graph: Dict[FunctionNode, Set[FunctionNode]] = {}
        # Sentinel ensures every file has a MODULE_LEVEL entry for bisect safety
        self.lineno_index: Dict[int, Tuple[str, Optional[int]]] = {0: (MODULE_LEVEL, None)}

    # -- Class and function boundaries ---------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node) -> None:
        # Qualified name:
        #   - Class method at the top level of its class body → "ClassName.method"
        #   - Everything else (top-level fn, nested fn) → bare "name"
        if self._class_stack and self._func_depth == 0:
            qual = f"{self._class_stack[-1]}.{node.name}"
        else:
            qual = node.name

        self.lineno_index[node.lineno] = (qual, getattr(node, "end_lineno", None))
        fn: FunctionNode = (self._file, qual)
        self.graph.setdefault(fn, set())

        self._func_stack.append(qual)
        self._func_depth += 1
        self.generic_visit(node)
        self._func_depth -= 1
        self._func_stack.pop()

    # -- Call sites ---------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        if self._func_stack:
            caller: FunctionNode = (self._file, self._func_stack[-1])
            callee = self._resolve_call(node)
            if callee is not None:
                self.graph.setdefault(caller, set()).add(callee)
        self.generic_visit(node)

    def _resolve_call(self, node: ast.Call) -> Optional[FunctionNode]:
        func = node.func

        # Resolution 1 & 2: bare call — foo()
        if isinstance(func, ast.Name):
            return self._resolve_name(func.id)

        if isinstance(func, ast.Attribute):
            attr = func.attr
            value = func.value

            # Resolution 3: self.method()
            if isinstance(value, ast.Name) and value.id == "self":
                return self._resolve_self_method(attr)

            # Resolution 4: module.func() where module is a simple Name
            if isinstance(value, ast.Name):
                return self._resolve_module_attr(value.id, attr)

        return None

    def _resolve_name(self, name: str) -> Optional[FunctionNode]:
        """Resolutions 1 & 2: same file first, then imported file."""
        # Resolution 1: defined in this file
        if name in self._project_functions.get(self._file, set()):
            return (self._file, name)
        # Resolution 2: imported from another project file
        source = self._file_imports.get(name)
        if source and name in self._project_functions.get(source, set()):
            return (source, name)
        return None

    def _resolve_self_method(self, attr: str) -> Optional[FunctionNode]:
        """Resolution 3: self.attr() within the current class."""
        if not self._class_stack:
            return None
        qual = f"{self._class_stack[-1]}.{attr}"
        if qual in self._project_functions.get(self._file, set()):
            return (self._file, qual)
        return None

    def _resolve_module_attr(self, obj_name: str, attr: str) -> Optional[FunctionNode]:
        """Resolution 4: obj.attr() where obj is an imported project module."""
        source = self._file_imports.get(obj_name)
        if source and attr in self._project_functions.get(source, set()):
            return (source, attr)
        return None
