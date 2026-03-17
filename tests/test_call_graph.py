"""Tests for intra-project call graph construction."""

import ast
import pytest
from pathlib import Path

from reachscan.call_graph import (
    build_call_graph,
    _build_reexport_map,
    _collect_file_imports,
    _collect_exportable_names,
    _resolve_module_to_file,
    MODULE_LEVEL,
    UNRESOLVABLE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, rel: str, content: str) -> Path:
    """Write content to tmp_path/rel, creating parent dirs as needed."""
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _parse(content: str) -> ast.AST:
    return ast.parse(content)


# ---------------------------------------------------------------------------
# _resolve_module_to_file
# ---------------------------------------------------------------------------

def test_resolve_absolute_import(tmp_path):
    """Absolute import resolves relative to root."""
    target = _write(tmp_path, "mypackage/utils.py", "")
    result = _resolve_module_to_file("mypackage.utils", tmp_path, tmp_path / "main.py", 0)
    assert result == str(target.resolve())


def test_resolve_relative_level1(tmp_path):
    """from . import sibling → sibling.py in same directory."""
    sibling = _write(tmp_path, "pkg/sibling.py", "")
    current = tmp_path / "pkg" / "tools.py"
    result = _resolve_module_to_file("sibling", tmp_path, current, 1)
    assert result == str(sibling.resolve())


def test_resolve_relative_level2(tmp_path):
    """from .. import utils in pkg/sub/tools.py → pkg/utils.py (one package up)."""
    # level=2 from pkg/sub/ → base is pkg/, so target is pkg/utils.py
    target = _write(tmp_path, "pkg/utils.py", "")
    current = tmp_path / "pkg" / "sub" / "tools.py"
    result = _resolve_module_to_file("utils", tmp_path, current, 2)
    assert result == str(target.resolve())


def test_resolve_package_init(tmp_path):
    """Module with __init__.py resolves to the init file."""
    init = _write(tmp_path, "mypackage/__init__.py", "")
    result = _resolve_module_to_file("mypackage", tmp_path, tmp_path / "main.py", 0)
    assert result == str(init.resolve())


def test_resolve_nonexistent_returns_none(tmp_path):
    result = _resolve_module_to_file("nonexistent", tmp_path, tmp_path / "main.py", 0)
    assert result is None


def test_resolve_outside_root_returns_none(tmp_path):
    """File that resolves outside root is rejected."""
    # Level-2 relative import from a top-level file would escape the root
    result = _resolve_module_to_file("utils", tmp_path, tmp_path / "main.py", 2)
    assert result is None


def test_resolve_empty_module_str_returns_none(tmp_path):
    result = _resolve_module_to_file("", tmp_path, tmp_path / "main.py", 0)
    assert result is None


# ---------------------------------------------------------------------------
# _build_reexport_map
# ---------------------------------------------------------------------------

def test_reexport_map_relative_from_utils(tmp_path):
    """from .utils import foo → reexport_map["foo"] = utils.py"""
    init = _write(tmp_path, "pkg/__init__.py", "from .utils import foo, bar\n")
    utils = _write(tmp_path, "pkg/utils.py", "")

    result = _build_reexport_map([init.resolve(), utils.resolve()], tmp_path)

    assert result["foo"] == str(utils.resolve())
    assert result["bar"] == str(utils.resolve())


def test_reexport_map_bare_submodule(tmp_path):
    """from . import utils → reexport_map["utils"] = utils.py"""
    init = _write(tmp_path, "pkg/__init__.py", "from . import utils\n")
    utils = _write(tmp_path, "pkg/utils.py", "")

    result = _build_reexport_map([init.resolve(), utils.resolve()], tmp_path)

    assert result["utils"] == str(utils.resolve())


def test_reexport_map_absolute_import_excluded(tmp_path):
    """Absolute import in __init__.py is not included (third-party)."""
    init = _write(tmp_path, "pkg/__init__.py", "from requests import get\n")
    result = _build_reexport_map([init.resolve()], tmp_path)
    assert "get" not in result


def test_reexport_map_star_import_excluded(tmp_path):
    """Star import in __init__.py is not included."""
    init = _write(tmp_path, "pkg/__init__.py", "from .utils import *\n")
    _write(tmp_path, "pkg/utils.py", "")
    result = _build_reexport_map([init.resolve()], tmp_path)
    assert result == {}


def test_reexport_map_empty_init(tmp_path):
    """Empty __init__.py produces empty reexport map."""
    init = _write(tmp_path, "pkg/__init__.py", "")
    result = _build_reexport_map([init.resolve()], tmp_path)
    assert result == {}


def test_reexport_map_asname(tmp_path):
    """from .utils import foo as bar → reexport_map["bar"] = utils.py"""
    init = _write(tmp_path, "pkg/__init__.py", "from .utils import foo as bar\n")
    utils = _write(tmp_path, "pkg/utils.py", "")

    result = _build_reexport_map([init.resolve(), utils.resolve()], tmp_path)

    assert "bar" in result
    assert result["bar"] == str(utils.resolve())


# ---------------------------------------------------------------------------
# _collect_file_imports
# ---------------------------------------------------------------------------

def test_collect_relative_import(tmp_path):
    """from .utils import foo → maps foo to utils.py"""
    utils = _write(tmp_path, "pkg/utils.py", "")
    tools = tmp_path / "pkg" / "tools.py"
    tree = _parse("from .utils import foo\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result.get("foo") == str(utils.resolve())


def test_collect_bare_submodule_import(tmp_path):
    """from . import utils → maps utils to utils.py"""
    utils = _write(tmp_path, "pkg/utils.py", "")
    tools = tmp_path / "pkg" / "tools.py"
    tree = _parse("from . import utils\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result.get("utils") == str(utils.resolve())


def test_collect_absolute_third_party_excluded(tmp_path):
    """from requests import get → not included (not in project)."""
    tools = tmp_path / "tools.py"
    tree = _parse("from requests import get\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert "get" not in result


def test_collect_future_import_excluded(tmp_path):
    """from __future__ import annotations → never included."""
    tools = tmp_path / "tools.py"
    tree = _parse("from __future__ import annotations\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result == {}


def test_collect_star_import_excluded(tmp_path):
    """Star imports are skipped."""
    _write(tmp_path, "utils.py", "")
    tools = tmp_path / "tools.py"
    tree = _parse("from utils import *\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result == {}


def test_collect_reexport_map_used_as_fallback(tmp_path):
    """When module resolves to __init__.py, reexport_map provides specific source."""
    utils = _write(tmp_path, "pkg/utils.py", "")
    _write(tmp_path, "pkg/__init__.py", "")
    tools = tmp_path / "tools.py"
    reexport_map = {str(utils.name): str(utils.resolve()), "process_auth": str(utils.resolve())}

    tree = _parse("from pkg import process_auth\n")
    result = _collect_file_imports(tools, tree, tmp_path, reexport_map)
    # Should resolve to utils.py via reexport_map, not __init__.py
    assert result.get("process_auth") == str(utils.resolve())


def test_collect_import_statement(tmp_path):
    """import mymodule → maps mymodule to mymodule.py"""
    mod = _write(tmp_path, "mymodule.py", "")
    tools = tmp_path / "tools.py"
    tree = _parse("import mymodule\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result.get("mymodule") == str(mod.resolve())


def test_collect_asname(tmp_path):
    """from .utils import process_auth as pa → maps pa to utils.py"""
    utils = _write(tmp_path, "pkg/utils.py", "")
    tools = tmp_path / "pkg" / "tools.py"
    tree = _parse("from .utils import process_auth as pa\n")
    result = _collect_file_imports(tools, tree, tmp_path, {})
    assert result.get("pa") == str(utils.resolve())


# ---------------------------------------------------------------------------
# _collect_exportable_names
# ---------------------------------------------------------------------------

def test_exportable_top_level_function():
    tree = _parse("def process_auth(): pass\n")
    names = _collect_exportable_names(tree)
    assert "process_auth" in names


def test_exportable_async_function():
    tree = _parse("async def fetch(url): pass\n")
    names = _collect_exportable_names(tree)
    assert "fetch" in names


def test_exportable_class_method():
    tree = _parse("class MyTool:\n    def _run(self, x): pass\n")
    names = _collect_exportable_names(tree)
    assert "MyTool._run" in names
    assert "_run" not in names  # bare name not exported


def test_exportable_two_classes_same_method():
    code = "class A:\n    def run(self): pass\nclass B:\n    def run(self): pass\n"
    names = _collect_exportable_names(_parse(code))
    assert "A.run" in names
    assert "B.run" in names


def test_exportable_nested_function_excluded():
    code = "def outer():\n    def inner(): pass\n"
    names = _collect_exportable_names(_parse(code))
    assert "outer" in names
    assert "inner" not in names


# ---------------------------------------------------------------------------
# build_call_graph — single file
# ---------------------------------------------------------------------------

def test_intra_file_direct_call(tmp_path):
    """A calls B in same file → edge (file, A) → (file, B)."""
    f = _write(tmp_path, "tools.py", """\
def helper(x):
    return x

def process(x):
    return helper(x)
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    caller = (fstr, "process")
    callee = (fstr, "helper")
    assert caller in graph
    assert callee in graph[caller]


def test_intra_file_self_method_call(tmp_path):
    """self.method() within a class → edge (file, ClassName.caller) → (file, ClassName.method)."""
    f = _write(tmp_path, "tools.py", """\
class MyTool:
    def _run(self, x):
        return self._helper(x)

    def _helper(self, x):
        return x
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    caller = (fstr, "MyTool._run")
    callee = (fstr, "MyTool._helper")
    assert callee in graph[caller]


def test_third_party_call_dropped(tmp_path):
    """Call to third-party library produces no edge."""
    f = _write(tmp_path, "tools.py", """\
import requests

def fetch(url):
    return requests.get(url)
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    callees = graph.get((fstr, "fetch"), set())
    assert all(callee[0] == fstr for callee in callees)  # no cross-file edges to third-party


def test_async_function_in_graph(tmp_path):
    """async def appears in graph and lineno index."""
    f = _write(tmp_path, "server.py", """\
async def fetch(url: str) -> str:
    return url
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    assert (fstr, "fetch") in graph
    assert any(v[0] == "fetch" for v in lineno[fstr].values())


def test_lineno_index_function_start_lines(tmp_path):
    """Lineno index maps function start lines to qualified names."""
    f = _write(tmp_path, "tools.py", """\
def alpha():
    pass

def beta():
    pass
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    idx = lineno[fstr]
    assert idx[1][0] == "alpha"
    assert idx[4][0] == "beta"


def test_lineno_index_module_sentinel(tmp_path):
    """Every file's lineno index has the 0 → '<module>' sentinel."""
    f = _write(tmp_path, "tools.py", "x = 1\n")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    assert 0 in lineno[fstr]
    assert lineno[fstr][0][0] == MODULE_LEVEL


def test_lineno_index_class_method(tmp_path):
    """Class method lineno uses qualified 'ClassName.method' name."""
    f = _write(tmp_path, "tools.py", """\
class Worker:
    def run(self):
        pass
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    assert any(v[0] == "Worker.run" for v in lineno[fstr].values())


def test_nested_function_in_lineno_not_in_exportable(tmp_path):
    """Nested function appears in lineno index but not as an independent graph node."""
    f = _write(tmp_path, "tools.py", """\
def outer():
    def inner():
        pass
    inner()
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    # inner appears in lineno index
    assert any(v[0] == "inner" for v in lineno[fstr].values())
    # inner is not in project_functions → outer→inner edge is not built
    # (inner cannot be imported; it's a nested closure)
    outer_callees = graph.get((fstr, "outer"), set())
    assert (fstr, "inner") not in outer_callees


def test_graph_node_exists_for_every_function(tmp_path):
    """Every detected function has at least an empty entry in the graph."""
    f = _write(tmp_path, "tools.py", """\
def a(): pass
def b(): pass
""")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    assert (fstr, "a") in graph
    assert (fstr, "b") in graph


# ---------------------------------------------------------------------------
# build_call_graph — cross-file
# ---------------------------------------------------------------------------

def test_cross_file_import_and_call(tmp_path):
    """A in tools.py imports and calls B from utils.py → edge A → B."""
    utils = _write(tmp_path, "utils.py", """\
def helper(x):
    return x
""")
    tools = _write(tmp_path, "tools.py", """\
from utils import helper

def process(x):
    return helper(x)
""")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    caller = (tools_str, "process")
    callee = (utils_str, "helper")
    assert callee in graph[caller]


def test_cross_file_module_attr_call(tmp_path):
    """import utils; utils.helper() → edge to utils.helper."""
    utils = _write(tmp_path, "utils.py", """\
def helper(x):
    return x
""")
    tools = _write(tmp_path, "tools.py", """\
import utils

def process(x):
    return utils.helper(x)
""")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    caller = (tools_str, "process")
    callee = (utils_str, "helper")
    assert callee in graph[caller]


def test_cross_file_chain(tmp_path):
    """A → B → C (three files): both edges are present."""
    c_file = _write(tmp_path, "c.py", "def dangerous(): pass\n")
    b_file = _write(tmp_path, "b.py", """\
from c import dangerous

def middle():
    dangerous()
""")
    a_file = _write(tmp_path, "a.py", """\
from b import middle

def entry():
    middle()
""")
    graph, lineno, imp_map = build_call_graph([c_file, b_file, a_file], tmp_path)
    a_str, b_str, c_str = str(a_file.resolve()), str(b_file.resolve()), str(c_file.resolve())
    assert (b_str, "middle") in graph[(a_str, "entry")]
    assert (c_str, "dangerous") in graph[(b_str, "middle")]


def test_reexport_resolution_in_call_graph(tmp_path):
    """Cross-file import via __init__.py re-export resolves to the defining file."""
    utils = _write(tmp_path, "pkg/utils.py", """\
def process_auth(token):
    return token
""")
    init = _write(tmp_path, "pkg/__init__.py", "from .utils import process_auth\n")
    caller_file = _write(tmp_path, "main.py", """\
from pkg import process_auth

def run():
    process_auth("tok")
""")
    files = [utils, init, caller_file]
    graph, lineno, imp_map = build_call_graph(files, tmp_path)
    main_str = str(caller_file.resolve())
    utils_str = str(utils.resolve())
    caller = (main_str, "run")
    callee = (utils_str, "process_auth")
    assert callee in graph.get(caller, set())


def test_relative_import_resolution(tmp_path):
    """from . import utils; utils.func() resolves cross-file."""
    utils = _write(tmp_path, "pkg/utils.py", """\
def helper():
    pass
""")
    tools = _write(tmp_path, "pkg/tools.py", """\
from . import utils

def do_work():
    utils.helper()
""")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    assert (utils_str, "helper") in graph.get((tools_str, "do_work"), set())


# ---------------------------------------------------------------------------
# Edge cases and robustness
# ---------------------------------------------------------------------------

def test_empty_file_list(tmp_path):
    """Empty input produces empty outputs without error."""
    graph, lineno, imp_map = build_call_graph([], tmp_path)
    assert graph == {}
    assert lineno == {}
    assert imp_map == {}


def test_file_with_no_functions(tmp_path):
    """File with only module-level assignments produces no graph nodes."""
    f = _write(tmp_path, "constants.py", "X = 1\nY = 2\n")
    graph, lineno, imp_map = build_call_graph([f], tmp_path)
    fstr = str(f.resolve())
    # No function nodes, but lineno entry exists (just the module sentinel)
    assert not any(k[0] == fstr for k in graph)
    assert 0 in lineno[fstr]


def test_syntax_error_file_skipped(tmp_path):
    """Unparseable file is silently skipped; other files still processed."""
    bad = _write(tmp_path, "bad.py", "def broken(:\n    pass\n")
    good = _write(tmp_path, "good.py", "def valid(): pass\n")
    graph, lineno, imp_map = build_call_graph([bad, good], tmp_path)
    good_str = str(good.resolve())
    bad_str = str(bad.resolve())
    assert (good_str, "valid") in graph
    assert bad_str not in lineno


def test_star_import_produces_no_edge(tmp_path):
    """Star imports are unresolvable — calls to star-imported names drop silently."""
    utils = _write(tmp_path, "utils.py", "def helper(): pass\n")
    tools = _write(tmp_path, "tools.py", """\
from utils import *

def process():
    helper()
""")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    # helper imported via star → not in import_map → no edge
    assert (utils_str, "helper") not in graph.get((tools_str, "process"), set())


def test_import_map_populated(tmp_path):
    """imp_map contains project-local import mappings."""
    utils = _write(tmp_path, "utils.py", "")
    tools = _write(tmp_path, "tools.py", "from utils import helper\n")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    assert imp_map[tools_str].get("helper") == utils_str


def test_call_inside_nested_function_attributed_to_nested(tmp_path):
    """A call inside a nested function is attributed to the nested function (innermost)."""
    helper = _write(tmp_path, "helper.py", "def target(): pass\n")
    f = _write(tmp_path, "tools.py", """\
from helper import target

def outer():
    def inner():
        target()
""")
    graph, lineno, imp_map = build_call_graph([helper, f], tmp_path)
    fstr = str(f.resolve())
    helper_str = str(helper.resolve())
    # target() is called inside inner, so edge is (file, "inner") → (helper, "target")
    inner_node = (fstr, "inner")
    target_node = (helper_str, "target")
    assert target_node in graph.get(inner_node, set())


def test_multiple_calls_in_one_function(tmp_path):
    """A function that calls B and C has edges to both."""
    utils = _write(tmp_path, "utils.py", """\
def alpha(): pass
def beta(): pass
""")
    tools = _write(tmp_path, "tools.py", """\
from utils import alpha, beta

def do_both():
    alpha()
    beta()
""")
    graph, lineno, imp_map = build_call_graph([utils, tools], tmp_path)
    tools_str = str(tools.resolve())
    utils_str = str(utils.resolve())
    callees = graph.get((tools_str, "do_both"), set())
    assert (utils_str, "alpha") in callees
    assert (utils_str, "beta") in callees
