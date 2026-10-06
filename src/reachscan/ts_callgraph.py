"""
TypeScript/JavaScript call graph, tool handlers, and reachability.

Works on the tree-sitter trees from ts_parser (one per parsed file).

Function nodes (FunctionNode = (file, qualname)):
  function declarations                      name
  arrow functions / function expressions
    bound to a variable                      name
  class methods                              Class.method
  object methods / function-valued pairs     var.key (or <object>.key)
  default exports                            default (or the function's name)
  any other function expression              <anonymous@line:col>

Edges:
  direct calls to functions in the same file or imported from a project file
  (relative ESM imports, including `./x.js` resolving to `x.ts`, CommonJS
  require, and namespace imports `ns.fn()`), `this.method()` within a class,
  `obj.method()` on an object literal bound in the same file, and
  enclosing function → function expressions it passes or defines inline
  (callbacks are assumed to run), and `new C()` → C's constructor. A method
  call on an object the graph can't resolve records every project method with
  that name as a possible target (TSGraph.dynamic): code reached only that way
  is "unknown", not "unreachable". Other calls add nothing.

Tool handlers (entry nodes) are the functions an MCP or LangChain tool runs:
  server.tool(...) / server.registerTool(...)   last argument (literal or
                                                dynamic name; dynamic needs an
                                                MCP SDK import in the file)
  server.addTool({ execute }) / addTool(obj)    the object's execute
  setRequestHandler(CallToolRequestSchema, h)   h
  new DynamicTool({ func })                     func
  tool-definition objects                       handler / execute of
    { name, description, inputSchema|schema|parameters|args, handler|execute }
  project registration wrappers                 execute / handler of the object
    registerTool({ name, ..., execute })        passed to a project function
                                                that itself calls .registerTool /
                                                .tool / .addTool
  xmcp file-based tools                         the default export of a file that
                                                also exports `metadata = { name }`,
                                                in projects that use xmcp
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from reachscan.ts_parser import iter_nodes, node_text, object_pairs, string_value

FunctionNode = Tuple[str, str]

_FUNCTION_TYPES = frozenset({
    "function_declaration", "generator_function_declaration", "arrow_function",
    "function_expression", "function", "generator_function", "method_definition",
})
_TS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_SDK_PREFIXES = ("@modelcontextprotocol/", "fastmcp", "mcp-framework", "xmcp")
_SCHEMA_KEYS = ("inputSchema", "schema", "parameters", "args")
_HANDLER_KEYS = ("handler", "execute")
_REGISTER_METHODS = frozenset({"registerTool", "tool", "addTool"})


@dataclass
class ToolHandler:
    name: str
    file: str
    lineno: int
    pattern_type: str
    node: FunctionNode


@dataclass
class TSGraph:
    graph: Dict[FunctionNode, Set[FunctionNode]] = field(default_factory=dict)
    node_line: Dict[FunctionNode, int] = field(default_factory=dict)
    by_start: Dict[Tuple[str, int], FunctionNode] = field(default_factory=dict)  # (file, start_byte)
    anonymous: Set[FunctionNode] = field(default_factory=set)
    # Calls on objects the graph can't resolve (`tool.execute()`, `this.client.run()`)
    # to a method name some project class defines: possible targets, never edges.
    dynamic: Dict[FunctionNode, Set[FunctionNode]] = field(default_factory=dict)
    handlers: List[ToolHandler] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Module resolution
# ---------------------------------------------------------------------------

def _resolve_relative(spec: str, current: str, known: Dict[str, str]) -> Optional[str]:
    """The project file a relative import names; known maps resolved path → file key."""
    if not spec.startswith("."):
        return None
    base = (Path(current).resolve().parent / spec).resolve()
    candidates = [base]
    stem = base
    if base.suffix in (".js", ".jsx", ".mjs", ".cjs"):
        stem = base.with_suffix("")
    candidates += [stem.with_suffix(ext) for ext in _TS_EXTS]
    candidates += [Path(str(stem) + ext) for ext in _TS_EXTS]
    candidates += [stem / f"index{ext}" for ext in _TS_EXTS]
    for c in candidates:
        if str(c) in known:
            return known[str(c)]
    return None


# ---------------------------------------------------------------------------
# Per-file symbol collection
# ---------------------------------------------------------------------------

@dataclass
class _FileSymbols:
    funcs: Dict[str, FunctionNode] = field(default_factory=dict)          # name → node
    methods: Dict[Tuple[str, str], FunctionNode] = field(default_factory=dict)  # (Class|var, key)
    objects: Dict[str, object] = field(default_factory=dict)              # var → object AST node
    default: Optional[FunctionNode] = None
    default_ref: Optional[str] = None                                     # export default <ident>
    imports: Dict[str, Tuple[str, str]] = field(default_factory=dict)     # local → (file, name|default|*)
    strings: Dict[str, str] = field(default_factory=dict)                 # const name = "literal"
    uses_sdk: bool = False


def _enclosing(node, types):
    parent = node.parent
    while parent is not None:
        if parent.type in types:
            return parent
        parent = parent.parent
    return None


def _func_name(fn) -> Tuple[str, bool]:
    """Qualified name for a function node, and whether it's anonymous."""
    t = fn.type
    parent = fn.parent
    if t in ("function_declaration", "generator_function_declaration"):
        name = fn.child_by_field_name("name")
        if name is not None:
            return node_text(name), False
    if t == "method_definition":
        key = node_text(fn.child_by_field_name("name")) if fn.child_by_field_name("name") else "?"
        container = parent.parent if parent is not None else None  # class_body / object → class / object
        if container is not None and container.type in ("class_declaration", "class", "abstract_class_declaration"):
            cname = container.child_by_field_name("name")
            return f"{node_text(cname) if cname is not None else '<class>'}.{key}", False
        if parent is not None and parent.type == "object":
            holder = parent.parent
            if holder is not None and holder.type == "variable_declarator":
                return f"{node_text(holder.child_by_field_name('name'))}.{key}", False
            return f"<object>.{key}", False
    if parent is not None:
        if parent.type == "variable_declarator" and parent.child_by_field_name("value") == fn:
            return node_text(parent.child_by_field_name("name")), False
        if parent.type == "pair" and parent.child_by_field_name("value") == fn:
            key = parent.child_by_field_name("key")
            obj = parent.parent
            holder = obj.parent if obj is not None else None
            kname = string_value(key) or node_text(key)
            if holder is not None and holder.type == "variable_declarator":
                return f"{node_text(holder.child_by_field_name('name'))}.{kname}", False
            return f"<object>.{kname}", False
        if parent.type == "export_statement":
            return "default", False
    line, col = fn.start_point
    return f"<anonymous@{line + 1}:{col}>", True


def _collect(file: str, root, known: Dict[str, str], g: TSGraph) -> _FileSymbols:
    syms = _FileSymbols()
    for node in iter_nodes(root):
        t = node.type
        if t in _FUNCTION_TYPES:
            qual, anon = _func_name(node)
            fnode: FunctionNode = (file, qual)
            if fnode in g.node_line:
                fnode = (file, f"{qual}@{node.start_point[0] + 1}")
            g.node_line[fnode] = node.start_point[0] + 1
            g.by_start[(file, node.start_byte)] = fnode
            g.graph.setdefault(fnode, set())
            if anon:
                g.anonymous.add(fnode)
            if "." in qual and not qual.startswith("<"):
                owner, key = qual.split(".", 1)
                syms.methods[(owner, key.split("@")[0])] = fnode
            elif not anon and qual != "default":
                syms.funcs.setdefault(qual, fnode)
            if node.parent is not None and node.parent.type == "export_statement" and \
                    any(c.type == "default" for c in node.parent.children):
                syms.default = fnode
        elif t == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                while value.type in ("as_expression", "satisfies_expression", "parenthesized_expression") \
                        and value.named_children:
                    value = value.named_children[0]
                if value.type == "object":
                    syms.objects[node_text(name)] = value
                elif value.type in ("string", "template_string") and string_value(value) \
                        and _enclosing(node, _FUNCTION_TYPES) is None:
                    syms.strings[node_text(name)] = string_value(value)
                # CommonJS require
                if value.type == "call_expression":
                    func = value.child_by_field_name("function")
                    args = value.child_by_field_name("arguments")
                    if func is not None and node_text(func) == "require" and args is not None and args.named_children:
                        spec = string_value(args.named_children[0])
                        target = _resolve_relative(spec, file, known) if spec else None
                        if target:
                            syms.imports[node_text(name)] = (target, "*")
            if name is not None and name.type == "object_pattern" and value is not None and value.type == "call_expression":
                func = value.child_by_field_name("function")
                args = value.child_by_field_name("arguments")
                if func is not None and node_text(func) == "require" and args is not None and args.named_children:
                    spec = string_value(args.named_children[0])
                    target = _resolve_relative(spec, file, known) if spec else None
                    if target:
                        for child in name.named_children:
                            if child.type == "shorthand_property_identifier_pattern":
                                syms.imports[node_text(child)] = (target, node_text(child))
                            elif child.type == "pair_pattern":
                                k, v = child.child_by_field_name("key"), child.child_by_field_name("value")
                                if k is not None and v is not None:
                                    syms.imports[node_text(v)] = (target, node_text(k))
        elif t == "import_statement":
            source = string_value(node.child_by_field_name("source"))
            if not source:
                continue
            if source.startswith(_SDK_PREFIXES) or source in ("fastmcp", "xmcp"):
                syms.uses_sdk = True
            target = _resolve_relative(source, file, known)
            if not target:
                continue
            clause = next((c for c in node.named_children if c.type == "import_clause"), None)
            if clause is None:
                continue
            for c in clause.named_children:
                if c.type == "identifier":
                    syms.imports[node_text(c)] = (target, "default")
                elif c.type == "namespace_import":
                    ident = next((x for x in c.named_children if x.type == "identifier"), None)
                    if ident is not None:
                        syms.imports[node_text(ident)] = (target, "*")
                elif c.type == "named_imports":
                    for spec in c.named_children:
                        if spec.type != "import_specifier":
                            continue
                        name = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias") or name
                        if name is not None:
                            syms.imports[node_text(alias)] = (target, node_text(name))
        elif t == "export_statement" and any(c.type == "default" for c in node.children):
            value = node.child_by_field_name("value")
            if value is not None and value.type == "identifier":
                syms.default_ref = node_text(value)
    return syms


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _function_owner(node, file: str, g: TSGraph) -> Optional[FunctionNode]:
    fn = node if node.type in _FUNCTION_TYPES else _enclosing(node, _FUNCTION_TYPES)
    return g.by_start.get((file, fn.start_byte)) if fn is not None else None


def build_ts_graph(trees: Dict[str, object], project_root: Optional[Path] = None) -> TSGraph:
    """Build the TS call graph and tool handlers for parsed files {file: root_node}."""
    g = TSGraph()
    files = {str(f): r for f, r in trees.items()}
    known = {str(Path(f).resolve()): f for f in files}
    syms = {f: _collect(f, r, known, g) for f, r in files.items()}

    def lookup(file: str, name: str, depth: int = 0) -> Optional[FunctionNode]:
        s = syms.get(file)
        if s is None or depth > 3:
            return None
        if name == "default":
            if s.default:
                return s.default
            return lookup(file, s.default_ref, depth + 1) if s.default_ref else None
        if name in s.funcs:
            return s.funcs[name]
        if name in s.imports:
            target, imported = s.imports[name]
            if imported != "*":
                return lookup(target, imported, depth + 1)
        return None

    def lookup_object(file: str, name: str, depth: int = 0):
        """(file, object AST node, var name) for an object literal bound to name (local or imported)."""
        s = syms.get(file)
        if s is None or depth > 3:
            return None
        if name in s.objects:
            return file, s.objects[name], name
        if name in s.imports:
            target, imported = s.imports[name]
            if imported not in ("*", "default"):
                return lookup_object(target, imported, depth + 1)
        return None

    def resolve_callee(callee, file: str) -> Optional[FunctionNode]:
        s = syms[file]
        if callee.type == "identifier":
            return lookup(file, node_text(callee))
        if callee.type == "member_expression":
            obj, prop = callee.child_by_field_name("object"), callee.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            pname = node_text(prop)
            if obj.type == "this":
                cls = _enclosing(callee, ("class_declaration", "class", "abstract_class_declaration"))
                cname = cls.child_by_field_name("name") if cls is not None else None
                if cname is not None:
                    return s.methods.get((node_text(cname), pname))
                return None
            if obj.type == "identifier":
                oname = node_text(obj)
                if (oname, pname) in s.methods:
                    return s.methods[(oname, pname)]
                if oname in s.imports:
                    target, imported = s.imports[oname]
                    if imported == "*":
                        return lookup(target, pname)
                    ts = syms.get(target)
                    if ts is not None and (imported, pname) in ts.methods:
                        return ts.methods[(imported, pname)]
        return None

    def resolve_function_value(value, file: str, depth: int = 0) -> Optional[FunctionNode]:
        """A function node for a handler value: inline function, method, or identifier reference."""
        if value is None:
            return None
        if value.type in _FUNCTION_TYPES:
            return g.by_start.get((file, value.start_byte))
        if value.type == "identifier":
            return lookup(file, node_text(value))
        if value.type == "member_expression":
            return resolve_callee(value, file)
        if value.type in ("as_expression", "satisfies_expression", "parenthesized_expression") \
                and value.named_children:
            return resolve_function_value(value.named_children[0], file)
        if value.type == "call_expression" and depth < 3:
            # handler.bind(this), or a wrapper: withTelemetry(async (req) => ...)
            func = value.child_by_field_name("function")
            if func is not None and func.type == "member_expression" and \
                    node_text(func.child_by_field_name("property")) == "bind":
                return resolve_function_value(func.child_by_field_name("object"), file, depth + 1)
            args = value.child_by_field_name("arguments")
            for arg in (args.named_children if args is not None else []):
                if arg.type in _FUNCTION_TYPES or arg.type == "identifier":
                    found = resolve_function_value(arg, file, depth + 1)
                    if found is not None:
                        return found
        return None

    def object_handler(obj, file: str):
        """(handler node) from an object literal's handler/execute pair or method."""
        for child in obj.named_children:
            if child.type == "method_definition":
                key = child.child_by_field_name("name")
                if key is not None and node_text(key) in _HANDLER_KEYS:
                    return g.by_start.get((file, child.start_byte))
        pairs = object_pairs(obj)
        for key in _HANDLER_KEYS:
            if key in pairs:
                return resolve_function_value(pairs[key], file)
        return None

    # Methods and function-valued properties by key: the possible targets of
    # `x.key()` when x can't be resolved (class instances, tool objects in a list).
    class_methods: Dict[str, Set[FunctionNode]] = {}
    for fnode in g.node_line:
        qual = fnode[1]
        if "." in qual and not qual.startswith("<anonymous"):
            key = qual.rsplit(".", 1)[1].split("@")[0]
            if key != "constructor":
                class_methods.setdefault(key, set()).add(fnode)

    # Edges
    for file, root in files.items():
        for node in iter_nodes(root):
            if node.type in ("call_expression", "new_expression"):
                owner = _function_owner(node, file, g) if _enclosing(node, _FUNCTION_TYPES) else None
                if owner is None:
                    continue
                callee = node.child_by_field_name("function" if node.type == "call_expression" else "constructor")
                if callee is None:
                    continue
                target = resolve_callee(callee, file)
                if target is None and node.type == "new_expression" and callee.type == "identifier":
                    callee_text = node_text(callee)
                    target = syms[file].methods.get((callee_text, "constructor"))
                    if target is None and callee_text in syms[file].imports:
                        tfile, tname = syms[file].imports[callee_text]
                        tsyms = syms.get(tfile)
                        if tsyms is not None:
                            target = tsyms.methods.get((tname, "constructor"))
                if target is not None and target != owner:
                    g.graph[owner].add(target)
                elif target is None and callee.type == "member_expression":
                    prop = callee.child_by_field_name("property")
                    candidates = class_methods.get(node_text(prop)) if prop is not None else None
                    if candidates:
                        g.dynamic.setdefault(owner, set()).update(candidates - {owner})
            elif node.type in _FUNCTION_TYPES and node.type != "function_declaration":
                parent_fn = _enclosing(node, _FUNCTION_TYPES)
                if parent_fn is None:
                    continue
                child = g.by_start.get((file, node.start_byte))
                parent = g.by_start.get((file, parent_fn.start_byte))
                if child and parent and (child in g.anonymous or node.type == "method_definition"):
                    g.graph[parent].add(child)

    # Tool handlers
    uses_xmcp = False
    if project_root is not None:
        root_dir = Path(project_root)
        root_dir = root_dir.parent if root_dir.is_file() else root_dir
        if any((root_dir / f"xmcp.config{ext}").exists() for ext in (".ts", ".js", ".mjs", ".json")):
            uses_xmcp = True
        pkg = root_dir / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                uses_xmcp = uses_xmcp or "xmcp" in deps
            except (ValueError, AttributeError):
                pass

    seen: Set[Tuple[str, int, str]] = set()

    def add(name: str, file: str, lineno: int, pattern: str, node: Optional[FunctionNode]) -> None:
        if node is None:
            return
        key = (file, lineno, name)
        if key in seen:
            return
        seen.add(key)
        g.handlers.append(ToolHandler(name=name, file=file, lineno=lineno, pattern_type=pattern, node=node))

    for file, root in files.items():
        s = syms[file]
        for node in iter_nodes(root):
            if node.type == "call_expression":
                func = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                arglist = list(args.named_children) if args is not None else []
                if func is None or not arglist:
                    continue
                while func.type in ("parenthesized_expression", "as_expression", "non_null_expression") \
                        and func.named_children:
                    func = func.named_children[0]
                if func.type == "member_expression":
                    prop = func.child_by_field_name("property")
                    method = node_text(prop) if prop is not None else ""
                    line = (prop.start_point[0] + 1) if prop is not None else node.start_point[0] + 1
                    if method in ("tool", "registerTool") and len(arglist) >= 2:
                        name = _name_value(arglist[0], s)
                        if name is None and not s.uses_sdk:
                            continue
                        add(name or "unknown", file, line, "mcp_tool", resolve_function_value(arglist[-1], file))
                    elif method == "addTool":
                        first = arglist[0]
                        obj_info = (file, first, None) if first.type == "object" else (
                            lookup_object(file, node_text(first)) if first.type == "identifier" else None)
                        if obj_info:
                            ofile, obj, _ = obj_info
                            name = string_value(object_pairs(obj).get("name"))
                            if name:
                                add(name, file, line, "mcp_tool", object_handler(obj, ofile))
                    elif method == "setRequestHandler" and len(arglist) >= 2:
                        schema = arglist[0]
                        sname = node_text(schema.child_by_field_name("property")) if schema.type == "member_expression" \
                            else node_text(schema)
                        if sname == "CallToolRequestSchema":
                            add(sname, file, line, "mcp_handler", resolve_function_value(arglist[1], file))
                elif func.type == "identifier" and arglist[0].type == "object":
                    # Project registration wrapper: registerTool({ name, ..., execute })
                    obj = arglist[0]
                    name = string_value(object_pairs(obj).get("name"))
                    target = lookup(file, node_text(func))
                    if name and target is not None and _calls_register(target, files, g):
                        add(name, file, obj.start_point[0] + 1 if obj.named_children else node.start_point[0] + 1,
                            "mcp_tool", object_handler(obj, file))
            elif node.type == "new_expression":
                ctor = node.child_by_field_name("constructor")
                cname = node_text(ctor.child_by_field_name("property")) if ctor is not None and ctor.type == "member_expression" \
                    else (node_text(ctor) if ctor is not None else "")
                args = node.child_by_field_name("arguments")
                if cname in ("DynamicTool", "DynamicStructuredTool") and args is not None and args.named_children \
                        and args.named_children[0].type == "object":
                    obj = args.named_children[0]
                    pairs = object_pairs(obj)
                    name = string_value(pairs.get("name")) or "unknown"
                    add(name, file, node.start_point[0] + 1, "langchain_tool", resolve_function_value(pairs.get("func"), file))
            elif node.type == "object":
                pairs = object_pairs(node)
                name_value = pairs.get("name")
                name = string_value(name_value)
                if name and "description" in pairs and any(k in pairs for k in _SCHEMA_KEYS):
                    handler = object_handler(node, file)
                    if handler is not None:
                        add(name, file, name_value.start_point[0] + 1, "mcp_tool_definition", handler)
            elif node.type == "export_statement" and uses_xmcp:
                decl = node.child_by_field_name("declaration")
                if decl is not None and decl.type == "lexical_declaration":
                    for d in decl.named_children:
                        if d.type == "variable_declarator" and node_text(d.child_by_field_name("name")) == "metadata":
                            value = d.child_by_field_name("value")
                            while value is not None and value.type in ("as_expression", "satisfies_expression") \
                                    and value.named_children:
                                value = value.named_children[0]
                            if value is not None and value.type == "object":
                                nv = object_pairs(value).get("name")
                                name = string_value(nv)
                                if name:
                                    add(name, file, nv.start_point[0] + 1, "mcp_tool", lookup(file, "default"))
    return g


def _name_value(node, syms: _FileSymbols) -> Optional[str]:
    """A tool name: a literal, a same-file string constant, or a `x || "literal"` fallback."""
    value = string_value(node)
    if value:
        return value
    if node.type == "identifier":
        return syms.strings.get(node_text(node))
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and node_text(op) in ("||", "??"):
            return string_value(node.child_by_field_name("right"))
    return None


def _calls_register(target: FunctionNode, files: Dict[str, object], g: TSGraph) -> bool:
    """True if the project function `target` itself calls .registerTool / .tool / .addTool."""
    file = target[0]
    root = files.get(file)
    if root is None:
        return False
    for (f, start), node_id in g.by_start.items():
        if node_id != target or f != file:
            continue
        for node in iter_nodes(root):
            if node.start_byte == start and node.type in _FUNCTION_TYPES:
                for sub in iter_nodes(node):
                    if sub.type == "call_expression":
                        fn = sub.child_by_field_name("function")
                        if fn is not None and fn.type == "member_expression":
                            prop = fn.child_by_field_name("property")
                            if prop is not None and node_text(prop) in _REGISTER_METHODS:
                                return True
                return False
    return False


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def ts_reachability(g: TSGraph, depth: int):
    """Shortest path from any tool handler, and what dynamic calls might reach.

    Returns (best, maybe): best is {FunctionNode → (handler, path of nodes)};
    maybe is the set of nodes not in best that a reached function might call
    through an unresolved method call (directly or onward), within depth hops.
    """
    from reachscan.reachability import _bfs
    best: Dict[FunctionNode, Tuple[ToolHandler, List[FunctionNode]]] = {}
    for h in g.handlers:
        reached, _skipped = _bfs(h.node, g.graph, depth)
        for node, path in reached.items():
            cur = best.get(node)
            if cur is None or (len(path), h.name) < (len(cur[1]), cur[0].name):
                best[node] = (h, path)
    combined = {n: g.graph.get(n, set()) | g.dynamic.get(n, set()) for n in g.graph}
    maybe: Set[FunctionNode] = set()
    frontier = [(n, len(path) - 1) for n, (_h, path) in best.items()]
    seen = {n: d for n, d in frontier}
    while frontier:
        node, d = frontier.pop()
        if d >= depth:
            continue
        for nxt in combined.get(node, ()):
            if nxt in best or seen.get(nxt, depth + 1) <= d + 1:
                continue
            seen[nxt] = d + 1
            maybe.add(nxt)
            frontier.append((nxt, d + 1))
    return best, maybe


def display_name(g: TSGraph, node: FunctionNode, handler: Optional[ToolHandler] = None) -> str:
    """Readable node name; anonymous handler functions show their tool name."""
    if handler is not None and node == handler.node and (node[1].startswith("<") or node[1] == "default"):
        return handler.name
    return node[1]
