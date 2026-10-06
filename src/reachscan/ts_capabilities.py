"""
Capability detection for TypeScript and JavaScript.

Works on tree-sitter trees from ts_parser. Imports are resolved first (ESM
imports, CommonJS require, TS `import x = require()`, `node:` prefixes, and
aliases), and a call counts as a sink only when it resolves to the module the
sink belongs to. `regex.exec()` or `db.exec()` is not child_process.exec.
Globals such as fetch, eval, and setInterval count only when the name isn't
declared locally in the file.

Detects the same seven capability classes as the Python detectors and reports
under the same detector names, so findings flow through the existing
enrichment, risk, and reporting code.

Known limitations:
  - Bindings are tracked per file, not per scope. A local declaration that
    shadows an imported name in one function is not distinguished.
  - Values passed around (const run = cp.exec; run()) are not followed, except
    for direct `const x = require("mod").fn` bindings.
  - Files tree-sitter can't parse are skipped (see scan_ts_capabilities).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from reachscan.detectors.base import CapabilityFinding
from reachscan.detectors.secrets import _env_key_confidence
from reachscan.ts_parser import iter_nodes, node_text, string_value

GLOBAL = "<global>"

# ---------------------------------------------------------------------------
# Sink tables
# ---------------------------------------------------------------------------
# Key: (module, attribute path). "" means calling or constructing the module's
# default export / the module object itself. Value: (capability, detector, label).

Sink = Tuple[str, str, str]
_SINKS: Dict[Tuple[str, str], Sink] = {}


def _add(module: str, attrs, capability: str, detector: str, label_module: Optional[str] = None):
    for attr in attrs:
        prefix = module if label_module is None else label_module
        label = ".".join(part for part in (prefix, attr) if part)
        _SINKS[(module, attr)] = (capability, detector, label)


# EXECUTE
_add("child_process", ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"],
     "EXECUTE", "shell_exec")
_add("execa", ["", "execa", "execaSync", "execaCommand", "execaCommandSync", "execaNode", "$"],
     "EXECUTE", "shell_exec")
_add(GLOBAL, ["Bun.spawn", "Bun.spawnSync"], "EXECUTE", "shell_exec", label_module="")

# READ / WRITE
_FS_READ = ["readFile", "readdir", "opendir", "readlink"]
_FS_WRITE = ["writeFile", "appendFile", "unlink", "rm", "rmdir", "rename", "mkdir",
             "copyFile", "cp", "truncate"]
for _mod in ("fs", "fs/promises"):
    _add(_mod, _FS_READ, "READ", "file_access")
    _add(_mod, _FS_WRITE, "WRITE", "file_access")
_add("fs", [f"{name}Sync" for name in _FS_READ], "READ", "file_access")
_add("fs", [f"{name}Sync" for name in _FS_WRITE], "WRITE", "file_access")
_add("fs", ["createReadStream"], "READ", "file_access")
_add("fs", ["createWriteStream"], "WRITE", "file_access")
# fs.open / openSync / fs/promises.open are classified by their flags argument.
_FS_OPEN = {("fs", "open"), ("fs", "openSync"), ("fs/promises", "open")}

# SEND
_add(GLOBAL, ["fetch"], "SEND", "network", label_module="")
_add(GLOBAL, ["WebSocket"], "SEND", "network", label_module="")
_add("node-fetch", [""], "SEND", "network")
_add("undici", ["fetch", "request", "stream", "pipeline", "connect", "Client", "Pool"],
     "SEND", "network")
_add("axios", ["", "get", "post", "put", "delete", "patch", "head", "options", "request"],
     "SEND", "network")
_add("got", ["", "get", "post", "put", "patch", "delete", "head", "stream"], "SEND", "network")
for _mod in ("http", "https"):
    _add(_mod, ["request", "get"], "SEND", "network")
_add("net", ["connect", "createConnection", "Socket"], "SEND", "network")
_add("tls", ["connect"], "SEND", "network")
_add("dgram", ["createSocket"], "SEND", "network")
_add("ws", ["", "WebSocket"], "SEND", "network")

# SECRETS (process.env is handled separately)
_add("dotenv", ["config", "configDotenv"], "SECRETS", "secrets")
_add("keytar", ["getPassword", "findPassword", "findCredentials"], "SECRETS", "secrets")
_SIDE_EFFECT_SECRET_IMPORTS = {"dotenv/config": "import 'dotenv/config'"}

# DYNAMIC (non-literal import()/require() are handled separately)
_add(GLOBAL, ["eval", "Function"], "DYNAMIC", "dynamic_exec", label_module="")
_add("vm", ["runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script"],
     "DYNAMIC", "dynamic_exec")

# AUTONOMY
_add(GLOBAL, ["setInterval"], "AUTONOMY", "autonomy", label_module="")
_add("node-cron", ["schedule"], "AUTONOMY", "autonomy")
_add("cron", ["CronJob", "CronJob.from"], "AUTONOMY", "autonomy")
_add("bree", [""], "AUTONOMY", "autonomy")
_add("agenda", ["", "Agenda"], "AUTONOMY", "autonomy")
_add("worker_threads", ["Worker"], "AUTONOMY", "autonomy")

_FUNCTION_NODES = frozenset({
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function_declaration", "generator_function",
})


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class TSCapabilityFinding:
    detector: str
    finding: CapabilityFinding
    in_function: bool  # False: module-level code that runs on import
    container: Optional[int] = None  # start_byte of the innermost enclosing function (internal)


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------

def _normalize_module(spec: str) -> str:
    return spec[5:] if spec.startswith("node:") else spec


def _normalize_target(module: str, attr: str) -> Tuple[str, str]:
    """fs + promises.readFile → fs/promises + readFile."""
    if module == "fs" and (attr == "promises" or attr.startswith("promises.")):
        return "fs/promises", attr[len("promises."):] if attr != "promises" else ""
    return module, attr


def _join(attr: str, prop: str) -> str:
    return f"{attr}.{prop}" if attr else prop


def _require_module(node, declared: Set[str]) -> Optional[str]:
    """Module name for a literal require("mod") call, else None."""
    if node is None or node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    if func is None or func.type != "identifier" or node_text(func) != "require":
        return None
    if "require" in declared:
        return None
    args = node.child_by_field_name("arguments")
    if args is None or len(args.named_children) != 1:
        return None
    spec = string_value(args.named_children[0])
    return _normalize_module(spec) if spec else None


class _Resolver:
    def __init__(self, root):
        self.declared: Set[str] = set()   # names declared locally (not imports)
        self.bindings: Dict[str, Tuple[str, str]] = {}  # local name → (module, attr)
        self.side_effect_imports: List[Tuple[str, object]] = []
        self._collect_declarations(root)
        self._collect_bindings(root)

    # -- declarations (for global shadowing) --------------------------------

    def _collect_declarations(self, root) -> None:
        for node in iter_nodes(root):
            t = node.type
            if t in ("function_declaration", "generator_function_declaration",
                     "class_declaration"):
                name = node.child_by_field_name("name")
                if name is not None:
                    self.declared.add(node_text(name))
            elif t == "variable_declarator":
                self._add_pattern(node.child_by_field_name("name"))
            elif t in ("required_parameter", "optional_parameter"):
                self._add_pattern(node.child_by_field_name("pattern"))
            elif t == "formal_parameters":
                for child in node.named_children:
                    if child.type in ("identifier", "object_pattern", "array_pattern",
                                      "assignment_pattern", "rest_pattern"):
                        self._add_pattern(child)
            elif t == "arrow_function":
                param = node.child_by_field_name("parameter")
                if param is not None:
                    self._add_pattern(param)
            elif t == "catch_clause":
                self._add_pattern(node.child_by_field_name("parameter"))

    def _add_pattern(self, node) -> None:
        if node is None:
            return
        if node.type in ("identifier", "shorthand_property_identifier_pattern"):
            self.declared.add(node_text(node))
            return
        for child in iter_nodes(node):
            if child is node:
                continue
            if child.type in ("identifier", "shorthand_property_identifier_pattern"):
                parent = child.parent
                # In `{ key: value }` patterns only the value side is a binding.
                if parent is not None and parent.type == "pair_pattern" and \
                        parent.child_by_field_name("key") == child:
                    continue
                self.declared.add(node_text(child))

    # -- import bindings ------------------------------------------------------

    def _collect_bindings(self, root) -> None:
        for node in iter_nodes(root):
            if node.type == "import_statement":
                self._import_statement(node)
            elif node.type == "variable_declarator":
                self._require_declarator(node)

    def _import_statement(self, node) -> None:
        if any(child.type == "type" for child in node.children):
            return  # import type { ... } — no runtime binding
        source = node.child_by_field_name("source")
        clause = next((c for c in node.named_children if c.type == "import_clause"), None)
        req = next((c for c in node.named_children if c.type == "import_require_clause"), None)
        if req is not None:
            ident = next((c for c in req.named_children if c.type == "identifier"), None)
            spec = string_value(req.child_by_field_name("source"))
            if ident is not None and spec:
                self._bind(node_text(ident), _normalize_module(spec), "")
            return
        spec = string_value(source)
        if not spec:
            return
        module = _normalize_module(spec)
        if clause is None:
            self.side_effect_imports.append((module, node))
            return
        for child in clause.named_children:
            if child.type == "identifier":  # default import
                self._bind(node_text(child), module, "")
            elif child.type == "namespace_import":
                ident = next((c for c in child.named_children if c.type == "identifier"), None)
                if ident is not None:
                    self._bind(node_text(ident), module, "")
            elif child.type == "named_imports":
                for spec_node in child.named_children:
                    if spec_node.type != "import_specifier":
                        continue
                    if any(c.type == "type" for c in spec_node.children):
                        continue
                    name = spec_node.child_by_field_name("name")
                    alias = spec_node.child_by_field_name("alias") or name
                    if name is None:
                        continue
                    imported = node_text(name)
                    attr = "" if imported == "default" else imported
                    self._bind(node_text(alias), module, attr)

    def _require_declarator(self, node) -> None:
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None:
            return
        while value.type in ("await_expression", "parenthesized_expression"):
            if not value.named_children:
                return
            value = value.named_children[0]
        module = _require_module(value, self.declared)
        attr = ""
        if module is None and value.type == "member_expression":
            module = _require_module(value.child_by_field_name("object"), self.declared)
            prop = value.child_by_field_name("property")
            if module is None or prop is None:
                return
            attr = node_text(prop)
        if module is None:
            return
        if name.type == "identifier":
            self._bind(node_text(name), module, attr)
        elif name.type == "object_pattern":
            for child in name.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    self._bind(node_text(child), module, _join(attr, node_text(child)))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        self._bind(node_text(val), module, _join(attr, node_text(key)))

    def _bind(self, local: str, module: str, attr: str) -> None:
        self.bindings[local] = (module, attr)

    # -- expression resolution ------------------------------------------------

    def resolve(self, node) -> Optional[Tuple[str, str]]:
        """Resolve a callee/constructor expression to (module, attribute path)."""
        if node is None:
            return None
        t = node.type
        if t == "identifier":
            name = node_text(node)
            if name in self.bindings:
                return self.bindings[name]
            if name in self.declared:
                return None
            return GLOBAL, name
        if t == "member_expression":
            prop = node.child_by_field_name("property")
            base = self.resolve(node.child_by_field_name("object"))
            if base is None or prop is None:
                return None
            return base[0], _join(base[1], node_text(prop))
        if t == "call_expression":
            module = _require_module(node, self.declared)
            return (module, "") if module else None
        if t in ("parenthesized_expression", "non_null_expression"):
            return self.resolve(node.named_children[0]) if node.named_children else None
        return None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _in_function(node) -> bool:
    return _container(node) is not None


def _container(node) -> Optional[int]:
    parent = node.parent
    while parent is not None:
        if parent.type in _FUNCTION_NODES:
            return parent.start_byte
        parent = parent.parent
    return None


def _open_capability(call) -> Tuple[str, float]:
    """Classify fs.open by its flags argument: read-only flags → READ, else WRITE."""
    args = call.child_by_field_name("arguments")
    flags_node = args.named_children[1] if args is not None and len(args.named_children) > 1 else None
    if flags_node is None or flags_node.type in ("arrow_function", "function_expression", "function"):
        return "READ", 0.9  # default flags are "r" (a callback may take the flags slot)
    flags = string_value(flags_node)
    if flags is None:
        return "READ", 0.5
    if flags.startswith("r") and "+" not in flags:
        return "READ", 0.9
    return "WRITE", 0.9


_WRAPPER_NODES = frozenset({
    "as_expression", "satisfies_expression", "parenthesized_expression",
    "non_null_expression", "type_assertion",
})


def _unwrap(node):
    """Strip TS casts and parentheses: ("x" as any) → "x"."""
    while node is not None and node.type in _WRAPPER_NODES and node.named_children:
        node = node.named_children[0]
    return node


def _is_dynamic_argument(call) -> bool:
    """True if the single argument of import()/require() is not a plain string."""
    args = call.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return False
    return string_value(_unwrap(args.named_children[0])) is None


def _is_env_write(node) -> bool:
    """True for `delete process.env.X` and `process.env.X = ...` (not secret reads)."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "unary_expression" and any(c.type == "delete" for c in parent.children):
        return True
    if parent.type in ("assignment_expression", "augmented_assignment_expression"):
        return parent.child_by_field_name("left") == node
    return False


def scan_ts_capabilities(file_path: str, root) -> List[TSCapabilityFinding]:
    """Detect capabilities in one parsed TS/JS file (root = tree.root_node)."""
    resolver = _Resolver(root)
    results: List[TSCapabilityFinding] = []
    seen: Set[tuple] = set()

    def emit(detector: str, capability: str, evidence: str, node, confidence: float) -> None:
        lineno = node.start_point[0] + 1
        key = (detector, capability, lineno, evidence)
        if key in seen:
            return
        seen.add(key)
        results.append(TSCapabilityFinding(
            detector=detector,
            finding=CapabilityFinding(
                capability=capability,
                evidence=evidence,
                file=file_path,
                lineno=lineno,
                confidence=confidence,
            ),
            in_function=_in_function(node),
            container=_container(node),
        ))

    for module, node in resolver.side_effect_imports:
        if module in _SIDE_EFFECT_SECRET_IMPORTS:
            emit("secrets", "SECRETS", _SIDE_EFFECT_SECRET_IMPORTS[module], node, 0.9)

    for node in iter_nodes(root):
        t = node.type
        if t in ("call_expression", "new_expression"):
            is_new = t == "new_expression"
            callee = node.child_by_field_name("constructor" if is_new else "function")
            if callee is None:
                continue

            if not is_new and callee.type == "import":
                if _is_dynamic_argument(node):
                    emit("dynamic_exec", "DYNAMIC", "import() with non-literal specifier",
                         node, 0.8)
                continue
            if not is_new and callee.type == "identifier" and node_text(callee) == "require" \
                    and "require" not in resolver.declared:
                if _is_dynamic_argument(node):
                    emit("dynamic_exec", "DYNAMIC", "require() with non-literal specifier",
                         node, 0.8)
                continue

            target = resolver.resolve(callee)
            if target is None:
                continue
            module, attr = _normalize_target(*target)

            if (module, attr) in _FS_OPEN and not is_new:
                capability, confidence = _open_capability(node)
                emit("file_access", capability, f"{module}.{attr}()", node, confidence)
                continue

            sink = _SINKS.get((module, attr))
            if sink is None:
                continue
            capability, detector, label = sink
            evidence = f"new {label}()" if is_new else f"{label}()"
            confidence = 0.85 if module == GLOBAL else 0.9
            emit(detector, capability, evidence, node, confidence)

        elif t in ("member_expression", "subscript_expression"):
            # process.env.NAME / process.env["NAME"]
            obj = node.child_by_field_name("object")
            if obj is None or resolver.resolve(obj) != (GLOBAL, "process.env"):
                continue
            if _is_env_write(node):
                continue
            if t == "member_expression":
                prop = node.child_by_field_name("property")
                key = node_text(prop) if prop is not None else None
            else:
                key = string_value(node.child_by_field_name("index"))
            if key:
                emit("secrets", "SECRETS", f"process.env.{key}", node, _env_key_confidence(key))
            else:
                emit("secrets", "SECRETS", "process.env[...]", node, 0.7)

        elif t == "variable_declarator":
            # const { API_KEY, PORT } = process.env
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None or value is None or name.type != "object_pattern":
                continue
            if resolver.resolve(value) != (GLOBAL, "process.env"):
                continue
            for child in name.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    key = node_text(child)
                elif child.type == "pair_pattern":
                    key_node = child.child_by_field_name("key")
                    key = node_text(key_node) if key_node is not None else None
                else:
                    continue
                if key:
                    emit("secrets", "SECRETS", f"process.env.{key}", child,
                         _env_key_confidence(key))

    results.sort(key=lambda r: (r.finding.lineno or 0, r.detector))
    return results
