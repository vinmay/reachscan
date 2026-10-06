"""
Project-level network pass: sends through HTTP clients returned by project helpers.

The per-file network detector sees `session.post(...)` only when `session` is
assigned from a client constructor in the same file. A common pattern hides
that send:

    # helpers.py
    def get_requests_session():
        session = requests.Session()
        session.mount("https://", HTTPAdapter(max_retries=retry))
        return session

    # server.py
    with get_requests_session() as session:
        session.post(ENDPOINT, json=payload)

This pass finds client factories (project functions that return an HTTP
client on every path) and flags send-method calls on clients obtained from
them. Resolution is one hop: a factory must construct the client itself;
factories returning other factories' results are not followed.

Client factories (every return path, including falling off the end, must
return one of these, either directly or through a local variable assigned only
from one):
  requests.Session() / requests.session() / the requests module itself
  httpx.Client() / httpx.AsyncClient()
  aiohttp.ClientSession()
  urllib3.PoolManager()

Only send methods are evidence. Configuration calls (mount, headers.update,
close, ...) on these clients stay non-evidence, as in the per-file detector.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .base import CapabilityFinding

# (module, constructor attribute) → client label used in evidence
_CLIENT_CONSTRUCTORS: Dict[Tuple[str, str], str] = {
    ("requests", "Session"): "requests.Session",
    ("requests", "session"): "requests.Session",
    ("httpx", "Client"): "httpx.Client",
    ("httpx", "AsyncClient"): "httpx.AsyncClient",
    ("aiohttp", "ClientSession"): "aiohttp.ClientSession",
    ("urllib3", "PoolManager"): "urllib3.PoolManager",
}
_COMMON_SEND_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "options"}
_SEND_METHODS: Dict[str, Set[str]] = {
    "requests.Session": _COMMON_SEND_METHODS | {"send"},
    "requests": _COMMON_SEND_METHODS,
    "httpx.Client": _COMMON_SEND_METHODS | {"send", "stream"},
    "httpx.AsyncClient": _COMMON_SEND_METHODS | {"send", "stream"},
    "aiohttp.ClientSession": _COMMON_SEND_METHODS | {"ws_connect"},
    "urllib3.PoolManager": {"request", "urlopen", "request_encode_url", "request_encode_body"},
}


def _imports(tree: ast.Module) -> Dict[str, Tuple[str, int, Optional[str]]]:
    """local name → (module, level, imported name or None for `import x`)."""
    out: Dict[str, Tuple[str, int, Optional[str]]] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = (alias.name, 0, None)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                out[alias.asname or alias.name] = (node.module or "", node.level, alias.name)
    return out


def _walk_function(fn: ast.AST):
    """Nodes in a function body, not descending into nested defs, classes, or lambdas."""
    stack = list(getattr(fn, "body", []))
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(child)


def _client_label(expr: ast.expr, imps) -> Optional[str]:
    """Client label for a constructor call, or for the requests module name itself."""
    if isinstance(expr, ast.Name):
        imported = imps.get(expr.id)
        if imported and imported[2] is None and imported[0] == "requests":
            return "requests"  # the module: requests.get(...) etc.
        return None
    if not isinstance(expr, ast.Call):
        return None
    func = expr.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        imported = imps.get(func.value.id)
        if imported and imported[2] is None:
            return _CLIENT_CONSTRUCTORS.get((imported[0], func.attr))
        return None
    if isinstance(func, ast.Name):
        imported = imps.get(func.id)
        if imported and imported[2] is not None:
            return _CLIENT_CONSTRUCTORS.get((imported[0], imported[2]))
    return None


def _ends_with_return(body: List[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], ast.Return)


def _factory_label(fn: ast.AST, imps) -> Optional[str]:
    """Client label if every return path of fn returns the same kind of client."""
    if not _ends_with_return(fn.body):
        return None  # can fall off the end (implicit None)
    var_labels: Dict[str, Set[Optional[str]]] = {}
    for node in _walk_function(fn):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name):
                    var_labels.setdefault(target.id, set()).add(
                        _client_label(value, imps) if value is not None else None
                    )
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            return None  # generators / context-manager factories are out of scope
    labels: Set[Optional[str]] = set()
    returns = [n for n in _walk_function(fn) if isinstance(n, ast.Return)]
    for ret in returns:
        value = ret.value
        if value is None:
            return None
        label = _client_label(value, imps)
        if label is None and isinstance(value, ast.Name):
            assigned = var_labels.get(value.id, set())
            label = assigned.pop() if len(assigned) == 1 else None
        labels.add(label)
    if len(labels) != 1 or None in labels:
        return None  # mixed or non-client return types
    return labels.pop()


def scan_client_factory_sends(py_files: List[Path], root: Path) -> List[CapabilityFinding]:
    """SEND findings for send-method calls on clients returned by project helpers."""
    from reachscan.call_graph import _resolve_module_to_file  # local import: avoids a cycle

    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    trees: Dict[str, ast.Module] = {}
    imports: Dict[str, dict] = {}
    for path in py_files:
        key = str(Path(path).resolve())
        try:
            trees[key] = ast.parse(Path(path).read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, ValueError, OSError):
            continue
        imports[key] = _imports(trees[key])

    # 1. Client factories: top-level functions only
    factories: Dict[Tuple[str, str], str] = {}
    for file, tree in trees.items():
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                label = _factory_label(node, imports[file])
                if label:
                    factories[(file, node.name)] = label
    if not factories:
        return []

    findings: List[CapabilityFinding] = []
    for file, tree in trees.items():
        imps = imports[file]
        current = Path(file)

        def factory_for(func: ast.expr) -> Optional[Tuple[str, str]]:
            """(factory name, client label) when func names a project client factory."""
            if isinstance(func, ast.Name):
                if (file, func.id) in factories:
                    return func.id, factories[(file, func.id)]
                imported = imps.get(func.id)
                if imported and imported[2] is not None:
                    target = _resolve_module_to_file(imported[0], root, current, imported[1])
                    if target and (target, imported[2]) in factories:
                        return imported[2], factories[(target, imported[2])]
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                imported = imps.get(func.value.id)
                if imported:
                    module = imported[0] if imported[2] is None else ".".join(
                        p for p in (imported[0], imported[2]) if p)
                    target = _resolve_module_to_file(module, root, current, imported[1])
                    if target and (target, func.attr) in factories:
                        return func.attr, factories[(target, func.attr)]
            return None

        def factory_call(expr: Optional[ast.expr]) -> Optional[Tuple[str, str]]:
            if isinstance(expr, ast.Await):
                expr = expr.value
            if isinstance(expr, ast.Call):
                return factory_for(expr.func)
            return None

        scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for scope in scopes:
            nodes = list(_walk_function(scope)) if scope is not tree else [
                n for stmt in tree.body
                if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                for n in ast.walk(stmt)
            ]
            bound: Dict[str, Tuple[str, str]] = {}
            for node in nodes:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    hit = factory_call(node.value)
                    if hit:
                        bound[node.targets[0].id] = hit
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        hit = factory_call(item.context_expr)
                        if hit and isinstance(item.optional_vars, ast.Name):
                            bound[item.optional_vars.id] = hit
            seen: Set[int] = set()
            for node in nodes:
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.lineno in seen:
                    continue
                method, receiver = node.func.attr, node.func.value
                hit = bound.get(receiver.id) if isinstance(receiver, ast.Name) else factory_call(receiver)
                if not hit:
                    continue
                factory, label = hit
                if method not in _SEND_METHODS.get(label, set()):
                    continue  # configuration calls (mount, headers.update, close, ...) aren't sends
                seen.add(node.lineno)
                findings.append(CapabilityFinding(
                    capability="SEND",
                    evidence=f"{label}.{method} (client from {factory}())",
                    file=file,
                    lineno=node.lineno,
                    confidence=0.9,
                ))
    return findings
