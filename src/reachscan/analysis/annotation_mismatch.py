"""
ANNOTATION_MISMATCH: MCP tool annotations contradicted by reachable capabilities.

An MCP tool's ToolAnnotations hints (readOnlyHint, openWorldHint,
destructiveHint) are claims the server makes to clients. A mismatch is
reported when a tool explicitly declares a hint and a call path from that
specific tool's entry point reaches a capability that contradicts it:

  read_only_contradicted     readOnlyHint: true    + reachable WRITE, EXECUTE, or DYNAMIC   high
  closed_world_contradicted  openWorldHint: false  + reachable outbound HTTP, websocket,
                             or raw socket connect (not to a literal loopback host)   high
  non_destructive_contradicted
                             destructiveHint: false + reachable destructive WRITE
                             (delete, move/rename, truncating write)                    medium
                             (only when readOnlyHint resolves false: the spec says
                             destructiveHint is meaningful only then)

EXECUTE doesn't count against destructiveHint: reachscan can't tell what a
command does, and on the phase-3 corpus every EXECUTE hit was a harmless
launch (V decision, 2026-10-05). It still contradicts readOnlyHint: true.

Only explicit hints are checked. Defaulted hints are the spec's conservative
values and claim nothing; unresolvable hints never produce findings. Every
mismatch carries the call path from the tool's entry point to the
contradicting sink, and a contradiction without such a path is not reported
(module-level code, which runs on import, is not a tool call path).

FastMCP tools use their decorated function as the entry node. For lowlevel
servers, a types.Tool declaration is linked to its branch in the call_tool
handler when the handler dispatches on its tool-name parameter with if/elif
`name == <literal | same-file constant | enum member>` (also inside an `and`
conjunction, e.g. `if name == "x" and arguments:`) or `match name:` cases
on the same. The tool's path then starts in that branch, plus the
handler statements outside the dispatch (shared setup that runs for every
tool). Tools that can't be linked this way get no per-tool path and so no
mismatch finding.

The result shape follows the declared-vs-inferred framing discussed for MCP
SEP-2793 (SARIF rule id "mcp-risk-mismatch"): each mismatch carries the
declared hint and the observed capability with its path.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from reachscan.call_graph import CallGraph, FunctionNode, LinenoIndex
from reachscan.py_annotations import EXPLICIT, ModuleContext, ToolAnnotationInfo
from reachscan.reachability import (
    TRAVERSAL_DEPTH,
    ReachabilityIndex,
    _bfs,
    _path_locations,
)

RULE_ID = "mcp-risk-mismatch"
RULE_READ_ONLY = "read_only_contradicted"
RULE_CLOSED_WORLD = "closed_world_contradicted"
RULE_NON_DESTRUCTIVE = "non_destructive_contradicted"

_READ_ONLY_CONTRADICTIONS = {"WRITE", "EXECUTE", "DYNAMIC"}

# WRITE evidence that deletes, moves, or truncates existing data. Appends,
# exclusive creates ("x"), mkdir, and copies are treated as additive.
_DESTRUCTIVE_WRITE_PATTERNS = [
    re.compile(p) for p in (
        r"\b(remove|unlink|rmtree|rmdir|rm|rmSync|truncate|truncateSync)\b",
        r"\b(rename|renameSync|replace|move)\b",
        r"mode='w'|mode='wb'|mode='w\+'|mode='wb\+'",
        r"\b(write_text|write_bytes)\b",
        r"\b(writeFile|writeFileSync|createWriteStream)\b",
    )
]


def is_destructive_write(evidence: str) -> bool:
    return any(p.search(evidence or "") for p in _DESTRUCTIVE_WRITE_PATTERNS)


# openWorldHint: false is contradicted only by outbound sends of these kinds
# (V decision, 2026-10-05):
#   HTTP       requests, httpx, aiohttp, urllib, urllib3, http, or an http(s):// URL
#   websocket  websocket, websockets, or a ws(s):// URL
#   socket     raw socket connects (socket/ssl/asyncio), except to a literal
#              loopback host (localhost, 127.0.0.0/8, ::1)
# Excluded: calls resolving to the project's own modules (a project wrapper's
# .connect() isn't evidence; library calls inside it are separate findings),
# database drivers, and other protocol clients, whose connections are the
# tool's configured, closed domain under the spec's open/closed-world wording.
_HTTP_ROOTS = {"requests", "httpx", "aiohttp", "urllib", "urllib3", "http"}
_WEBSOCKET_ROOTS = {"websocket", "websockets"}
_SOCKET_ROOTS = {"socket", "ssl", "asyncio"}
_SOCKET_CONNECT_CALLS = {"create_connection", "open_connection", "connect"}


def _is_loopback(host: str) -> bool:
    import ipaddress
    host = host.strip().strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@lru_cache(maxsize=256)
def _parse_file(path: str):
    try:
        return ast.parse(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, ValueError, OSError):
        return None


def _socket_host_literal(file: str, lineno: Optional[int], call_name: str) -> Optional[str]:
    """The literal host argument of a socket connect call at file:lineno, if any."""
    tree = _parse_file(file)
    if tree is None or lineno is None:
        return None
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node, "lineno", None) == lineno):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != call_name:
            continue
        candidates = list(node.args[:1]) + [kw.value for kw in node.keywords
                                            if kw.arg in ("host", "address")]
        for arg in candidates:
            if isinstance(arg, ast.Tuple) and arg.elts:
                arg = arg.elts[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
    return None


def _root_is_project_module(file: str, root: str, project_root: Optional[Path]) -> bool:
    """True when `root` in this file is imported from a module inside the project."""
    if project_root is None:
        return False
    tree = _parse_file(file)
    if tree is None:
        return False
    from reachscan.call_graph import _resolve_module_to_file
    current = Path(file).resolve()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == root:
                    if _resolve_module_to_file(alias.name, project_root, current, 0):
                        return True
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == root:
                    module = ".".join(p for p in (node.module or "", alias.name) if p)
                    if _resolve_module_to_file(module, project_root, current, node.level) or \
                            _resolve_module_to_file(node.module or "", project_root, current, node.level):
                        return True
    return False


def outbound_send_kind(finding: dict, project_root: Optional[Path] = None) -> Optional[str]:
    """Classify a SEND finding for the openWorldHint rule: "HTTP", "websocket", "socket", or None."""
    evidence = finding.get("evidence") or ""
    base, _, target = evidence.partition(" -> ")
    parts = base.split(".")
    root = parts[0]
    file = finding.get("file") or ""

    if root in _HTTP_ROOTS | _WEBSOCKET_ROOTS | _SOCKET_ROOTS:
        if file and _root_is_project_module(file, root, project_root):
            return None  # a project module shadowing a library name
        if root in _HTTP_ROOTS:
            return "HTTP"
        if root in _WEBSOCKET_ROOTS:
            return "websocket"
        call = parts[-1]
        if call not in _SOCKET_CONNECT_CALLS:
            return None  # e.g. socket.socket(): creating a socket isn't an outbound connect
        host = _socket_host_literal(file, finding.get("lineno"), call)
        if host is not None and _is_loopback(host):
            return None
        return "socket"

    url = target.strip().lower()
    if url.startswith(("http://", "https://")):
        return "HTTP"
    if url.startswith(("ws://", "wss://")):
        return "websocket"
    return None


@dataclass
class ToolTarget:
    """One MCP tool to check: its annotations and its own reach map."""
    tool: str
    entry_point: object                 # py_entry_points.EntryPoint
    annotations: ToolAnnotationInfo
    entry_node: FunctionNode
    reach: Dict[FunctionNode, List[FunctionNode]]
    dispatch: str                       # "decorator" | "lowlevel"
    # For lowlevel tools: line ranges of the handler that belong to this tool
    # (its branch plus shared setup). Sinks directly inside the handler count
    # only within these ranges. None means the whole entry function.
    entry_line_ranges: Optional[List[Tuple[int, int]]] = None


@dataclass
class LinkageStats:
    linked: List[str] = field(default_factory=list)
    unlinked: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _contradictions(annotations: ToolAnnotationInfo, capability: str, evidence: str,
                    send_kind: Optional[str] = None):
    """Yield (rule, hint, declared value, risk level) for each rule this sink breaks.

    send_kind is the outbound_send_kind() of a SEND sink (None if excluded).
    """
    ro = annotations.read_only
    if ro.source == EXPLICIT and ro.value is True and capability in _READ_ONLY_CONTRADICTIONS:
        yield RULE_READ_ONLY, "readOnlyHint", True, "high"
    ow = annotations.open_world
    if ow.source == EXPLICIT and ow.value is False and capability == "SEND" and send_kind:
        yield RULE_CLOSED_WORLD, "openWorldHint", False, "medium"
    de = annotations.destructive
    if (
        de.source == EXPLICIT and de.value is False
        and ro.value is False  # destructiveHint is meaningful only when readOnlyHint is false
        and capability == "WRITE" and is_destructive_write(evidence)
    ):
        yield RULE_NON_DESTRUCTIVE, "destructiveHint", False, "medium"


def _message(tool: str, hint: str, value: bool, capability: str, evidence: str,
             send_kind: Optional[str] = None) -> str:
    claim = f"{hint}: {str(value).lower()}"
    if hint == "openWorldHint" and send_kind:
        return f"Tool '{tool}' declares {claim}; reaches outbound {send_kind} call: {evidence}."
    return f"Tool '{tool}' declares {claim}, but a call path from the tool reaches {capability} via {evidence}."


# ---------------------------------------------------------------------------
# Lowlevel dispatch linkage
# ---------------------------------------------------------------------------

def _resolve_str(node: ast.expr, ctx: ModuleContext) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        ref = ctx.assignments.get(node.id)
        if isinstance(ref, ast.Constant) and isinstance(ref.value, str):
            return ref.value
        return None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return ctx.class_strings.get((node.value.id, node.attr))
    return None


def _compare_value(test: ast.expr, param: str, ctx: ModuleContext) -> Optional[str]:
    """Tool name for `param == X` or `X == param`, else None."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Name) and left.id == param:
        return _resolve_str(right, ctx)
    if isinstance(right, ast.Name) and right.id == param:
        return _resolve_str(left, ctx)
    return None


def _tool_name_test(test: ast.expr, param: str, ctx: ModuleContext) -> Optional[str]:
    """Tool name selected by an if/elif test, or None.

    Accepts the plain comparison `param == X` (see _compare_value) and `and`
    conjunctions where operands include that comparison, e.g.
    `if name == "x" and arguments:`. Nested `and`s are flattened. The test
    must name exactly one tool; `or`, conflicting names, or no comparison at
    all return None.
    """
    value = _compare_value(test, param, ctx)
    if value is not None:
        return value
    if not (isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And)):
        return None
    names = set()
    stack = list(test.values)
    while stack:
        operand = stack.pop()
        if isinstance(operand, ast.BoolOp) and isinstance(operand.op, ast.And):
            stack.extend(operand.values)
            continue
        name = _compare_value(operand, param, ctx)
        if name is not None:
            names.add(name)
    return names.pop() if len(names) == 1 else None


def _case_values(pattern: ast.pattern, ctx: ModuleContext) -> Optional[List[str]]:
    if isinstance(pattern, ast.MatchValue):
        value = _resolve_str(pattern.value, ctx)
        return [value] if value is not None else None
    if isinstance(pattern, ast.MatchOr):
        values = []
        for sub in pattern.patterns:
            sub_values = _case_values(sub, ctx)
            if sub_values is None:
                return None
            values.extend(sub_values)
        return values
    return None


def _walk_no_nested_defs(nodes: Iterable[ast.AST]):
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                stack.append(child)


def _dispatch_branches(func: ast.AST, param: str, ctx: ModuleContext):
    """Return ({tool name → branch statements}, [dispatch statements])."""
    branches: Dict[str, List[ast.stmt]] = {}
    dispatch_nodes: List[ast.stmt] = []
    inside_dispatch: set = set()
    for node in _walk_no_nested_defs(func.body):
        if id(node) in inside_dispatch:
            continue
        if isinstance(node, ast.Match) and isinstance(node.subject, ast.Name) \
                and node.subject.id == param:
            matched = False
            for case in node.cases:
                values = _case_values(case.pattern, ctx) if case.guard is None else None
                for value in values or []:
                    branches.setdefault(value, case.body)
                    matched = True
            if matched:
                dispatch_nodes.append(node)
                inside_dispatch.update(id(n) for n in ast.walk(node))
        elif isinstance(node, ast.If) and _tool_name_test(node.test, param, ctx) is not None:
            matched = False
            current: Optional[ast.If] = node
            while current is not None:
                value = _tool_name_test(current.test, param, ctx)
                if value is None:
                    break
                branches.setdefault(value, current.body)
                matched = True
                orelse = current.orelse
                current = orelse[0] if len(orelse) == 1 and isinstance(orelse[0], ast.If) else None
            if matched:
                dispatch_nodes.append(node)
                inside_dispatch.update(id(n) for n in ast.walk(node))
    return branches, dispatch_nodes


def _line_ranges(stmts: Sequence[ast.stmt]) -> List[Tuple[int, int]]:
    return [(s.lineno, getattr(s, "end_lineno", s.lineno) or s.lineno) for s in stmts]


def _callee_names(stmts: Sequence[ast.stmt]) -> List[str]:
    names = []
    for node in _walk_no_nested_defs(stmts):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(func.attr)
    return names


def _lowlevel_targets(
    py_entry_points: list,
    index: ReachabilityIndex,
    graph: CallGraph,
    lineno_index: LinenoIndex,
    stats: LinkageStats,
) -> List[ToolTarget]:
    from reachscan.py_entry_points import _collect_imports, _decorator_key

    targets: List[ToolTarget] = []
    by_file: Dict[str, List[int]] = {}
    for idx, ep in enumerate(py_entry_points):
        by_file.setdefault(ep.file, []).append(idx)

    for file, idxs in by_file.items():
        declared = [t for i in idxs for t in py_entry_points[i].declared_tools]
        if not declared:
            continue
        try:
            tree = ast.parse(Path(file).read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, ValueError, OSError):
            stats.unlinked.extend(t.name for t in declared)
            continue
        ctx = ModuleContext.from_tree(tree, _collect_imports(tree))

        # The call_tool handler in this file, matched to its entry point by line.
        handler = handler_idx = None
        lines = {py_entry_points[i].lineno: i for i in idxs}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno in lines \
                    and any(_decorator_key(d)[0] == "call_tool" for d in node.decorator_list):
                handler, handler_idx = node, lines[node.lineno]
                break
        positional = [*(handler.args.posonlyargs if handler else []), *(handler.args.args if handler else [])]
        params = [a.arg for a in positional if a.arg not in ("self", "cls")]
        if handler is None or handler_idx not in index.entry_nodes or not params:
            stats.unlinked.extend(t.name for t in declared)
            continue

        entry_node = index.entry_nodes[handler_idx]
        branches, dispatch_nodes = _dispatch_branches(handler, params[0], ctx)
        dispatch_ids = {id(n) for n in dispatch_nodes}
        shared = [stmt for stmt in handler.body if id(stmt) not in dispatch_ids]
        callees = graph.get(entry_node, set())

        for tool in declared:
            branch = branches.get(tool.name)
            if branch is None:
                stats.unlinked.append(tool.name)
                continue
            stats.linked.append(tool.name)
            stmts = [*branch, *shared]
            reach: Dict[FunctionNode, List[FunctionNode]] = {entry_node: [entry_node]}
            for name in set(_callee_names(stmts)):
                candidates = [n for n in callees if n[1].split(".")[-1] == name]
                if len(candidates) != 1:
                    continue  # unknown or ambiguous: no claimed path
                for node, path in _bfs(candidates[0], graph, TRAVERSAL_DEPTH - 1)[0].items():
                    full = [entry_node, *path]
                    if node not in reach or len(full) < len(reach[node]):
                        reach[node] = full
            targets.append(ToolTarget(
                tool=tool.name,
                entry_point=py_entry_points[handler_idx],
                annotations=tool.annotations,
                entry_node=entry_node,
                reach=reach,
                dispatch="lowlevel",
                entry_line_ranges=_line_ranges(stmts),
            ))
    return targets


# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------

def _decorator_targets(py_entry_points: list, index: ReachabilityIndex) -> List[ToolTarget]:
    targets = []
    for idx, ep in enumerate(py_entry_points):
        if ep.annotations is None or idx not in index.reached:
            continue
        targets.append(ToolTarget(
            tool=ep.name,
            entry_point=ep,
            annotations=ep.annotations,
            entry_node=index.entry_nodes[idx],
            reach=index.reached[idx],
            dispatch="decorator",
        ))
    return targets


def _in_ranges(lineno: Optional[int], ranges: Optional[List[Tuple[int, int]]]) -> bool:
    if ranges is None:
        return True
    return lineno is not None and any(start <= lineno <= end for start, end in ranges)


def find_annotation_mismatches(
    findings: List[dict],
    py_entry_points: list,
    index: ReachabilityIndex,
    graph: CallGraph,
    lineno_index: LinenoIndex,
    project_root: Optional[Path] = None,
) -> Tuple[List[dict], LinkageStats]:
    """Return (mismatch dicts, lowlevel linkage stats)."""
    if project_root is not None:
        project_root = Path(project_root).resolve()
        if project_root.is_file():
            project_root = project_root.parent
    stats = LinkageStats()
    targets = _decorator_targets(py_entry_points, index)
    targets += _lowlevel_targets(py_entry_points, index, graph, lineno_index, stats)

    grouped: Dict[tuple, dict] = {}
    for target in targets:
        if not any(h.source == EXPLICIT for h in target.annotations.hints().values()):
            continue
        for finding in findings:
            fid = finding.get("finding_id")
            node = index.containing.get(fid)
            if node is None or node not in target.reach:
                continue
            if node == target.entry_node and not _in_ranges(finding.get("lineno"), target.entry_line_ranges):
                continue
            capability = finding.get("capability", "")
            evidence = finding.get("evidence", "")
            send_kind = outbound_send_kind(finding, project_root) if capability == "SEND" else None
            for rule, hint, value, risk in _contradictions(target.annotations, capability, evidence,
                                                           send_kind):
                path_nodes = target.reach[node]
                ep = target.entry_point
                observation = {
                    "capability": capability,
                    **({"send_kind": send_kind} if rule == RULE_CLOSED_WORLD else {}),
                    "evidence": evidence,
                    "file": finding.get("file"),
                    "lineno": finding.get("lineno"),
                    "finding_id": fid,
                    "reachability_path": [qual for _file, qual in path_nodes],
                }
                key = (target.tool, ep.file, rule)
                if key in grouped:
                    grouped[key]["additional_observations"].append(observation)
                    grouped[key]["_locations_by_finding"][fid] = _path_locations(path_nodes, lineno_index)
                    continue
                grouped[key] = ({
                    "rule_id": RULE_ID,
                    "rule": rule,
                    "risk_level": risk,
                    "tool": target.tool,
                    "entry_point": {
                        "name": ep.name,
                        "file": ep.file,
                        "lineno": ep.lineno,
                        "dispatch": target.dispatch,
                    },
                    "declared": {"hint": hint, "value": value},
                    "observed": {
                        "capability": capability,
                        **({"send_kind": send_kind} if rule == RULE_CLOSED_WORLD else {}),
                        "evidence": evidence,
                        "file": finding.get("file"),
                        "lineno": finding.get("lineno"),
                        "finding_id": fid,
                    },
                    "reachability_path": [qual for _file, qual in path_nodes],
                    "reachability_path_locations": _path_locations(path_nodes, lineno_index),
                    "_locations_by_finding": {},
                    "message": _message(target.tool, hint, value, capability, evidence, send_kind),
                    "mismatch_id": hashlib.sha1(
                        f"{target.tool}|{ep.file}|{rule}".encode()
                    ).hexdigest()[:12],
                    "additional_observations": [],
                })

    # The primary observation is the one with the shortest path (then file/line);
    # the rest stay listed as additional observations of the same false claim.
    mismatches: List[dict] = []
    for m in grouped.values():
        primary = {**m["observed"], "reachability_path": m["reachability_path"]}
        candidates = [primary, *m["additional_observations"]]
        candidates.sort(key=lambda o: (len(o["reachability_path"]), o["file"] or "", o["lineno"] or 0))
        if candidates[0] is not primary:
            best = candidates[0]
            m["observed"] = {k: v for k, v in best.items() if k != "reachability_path"}
            m["reachability_path"] = best["reachability_path"]
            m["message"] = _message(m["tool"], m["declared"]["hint"], m["declared"]["value"],
                                    best["capability"], best["evidence"], best.get("send_kind"))
            m["reachability_path_locations"] = m["_locations_by_finding"][best["finding_id"]]
        m["additional_observations"] = candidates[1:]
        m.pop("_locations_by_finding", None)
        mismatches.append(m)
    order = {"high": 0, "medium": 1}
    mismatches.sort(key=lambda m: (order.get(m["risk_level"], 2), m["tool"], m["observed"]["file"] or "",
                                   m["observed"]["lineno"] or 0))
    return mismatches, stats


def unresolvable_annotations(py_entry_points: list) -> List[dict]:
    """Tools whose annotations (or some hints) couldn't be resolved, for --explain."""
    notes = []

    def add(tool: str, file: str, lineno: int, ann: ToolAnnotationInfo) -> None:
        hints = [k for k, v in ann.hints().items() if v.source == "unresolvable"]
        if hints:
            notes.append({
                "tool": tool, "file": file, "lineno": lineno, "hints": hints,
                "reason": "annotations passed by a reference that couldn't be resolved"
                if ann.unresolved_reference else "non-literal or SDK-version-dependent hint values",
            })

    for ep in py_entry_points:
        if ep.annotations is not None:
            add(ep.name, ep.file, ep.lineno, ep.annotations)
        for tool in ep.declared_tools:
            add(tool.name, ep.file, tool.lineno, tool.annotations)
    return notes


__all__ = [
    "RULE_ID",
    "RULE_READ_ONLY",
    "RULE_CLOSED_WORLD",
    "RULE_NON_DESTRUCTIVE",
    "find_annotation_mismatches",
    "is_destructive_write",
    "outbound_send_kind",
    "unresolvable_annotations",
]
