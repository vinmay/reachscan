"""
Reachability analysis data model and constants.

This module defines the four reachability states, depth limits, and the
ReachabilityResult dataclass. Analysis logic lives here in a later step;
this file is the data contract between the call graph (Step 3) and the
scanner/reporter (Steps 4-5).

Reachability states:
    REACHABLE       — confirmed on a call path from an entry point within
                      TRAVERSAL_DEPTH hops.
    UNREACHABLE     — entry points exist but this finding is not on any path
                      from them within TRAVERSAL_DEPTH hops. The capability
                      exists but the LLM probably cannot trigger it directly.
    NO_ENTRY_POINTS — no entry points were detected in this codebase. Cannot
                      assess reachability; the codebase may use an unrecognised
                      framework or may be a library rather than an agent.
    MODULE_LEVEL    — this finding is in module-level code (outside any
                      function). It executes on import, not on any LLM call
                      path, so its reachability cannot be assessed by tracing
                      function calls.
    UNKNOWN         — this specific finding is inside code that cannot be
                      statically resolved: dynamic dispatch via getattr,
                      string-based routing, nested functions not in the call
                      graph, or files that failed to parse. Rare; worth
                      surfacing explicitly when it occurs.

Depth constants:
    TRAVERSAL_DEPTH — maximum hops the BFS follows before stopping.
    DISPLAY_DEPTH   — maximum hops shown in text output. Paths longer than
                      this are truncated, always preserving the entry point
                      and the terminal finding. Full path is always stored in
                      JSON output regardless of this limit.
"""

from __future__ import annotations

import bisect
import warnings
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from reachscan.call_graph import CallGraph, FunctionNode, LinenoIndex, MODULE_LEVEL
from reachscan.py_entry_points import PATTERN_CLASS_ATTRIBUTE

# ---------------------------------------------------------------------------
# Reachability state constants
# ---------------------------------------------------------------------------

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
NO_ENTRY_POINTS = "no_entry_points"
MODULE_LEVEL_STATE = "module_level"
UNKNOWN = "unknown"

REACHABILITY_STATES = frozenset({REACHABLE, UNREACHABLE, NO_ENTRY_POINTS, MODULE_LEVEL_STATE, UNKNOWN})

# ---------------------------------------------------------------------------
# Depth limits
# ---------------------------------------------------------------------------

TRAVERSAL_DEPTH = 8   # max call hops the BFS will follow
DISPLAY_DEPTH = 5     # max hops rendered in text output before truncation

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReachabilityResult:
    """
    Reachability verdict for a single finding.

    Produced by the reachability analysis pass and written into the finding
    dict under the keys defined in REACHABILITY_FIELDS below.

    Fields:
        state             — one of the four REACHABILITY_STATES constants
        entry_point_name  — name of the entry point that reaches this finding,
                            or None if state is not REACHABLE
        path              — full call chain from entry point to the function
                            containing the finding, e.g.:
                            ["read_logs", "process_auth", "os.getenv"]
                            Empty list when state is not REACHABLE.
        path_truncated    — True if len(path) > DISPLAY_DEPTH. The full path
                            is always stored; truncation is a display hint only.
    """
    state: str
    entry_point_name: Optional[str] = None
    path: List[str] = field(default_factory=list)
    path_truncated: bool = False

    def as_finding_fields(self) -> dict:
        """Return the dict fragment written into a finding."""
        return {
            "reachability": self.state,
            "entry_point_name": self.entry_point_name,
            "reachability_path": self.path if self.path else None,
            "reachability_path_truncated": self.path_truncated,
        }


# ---------------------------------------------------------------------------
# Finding schema field names (single source of truth)
# ---------------------------------------------------------------------------

# These keys are added to every finding dict by finding_enrichment.py with
# None defaults, then overwritten by the reachability pass.
REACHABILITY_FIELDS = (
    "reachability",
    "entry_point_name",
    "reachability_path",
    "reachability_path_truncated",
)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _canonical_file(file: str, lineno_index: LinenoIndex) -> Optional[str]:
    """Return the key in lineno_index for a given file path, or None if not found.

    Tries the raw string first, then the resolved absolute path as a fallback
    to handle cases where entry point files and lineno_index keys were created
    with different resolution levels.
    """
    if file in lineno_index:
        return file
    resolved = str(Path(file).resolve(strict=False))
    if resolved in lineno_index:
        return resolved
    return None


def _find_class_run_method(class_lineno: int, file_map: Dict[int, str]) -> Optional[str]:
    """For a class-based entry point at class_lineno, find its _run/_arun/__call__ method.

    Class definition lines are NOT recorded in lineno_index (only function/method
    start lines are). This fallback scans forward from class_lineno and returns
    the first method whose qualified name ends with ._run, ._arun, or .__call__.

    Stops early if a bare name (top-level function) is encountered, which signals
    that we've left the class body.
    """
    _RUN_SUFFIXES = ("._run", "._arun", ".__call__")
    for lineno in sorted(k for k in file_map if k > class_lineno):
        qual, _end = file_map[lineno]
        if qual.endswith(_RUN_SUFFIXES):
            return qual
        # A bare name (no dot) means a new top-level function — we've exited the class
        if "." not in qual:
            break
    return None


def _containing_function(
    file: str, lineno: int, lineno_index: LinenoIndex
) -> Optional[Tuple[str, str]]:
    """Return (canonical_file, qual_name) for the function enclosing lineno.

    Uses bisect on sorted lineno keys, then walks backward to handle nested
    functions correctly. A nested function (e.g. a local ``def`` inside an
    outer function) has a limited span; once its ``end_lineno`` is passed,
    subsequent lines belong to the enclosing function, not the nested one.

    The sentinel 0 → (MODULE_LEVEL, None) is always present, so the result is
    always defined when the file exists in the index.
    Returns None if file is not in lineno_index (parse failed for that file).
    """
    canonical = _canonical_file(file, lineno_index)
    if canonical is None:
        return None
    file_map = lineno_index[canonical]
    sorted_keys = sorted(file_map.keys())
    idx = bisect.bisect_right(sorted_keys, lineno) - 1
    if idx < 0:
        return None

    # Walk backward from the bisect hit: the first function whose end_lineno
    # covers our target line (or has no end_lineno, like MODULE_LEVEL) is the
    # true enclosing scope.
    while idx >= 0:
        qual, end_lineno = file_map[sorted_keys[idx]]
        if end_lineno is None or lineno <= end_lineno:
            return (canonical, qual)
        idx -= 1

    return None


# ---------------------------------------------------------------------------
# BFS
# ---------------------------------------------------------------------------

def _bfs(
    start: FunctionNode,
    graph: CallGraph,
    max_depth: int,
    visited_cap: int = 50_000,
) -> Tuple[Dict[FunctionNode, List[str]], int]:
    """BFS from start, up to max_depth hops.

    Returns:
        reached: {FunctionNode → path_of_qualnames} for every reached node.
                 path_of_qualnames[0] is the start node's qualname;
                 len(path) - 1 equals the number of hops.
        nodes_skipped_by_depth: count of unvisited children skipped because
                                 their parent was already at max_depth.
    """
    queue: deque = deque()
    queue.append((start, [start[1]]))
    visited: set = {start}
    reached: Dict[FunctionNode, List[str]] = {}
    nodes_skipped_by_depth = 0

    while queue:
        if len(visited) >= visited_cap:
            warnings.warn(
                f"BFS cap hit at {len(visited)} nodes — graph may be very large; "
                "partial reachability result returned"
            )
            break

        node, path = queue.popleft()
        reached[node] = path

        if len(path) - 1 >= max_depth:
            # Depth limit reached — count unvisited children as skipped
            for child in graph.get(node, set()):
                if child not in visited:
                    nodes_skipped_by_depth += 1
            continue

        for child in graph.get(node, set()):
            if child not in visited:
                visited.add(child)
                queue.append((child, path + [child[1]]))

    return reached, nodes_skipped_by_depth


# ---------------------------------------------------------------------------
# Main reachability pass
# ---------------------------------------------------------------------------

def analyze_reachability(
    findings: List[dict],
    py_entry_points: list,
    graph: CallGraph,
    lineno_index: LinenoIndex,
) -> None:
    """Tag each finding dict with its reachability state. Mutates findings in place.

    Also populates EntryPoint.reachable_findings for each REACHABLE finding.

    Args:
        findings:         List of enriched finding dicts (from scanner.py).
        py_entry_points:  List of EntryPoint objects (from py_entry_points.py).
        graph:            CallGraph from build_call_graph().
        lineno_index:     LinenoIndex from build_call_graph().
    """
    for f in findings:
        assert "reachability" in f, f"Finding missing reachability field: {f}"

    if not py_entry_points:
        for f in findings:
            f.update(ReachabilityResult(state=NO_ENTRY_POINTS).as_finding_fields())
        return

    # BFS from every entry point; accumulate best (shortest, then alphabetical) path
    reachable_from: Dict[FunctionNode, Tuple[str, int, List[str]]] = {}
    # ^ node → (ep_name, ep_idx, path)
    total_nodes_skipped = 0

    for ep_idx, ep in enumerate(py_entry_points):
        canonical = _canonical_file(ep.file, lineno_index)
        if canonical is None:
            continue
        entry = lineno_index[canonical].get(ep.lineno)
        py_name = entry[0] if entry is not None else None
        if (py_name is None or py_name == MODULE_LEVEL) and ep.pattern_type == PATTERN_CLASS_ATTRIBUTE:
            # Class definition lines are not in lineno_index — fall back to the
            # _run / _arun / __call__ method defined in the class body.
            py_name = _find_class_run_method(ep.lineno, lineno_index[canonical])
        if py_name is None or py_name == MODULE_LEVEL:
            continue

        start: FunctionNode = (canonical, py_name)
        reached, nodes_skipped = _bfs(start, graph, TRAVERSAL_DEPTH)
        total_nodes_skipped += nodes_skipped

        for node, path in reached.items():
            existing = reachable_from.get(node)
            if existing is None:
                reachable_from[node] = (ep.name, ep_idx, path)
            else:
                # Tiebreaker: shorter path wins; on equal length, ep.name alphabetically first
                if (len(path), ep.name) < (len(existing[2]), existing[0]):
                    reachable_from[node] = (ep.name, ep_idx, path)

    if total_nodes_skipped > 0:
        warnings.warn(
            f"Reachability: {total_nodes_skipped} nodes skipped — "
            "consider raising TRAVERSAL_DEPTH"
        )

    # Tag each finding
    for finding in findings:
        file = finding["file"]
        lineno = finding["lineno"]
        containing = _containing_function(file, lineno, lineno_index)

        if containing is None:
            warnings.warn(
                f"Reachability: {file} not in lineno index — marking UNKNOWN"
            )
            finding.update(ReachabilityResult(state=UNKNOWN).as_finding_fields())
        elif containing[1] == MODULE_LEVEL:
            finding.update(ReachabilityResult(state=MODULE_LEVEL_STATE).as_finding_fields())
        elif containing in reachable_from:
            ep_name, ep_idx, path = reachable_from[containing]
            path_truncated = len(path) > DISPLAY_DEPTH
            finding.update(ReachabilityResult(
                state=REACHABLE,
                entry_point_name=ep_name,
                path=path,
                path_truncated=path_truncated,
            ).as_finding_fields())
            finding_id = finding.get("finding_id")
            if finding_id is not None:
                py_entry_points[ep_idx].reachable_findings.append(finding_id)
        elif containing not in graph:
            # Containing function is not in the call graph (e.g. nested function
            # not resolvable as a project function) — reachability is undecidable.
            finding.update(ReachabilityResult(state=UNKNOWN).as_finding_fields())
        else:
            finding.update(ReachabilityResult(state=UNREACHABLE).as_finding_fields())
