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
    UNKNOWN         — this specific finding is inside code that cannot be
                      statically resolved: dynamic dispatch via getattr,
                      string-based routing, or generated callsites. Rare;
                      worth surfacing explicitly when it occurs.

Depth constants:
    TRAVERSAL_DEPTH — maximum hops the BFS follows before stopping.
    DISPLAY_DEPTH   — maximum hops shown in text output. Paths longer than
                      this are truncated, always preserving the entry point
                      and the terminal finding. Full path is always stored in
                      JSON output regardless of this limit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Reachability state constants
# ---------------------------------------------------------------------------

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
NO_ENTRY_POINTS = "no_entry_points"
UNKNOWN = "unknown"

REACHABILITY_STATES = frozenset({REACHABLE, UNREACHABLE, NO_ENTRY_POINTS, UNKNOWN})

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
