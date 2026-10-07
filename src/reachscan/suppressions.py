"""
Inline suppressions.

    # reachscan:allow-<capability> <reason>      (Python)
    // reachscan:allow-<capability> <reason>     (TypeScript / JavaScript)
    # reachscan:allow-mismatch <reason>          (on a tool's decorator / registration)

A tag applies to the line it's on when it trails code, or to the next line of
code when the comment stands on its own line (other comment-only lines in
between are skipped, so tags can stack; a blank line ends the search).

A reason is required. A tag without one, with an unknown capability, or with
no code after it is ignored and reported as a warning. Suppressed findings and
mismatches stay in the output, marked with the reason, and don't affect the
exit code. A capability tag never suppresses an annotation mismatch: that needs
its own allow-mismatch tag on the tool's declaration.
"""

from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from reachscan.ts_parser import iter_nodes, node_text

CAPABILITY_KINDS = frozenset({"EXECUTE", "READ", "WRITE", "SEND", "SECRETS", "DYNAMIC", "AUTONOMY"})
MISMATCH = "MISMATCH"

_TAG = re.compile(r"reachscan:allow-([A-Za-z_-]+)(.*)")


@dataclass(frozen=True)
class Suppression:
    kind: str     # a capability (EXECUTE, ...) or MISMATCH
    reason: str
    line: int     # line of the comment

    def as_dict(self) -> dict:
        return {"reason": self.reason, "line": self.line}


@dataclass
class FileSuppressions:
    by_line: Dict[int, List[Suppression]]  # target line → suppressions
    warnings: List[dict]

    def find(self, line: Optional[int], kind: str) -> Optional[Suppression]:
        for s in self.by_line.get(line or -1, ()):
            if s.kind == kind:
                return s
        return None


# ---------------------------------------------------------------------------
# Comment extraction: (line, end_line, text, comment_only)
# ---------------------------------------------------------------------------

def _python_comments(source: str) -> List[Tuple[int, int, str, bool]]:
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                line = tok.start[0]
                comment_only = not tok.line[: tok.start[1]].strip()
                out.append((line, line, tok.string, comment_only))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return out


def _ts_comments(root, lines: List[str]) -> List[Tuple[int, int, str, bool]]:
    out = []
    for node in iter_nodes(root):
        if node.type != "comment":
            continue
        line, col = node.start_point
        end_line = node.end_point[0]
        before = lines[line][:col] if line < len(lines) else ""
        out.append((line + 1, end_line + 1, node_text(node), not before.strip()))
    return out


def _comment_only_lines(comments) -> set:
    lines = set()
    for line, end_line, _text, comment_only in comments:
        if comment_only:
            lines.update(range(line, end_line + 1))
    return lines


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse(file: str, comments, lines: List[str]) -> FileSuppressions:
    by_line: Dict[int, List[Suppression]] = {}
    warnings: List[dict] = []
    comment_only = _comment_only_lines(comments)

    def warn(line: int, message: str) -> None:
        warnings.append({"file": file, "lineno": line, "message": message})

    for line, end_line, text, is_comment_only in comments:
        match = _TAG.search(text)
        if match is None:
            continue
        name = match.group(1).upper().replace("-", "_").rstrip("_")
        reason = match.group(2)
        reason = reason.split("*/", 1)[0] if text.startswith("/*") else reason
        reason = reason.strip(" \t:-")
        tag = f"reachscan:allow-{match.group(1)}"
        kind = MISMATCH if name == MISMATCH else name
        if kind != MISMATCH and kind not in CAPABILITY_KINDS:
            warn(line, f"{tag}: unknown capability; suppression ignored")
            continue
        if not reason:
            warn(line, f"{tag} has no reason; suppression ignored (add one: {tag} <reason>)")
            continue
        if is_comment_only:
            target = end_line + 1
            while target in comment_only:
                target += 1
            if target > len(lines) or not lines[target - 1].strip():
                warn(line, f"{tag}: no code follows this comment; suppression ignored")
                continue
        else:
            target = line
        by_line.setdefault(target, []).append(Suppression(kind=kind, reason=reason, line=line))
    return FileSuppressions(by_line=by_line, warnings=warnings)


def python_suppressions(file: str) -> FileSuppressions:
    try:
        source = Path(file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FileSuppressions({}, [])
    if "reachscan:allow-" not in source:
        return FileSuppressions({}, [])
    return _parse(file, _python_comments(source), source.splitlines())


def ts_suppressions(file: str, root) -> FileSuppressions:
    try:
        source = Path(file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FileSuppressions({}, [])
    if "reachscan:allow-" not in source or root is None:
        return FileSuppressions({}, [])
    lines = source.splitlines()
    return _parse(file, _ts_comments(root, lines), lines)


# ---------------------------------------------------------------------------
# Applying to a scan
# ---------------------------------------------------------------------------

def apply_suppressions(findings: List[dict], mismatches: List[dict], py_files, ts_trees: Dict[str, object]) -> List[dict]:
    """Mark suppressed findings and mismatches in place; return suppression warnings.

    findings are the scanner's {"detector", "finding"} entries; mismatches are
    annotation mismatch dicts carrying an internal "_registration" (file, first,
    last), which is removed here.
    """
    loaded: Dict[str, FileSuppressions] = {}
    for f in py_files:
        loaded[str(f)] = python_suppressions(str(f))
    for f, root in ts_trees.items():
        loaded[str(f)] = ts_suppressions(str(f), root)

    for entry in findings:
        finding = entry["finding"]
        fs = loaded.get(str(finding.get("file")))
        if fs is None:
            continue
        s = fs.find(finding.get("lineno"), finding.get("capability", ""))
        if s is not None:
            finding["suppression"] = s.as_dict()

    for m in mismatches:
        registration = m.pop("_registration", None)
        if not registration:
            continue
        file, first, last = registration
        fs = loaded.get(str(file))
        if fs is None:
            continue
        for line in range(first, last + 1):
            s = fs.find(line, MISMATCH)
            if s is not None:
                m["suppression"] = s.as_dict()
                break

    warnings = [w for fs in loaded.values() for w in fs.warnings]
    return sorted(warnings, key=lambda w: (w["file"], w["lineno"]))
