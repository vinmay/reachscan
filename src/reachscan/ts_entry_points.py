"""
TypeScript/JavaScript entry point detector for reachscan.

Detects functions exposed to LLMs in .ts and .js source files using
regex-based pattern matching. Does NOT perform full TypeScript AST analysis —
reachscan intentionally avoids requiring a Node.js runtime dependency.

Coverage (v1):
  mcp_tool            — server.tool("name", schema, handler)       [MCP SDK]
  mcp_tool            — server.registerTool("name", schema, handler) [MCP SDK v1.6+]
  mcp_tool            — server.addTool({ name: "name", ... })      [FastMCP]
  mcp_handler         — server.setRequestHandler(Schema, ...)       [MCP SDK]
  mcp_tool_definition — { name: "...", description: ..., inputSchema: ... }  [MCP tool objects]
  langchain_tool      — new DynamicTool({ name: "...", ... })      [LangChain.js]

Known limitations (document these, don't hide them):
  - Dynamic registration (variable tool names) is not detected
  - Minified/bundled code (.min.js) is not analyzed
  - TypeScript function bodies are not capability-analyzed, only entry points
  - Template literal tool names (`tool-${var}`) are not detected
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TSEntryPoint:
    """A single LLM-callable entry point detected in TypeScript/JavaScript source."""
    name: str           # Tool name if extractable; schema name for handlers; "unknown" otherwise
    file: str           # Absolute file path
    lineno: int         # 1-based line number of the registration statement
    pattern_type: str   # "mcp_tool" | "mcp_handler" | "langchain_tool"
    confidence: float   # Detection confidence 0.0–1.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "file": self.file,
            "lineno": self.lineno,
            "pattern_type": self.pattern_type,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

_TS_EXTENSIONS = frozenset({".ts", ".js", ".mts", ".mjs", ".cts", ".cjs"})

# Directory components that mean "don't scan this" for TypeScript repos.
_EXCLUDED_TS_DIR_PARTS = frozenset({
    "node_modules", "dist", "build", "out", "coverage",
    ".git", ".github",
    ".next", ".nuxt", ".svelte-kit",
    "site-packages", ".venv", "venv", "__pycache__",
    "tests", "test", "benchmark", "benchmarks",
})


def _is_excluded_ts_file(path: Path) -> bool:
    """Return True if this file should be skipped."""
    name = path.name.lower()

    # TypeScript declaration files — types only, no runtime code
    if name.endswith(".d.ts") or name.endswith(".d.mts") or name.endswith(".d.cts"):
        return True

    # Test and spec files
    if ".test." in name or ".spec." in name:
        return True

    # Minified bundles — not analyzable with regex
    if ".min.js" in name or ".min.mjs" in name or ".min.cjs" in name:
        return True

    # Excluded directory components
    parts = {part.lower() for part in path.parts}
    return bool(parts & _EXCLUDED_TS_DIR_PARTS)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# --- MCP SDK: server.tool("name", schema, handler) — name on same line ---
# Matches any identifier followed by .tool("literal_name", ...)
# The string-literal first argument is the key constraint — distinguishes this
# from other .tool() calls that take non-string first args.
_MCP_TOOL_RE = re.compile(
    r'(\w+)\s*\.\s*tool\s*\(\s*["\']([^"\']+)["\']'
)

# --- MCP SDK: server.tool( — trigger when name is on the next line ---
# Some codebases pass the name as the first argument on the following line.
# We trigger on .tool( with no string literal on the same line, then look ahead.
_MCP_TOOL_OPEN_RE = re.compile(r'\w+\s*\.\s*tool\s*\(')

# First non-whitespace content on a line is a quoted string (the tool name argument)
_STRING_FIRST_RE = re.compile(r'^\s*["\']([^"\']+)["\']')

# --- MCP SDK v1.6+: server.registerTool("name", schema, handler) — name on same line ---
# Identical call convention to server.tool(); just a different method name.
_MCP_REGISTER_TOOL_RE = re.compile(
    r'(\w+)\s*\.\s*registerTool\s*\(\s*["\']([^"\']+)["\']'
)

# --- MCP SDK v1.6+: server.registerTool( — name on the next line ---
_MCP_REGISTER_TOOL_OPEN_RE = re.compile(r'\w+\s*\.\s*registerTool\s*\(')

# --- FastMCP: server.addTool({ name: "name", ... }) ---
# Trigger on .addTool( then look for name: property on the same or following lines.
_MCP_ADD_TOOL_RE = re.compile(r'\w+\s*\.\s*addTool\s*\(')

# How many lines to look ahead for the name: property inside addTool({...})
_ADD_TOOL_LOOKAHEAD = 10

# --- MCP SDK: server.setRequestHandler(CallToolRequestSchema, handler) ---
# Detects handler registration. The schema name (group 1) is more informative
# than "unknown" and tells us what kind of request is being handled.
_MCP_HANDLER_RE = re.compile(
    r'\.setRequestHandler\s*\(\s*(\w+)\s*,'
)

# --- MCP SDK: .setRequestHandler( — schema argument on the next line ---
_MCP_HANDLER_OPEN_RE = re.compile(r'\.setRequestHandler\s*\(')

# First non-whitespace content is a bare identifier followed by a comma (schema arg)
_IDENTIFIER_FIRST_RE = re.compile(r'^\s*(\w+)\s*,')

# --- MCP tool definition object: { name: "...", description: ..., inputSchema: ... } ---
# This is the canonical MCP tool schema format used when tools are defined as objects
# rather than passed directly to server.tool(). Common in Zod-typed ToolSchema patterns
# and in functions that return arrays of tool definitions.
# We require name: with a string literal, then check context window for the other two fields.
_MCP_DEF_NAME_RE = re.compile(
    r'^\s*name\s*:\s*["\']([^"\']+)["\']'
)
_MCP_DEF_DESCRIPTION_RE = re.compile(r'\bdescription\s*:')
_MCP_DEF_INPUT_SCHEMA_RE = re.compile(r'\binputSchema\s*:')
# How many lines around the name: line to look for the other required fields
_MCP_DEF_CONTEXT_WINDOW = 8

# --- LangChain.js: new DynamicTool({ name: "...", ... }) — name on same line ---
# Also matches DynamicStructuredTool.
_LANGCHAIN_INLINE_RE = re.compile(
    r'new\s+Dynamic(?:Structured)?Tool\s*\([^)]*?name\s*:\s*["\']([^"\']+)["\']'
)

# --- LangChain.js: new DynamicTool({ — trigger when name is on a following line ---
_LANGCHAIN_TRIGGER_RE = re.compile(
    r'new\s+Dynamic(?:Structured)?Tool\s*\('
)

# --- name: "value" — used in lookahead after DynamicTool trigger ---
_NAME_PROP_RE = re.compile(
    r'\bname\s*:\s*["\']([^"\']+)["\']'
)

# How many lines ahead to search after a multi-line DynamicTool trigger
_LOOKAHEAD_LINES = 12


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def detect_ts_entry_points(file_path: str, content: str) -> List[TSEntryPoint]:
    """
    Scan a single TypeScript/JavaScript file's content for LLM entry points.

    Args:
        file_path: Path string used for reporting (typically absolute).
        content:   Full text content of the file.

    Returns:
        List of TSEntryPoint objects, deduplicated by (lineno, name).
    """
    results: List[TSEntryPoint] = []
    seen: set[tuple] = set()   # (lineno, name) pairs already emitted

    lines = content.splitlines()

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1  # convert to 1-based

        # --- MCP server.tool("name", ...) — name on same line ---
        m = _MCP_TOOL_RE.search(line)
        if m:
            name = m.group(2)
            key = (lineno, name)
            if key not in seen:
                seen.add(key)
                results.append(TSEntryPoint(
                    name=name,
                    file=file_path,
                    lineno=lineno,
                    pattern_type="mcp_tool",
                    confidence=0.95,
                ))
        # --- MCP server.tool( — name on the next line ---
        # Pattern: server.tool(\n    "tool_name",  — common when there are many args.
        # Lookahead of 1: the name must be the very first argument (next line).
        # If line 1 is not a string literal, the name is dynamic — skip.
        elif _MCP_TOOL_OPEN_RE.search(line):
            name = _find_string_on_next_lines(lines, lineno_0, lookahead=1)
            if name:
                key = (lineno, name)
                if key not in seen:
                    seen.add(key)
                    results.append(TSEntryPoint(
                        name=name,
                        file=file_path,
                        lineno=lineno,
                        pattern_type="mcp_tool",
                        confidence=0.95,
                    ))

        # --- MCP server.registerTool("name", ...) — name on same line ---
        m = _MCP_REGISTER_TOOL_RE.search(line)
        if m:
            name = m.group(2)
            key = (lineno, name)
            if key not in seen:
                seen.add(key)
                results.append(TSEntryPoint(
                    name=name,
                    file=file_path,
                    lineno=lineno,
                    pattern_type="mcp_tool",
                    confidence=0.95,
                ))
        # --- MCP server.registerTool( — name on the next line ---
        elif _MCP_REGISTER_TOOL_OPEN_RE.search(line):
            name = _find_string_on_next_lines(lines, lineno_0, lookahead=1)
            if name:
                key = (lineno, name)
                if key not in seen:
                    seen.add(key)
                    results.append(TSEntryPoint(
                        name=name,
                        file=file_path,
                        lineno=lineno,
                        pattern_type="mcp_tool",
                        confidence=0.95,
                    ))

        # --- FastMCP server.addTool({ name: "name", ... }) ---
        if _MCP_ADD_TOOL_RE.search(line):
            name = _find_name_ahead(lines, lineno_0, lookahead=_ADD_TOOL_LOOKAHEAD)
            if name != "unknown":
                key = (lineno, name)
                if key not in seen:
                    seen.add(key)
                    results.append(TSEntryPoint(
                        name=name,
                        file=file_path,
                        lineno=lineno,
                        pattern_type="mcp_tool",
                        confidence=0.90,
                    ))

        # --- MCP setRequestHandler — schema on same line ---
        m = _MCP_HANDLER_RE.search(line)
        if m:
            schema_name = m.group(1)
            key = (lineno, schema_name)
            if key not in seen:
                seen.add(key)
                results.append(TSEntryPoint(
                    name=schema_name,
                    file=file_path,
                    lineno=lineno,
                    pattern_type="mcp_handler",
                    confidence=0.80,
                ))
        # --- MCP setRequestHandler — schema on the next line ---
        elif _MCP_HANDLER_OPEN_RE.search(line):
            if lineno_0 + 1 < len(lines):
                m2 = _IDENTIFIER_FIRST_RE.match(lines[lineno_0 + 1])
                if m2:
                    schema_name = m2.group(1)
                    key = (lineno, schema_name)
                    if key not in seen:
                        seen.add(key)
                        results.append(TSEntryPoint(
                            name=schema_name,
                            file=file_path,
                            lineno=lineno,
                            pattern_type="mcp_handler",
                            confidence=0.80,
                        ))

        # --- MCP tool definition object: name: "...", description: ..., inputSchema: ... ---
        # Must appear on its own line (leading whitespace only) with a string literal value.
        # We then check a context window for both description: and inputSchema: to avoid FPs.
        m = _MCP_DEF_NAME_RE.match(line)
        if m:
            name = m.group(1)
            start = max(0, lineno_0 - _MCP_DEF_CONTEXT_WINDOW)
            end = min(len(lines), lineno_0 + _MCP_DEF_CONTEXT_WINDOW + 1)
            context_block = "\n".join(lines[start:end])
            if _MCP_DEF_DESCRIPTION_RE.search(context_block) and _MCP_DEF_INPUT_SCHEMA_RE.search(context_block):
                key = (lineno, name)
                if key not in seen:
                    seen.add(key)
                    results.append(TSEntryPoint(
                        name=name,
                        file=file_path,
                        lineno=lineno,
                        pattern_type="mcp_tool_definition",
                        confidence=0.85,
                    ))

        # --- LangChain DynamicTool — name on same line ---
        m = _LANGCHAIN_INLINE_RE.search(line)
        if m:
            name = m.group(1)
            key = (lineno, name)
            if key not in seen:
                seen.add(key)
                results.append(TSEntryPoint(
                    name=name,
                    file=file_path,
                    lineno=lineno,
                    pattern_type="langchain_tool",
                    confidence=0.85,
                ))

        # --- LangChain DynamicTool — name on a following line ---
        elif _LANGCHAIN_TRIGGER_RE.search(line):
            name = _find_name_ahead(lines, lineno_0)
            key = (lineno, name)
            if key not in seen:
                seen.add(key)
                results.append(TSEntryPoint(
                    name=name,
                    file=file_path,
                    lineno=lineno,
                    pattern_type="langchain_tool",
                    confidence=0.85,
                ))

    return results


def _find_string_on_next_lines(lines: List[str], start_idx: int, lookahead: int) -> Optional[str]:
    """
    Check the next `lookahead` lines for a line whose first non-whitespace content
    is a quoted string (the tool name argument in a multi-line server.tool() call).
    Returns the string value if found, None otherwise.
    """
    end = min(start_idx + lookahead + 1, len(lines))
    for line in lines[start_idx + 1:end]:
        m = _STRING_FIRST_RE.match(line)
        if m:
            return m.group(1)
    return None


def _find_name_ahead(lines: List[str], start_idx: int, lookahead: int = _LOOKAHEAD_LINES) -> str:
    """
    Look ahead up to `lookahead` lines (starting from start_idx) for a `name: "value"` property.
    Returns the name if found, "unknown" otherwise.
    """
    end = min(start_idx + lookahead, len(lines))
    for line in lines[start_idx:end]:
        m = _NAME_PROP_RE.search(line)
        if m:
            return m.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def scan_ts_files(root: Path) -> List[TSEntryPoint]:
    """
    Walk root and detect TypeScript/JavaScript entry points in all eligible files.

    Skips: .d.ts, .test.ts, .spec.ts, .min.js, and any file under
    node_modules, dist, build, or other excluded directory components.
    """
    results: List[TSEntryPoint] = []
    for p in _iter_ts_files(Path(root)):
        _scan_one(p, results)

    return results


def count_ts_files(root: Path) -> int:
    """Return the number of TypeScript/JavaScript source files eligible for scanning."""
    return len(_iter_ts_files(Path(root)))


def _iter_ts_files(root: Path) -> List[Path]:
    """Collect all eligible TypeScript/JavaScript files under root."""
    if root.is_file():
        if root.suffix in _TS_EXTENSIONS and not _is_excluded_ts_file(root):
            return [root]
        return []

    files: List[Path] = []
    for ext in _TS_EXTENSIONS:
        for p in root.rglob(f"*{ext}"):
            if not _is_excluded_ts_file(p):
                files.append(p)
    return files


def _scan_one(path: Path, results: List[TSEntryPoint]) -> None:
    """Read one file and append findings to results. Silently skips unreadable files."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    results.extend(detect_ts_entry_points(str(path), content))
