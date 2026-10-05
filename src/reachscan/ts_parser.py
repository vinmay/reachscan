"""
Tree-sitter parsing for TypeScript and JavaScript sources.

Uses the tree-sitter Python bindings with prebuilt grammar wheels, so no
Node.js runtime is needed. Each file extension maps to the grammar that can
parse it: plain .ts files cannot contain JSX, so .tsx needs the TSX grammar,
while the JavaScript grammar accepts JSX in .js and .jsx files.

parse_ts() returns None when a file cannot be parsed cleanly (bindings
unavailable, an exception, or a tree containing syntax errors). Callers fall
back to regex detection for that file.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Dict, Iterator, Optional

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Node, Parser, Tree

    _AVAILABLE = True
except ImportError:  # pragma: no cover - dependencies are declared in pyproject
    _AVAILABLE = False

GRAMMAR_TYPESCRIPT = "typescript"
GRAMMAR_TSX = "tsx"
GRAMMAR_JAVASCRIPT = "javascript"

_GRAMMAR_BY_SUFFIX = {
    ".ts": GRAMMAR_TYPESCRIPT,
    ".mts": GRAMMAR_TYPESCRIPT,
    ".cts": GRAMMAR_TYPESCRIPT,
    ".tsx": GRAMMAR_TSX,
    ".js": GRAMMAR_JAVASCRIPT,
    ".jsx": GRAMMAR_JAVASCRIPT,
    ".mjs": GRAMMAR_JAVASCRIPT,
    ".cjs": GRAMMAR_JAVASCRIPT,
}

_parsers: Dict[str, "Parser"] = {}


def grammar_for(path: str) -> Optional[str]:
    """Return the grammar name for a file path, or None if the suffix is not TS/JS."""
    return _GRAMMAR_BY_SUFFIX.get(PurePath(path).suffix.lower())


def _language(grammar: str) -> "Language":
    if grammar == GRAMMAR_TYPESCRIPT:
        return Language(tree_sitter_typescript.language_typescript())
    if grammar == GRAMMAR_TSX:
        return Language(tree_sitter_typescript.language_tsx())
    return Language(tree_sitter_javascript.language())


def _parser(grammar: str) -> "Parser":
    parser = _parsers.get(grammar)
    if parser is None:
        parser = Parser(_language(grammar))
        _parsers[grammar] = parser
    return parser


def parse_ts(path: str, content: str | bytes) -> Optional["Tree"]:
    """Parse a TS/JS source file. Returns None if it cannot be parsed cleanly."""
    if not _AVAILABLE:
        return None
    grammar = grammar_for(path)
    if grammar is None:
        return None
    source = content.encode("utf-8", errors="replace") if isinstance(content, str) else content
    try:
        tree = _parser(grammar).parse(source)
    except Exception:
        return None
    if tree.root_node.has_error:
        return None
    return tree


def iter_nodes(root: "Node") -> Iterator["Node"]:
    """Yield every named node under root in source (pre-)order, without recursion."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def node_text(node: "Node") -> str:
    return node.text.decode("utf-8", errors="replace") if node.text is not None else ""


def string_value(node: Optional["Node"]) -> Optional[str]:
    """Return the value of a string literal or substitution-free template string.

    Returns None for anything else, including template strings with ${...}.
    """
    if node is None:
        return None
    if node.type == "string":
        text = node_text(node)
        return text[1:-1] if len(text) >= 2 else None
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.named_children):
            return None
        text = node_text(node)
        return text[1:-1] if len(text) >= 2 else None
    return None


def property_key(pair: "Node") -> Optional[str]:
    """Return the key name of an object `pair` node (identifier or string key)."""
    key = pair.child_by_field_name("key")
    if key is None:
        return None
    if key.type == "property_identifier":
        return node_text(key)
    return string_value(key)


def object_pairs(obj: "Node") -> Dict[str, "Node"]:
    """Map key name → value node for the `pair` children of an object literal."""
    pairs: Dict[str, "Node"] = {}
    for child in obj.named_children:
        if child.type != "pair":
            continue
        key = property_key(child)
        value = child.child_by_field_name("value")
        if key is not None and value is not None and key not in pairs:
            pairs[key] = value
    return pairs
