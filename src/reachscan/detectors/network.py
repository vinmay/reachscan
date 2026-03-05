"""
Network capability detector.

Detects common patterns that indicate ability to send data to external systems,
such as usage of `requests`, `httpx`, `urllib`, `socket`, `aiohttp`, `websockets`, etc.

Returns CapabilityFinding(capability="SEND", evidence=..., file=..., lineno=..., confidence=...)
"""
from typing import List
import ast
import warnings
from .base import CapabilityFinding
from .registry import register_detector

# common module/function names that imply network access
NETWORK_CALL_ATTRS = {
    # module.attr -> evidence label
    ("requests", "get"): "requests.get",
    ("requests", "post"): "requests.post",
    ("requests", "put"): "requests.put",
    ("requests", "delete"): "requests.delete",
    ("httpx", "get"): "httpx.get",
    ("httpx", "post"): "httpx.post",
    ("urllib", "request"): "urllib.request",
    ("urllib.request", "urlopen"): "urllib.request.urlopen",
    ("urllib3", "PoolManager"): "urllib3.PoolManager",
    ("socket", "socket"): "socket.socket",
    ("aiohttp", "ClientSession"): "aiohttp.ClientSession",
    ("websockets", "connect"): "websockets.connect",
    ("websocket", "create_connection"): "websocket.create_connection",
}

# also detect direct usage of lower-level socket functions
SOCKET_FUNCS = {"socket", "create_connection", "connect"}

# Local file-based database modules whose .connect() does NOT make a network call.
LOCAL_DB_MODULES = {"sqlite3", "aiosqlite", "duckdb"}

# Config/type objects from HTTP libraries that do NOT make a network connection.
HTTP_CONFIG_ATTRS = {
    "Timeout", "ClientTimeout", "HTTPTransport", "AsyncHTTPTransport",
    "Request", "Response", "Headers", "Cookies", "Subprotocol",
}

# MCP server-side transport module prefixes.
# These contain "http" in their name but are SERVER infrastructure,
# not outbound network clients. Suppress the catch-all http-module heuristic for them.
_MCP_SERVER_MODULE_PREFIXES = frozenset({
    "mcp.server",
})

# Function names that are plausibly an HTTP call when a URL literal is passed.
LITERAL_URL_CALL_NAMES = {
    "get", "post", "put", "delete", "patch", "head", "options",
    "request", "urlopen", "open", "fetch", "send", "mount",
}

@register_detector("network")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except Exception:
        return findings

    # collect imports mapping: alias -> full module (simple)
    imports = {}  # e.g. {"req": "requests", "u": "urllib.request"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                asname = alias.asname or alias.name
                imports[asname] = alias.name  # map alias -> module
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                asname = alias.asname or alias.name
                full = f"{module}.{alias.name}" if module else alias.name
                imports[asname] = full

    # helper to resolve name (very simple)
    def resolve_name(node):
        # handle Name and Attribute chains
        if isinstance(node, ast.Name):
            return imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            parts.reverse()
            # try to resolve first part via imports
            if parts:
                first = parts[0]
                base = imports.get(first, first)
                rest = parts[1:]
                return ".".join([base] + rest) if rest else base
        return None

    # check call sites for known network functions
    for node in ast.walk(tree):
        # Call nodes like requests.post(...)
        if isinstance(node, ast.Call):
            func = node.func
            # attribute calls: module.func(...) or alias.func(...)
            if isinstance(func, ast.Attribute):
                resolved = resolve_name(func)
                if resolved:
                    # check if resolved matches any known patterns
                    for (mod, attr), label in NETWORK_CALL_ATTRS.items():
                        # match if resolved startswith module and endswith attr
                        if resolved.startswith(mod) and resolved.endswith(attr):
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=label,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.95
                            ))
                            break
                    else:
                        # detect socket.create_connection or .connect() calls,
                        # but skip local file-based databases (no network involved)
                        if any(resolved.endswith(s) for s in SOCKET_FUNCS):
                            if not any(resolved.startswith(m) for m in LOCAL_DB_MODULES):
                                findings.append(CapabilityFinding(
                                    capability="SEND",
                                    evidence=resolved,
                                    file=path,
                                    lineno=getattr(node, "lineno", None),
                                    confidence=0.85
                                ))
            elif isinstance(func, ast.Name):
                # direct calls like urlopen(...) if imported via `from urllib.request import urlopen`
                name = func.id
                full = imports.get(name)
                if full:
                    # full may be urllib.request.urlopen — match against NETWORK_CALL_ATTRS
                    for (mod, attr), label in NETWORK_CALL_ATTRS.items():
                        full_prefix = f"{mod}.{attr}"
                        if full.endswith(full_prefix) or full == full_prefix or full.startswith(full_prefix):
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=full,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.9
                            ))
                            break
                    else:
                        # Catch-all for names imported from HTTP-related modules.
                        # Require urllib.request (not urllib.parse) or "http" in path,
                        # but exclude:
                        #   - urllib.parse.* (URL string manipulation, no network)
                        #   - qdrant_client.http.models.* (data-model classes, no network)
                        #   - known config/type objects that create no connection
                        last_part = full.rsplit(".", 1)[-1] if "." in full else full
                        is_http_module = (
                            "urllib.request" in full
                            or (
                                "http" in full
                                and "urllib.parse" not in full
                                and "qdrant_client.http.models" not in full
                                and last_part not in HTTP_CONFIG_ATTRS
                                and not any(full.startswith(p) for p in _MCP_SERVER_MODULE_PREFIXES)
                            )
                        )
                        if is_http_module:
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=full,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.8
                            ))

    # Literal-URL heuristic: flag calls that receive an http(s):// string literal,
    # but only when the called function is a known HTTP verb or method name.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    v = arg.value.strip()
                    if v.startswith("http://") or v.startswith("https://"):
                        func = node.func
                        func_name = None
                        if isinstance(func, ast.Attribute):
                            func_name = func.attr
                        elif isinstance(func, ast.Name):
                            func_name = func.id
                        # Only flag when the function is a known HTTP action verb
                        if func_name and func_name in LITERAL_URL_CALL_NAMES:
                            resolved_name = resolve_name(func) if isinstance(func, ast.Attribute) else (imports.get(func.id, func.id) if isinstance(func, ast.Name) else None)
                            evidence = resolved_name or func_name
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=f"{evidence} -> {v}",
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.9
                            ))
                        break  # only check first string arg per call

    # Deduplicate by (evidence, lineno)
    seen = set()
    unique: List[CapabilityFinding] = []
    for f in findings:
        key = (f.evidence, f.lineno)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique
