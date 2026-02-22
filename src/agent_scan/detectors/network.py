"""
Network capability detector.

Detects common patterns that indicate ability to send data to external systems,
such as usage of `requests`, `httpx`, `urllib`, `socket`, `aiohttp`, `websockets`, etc.

Returns CapabilityFinding(capability="SEND", evidence=..., file=..., lineno=..., confidence=...)
"""
from typing import List
import ast
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

@register_detector("network")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
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
                        # also flag socket.create_connection or connect calls
                        if any(resolved.endswith(s) for s in SOCKET_FUNCS):
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
                    # full may be urllib.request.urlopen
                    for (mod, attr), label in NETWORK_CALL_ATTRS.items():
                        full_prefix = f"{mod}.{attr}"
                        if full.endswith(f"{mod}.{attr}") or full == full_prefix or full.startswith(mod):
                            # rough match
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=full,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.9
                            ))
                            break
                    else:
                        # generic name that resolves to a module with "request" in it
                        if full and ("urllib" in full or "http" in full):
                            findings.append(CapabilityFinding(
                                capability="SEND",
                                evidence=full,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.8
                            ))

    # Also look for raw string URL patterns used in open network libs (heuristic)
    # e.g., requests.get("https://example.com")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    v = arg.value.strip()
                    if v.startswith("http://") or v.startswith("https://"):
                        # attribute evidence from func if present
                        func = node.func
                        func_name = None
                        if isinstance(func, ast.Attribute):
                            func_name = resolve_name(func)
                        elif isinstance(func, ast.Name):
                            func_name = imports.get(func.id, func.id)
                        evidence = func_name or "network_call_with_literal_url"
                        findings.append(CapabilityFinding(
                            capability="SEND",
                            evidence=f"{evidence} -> {v}",
                            file=path,
                            lineno=getattr(node, "lineno", None),
                            confidence=0.9
                        ))

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