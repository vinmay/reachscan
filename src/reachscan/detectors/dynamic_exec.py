"""
Dynamic execution capability detector.

Detects common patterns that indicate dynamic code execution:
- eval(...)
- exec(...)
- compile(...)
- builtins.eval / builtins.exec
- importlib.import_module / __import__ (dynamic import)
- runpy.run_module / runpy.run_path

Returns CapabilityFinding(capability="DYNAMIC", evidence=..., file=..., lineno=..., confidence=...)
"""
import ast
import warnings
from typing import List
from .base import CapabilityFinding
from .registry import register_detector

DYNAMIC_CALL_ATTRS = {
    ("builtins", "eval"): "builtins.eval",
    ("builtins", "exec"): "builtins.exec",
    ("importlib", "import_module"): "importlib.import_module",
    ("runpy", "run_module"): "runpy.run_module",
    ("runpy", "run_path"): "runpy.run_path",
}

DYNAMIC_FUNC_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
}

@register_detector("dynamic_exec")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except Exception:
        return findings

    # collect imports mapping: alias -> full module
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                fullname = f"{module}.{alias.name}" if module else alias.name
                imports[alias.asname or alias.name] = fullname

    def resolve_name(node):
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
            if not parts:
                return None
            first = parts[0]
            mapped = imports.get(first, first)
            return ".".join([mapped] + parts[1:]) if parts[1:] else mapped
        return None

    # Detect direct calls: eval/exec/compile/__import__
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
                full = imports.get(name)
                if name in DYNAMIC_FUNC_NAMES or (full and any(full.endswith(f".{n}") for n in DYNAMIC_FUNC_NAMES)):
                    # __import__("literal") is the idiomatic namespace-package boilerplate:
                    #   __import__("pkgutil").extend_path(__path__, __name__)
                    # It is semantically identical to a static import and carries no
                    # dynamic execution risk — the module name is a compile-time constant.
                    if name == "__import__":
                        if (node.args
                                and isinstance(node.args[0], ast.Constant)
                                and isinstance(node.args[0].value, str)):
                            continue
                    evidence = full or name
                    findings.append(CapabilityFinding(
                        capability="DYNAMIC",
                        evidence=evidence,
                        file=path,
                        lineno=getattr(node, "lineno", None),
                        confidence=0.95 if name in {"eval", "exec"} else 0.9,
                    ))
            elif isinstance(func, ast.Attribute):
                resolved = resolve_name(func)
                if resolved:
                    for (mod, attr), label in DYNAMIC_CALL_ATTRS.items():
                        if resolved == f"{mod}.{attr}":
                            findings.append(CapabilityFinding(
                                capability="DYNAMIC",
                                evidence=label,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.9,
                            ))
                            break

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
