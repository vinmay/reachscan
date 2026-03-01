"""
File access capability detector.

Detects common patterns that indicate reading or writing files:
 - open(..., "r"/no mode) / open(..., "w"/"a"/"x")
 - pathlib.Path.read_text / read_bytes
 - pathlib.Path.write_text / write_bytes
 - shutil.copy, shutil.copyfile, os.remove, os.rename, os.replace
 - json.load(open(...)) and similar idioms

Returns CapabilityFinding(capability="READ"|"WRITE", evidence=..., file=..., lineno=..., confidence=...)
"""
import ast
import warnings
from typing import List
from .base import CapabilityFinding
from .registry import register_detector

READ_OPEN_MODES = {"r", "rb", ""}  # empty string = default -> read
WRITE_OPEN_MODES = {"w", "wb", "a", "ab", "x"}

PATHLIB_READ_ATTRS = {"read_text", "read_bytes"}
PATHLIB_WRITE_ATTRS = {"write_text", "write_bytes"}

SHUTIL_WRITE_FUNCS = {"copy", "copyfile", "copy2", "move"}
OS_WRITE_FUNCS = {"remove", "unlink", "replace", "rename"}

@register_detector("file_access")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except Exception:
        return findings

    # collect simple imports mapping for resolving names
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
        """Resolve Name or Attribute to dotted string where possible."""
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
            # try to map first part via imports
            first = parts[0]
            mapped = imports.get(first, first)
            return ".".join([mapped] + parts[1:]) if parts[1:] else mapped
        # For call expressions like Path(path) or Path(...).method, resolve the function
        if isinstance(node, ast.Call):
            return resolve_name(node.func)
        return None

    # Helper to check open() modes in Call node
    def open_mode_from_call(node: ast.Call):
        # only consider first two positional args and keyword 'mode'
        mode = None
        # keyword overrides
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                mode = kw.value.value
                return mode
        # positional args: second arg if present
        if len(node.args) >= 2:
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                mode = arg.value
                return mode
        return mode  # may be None

    for node in ast.walk(tree):
        # detect open(...) usages
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = open_mode_from_call(node) or ""  # default read
            evidence = f"open(..., mode={mode!r})"
            if mode in WRITE_OPEN_MODES:
                findings.append(CapabilityFinding("WRITE", evidence, path, getattr(node, "lineno", None), 0.95))
            else:
                # treat default/read modes and unknown modes conservatively as READ
                findings.append(CapabilityFinding("READ", evidence, path, getattr(node, "lineno", None), 0.9))

        # attribute calls: Path.read_text(), Path.write_text(), json.load(open(...)), etc.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func_attr = node.func.attr  # like read_text, write_text, load, dump
            resolved = resolve_name(node.func.value)

            # pathlib read/write
            if func_attr in PATHLIB_READ_ATTRS:
                evidence = f"{resolved}.{func_attr}()"
                findings.append(CapabilityFinding("READ", evidence, path, getattr(node, "lineno", None), 0.95))
            if func_attr in PATHLIB_WRITE_ATTRS:
                evidence = f"{resolved}.{func_attr}()"
                findings.append(CapabilityFinding("WRITE", evidence, path, getattr(node, "lineno", None), 0.95))

            # json.load(open(...)) patterns: treat json.load as read evidence when arg is open()
            if func_attr in {"load", "loads"}:
                # if json.load(x) and x is Call to open -> read
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Call) and isinstance(first.func, ast.Name) and first.func.id == "open":
                        evidence = f"{resolved}.{func_attr}(<open(...)>)"
                        findings.append(CapabilityFinding("READ", evidence, path, getattr(node, "lineno", None), 0.9))

            # shutil/os utilities indicating write/delete
            if resolved:
                # resolved might be like "shutil" or "os"
                if resolved.startswith("shutil") and func_attr in SHUTIL_WRITE_FUNCS:
                    evidence = f"{resolved}.{func_attr}()"
                    findings.append(CapabilityFinding("WRITE", evidence, path, getattr(node, "lineno", None), 0.9))
                if resolved.startswith("os") and func_attr in OS_WRITE_FUNCS:
                    evidence = f"{resolved}.{func_attr}()"
                    findings.append(CapabilityFinding("WRITE", evidence, path, getattr(node, "lineno", None), 0.9))

        # direct Name calls that map to imported os.remove/open aliases etc.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            full = imports.get(name)
            if full:
                # os.remove imported as remove
                if full.startswith("os.") and any(full.endswith(f".{fn}") for fn in OS_WRITE_FUNCS):
                    findings.append(CapabilityFinding("WRITE", full, path, getattr(node, "lineno", None), 0.9))
                # shutil.* imported directly
                if full.startswith("shutil.") and any(full.endswith(f".{fn}") for fn in SHUTIL_WRITE_FUNCS):
                    findings.append(CapabilityFinding("WRITE", full, path, getattr(node, "lineno", None), 0.9))
                # pathlib.Path.read_text imported as read_text (rare) - best-effort
                if any(part in full for part in ("pathlib", "Path")) and any(attr in full for attr in PATHLIB_READ_ATTRS):
                    findings.append(CapabilityFinding("READ", full, path, getattr(node, "lineno", None), 0.9))

        # detect open file patterns in with-statement targets e.g., with open(...) as f:
        if isinstance(node, ast.With):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name) and ctx.func.id == "open":
                    mode = open_mode_from_call(ctx) or ""
                    evidence = f"with open(..., mode={mode!r})"
                    if mode in WRITE_OPEN_MODES:
                        findings.append(CapabilityFinding("WRITE", evidence, path, getattr(node, "lineno", None), 0.95))
                    else:
                        findings.append(CapabilityFinding("READ", evidence, path, getattr(node, "lineno", None), 0.9))

    # Deduplicate by (capability, evidence, lineno)
    seen = set()
    unique: List[CapabilityFinding] = []
    for f in findings:
        key = (f.capability, f.evidence, f.lineno)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique
