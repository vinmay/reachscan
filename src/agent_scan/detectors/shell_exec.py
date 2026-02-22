from pathlib import Path
from typing import List
from .base import CapabilityFinding
from .registry import register_detector
import ast

@register_detector("shell_exec")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    results = []
    try:
        tree = ast.parse(content)
    except Exception:
        return results
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                mod = getattr(func.value, "id", None)
                name = func.attr
                if mod == "subprocess" and name in {"run", "Popen", "call"}:
                    results.append(CapabilityFinding("EXECUTE", f"subprocess.{name}()", path, node.lineno, 0.95))
            elif isinstance(func, ast.Name):
                if func.id in {"system", "exec", "eval"}:
                    results.append(CapabilityFinding("EXECUTE", f"{func.id}()", path, node.lineno, 0.95))
    return results