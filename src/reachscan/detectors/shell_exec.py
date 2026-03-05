from pathlib import Path
from typing import List
from .base import CapabilityFinding
from .registry import register_detector
import ast
import warnings

@register_detector("shell_exec")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    results = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
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
                # Only flag os.system() as an attribute call — bare system() is too
                # ambiguous since any local import can shadow it (e.g. xai_sdk.chat.system).
                elif mod == "os" and name == "system":
                    results.append(CapabilityFinding("EXECUTE", "os.system()", path, node.lineno, 0.95))
            elif isinstance(func, ast.Name):
                if func.id in {"exec", "eval"}:
                    results.append(CapabilityFinding("EXECUTE", f"{func.id}()", path, node.lineno, 0.95))
    return results