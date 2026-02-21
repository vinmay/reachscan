import ast
from typing import List, Tuple
import sys
from pathlib import Path

# patterns we consider indicative of shell execution
SHELL_NAMES = {
    "system", "popen", "Popen", "run", "call", "check_call",
    "check_output", "spawn", "execv", "execvp", "execve"
}
SHELL_MODULES = {"subprocess", "os", "pty", "shutil"}

def detect_in_code(source: str) -> List[Tuple[int, str]]:
    """
    Return list of (lineno, evidence) where shell-exec-like usage found.
    """
    results = []
    try:
        tree = ast.parse(source)
    except Exception:
        return results

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                module_name = getattr(func.value, "id", None) or getattr(func.value, "attr", None)
                func_name = func.attr
                if module_name in SHELL_MODULES and func_name in SHELL_NAMES:
                    results.append((node.lineno, f"{module_name}.{func_name}()"))
            elif isinstance(func, ast.Name):
                name = func.id
                if name in {"exec", "eval"} or name in SHELL_NAMES:
                    results.append((node.lineno, f"{name}()"))

        if isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                if node.value.func.id in {"exec", "eval"}:
                    results.append((node.lineno, node.value.func.id + "()"))

    return results

def scan_path(path: Path):
    py_files = list(path.rglob("*.py"))
    findings = []
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8")
        except Exception:
            continue
        hits = detect_in_code(src)
        if hits:
            findings.append({"path": str(p), "hits": hits})
    return findings

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    findings = scan_path(target)
    if not findings:
        print("No shell-exec patterns found.")
        sys.exit(0)
    print("Shell execution evidence found:")
    for f in findings:
        print(f"- {f['path']}")
        for lineno, ev in f["hits"]:
            print(f"  line {lineno}: {ev}")
    sys.exit(0)