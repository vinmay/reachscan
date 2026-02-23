"""
Autonomy capability detector.

Detects common patterns that indicate an agent can act without explicit
human approval or synchronous control, such as background tasks,
periodic schedulers, or async task creation.

Heuristics include:
- threading.Thread / threading.Timer and their .start()
- multiprocessing.Process and .start()
- asyncio.create_task / loop.create_task
- sched.scheduler + .enter/.enterabs
- schedule.every(...)
- apscheduler BackgroundScheduler.start

Returns CapabilityFinding(capability="AUTONOMY", evidence=..., file=..., lineno=..., confidence=...)
"""
import ast
from typing import List
from .base import CapabilityFinding
from .registry import register_detector

AUTONOMY_CALL_ATTRS = {
    ("threading", "Thread"): "threading.Thread",
    ("threading", "Timer"): "threading.Timer",
    ("multiprocessing", "Process"): "multiprocessing.Process",
    ("asyncio", "create_task"): "asyncio.create_task",
    ("sched", "scheduler"): "sched.scheduler",
    ("schedule", "every"): "schedule.every",
    ("apscheduler.schedulers.background", "BackgroundScheduler"): "apscheduler.schedulers.background.BackgroundScheduler",
}

# Methods that typically start background execution
AUTONOMY_START_METHODS = {
    "start",       # thread/process/scheduler start
    "enter",       # sched.scheduler.enter
    "enterabs",    # sched.scheduler.enterabs
    "add_job",     # apscheduler add_job
}

@register_detector("autonomy")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
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

    # Detect constructor calls or factory calls that create autonomous runners
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                resolved = resolve_name(func)
                if resolved:
                    for (mod, attr), label in AUTONOMY_CALL_ATTRS.items():
                        if resolved == f"{mod}.{attr}":
                            findings.append(CapabilityFinding(
                                capability="AUTONOMY",
                                evidence=label,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.85,
                            ))
                            break
                    else:
                        # detect start/enter/add_job patterns
                        if func.attr in AUTONOMY_START_METHODS:
                            findings.append(CapabilityFinding(
                                capability="AUTONOMY",
                                evidence=f"{resolved}()",
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.8,
                            ))
            elif isinstance(func, ast.Name):
                name = func.id
                full = imports.get(name)
                if full:
                    for (mod, attr), label in AUTONOMY_CALL_ATTRS.items():
                        if full == f"{mod}.{attr}":
                            findings.append(CapabilityFinding(
                                capability="AUTONOMY",
                                evidence=label,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.85,
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
