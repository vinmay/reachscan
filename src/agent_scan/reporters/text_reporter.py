from typing import Dict, Any

def human_report(results: Dict[str, Any]) -> str:
    lines = []
    lines.append("Agent Capability Report")
    lines.append("=" * 23)
    lines.append("")

    caps = results.get("capabilities", [])
    if caps:
        lines.append("Capabilities")
        lines.append("-" * 12)
        for c in caps:
            lines.append(f"  • {c}")
        lines.append("")
    else:
        lines.append("No detected capabilities (phase-1 checks).")
        lines.append("")

    lines.append("Possible Impact")
    lines.append("-" * 15)
    for imp in results.get("possible_impacts", []):
        lines.append(f"  {imp}")
    lines.append("")
    lines.append(f"Scanned: {results.get('num_files_scanned', 0)} python files under {results.get('target')}")
    return "\n".join(lines)