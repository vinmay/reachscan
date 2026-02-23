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

    lines.append("Combined Risks")
    lines.append("-" * 14)
    risks = results.get("risks", [])
    if risks:
        for risk in risks:
            severity = str(risk.get("severity", "unknown")).upper()
            title = risk.get("title", "Unknown Risk")
            lines.append(f"  [{severity}] {title}")
            lines.append(f"    why: {risk.get('why', '')}")
            caps = ", ".join(risk.get("capabilities_triggered", []))
            lines.append(f"    capabilities: {caps}")
    else:
        lines.append("  None inferred from combined-capability rules.")
    lines.append("")

    lines.append("Findings")
    lines.append("-" * 8)
    findings = results.get("findings", [])
    if findings:
        for item in findings:
            finding = item.get("finding", {})
            detector = item.get("detector", "unknown")
            file_path = finding.get("file", "unknown")
            lineno = finding.get("lineno")
            location = f"{file_path}:{lineno}" if lineno else file_path
            risk_level = str(finding.get("risk_level", "unknown")).upper()
            lines.append(
                f"  [{risk_level}] {finding.get('capability')} via {finding.get('evidence')} "
                f"({detector} @ {location})"
            )
            lines.append(f"    explanation: {finding.get('explanation', '')}")
            lines.append(f"    impact: {finding.get('impact', '')}")
    else:
        lines.append("  No findings detected.")
    lines.append("")

    if results.get("num_files_scanned", 0) == 0:
        lines.append("No Python files were found for analysis.")
        lines.append("Current support: Python code only.")
        lines.append("")

    lines.append("Static analysis only: this report reflects code patterns, not runtime behavior or exploitability.")
    lines.append(f"Scanned: {results.get('num_files_scanned', 0)} python files under {results.get('target')}")
    return "\n".join(lines)
