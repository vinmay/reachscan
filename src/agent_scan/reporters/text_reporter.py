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

    # Python entry points
    py_entry_points = results.get("py_entry_points", [])
    if py_entry_points:
        lines.append("Python Entry Points (LLM-controlled surface)")
        lines.append("-" * 46)
        for ep in py_entry_points:
            fw   = ep.get("framework", "unknown")
            pt   = ep.get("pattern_type", "unknown")
            name = ep.get("name", "unknown")
            fpath = ep.get("file", "")
            lno   = ep.get("lineno", "")
            lines.append(f"  • {name}  ({fw}/{pt} @ {fpath}:{lno})")
        lines.append("")

    # TypeScript entry points
    ts_entry_points = results.get("ts_entry_points", [])
    if ts_entry_points:
        lines.append("TypeScript Entry Points (LLM-controlled surface)")
        lines.append("-" * 49)
        for ep in ts_entry_points:
            ptype = ep.get("pattern_type", "unknown")
            name  = ep.get("name", "unknown")
            fpath = ep.get("file", "")
            lno   = ep.get("lineno", "")
            lines.append(f"  • {name}  ({ptype} @ {fpath}:{lno})")
        lines.append("")

    if results.get("num_files_scanned", 0) == 0:
        other_languages = results.get("other_languages", [])
        if ts_entry_points:
            lines.append("⚠  Full capability analysis requires Python source.")
            lines.append("   TypeScript function bodies are not yet analyzed.")
            lines.append("   Entry points above show what the LLM can call.")
        elif other_languages:
            lang_summary = ", ".join(
                f"{l['language']} ({l['count']} files)" for l in other_languages
            )
            lines.append(f"No Python or TypeScript files were found for analysis.")
            lines.append(f"Detected: {lang_summary}")
            lines.append("agent-scan currently supports Python (full analysis) and TypeScript (entry points).")
        else:
            lines.append("No Python or TypeScript files were found for analysis.")
        lines.append("")

    lines.append("Static analysis only: this report reflects code patterns, not runtime behavior or exploitability.")
    lines.append(f"Scanned: {results.get('num_files_scanned', 0)} python files under {results.get('target')}")
    return "\n".join(lines)
