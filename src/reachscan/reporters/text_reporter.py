from typing import Dict, Any, List


def _format_path(path: list, truncated: bool, explain: bool = False) -> str:
    if not path:
        return ""
    if explain:
        parts = []
        for node in path:
            if "::" in node:
                file_part, func_part = node.split("::", 1)
                parts.append(f"{func_part} @ {file_part}")
            else:
                parts.append(node)
        return "\n      → ".join(parts)
    if truncated and len(path) > 2:
        nodes = [path[0], "…", path[-1]]
    else:
        nodes = path
    return " → ".join(nodes)


def _render_finding(item: dict, lines: List[str], show_path: bool, show_state_prefix: bool, explain: bool = False) -> None:
    finding = item.get("finding", {})
    detector = item.get("detector", "unknown")
    file_path = finding.get("file", "unknown")
    lineno = finding.get("lineno")
    location = f"{file_path}:{lineno}" if lineno else file_path
    risk_level = str(finding.get("risk_level", "unknown")).upper()
    state = finding.get("reachability")

    state_prefix = ""
    if show_state_prefix:
        if state == "unreachable":
            state_prefix = "UNREACHABLE  "
        elif state == "unknown":
            state_prefix = "UNKNOWN  "
        elif state == "module_level":
            state_prefix = "MODULE_LEVEL  "

    lines.append(
        f"  [{risk_level}] {state_prefix}{finding.get('capability')} via {finding.get('evidence')} "
        f"({detector} @ {location})"
    )

    if show_path and state == "reachable":
        path = finding.get("reachability_path") or []
        truncated = finding.get("reachability_path_truncated", False)
        if explain:
            formatted = _format_path(path, truncated, explain=True)
            if formatted:
                lines.append(f"    call chain:")
                lines.append(f"      {formatted}")
        else:
            formatted = _format_path(path, truncated)
            if formatted:
                lines.append(f"    path: {formatted}")
    elif state == "module_level":
        lines.append("    reachability: Executes on import — runs whenever this module loads")

    lines.append(f"    explanation: {finding.get('explanation', '')}")
    lines.append(f"    impact: {finding.get('impact', '')}")


def human_report(results: Dict[str, Any], explain: bool = False) -> str:
    lines = []
    lines.append("Agent Capability Report")
    lines.append("=" * 23)
    lines.append("")

    # Python entry points — moved to top so the reader sees the LLM surface first
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

    findings = results.get("findings", [])
    all_states = {item["finding"].get("reachability") for item in findings}
    has_reachability = bool(all_states & {"reachable", "unreachable", "unknown", "module_level"})

    if has_reachability:
        reachable     = [f for f in findings if f["finding"].get("reachability") == "reachable"]
        unreachable   = [f for f in findings if f["finding"].get("reachability") == "unreachable"]
        module_level  = [f for f in findings if f["finding"].get("reachability") == "module_level"]
        unknown       = [f for f in findings if f["finding"].get("reachability") == "unknown"]

        # Reachability Summary
        lines += ["Reachability Summary", "-" * 20]
        lines.append(f"  {len(reachable):>4} reachable     — LLM can trigger these directly")
        lines.append(f"  {len(unreachable):>4} unreachable   — exist in codebase, not on any LLM call path")
        if module_level:
            lines.append(f"  {len(module_level):>4} module-level  — execute on import, not on any call path")
        if unknown:
            lines.append(f"  {len(unknown):>4} unknown       — unresolvable (dynamic dispatch or parse failure)")
        lines.append("")

        # Reachable Findings
        lines += ["Reachable Findings  —  LLM can trigger these directly", "-" * 52]
        if reachable:
            for item in reachable:
                _render_finding(item, lines, show_path=True, show_state_prefix=False, explain=explain)
        else:
            lines.append("  No findings reachable from the detected entry points.")
        lines.append("")

        # Other Findings (only if any)
        other = unreachable + module_level + unknown
        if other:
            lines += ["Other Findings  —  not on LLM call path", "-" * 41]
            for item in other:
                _render_finding(item, lines, show_path=False, show_state_prefix=True)
            lines.append("")

    else:
        # no_entry_points or reachability field is None
        lines += ["Findings", "-" * 8]
        if findings:
            if "no_entry_points" in all_states:
                lines.append(
                    "  No Python entry points detected — "
                    "showing all findings without reachability context."
                )
                lines.append("")
            for item in findings:
                _render_finding(item, lines, show_path=False, show_state_prefix=False)
        else:
            lines.append("  No findings detected.")
        lines.append("")

    # TypeScript entry points
    ts_entry_points = results.get("ts_entry_points", [])
    ts_files_scanned = int(results.get("num_ts_files_scanned", 0) or 0)
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
    elif ts_files_scanned > 0:
        lines.append(
            f"TypeScript/JavaScript files scanned: {ts_files_scanned} "
            "(no supported LLM entry-point patterns detected)"
        )
        lines.append("")

    if results.get("num_files_scanned", 0) == 0:
        other_languages = results.get("other_languages", [])
        if ts_entry_points:
            lines.append("⚠  Full capability analysis requires Python source.")
            lines.append("   TypeScript function bodies are not yet analyzed.")
            lines.append("   Entry points above show what the LLM can call.")
        elif ts_files_scanned > 0:
            lines.append(
                f"Found {ts_files_scanned} TypeScript/JavaScript files, "
                "but no supported entry-point registrations were detected."
            )
            lines.append(
                "Supported patterns currently include MCP tool/handler registration and LangChain DynamicTool."
            )
        elif other_languages:
            lang_summary = ", ".join(
                f"{l['language']} ({l['count']} files)" for l in other_languages
            )
            lines.append(f"No Python or TypeScript files were found for analysis.")
            lines.append(f"Detected: {lang_summary}")
            lines.append("reachscan currently supports Python (full analysis) and TypeScript (entry points).")
        else:
            lines.append("No Python or TypeScript files were found for analysis.")
        lines.append("")

    lines.append("Static analysis only: this report reflects code patterns, not runtime behavior or exploitability.")
    resolved_version = results.get("resolved_version")
    target_str = results.get("target", "")
    version_note = ""
    if resolved_version and resolved_version not in target_str:
        version_note = f" (version {resolved_version})"
    lines.append(
        f"Scanned: {results.get('num_files_scanned', 0)} python files, "
        f"{ts_files_scanned} TypeScript/JavaScript files under {target_str}{version_note}"
    )
    return "\n".join(lines)
