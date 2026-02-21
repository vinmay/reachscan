def human_report(findings):
    lines = ["Agent Capability Report", "─" * 25, ""]
    caps = set()
    for f in findings:
        for (_, ev) in f["hits"]:
            caps.add("Execute shell commands")
    if caps:
        lines.append("This agent can:")
        for c in sorted(caps):
            lines.append(f"• {c}")
        lines.append("")
        lines.append("Possible impact:")
        if "Execute shell commands" in caps:
            lines.append("Local commands may be run on your machine.")
    else:
        lines.append("No risky capabilities detected.")
    return "\n".join(lines)