import argparse
import json
import sys
from reachscan.scanner import scan_target
from reachscan.reporters.text_reporter import human_report
from reachscan.reporters.json_reporter import json_report

_SEVERITY_LEVELS = {"high": {"high"}, "medium": {"high", "medium"}}


def _format_progress_bar(percent: int, width: int = 28) -> str:
    filled = max(0, min(width, int(width * percent / 100)))
    return "█" * filled + "░" * (width - filled)


def _progress_callback(stage: str, percent: int | None, detail: str) -> None:
    pct = 0 if percent is None else max(0, min(100, percent))
    bar = _format_progress_bar(pct)
    if stage == "github_clone":
        label = "Cloning GitHub repository"
    elif stage == "pypi_download":
        label = "Downloading from PyPI    "
    elif stage == "analysis_scan":
        label = "Analyzing Python files   "
    else:
        return
    line = f"\r{label} [{bar}] {pct:3d}% {detail:<24}"
    print(line, end="", file=sys.stderr, flush=True)
    if pct >= 100:
        print(file=sys.stderr, flush=True)


def _compute_exit_code(results: dict, severity: str) -> int:
    if severity == "none":
        return 0
    trigger_levels = _SEVERITY_LEVELS.get(severity, {"high"})
    for item in results.get("findings", []):
        f = item.get("finding", {})
        if f.get("reachability") == "reachable" and f.get("risk_level") in trigger_levels:
            return 1
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="reachscan",
        description="Tells you what your AI agent can access, change, and send — before it does."
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Local path, GitHub repo URL, MCP endpoint (mcp+https://...), or PyPI package (pypi:name or pypi:name==version)",
    )
    p.add_argument("--json", action="store_true", dest="as_json", help="Print machine-readable JSON output")
    p.add_argument("--rules", choices=["core", "all"], default="core", help="Ruleset to run (currently: core)")
    p.add_argument(
        "--severity",
        choices=["high", "medium", "none"],
        default="high",
        help="Exit 1 when reachable findings meet this risk threshold (default: high)",
    )
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = scan_target(args.path, ruleset=args.rules, progress_callback=_progress_callback)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.as_json:
        print(json_report(results))
    else:
        print(human_report(results))

    sys.exit(_compute_exit_code(results, args.severity))


if __name__ == "__main__":
    main()
