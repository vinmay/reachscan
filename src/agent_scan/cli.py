import argparse
import json
import sys
from agent_scan.scanner import scan_target
from agent_scan.reporters.text_reporter import human_report

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


def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-scan",
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
    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    results = scan_target(args.path, ruleset=args.rules, progress_callback=_progress_callback)

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        print(human_report(results))

if __name__ == "__main__":
    main()
