import argparse
import json
from pathlib import Path
from agent_scan.scanner import scan_path
from agent_scan.reporters.text_reporter import human_report

def build_parser():
    p = argparse.ArgumentParser(
        prog="agent-scan",
        description="Tells you what your AI agent can access, change, and send — before it does."
    )
    p.add_argument("path", nargs="?", default=".", help="Path to scan (file or directory)")
    p.add_argument("--json", action="store_true", dest="as_json", help="Print machine-readable JSON output")
    p.add_argument("--rules", choices=["core", "all"], default="core", help="Ruleset to run (currently: core)")
    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path).resolve()

    results = scan_path(target, ruleset=args.rules)

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        print(human_report(results))

if __name__ == "__main__":
    main()