#!/usr/bin/env python3
"""
T16a: Python-only MCP registry annotation sweep.

Selection (documented, reproducible):
  1. Enumerate the official MCP registry (registry.modelcontextprotocol.io/v0/servers),
     keeping each server's latest active version.
  2. Python servers: at least one package with registryType "pypi".
  3. Public GitHub source: server.repository.url on github.com (subfolder honoured).
  4. Rank by GitHub stars (descending, then name) and keep the top --limit (default 300).

Per server it records: tool count, annotation coverage, explicit-hint count,
mismatches by rule, and linked/unlinked lowlevel tools. Resumable (results.jsonl
in --out), with cached shallow clones. Mismatch details go to
mismatches_private.jsonl in --out only. They must never be published.

Usage:
  python research/registry_scan/sweep_python.py --out ~/.cache/reachscan-registry-sweep
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"

WORKER = r"""
import json, sys
from collections import Counter
from pathlib import Path
from reachscan.scanner import scan_path
r = scan_path(Path(sys.argv[1]))
tools = []
for ep in r["py_entry_points"]:
    if "annotations" in ep:
        tools.append(ep["annotations"])
    for t in ep.get("declared_tools", []):
        tools.append(t["annotations"])
explicit_tools = sum(1 for a in tools if any(
    v.get("source") == "explicit" for k, v in a.items() if isinstance(v, dict)))
explicit_hints = sum(sum(1 for k, v in a.items() if isinstance(v, dict) and v.get("source") == "explicit")
                     for a in tools)
out = {
    "py_files": r["num_files_scanned"],
    "py_entry_points": len(r["py_entry_points"]),
    "tools": len(tools),
    "tools_declaring_annotations": sum(1 for a in tools if a.get("declared")),
    "tools_with_explicit_hint": explicit_tools,
    "explicit_hints": explicit_hints,
    "tools_with_unresolvable_hint": sum(1 for a in tools if any(
        isinstance(v, dict) and v.get("source") == "unresolvable" for v in a.values())),
    "mismatches_by_rule": dict(Counter(m["rule"] for m in r["annotation_mismatches"])),
    "lowlevel_linked": len(r["lowlevel_tool_linkage"]["linked"]),
    "lowlevel_unlinked": len(r["lowlevel_tool_linkage"]["unlinked"]),
    "mismatches": [
        {"tool": m["tool"], "rule": m["rule"], "declared": m["declared"],
         "observed": {k: m["observed"].get(k) for k in ("capability", "send_kind", "evidence", "file", "lineno")},
         "path": m["reachability_path"], "entry_point": m["entry_point"],
         "additional_observations": len(m["additional_observations"])}
        for m in r["annotation_mismatches"]
    ],
}
print(json.dumps(out))
"""


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def enumerate_registry() -> list:
    servers, cursor = {}, None
    while True:
        url = REGISTRY + "?limit=100" + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else "")
        page = fetch_json(url)
        for item in page.get("servers", []):
            meta = item.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
            if meta.get("status", "active") != "active" or not meta.get("isLatest", False):
                continue
            servers[item["server"]["name"]] = item["server"]
        cursor = page.get("metadata", {}).get("nextCursor")
        if not cursor:
            return list(servers.values())


def python_github(server: dict):
    pkgs = server.get("packages") or []
    if not any((p.get("registryType") or p.get("registry_type")) == "pypi" for p in pkgs):
        return None
    repo = server.get("repository") or {}
    url = (repo.get("url") or "").rstrip("/").removesuffix(".git")
    if "github.com/" not in url:
        return None
    owner_repo = "/".join(url.split("github.com/", 1)[1].split("/")[:2])
    if owner_repo.count("/") != 1:
        return None
    return owner_repo, (repo.get("subfolder") or "").strip("/")


def stars(owner_repo: str, cache: dict) -> int:
    if owner_repo in cache:
        return cache[owner_repo]
    res = subprocess.run(["gh", "api", f"repos/{owner_repo}", "--jq", ".stargazers_count"],
                         capture_output=True, text=True)
    cache[owner_repo] = int(res.stdout.strip()) if res.returncode == 0 and res.stdout.strip().isdigit() else -1
    return cache[owner_repo]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    out = args.out.expanduser()
    (out / "clones").mkdir(parents=True, exist_ok=True)

    sel_file = out / "selection.json"
    if sel_file.exists():
        selection = json.loads(sel_file.read_text())
    else:
        servers = enumerate_registry()
        star_cache_file = out / "stars.json"
        star_cache = json.loads(star_cache_file.read_text()) if star_cache_file.exists() else {}
        eligible = {}
        for s in servers:
            pg = python_github(s)
            if pg:
                eligible.setdefault((pg[0], pg[1]), s["name"])
        rows = []
        for (owner_repo, sub), name in eligible.items():
            rows.append({"name": name, "repo": owner_repo, "subfolder": sub, "stars": stars(owner_repo, star_cache)})
        star_cache_file.write_text(json.dumps(star_cache))
        rows = [r for r in rows if r["stars"] >= 0]  # drop repos that are gone or private
        rows.sort(key=lambda r: (-r["stars"], r["name"]))
        selection = {"registry_latest_active": len(servers), "python_github_eligible": len(eligible),
                     "selected": rows[: args.limit], "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        sel_file.write_text(json.dumps(selection, indent=1))

    results_file, private_file = out / "results.jsonl", out / "mismatches_private.jsonl"
    done = set()
    if results_file.exists():
        done = {json.loads(line)["name"] for line in results_file.read_text().splitlines() if line.strip()}
    for i, row in enumerate(selection["selected"], 1):
        if row["name"] in done:
            continue
        clone = out / "clones" / row["repo"].replace("/", "__")
        rec = dict(row)
        if not clone.exists():
            res = subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{row['repo']}", str(clone)],
                                 capture_output=True, text=True, timeout=600)
            if res.returncode != 0:
                rec["error"] = "clone failed"
        target = clone / row["subfolder"] if row["subfolder"] else clone
        if "error" not in rec:
            if not target.exists():
                rec["error"] = "subfolder missing"
            else:
                try:
                    res = subprocess.run([sys.executable, "-c", WORKER, str(target)], capture_output=True,
                                         text=True, timeout=args.timeout)
                    if res.returncode == 0:
                        data = json.loads(res.stdout.strip().splitlines()[-1])
                        mismatches = data.pop("mismatches")
                        rec.update(data)
                        if mismatches:
                            with private_file.open("a") as fh:
                                fh.write(json.dumps({"name": row["name"], "repo": row["repo"],
                                                     "subfolder": row["subfolder"], "mismatches": mismatches}) + "\n")
                    else:
                        rec["error"] = "scan failed: " + res.stderr.strip().splitlines()[-1][:200] if res.stderr.strip() else "scan failed"
                except subprocess.TimeoutExpired:
                    rec["error"] = f"scan timeout ({args.timeout}s)"
        with results_file.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(f"[{i}/{len(selection['selected'])}] {row['name']}: {rec.get('error') or 'ok'}", flush=True)


if __name__ == "__main__":
    main()
