#!/usr/bin/env python3
"""Build the ZIP for submitting the reachscan agent plugin to OpenAI's plugin directory.

Packages integrations/agent-plugins (portable plugin.json with OpenAI metadata
under extensions.com.openai, the .codex-plugin compatibility manifest, skills,
assets, README) plus the repository LICENSE. The Claude Code manifest
(.claude-plugin/) is left out because OpenAI doesn't use it.

Usage:
    python scripts/build_openai_plugin_zip.py            # writes dist/reachscan-plugin-<version>.zip
    python scripts/build_openai_plugin_zip.py --out X.zip

Upload the ZIP at https://platform.openai.com/plugins (see
https://developers.openai.com/plugins/deploy/submission).
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO_ROOT / "integrations" / "agent-plugins"
EXCLUDED_DIRS = {".claude-plugin", "__pycache__"}
# Fixed timestamp so the ZIP is byte-for-byte reproducible.
ZIP_DATE = (2026, 1, 1, 0, 0, 0)


def plugin_files() -> list[tuple[Path, str]]:
    """(source path, archive name) pairs, sorted."""
    files = []
    for path in sorted(PLUGIN_DIR.rglob("*")):
        rel = path.relative_to(PLUGIN_DIR)
        if path.is_dir() or EXCLUDED_DIRS & set(rel.parts) or path.name.startswith(".DS_Store"):
            continue
        files.append((path, rel.as_posix()))
    files.append((REPO_ROOT / "LICENSE", "LICENSE"))
    return files


def check_manifest() -> str:
    """Check the fields OpenAI's upload validates; return the plugin version."""
    manifest = json.loads((PLUGIN_DIR / "plugin.json").read_text(encoding="utf-8"))
    interface = manifest["extensions"]["com.openai"]["interface"]
    problems = []
    if len(interface.get("displayName", "")) > 30:
        problems.append("interface.displayName is over 30 characters")
    if not 0 < len(interface.get("shortDescription", "")) <= 30:
        problems.append("interface.shortDescription must be 1-30 characters")
    for key in ("logo", "composerIcon"):
        icon = interface.get(key)
        if not icon or not (PLUGIN_DIR / icon).is_file():
            problems.append(f"interface.{key} is missing or points to a missing file")
    if not (PLUGIN_DIR / "skills").is_dir():
        problems.append("skills/ directory is missing")
    if problems:
        sys.exit("Manifest problems:\n  - " + "\n  - ".join(problems))
    return manifest["version"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="output ZIP path")
    args = parser.parse_args()

    version = check_manifest()
    out = args.out or REPO_ROOT / "dist" / f"reachscan-plugin-{version}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for source, name in plugin_files():
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, source.read_bytes())

    print(f"Wrote {out}")
    with zipfile.ZipFile(out) as zf:
        for name in zf.namelist():
            print(f"  {name}")


if __name__ == "__main__":
    main()
