"""
Demo agent that intentionally contains many file read/write patterns.
This file is designed to be *scanned* (statically) by reachscan and should
produce high-severity signals (READ, WRITE).

**SAFETY:** This script will NOT perform any destructive or exfiltrating actions
unless you explicitly opt in. To run it you must:
  1) set the env var AGENT_SCAN_DEMO_RUN=1
  2) run the script interactively and type "YES" when prompted

Do NOT run this on machines you do not control.
"""

import os
import shutil
from pathlib import Path
import json
import zipfile

DEMO_HOME = Path("/tmp/reachscan_demo_home")
DEMO_DOCUMENTS = DEMO_HOME / "documents"
DEMO_SENSITIVE_PATHS = [
    DEMO_HOME / ".ssh" / "id_rsa",
    DEMO_HOME / ".aws" / "credentials",
    Path("/etc/passwd"),
    DEMO_DOCUMENTS,
]

# --- Suspicious-looking operations (static detectors should flag these) ---

def read_sensitive_files():
    """Examples of reading files that often contain secrets or sensitive info."""
    candidates = DEMO_SENSITIVE_PATHS
    results = {}
    for p in candidates:
        try:
            if p.is_file():
                # normal read
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    # read first chunk only (we are not exfiltrating by default)
                    results[str(p)] = fh.read(1024)
            elif p.is_dir():
                # list directory
                results[str(p)] = [str(x) for x in p.iterdir()][:50]
        except Exception:
            # ignore permission errors in demo
            results[str(p)] = "<unable to read>"
    return results


def copy_user_documents(target_dir: Path):
    """Copy documents (dangerous if real) to a new folder. Demonstrates write permissions."""
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    src = DEMO_DOCUMENTS
    if not src.exists():
        return {"status": "no_documents"}
    # WARNING: this could copy many files; require explicit run to execute
    shutil.copytree(src, target_dir / "Documents_copy", dirs_exist_ok=True)
    return {"status": "copied", "dest": str(target_dir / "Documents_copy")}


def write_config_override():
    """Write or overwrite a local config file — demonstrates write capability."""
    cfg_path = Path.cwd() / "dangerous_config.json"
    payload = {"overwritten_by_agent": True, "note": "demo"}
    # this will create or replace a file in CWD
    with cfg_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return {"wrote": str(cfg_path)}


def archive_documents(out_zip: Path):
    """Create a zip archive of Documents — shows archive/write behavior."""
    out_zip = Path(out_zip)
    src = DEMO_DOCUMENTS
    if not src.exists():
        return {"status": "no_documents"}
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        # add first-level entries only (demo)
        for p in src.rglob("*"):
            if p.is_file():
                # store with relative path
                try:
                    zf.write(p, arcname=str(p.relative_to(src)))
                except Exception:
                    pass
    return {"archived": str(out_zip)}


def delete_temp_file(temp_path: Path):
    """Example destructive write operation (delete). Present to be flagged, but not executed by default."""
    temp_path = Path(temp_path)
    if temp_path.exists():
        temp_path.unlink()
        return {"deleted": str(temp_path)}
    return {"status": "missing"}


# --- Safe-run guard: requires explicit opt-in ---
def _confirm_run():
    # require environment switch AND interactive confirmation
    if os.environ.get("AGENT_SCAN_DEMO_RUN") != "1":
        print("Demo file contains dangerous patterns. To run, set AGENT_SCAN_DEMO_RUN=1 and re-run.")
        return False
    try:
        ans = input("You enabled demo run. Type YES to proceed: ").strip()
    except Exception:
        return False
    return ans == "YES"


def main():
    print("Demo agent: file_power_agent (static-only by default).")
    print(f"Using generic demo base path: {DEMO_HOME}")
    if not _confirm_run():
        print("Run aborted - not executing any file actions.")
        return

    # If user confirmed, run the dangerous-looking workflows (use with care)
    print("Reading sensitive files (first 1KB each):")
    r = read_sensitive_files()
    for k, v in r.items():
        print(f" - {k}: {str(v)[:120]!r}")

    print("Archiving demo documents to /tmp/documents_demo.zip ...")
    a = archive_documents(Path("/tmp/documents_demo.zip"))
    print("Archive result:", a)

    print("Writing a demo config to CWD ...")
    w = write_config_override()
    print("Write result:", w)

    print("Attempting to copy Documents to ./staging ...")
    c = copy_user_documents(Path.cwd() / "staging")
    print("Copy result:", c)

    # destructive example (skipped unless file exists and user confirmed)
    tmp_example = Path.cwd() / "staging" / ".delete_me_demo"
    tmp_example.write_text("temporary")  # create temp
    print("Deleting temp file (example):", delete_temp_file(tmp_example))


if __name__ == "__main__":
    main()
