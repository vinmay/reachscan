# Registry scan

`sweep_python.py` is the T16a Python-only annotation sweep over the official MCP registry.

**Selection.** It enumerates `registry.modelcontextprotocol.io/v0/servers`, keeping each server's latest active version. It keeps servers with a PyPI package (`registryType: "pypi"`) and a public GitHub repository (honouring `repository.subfolder`), ranks them by GitHub stars (then name), and keeps the top 300 (`--limit`). Repositories that no longer resolve are dropped before ranking.

**Per server.** Each selected server is shallow-cloned (cached) and scanned in a subprocess with a timeout. It records:
- tool count (FastMCP decorator tools plus lowlevel `types.Tool` declarations);
- how many tools declare annotations, and how many have at least one explicit hint;
- the total number of explicit hints, and how many tools have unresolvable hints;
- mismatches by rule;
- linked and unlinked lowlevel tools.

Runs are resumable (`results.jsonl`).

**Privacy.** All output goes to `--out` (e.g. `~/.cache/reachscan-registry-sweep`), outside the repository. Mismatch details (`mismatches_private.jsonl`) name specific third-party servers and are for private, responsible disclosure only. Never commit or publish them.

```bash
python research/registry_scan/sweep_python.py --out ~/.cache/reachscan-registry-sweep
```
