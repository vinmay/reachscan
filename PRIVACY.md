# Privacy

reachscan is a static analysis tool that runs entirely on your own machine or CI runner. This policy covers the reachscan CLI, the reachscan GitHub Action (`vinmay/reachscan-action`), and the reachscan agent plugin for Claude Code and Codex.

## What reachscan collects

Nothing. reachscan has no telemetry, analytics, accounts, or servers of its own. It doesn't send your code, scan results, or any personal data to the reachscan project or to anyone else.

## Network access

reachscan only makes network requests that you ask for, to fetch the target you choose to scan:

- `reachscan https://github.com/...` clones that repository from GitHub.
- `reachscan pypi:package` downloads that package from PyPI.
- `reachscan mcp+https://...` reads resources from the MCP endpoint you name.

Scanning a local path makes no network requests. Those requests go to the services you name, under their own privacy policies.

## Where results go

Results are printed to your terminal or written to the output you choose (JSON or SARIF). In the GitHub Action, SARIF results are uploaded to your repository's GitHub code scanning, under GitHub's policies, and you can turn that off with `sarif: false`. With the agent plugin, results are shown to the AI assistant you're using (Claude Code or Codex), under that product's policies.

## Contact

Questions about this policy: open an issue at https://github.com/vinmay/reachscan/issues.

Last updated: 2026-10-05
