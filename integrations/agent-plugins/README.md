# reachscan agent plugin (Claude Code and Codex)

One skill, `vet-mcp-server`, packaged for both Claude Code and Codex. Before you add an MCP server, ask your agent to vet it. The agent runs the reachscan CLI on the server and tells you what each tool can execute, read, write, and send, then gives an **Install / Review first / Avoid** verdict based only on the scan findings.

```
> vet this MCP server before I add it: https://github.com/org/some-mcp-server
```

The skill calls the `reachscan` CLI directly. There's no MCP server and no network service. If reachscan isn't installed, the skill tells you to run `pipx install reachscan` and stops. It never installs anything on its own.

## Requirements

- `reachscan` on your `PATH`: `pipx install reachscan`
- Python 3.11 or later (for reachscan)

## Install in Claude Code

From inside Claude Code:

```
/plugin marketplace add vinmay/reachscan
/plugin install reachscan@reachscan
```

Or from a local checkout, for testing:

```bash
claude --plugin-dir ./integrations/agent-plugins
```

## Install in Codex

Add this repo as a marketplace:

```bash
codex plugin marketplace add vinmay/reachscan
```

Then open the Plugins Directory, choose the **reachscan** marketplace, and install the plugin. The repo marketplace file is `.agents/plugins/marketplace.json` at the repo root.

## What's in here

```
integrations/agent-plugins/
├── plugin.json                  # portable Agent Plugins manifest, with OpenAI metadata under extensions.com.openai
├── .claude-plugin/plugin.json   # Claude Code manifest
├── .codex-plugin/plugin.json    # Codex compatibility manifest, for older Codex clients
└── skills/vet-mcp-server/SKILL.md
```

Marketplace files at the repo root:

- `.claude-plugin/marketplace.json` for Claude Code
- `.agents/plugins/marketplace.json` for Codex

## Supported targets

GitHub URLs, `pypi:name[==version]`, local paths, and `mcp+https://` endpoints. npm packages aren't supported yet.

## Limits

reachscan analyzes Python tool bodies. TypeScript/JavaScript tool handlers are detected, but their bodies aren't analyzed yet, and the skill says so when it matters. The verdict reflects code patterns, not proven runtime behavior.
