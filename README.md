# reachscan

[![PyPI version](https://img.shields.io/pypi/v/reachscan)](https://pypi.org/project/reachscan/)
[![CI](https://github.com/vinmay/reachscan/actions/workflows/ci.yml/badge.svg)](https://github.com/vinmay/reachscan/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/vinmay/reachscan?style=social)](https://github.com/vinmay/reachscan)

> Static capability analysis for Python and TypeScript/JavaScript AI code.
> Know what it can do before it does it.

## Quick start

| You want to... | Use |
|---|---|
| Scan any agent or MCP server from your terminal | `pipx install reachscan`, then `reachscan <path \| github-url \| pypi:package>` |
| Check your own agent or MCP server on every pull request | The [GitHub Action](https://github.com/marketplace/actions/reachscan): `uses: vinmay/reachscan-action@v1` ([CI integration](#ci-integration)) |
| Vet someone else's MCP server before you install it | The plugin for Claude Code or Codex: ask "vet this MCP server before I add it: &lt;url&gt;" ([setup](#use-it-from-claude-code-or-codex)) |

---

## The problem

You're giving an LLM tools. Tools mean real-world access — files, shell, network, credentials.

Most developers add tools without a clear accounting of what permissions they're actually granting. The agent docs tell you what the tool is *for*. They don't tell you what it *can do*.

`reachscan` is the accounting.

It analyzes Python and TypeScript/JavaScript code and reports the actual capabilities present: what the code can read, write, execute, send, and access. Not what the README says. What the code does.

---

## What it detects

Seven capability classes, built from AST analysis of Python and TypeScript/JavaScript code:

| Capability | What it means |
|---|---|
| `EXECUTE` | Shell commands, subprocess, OS exec APIs |
| `READ` | Local file reads, path traversal |
| `WRITE` | File creation, modification, deletion |
| `SEND` | Outbound HTTP, websockets, raw sockets |
| `SECRETS` | Env vars, credential managers, secret stores |
| `DYNAMIC` | eval, exec, dynamic imports |
| `AUTONOMY` | Background tasks, schedulers, self-directed execution |

Cross-capability risks are also flagged when both capabilities are reachable (or run at module level, on import): READ + SEND (secret leakage), SEND + WRITE (data exfiltration), EXECUTE + SEND (remote control), and EXECUTE + destructive WRITE (destructive agent).

---

## Reachability analysis

Knowing a capability exists in a codebase is useful. Knowing whether the LLM can actually trigger it is what matters.

`reachscan` detects the LLM-facing entry points in your codebase, builds an intra-project call graph, and traces which capabilities are reachable from those entry points. Every finding is tagged with one of five states:

| State | Meaning |
|---|---|
| `reachable` | Confirmed on a call path from an LLM entry point |
| `unreachable` | Exists in the codebase, not on any LLM call path |
| `module_level` | Runs on import — executes when the module loads, not via a function call |
| `unknown` | Might be on a call path the analysis can't resolve (method calls on instances, dynamic dispatch, parse failure) |
| `no_entry_points` | No entry points detected — full reachability analysis not possible |

The call graph follows up to 8 hops from each entry point. Call paths are shown in the report so you can see exactly how the LLM reaches a capability.

**Known limitations of the Python call graph.** It resolves:
- plain calls to project functions (`helper()`, including ones imported from another project file);
- `self.method()` calls to methods defined in the same class and file;
- `module.function()` calls.

It doesn't yet resolve method calls on object instances (`client.fetch()`, `self.db.query()`), chained attribute calls (`a.b.c()`), `super().method()`, or inherited methods. When reachable code makes such a call and the project defines a method with that name, findings in that method (and in what it calls) are reported as `unknown` rather than `unreachable`. They can't produce an annotation mismatch and don't affect the exit code.

### Entry point detection — Python

`reachscan` recognises LLM-callable functions across all major Python agent frameworks:

| Framework | Detection pattern |
|---|---|
| MCP (Python SDK / FastMCP) | `@mcp.tool()`, `@server.tool()` |
| MCP (lowlevel server API) | `@app.call_tool()`, `@app.list_tools()` |
| Pydantic AI | `@agent.tool`, `@agent.tool_plain` |
| LangChain / CrewAI | `@tool`, `class MyTool(BaseTool)`, `StructuredTool` |
| OpenAI Agents SDK | `@function_tool` |
| Semantic Kernel | `@kernel_function` |
| AutoGen | `@register_for_llm` |
| LlamaIndex | `FunctionTool.from_defaults(fn=...)`, `QueryEngineTool.from_defaults(...)` |
| DSPy | `dspy.Tool(func)` |
| Google ADK | `Agent(tools=[...])` |
| OpenAI Swarm | `Agent(functions=[...])` |
| CAMEL AI | `FunctionTool(func)` |
| smolagents, Strands, Haystack | `@tool` |
| Agno / Phidata | `@tool`, `class MyTools(Toolkit)` |
| Agency Swarm | `@function_tool` |
| MetaGPT | `@register_tool()` |
| Marvin | `@marvin.fn`, `@ai_model` |

Framework attribution uses a confidence-graded resolution chain: direct imports are resolved at 0.95 confidence, inferred instance variables (e.g. `weather_agent = Agent[Deps, T](...)`) at 0.80, and unresolvable decorator names fall back to the best available label at 0.60.

Python entry points feed into the reachability pass — the call graph is traced from each detected entry point to identify which capabilities the LLM can actually trigger.

### Entry point detection — TypeScript and JavaScript

`reachscan` parses `.ts`, `.tsx`, `.js`, `.jsx`, `.mts`, `.mjs`, `.cts`, and `.cjs` files with [tree-sitter](https://tree-sitter.github.io/), using prebuilt Python wheels, so no Node.js runtime is required. Comments and strings don't produce entry points. If a file can't be parsed (for example, TypeScript syntax newer than the bundled grammar), reachscan falls back to regex matching for that file.

| Pattern | What it detects | Confidence |
|---|---|---|
| `mcp_tool` | `server.tool("name", schema, handler)` — MCP SDK | 0.95 |
| `mcp_tool` | `server.registerTool("name", schema, handler)` — MCP SDK v1.6+ | 0.95 |
| `mcp_tool` | `server.addTool({ name: "...", ... })` — FastMCP | 0.90 |
| `mcp_tool_definition` | `{ name: "...", description: ..., inputSchema: ... }` objects | 0.85 |
| `langchain_tool` | `new DynamicTool({ name: "...", ... })` | 0.85 |
| `mcp_handler` | `server.setRequestHandler(Schema, ...)` | 0.80 |

Registration calls are matched however they're formatted. Declaration files (`.d.ts`), test files, minified bundles, and `node_modules`/`dist`/`build` directories are automatically excluded.

TypeScript and JavaScript code is also analyzed for capabilities: `child_process` and `execa` (EXECUTE), `fs` and `fs/promises` (READ/WRITE), `fetch`, `axios`, `got`, `undici`, `http(s)`, `net`, and WebSockets (SEND), `process.env`, `dotenv`, and `keytar` (SECRETS), `eval`, `new Function`, `vm`, and non-literal `import()`/`require()` (DYNAMIC), and `setInterval`, cron libraries, and worker threads (AUTONOMY). Imports are resolved first, so `regex.exec()` or a local `exec` helper isn't mistaken for `child_process.exec`.

TypeScript reachability works like Python's. Each tool's handler is an entry node, and the call graph follows direct calls to functions in the same file, relative imports (ESM, including `./x.js` → `x.ts`, CommonJS `require`, and namespace imports), `this.method()` within a class, and methods of object literals. Callbacks defined inside a function are treated as part of it. Method calls the graph can't resolve, such as `tool.execute()` on a class instance or on a tool object taken from a list, aren't followed: code that only such a call could reach is `unknown`. Other code that isn't on a path, including code reached only through computed calls (`table[name](...)`) or only from top-level code (for example the constructor of a module-level singleton), is `unreachable`. Path depth, states, and exit codes match the Python analysis.

Handlers are found for the patterns above, and also for: `addTool(toolObject)` with a tool object defined in the project; tool-definition objects using `schema`, `parameters`, or `args` instead of `inputSchema`, with a `handler` or `execute` property or method (for example `defineTool({ ..., handler })`); objects passed to a project wrapper that itself calls `registerTool` / `tool` / `addTool`; [xmcp](https://xmcp.dev) file-based tools (a file exporting `metadata` and a default function, in projects that depend on xmcp); and `server.tool(...)` / `registerTool(...)` calls whose name isn't a literal (reported with the name `unknown`, in files that import an MCP SDK).

### Verifying MCP tool annotations

MCP tools can declare [`ToolAnnotations`](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations) hints such as `readOnlyHint`, `openWorldHint`, and `destructiveHint`. Clients use them to decide what to auto-approve, but they're claims the server makes about itself. For Python MCP servers, reachscan checks each claim against what the tool can actually reach:

| Declared | Contradicted by a reachable... | Severity |
|---|---|---|
| `readOnlyHint: true` | WRITE, EXECUTE, or DYNAMIC | high |
| `openWorldHint: false` | outbound HTTP, websocket, or raw socket connect (not to a literal loopback host such as `localhost` or `127.0.0.1`; calls into the project's own modules, database drivers, and other protocol clients don't count) | medium |
| `destructiveHint: false` (with `readOnlyHint: false`) | delete, move/rename, or truncating write | medium |

```text
Annotation Mismatches  —  MCP tool annotations contradicted by reachable code
-----------------------------------------------------------------------------
  [HIGH] get_report declares readOnlyHint: true
    but reaches WRITE via os.remove() (server.py:9)
    path: get_report → _cleanup → os.remove()
```

Every mismatch comes with the call path from that tool to the contradicting code. A contradiction without such a path isn't reported. Only explicitly declared hints are checked: absent hints fall back to the spec's conservative defaults, which claim nothing, and hints reachscan can't resolve statically (imported from outside the project, built by a helper function) are skipped and listed under `--explain`. FastMCP `@mcp.tool(annotations=...)` and lowlevel `types.Tool(...)` declarations are both supported. Lowlevel tools are linked to their branch in the `call_tool` handler when it dispatches with `if name == ...` or `match name:`. Mismatches appear in the text report, in JSON (`annotation_mismatches`, schema 1.1), and in SARIF as rule `mcp-risk-mismatch`. They count toward the [exit code](#exit-codes) through the same `--severity` threshold as findings: a high mismatch fails the scan by default, and medium mismatches do under `--severity medium`. TypeScript support is planned.

---

## What it looks like

```text
Agent Capability Report
=======================

Python Entry Points (LLM-controlled surface)
----------------------------------------------
  • get_lat_lng  (pydantic_ai/decorator @ weather_agent.py:50)
  • get_weather  (pydantic_ai/decorator @ weather_agent.py:67)

Capabilities
------------
  • SEND

Combined Risks
--------------
  None inferred from combined-capability rules.

Reachability Summary
--------------------
     3 reachable     — LLM can trigger these directly
   117 unreachable   — exist in codebase, not on any LLM call path
     3 module-level  — execute on import, not on any call path

Reachable Findings  —  LLM can trigger these directly
------------------------------------------------------
  [HIGH] SEND via ctx.deps.client.get -> https://api.weather.example.com (network @ weather_agent.py:58)
    path: get_lat_lng
    explanation: This code can send data over the network to external services.
    impact: Sensitive local data could be transmitted to untrusted endpoints.

Other Findings  —  not on LLM call path
-----------------------------------------
  [HIGH] UNREACHABLE  SECRETS via os.getenv('ANTHROPIC_API_KEY') (secrets @ model_client.py:12)
    explanation: This code accesses secrets or credential sources.
    impact: Credentials may be disclosed and used for unauthorized access.

  [HIGH] MODULE_LEVEL  SECRETS via os.getenv('PYDANTIC_AI_MODEL') (secrets @ config.py:25)
    reachability: Executes on import — runs whenever this module loads
    explanation: This code accesses secrets or credential sources.
    impact: Credentials may be disclosed and used for unauthorized access.
```

You get file paths and line numbers. Not just "this repo uses subprocess" — you get exactly where, how, and whether the LLM can reach it.

---

## Who needs this

**Agent developers** — audit your own code before shipping. Know exactly what you're granting the LLM access to, and where those grants live in your codebase. Add the [GitHub Action](#ci-integration) to catch new reachable capabilities in every pull request.

**Security and platform teams** — you're deploying agents your developers wrote, or agents that use third-party frameworks. Before they hit production, run a scan. Get a fast, defensible answer to "what can this thing actually do?"

**Anyone integrating third-party tools** — tools, plugins, and MCP servers come with capabilities attached. Scan them *before* wiring them into your agent. `reachscan https://github.com/some-org/some-tool` takes seconds and requires nothing installed on that repo, or ask your coding agent to do it with the [Claude Code / Codex plugin](#use-it-from-claude-code-or-codex).

**MCP server authors** — show your users exactly what your server can reach, with call paths, and check that your tool annotations match. The [GitHub Action](#ci-integration) flags new reachable capabilities and contradicted annotations as the server changes.

---

## It's not just for agents

The name is intentional but the scope is broader.

Any Python or TypeScript/JavaScript code that runs in an AI-adjacent context is a valid target — tool libraries, retrieval pipelines, memory modules, execution sandboxes. If an LLM can call it, you want to know what it can do.

---

## Precision

Detection quality was validated in a structured false positive audit across 10 major open-source agent repos (AutoGPT, LangChain, LlamaIndex, CrewAI, OpenAI Agents SDK, Autogen, pydantic-ai, agentops, anthropic-cookbook, python-sdk) — approximately 3,900 labeled findings:

| Detector | FP Rate |
|---|---|
| `file_access` | 0.0% |
| `secrets` | 0.0% |
| `dynamic_exec` | 0.0% |
| `network` | 0.7% |
| `autonomy` | 1.6% |
| `shell_exec` | 1.9% |
| **Overall** | **0.47%** |

Low noise by design. When it fires, it's real.

This audit covers the Python detectors. The TypeScript/JavaScript detectors are newer and will get their own audit.

---

## What this is NOT

- Not a vulnerability scanner
- Not a linter
- Not a dependency checker
- Not a compliance tool
- Not a prompt injection detector

**It is a capability audit.** Static analysis only — results describe what the code is capable of, not what it will do in any given execution.

---

## Installation

### Option 1 — Recommended (install as a CLI tool)

```bash
pipx install reachscan
```

Or with pip:

```bash
pip install reachscan
```

Then run:

```bash
reachscan .
```

### Option 2 — Install from source (development)

```bash
git clone https://github.com/vinmay/reachscan.git
cd reachscan

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .[dev]
```

### Option 3 — Run without installing

```bash
python -m reachscan.cli examples/demo_agent
```

---

## Use it from Claude Code or Codex

The reachscan plugin adds a `vet-mcp-server` skill to your coding agent. Before you add an MCP server, ask:

```
vet this MCP server before I add it: https://github.com/org/some-mcp-server
```

The agent runs reachscan on the server and tells you what each tool can execute, read, write, and send, with call paths for high-risk findings and an **Install / Review first / Avoid** verdict based only on the scan results. The plugin needs the reachscan CLI on your `PATH` (`pipx install reachscan`) and a terminal, so it works in Claude Code and Codex.

**Claude Code** (inside a session):

```
/plugin marketplace add vinmay/reachscan
/plugin install reachscan@reachscan
```

**Codex:**

```bash
codex plugin marketplace add vinmay/reachscan
```

Then open the Plugins Directory, choose the **reachscan** marketplace, and install the plugin. Details are in [`integrations/agent-plugins`](integrations/agent-plugins/README.md).

---

## Requirements

- Python 3.11+
- pip or pipx

---

## Usage

```
reachscan [target] [--json | --sarif] [--sarif-include-unreachable] [--severity {high,medium,none}] [--explain]
```

`target` accepts:

| Input | Example |
|---|---|
| Local path | `reachscan .` |
| Local path, JSON output | `reachscan ./my_agent --json` |
| Local path, SARIF output | `reachscan ./my_agent --sarif` |
| GitHub repository URL | `reachscan https://github.com/org/repo` |
| MCP HTTP endpoint | `reachscan mcp+https://mcp.example.com` |
| PyPI package (latest) | `reachscan pypi:requests` |
| PyPI package (pinned) | `reachscan pypi:requests==2.31.0` |

The GitHub URL path does a shallow clone — you don't need the repo checked out locally.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, threshold not exceeded |
| `1` | Scan complete, ≥1 reachable finding or annotation mismatch meets the severity threshold (findings and mismatches [suppressed in source](#suppressing-findings) don't count) |
| `2` | Scan failed (bad target, network error, unhandled exception) |

### Suppressing findings

When a capability is intended, say so next to the code, with a reason:

```python
subprocess.run(cmd, shell=True)  # reachscan:allow-execute this tool runs operator-provided commands
```

```ts
// reachscan:allow-send posts to our own API
await fetch(API_URL, { method: "POST", body });
```

The tag names one capability (`allow-execute`, `allow-read`, `allow-write`, `allow-send`, `allow-secrets`, `allow-dynamic`, `allow-autonomy`). It applies to its own line when it follows code, or to the next line of code when the comment stands alone (stacked comment lines are fine; a blank line ends it). A reason is required: a tag without one is ignored and reported under "Suppression Warnings".

Suppressed findings stay in every output, marked with the reason: `SUPPRESSED` in the text report, `suppression` in JSON, and an in-source suppression in SARIF, which GitHub code scanning shows as suppressed rather than open. They don't affect the exit code. They still count toward combined risks, since the capability is still there; a risk that includes suppressed findings says so and lists them.

An annotation mismatch is a different claim, that a tool's declared hint is false, so suppressing the sink doesn't suppress it. To accept a mismatch, put `reachscan:allow-mismatch <reason>` on the tool's decorator or `types.Tool(...)` line, or on a comment line directly above it:

```python
# reachscan:allow-mismatch writes only to its own cache; no user data is modified
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_report(...): ...
```

### `--severity` flag

Controls when the CLI exits 1:

| Value | Exit 1 when... |
|-------|----------------|
| `high` *(default)* | reachable finding or annotation mismatch with `risk_level == "high"` |
| `medium` | reachable finding or annotation mismatch with `risk_level in ("high", "medium")` |
| `none` | never — always exits 0 |

### `--explain` flag

Expands the call chain for every reachable finding, showing each hop with its source file. Use this when you want to understand exactly how the LLM reaches a capability — not just that it can, but through which functions.

Without `--explain`:
```
  [HIGH] DYNAMIC via exec() (dynamic_exec @ addon.py:431)
    path: execute_blender_code → … → execute_code
```

With `--explain`:
```
  [HIGH] DYNAMIC via exec() (dynamic_exec @ addon.py:431)
    call chain:
      execute_blender_code @ server.py
      → send_command @ server.py
      → execute_code @ addon.py
```

Only applies to the text report. Has no effect with `--json` or `--sarif`.

### `--sarif` flag

Writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) to stdout, for GitHub code scanning and other SARIF viewers. It can't be combined with `--json`, and exit codes are the same.

- One rule per capability (`reachscan/EXECUTE`, `reachscan/SEND`, ...) and one per combined risk (`reachscan/combined/remote_control`, ...).
- Levels: a reachable high-risk finding is `error`, a reachable medium-risk finding is `warning`, and everything else is `note`.
- Each reachable finding has a `codeFlow` that walks the call chain from the LLM entry point to the sink, so the code scanning UI shows the path step by step.
- Reachability state, confidence, and entry point are in each result's `properties`.
- By default only `reachable` and `module_level` findings are included, so the Security tab shows only what an LLM can trigger. Add `--sarif-include-unreachable` to include everything.
- When a language has findings but no detected entry points, reachability isn't evaluated for it and its findings are left out by default. The SARIF run then carries a warning notification (`invocations[].toolExecutionNotifications`) saying how many findings weren't shown, so an empty Security tab isn't mistaken for a clean scan.

---

## CI Integration

The easiest way is the [reachscan GitHub Action](https://github.com/marketplace/actions/reachscan). It installs reachscan, uploads findings to the GitHub Security tab with call chains, and fails the job when a reachable finding meets your severity threshold:

```yaml
name: reachscan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  reachscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: vinmay/reachscan-action@v1
        # with:
        #   severity: medium   # or none for report-only
        #   path: servers/my-mcp-server
```

Inputs, outputs, and more examples are in the [action's README](https://github.com/vinmay/reachscan-action).

To run the CLI yourself instead, for example to keep a JSON report as a build artifact:

```yaml
- uses: actions/checkout@v7
- run: pipx install reachscan
- name: Run capability audit
  run: reachscan . --json > reachscan-report.json
  # Exits 1 if HIGH reachable capabilities found
- uses: actions/upload-artifact@v7
  if: always()
  with:
    name: reachscan-report
    path: reachscan-report.json
```

To audit without blocking the pipeline (report only):

```yaml
- run: reachscan . --json --severity none > reachscan-report.json
```

To upload SARIF to the GitHub Security tab without the action:

```yaml
permissions:
  security-events: write
  contents: read
steps:
  - uses: actions/checkout@v7
  - run: pipx install reachscan
  - name: Run reachscan
    run: reachscan . --sarif > reachscan.sarif
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: reachscan.sarif
      category: reachscan
```

---

## Project direction

The goal:

> Give AI systems a permission model they've never had.

Static capability detection is the foundation. Reachability analysis on top of it answers the harder question: not just *can* this code do something, but *can the LLM trigger it*.

---

## Status

What works today:

| Area | Status |
|---|---|
| Python | Capability detection, entry points for the frameworks above, call-graph reachability (up to 8 hops), MCP annotation verification |
| TypeScript / JavaScript | Parsed with tree-sitter (no Node.js needed). Entry point detection, capability detection for all seven classes, and reachability through TS call paths |
| Scan targets | Local paths, GitHub URLs, PyPI packages (`pypi:name[==version]`), MCP HTTP endpoints (`mcp+https://...`) |
| Output | Text report, JSON ([schema v1](docs/schema_v1.md)), SARIF 2.1.0 with call chains, `--explain` call traces |
| CI | [GitHub Action](https://github.com/marketplace/actions/reachscan) with Security tab upload and a severity gate; exit codes for any other CI |
| Coding agents | [Plugin for Claude Code and Codex](#use-it-from-claude-code-or-codex) that vets MCP servers before you install them |
| Precision | 0.47% false-positive rate across ~3,900 labeled Python findings ([details](#precision)); a TypeScript audit is planned |

The JSON output schema is stable at v1 — see [`docs/schema_v1.md`](docs/schema_v1.md) for the full field reference. Feedback, edge cases, and false positive reports are especially valuable — open an issue.

---

## Support

If reachscan is useful to you, [star the repo](https://github.com/vinmay/reachscan) — it helps others find it and tells us people care about this problem.
