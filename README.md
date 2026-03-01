# agent-scan

> Static capability analysis for Python and TypeScript/JavaScript AI code.
> Know what it can do before it does it.

---

## The problem

You're giving an LLM tools. Tools mean real-world access — files, shell, network, credentials.

Most developers add tools without a clear accounting of what permissions they're actually granting. The agent docs tell you what the tool is *for*. They don't tell you what it *can do*.

`agent-scan` is the accounting.

It analyzes Python and TypeScript/JavaScript code and reports the actual capabilities present: what the code can read, write, execute, send, and access. Not what the README says. What the code does.

---

## What it detects

Seven capability classes, built from AST analysis and pattern matching:

| Capability | What it means |
|---|---|
| `EXECUTE` | Shell commands, subprocess, OS exec APIs |
| `READ` | Local file reads, path traversal |
| `WRITE` | File creation, modification, deletion |
| `SEND` | Outbound HTTP, websockets, raw sockets |
| `SECRETS` | Env vars, credential managers, secret stores |
| `DYNAMIC` | eval, exec, dynamic imports |
| `AUTONOMY` | Background tasks, schedulers, self-directed execution |

Cross-capability risks are also flagged — READ + SEND detected together raises a data exfiltration flag. SECRETS + SEND raises a credential leak flag.

---

## Reachability analysis

Knowing a capability exists in a codebase is useful. Knowing whether the LLM can actually trigger it is what matters.

`agent-scan` detects the LLM-facing entry points in your codebase, builds an intra-project call graph, and traces which capabilities are reachable from those entry points. Every finding is tagged with one of five states:

| State | Meaning |
|---|---|
| `reachable` | Confirmed on a call path from an LLM entry point |
| `unreachable` | Exists in the codebase, not on any LLM call path |
| `module_level` | Runs on import — executes when the module loads, not via a function call |
| `unknown` | Inside code that can't be statically resolved (dynamic dispatch, parse failure) |
| `no_entry_points` | No entry points detected — full reachability analysis not possible |

The call graph follows up to 8 hops from each entry point. Call paths are shown in the report so you can see exactly how the LLM reaches a capability.

### Entry point detection — Python

`agent-scan` recognises LLM-callable functions across all major Python agent frameworks:

| Framework | Detection pattern |
|---|---|
| Pydantic AI | `@agent.tool`, `@agent.tool_plain` |
| LangChain / CrewAI | `@tool`, `class MyTool(BaseTool)` |
| OpenAI Agents SDK | `@function_tool` |
| MCP (Python SDK / FastMCP) | `@mcp.tool()`, `@server.tool()` |
| Semantic Kernel | `@kernel_function` |
| AutoGen | `@register_for_llm` |

Framework attribution uses a confidence-graded resolution chain: direct imports are resolved at 0.95 confidence, inferred instance variables (e.g. `weather_agent = Agent[Deps, T](...)`) at 0.80, and unresolvable decorator names fall back to the best available label at 0.60.

Python entry points feed into the reachability pass — the call graph is traced from each detected entry point to identify which capabilities the LLM can actually trigger.

### Entry point detection — TypeScript and JavaScript

`agent-scan` scans `.ts`, `.js`, `.mts`, `.mjs`, `.cts`, and `.cjs` files using regex-based pattern matching. No Node.js runtime is required.

| Pattern | What it detects | Confidence |
|---|---|---|
| `mcp_tool` | `server.tool("name", schema, handler)` | 0.95 |
| `mcp_tool_definition` | `{ name: "...", description: ..., inputSchema: ... }` objects | 0.85 |
| `langchain_tool` | `new DynamicTool({ name: "...", ... })` | 0.85 |
| `mcp_handler` | `server.setRequestHandler(Schema, ...)` | 0.80 |

Both same-line and multi-line registration styles are handled for each pattern. Declaration files (`.d.ts`), test files, minified bundles, and `node_modules`/`dist`/`build` directories are automatically excluded.

**Current limitation:** TypeScript and JavaScript function bodies are not capability-analyzed — only entry points are detected. When a project mixes Python and TypeScript, capability findings come from the Python side and TypeScript entry points are listed separately in the report.

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

**Agent developers** — audit your own code before shipping. Know exactly what you're granting the LLM access to, and where those grants live in your codebase.

**Security and platform teams** — you're deploying agents your developers wrote, or agents that use third-party frameworks. Before they hit production, run a scan. Get a fast, defensible answer to "what can this thing actually do?"

**Anyone integrating third-party tools** — tools, plugins, and MCP servers come with capabilities attached. Scan them *before* wiring them into your agent. `agent-scan https://github.com/some-org/some-tool` takes seconds and requires nothing installed on that repo.

**MCP server authors** — show your users exactly what your server can and cannot do. A clean scan result is a trust signal.

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

---

## What this is NOT

- Not a vulnerability scanner
- Not a linter
- Not a dependency checker
- Not a compliance tool
- Not a prompt injection detector *(planned)*

**It is a capability audit.** Static analysis only — results describe what the code is capable of, not what it will do in any given execution.

---

## Installation

### Option 1 — Recommended (install as a CLI tool)

```bash
pipx install git+https://github.com/vinmay/agent-scan.git
```

Then run:

```bash
agent-scan .
```

### Option 2 — Install from source (development)

```bash
git clone https://github.com/vinmay/agent-scan.git
cd agent-scan

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .[dev]
```

### Option 3 — Run without installing

```bash
python -m agent_scan.cli examples/demo_agent
```

---

## Requirements

- Python 3.11+
- pip or pipx

---

## Usage

```
agent-scan [target] [--json] [--severity {high,medium,none}]
```

`target` accepts:

| Input | Example |
|---|---|
| Local path | `agent-scan .` |
| Local path, JSON output | `agent-scan ./my_agent --json` |
| GitHub repository URL | `agent-scan https://github.com/org/repo` |
| MCP HTTP endpoint | `agent-scan mcp+https://mcp.example.com` |
| PyPI package (latest) | `agent-scan pypi:requests` |
| PyPI package (pinned) | `agent-scan pypi:requests==2.31.0` |

The GitHub URL path does a shallow clone — you don't need the repo checked out locally.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, threshold not exceeded |
| `1` | Scan complete, ≥1 reachable finding exceeds severity threshold |
| `2` | Scan failed (bad target, network error, unhandled exception) |

### `--severity` flag

Controls when the CLI exits 1:

| Value | Exit 1 when... |
|-------|----------------|
| `high` *(default)* | reachable finding with `risk_level == "high"` |
| `medium` | reachable finding with `risk_level in ("high", "medium")` |
| `none` | never — always exits 0 |

---

## CI Integration

```yaml
name: Agent Capability Audit
on: [push, pull_request]
jobs:
  agent-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install agent-scan
      - name: Run capability audit
        run: agent-scan . --json > agent-scan-report.json
        # Exits 1 if HIGH reachable capabilities found
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agent-scan-report
          path: agent-scan-report.json
```

To audit without blocking the pipeline (report only):

```yaml
- run: agent-scan . --json --severity none > agent-scan-report.json
```

---

## Project direction

The goal:

> Give AI systems a permission model they've never had.

Static capability detection is the foundation. Reachability analysis on top of it answers the harder question: not just *can* this code do something, but *can the LLM trigger it*.

---

## Status

Capability detection is stable. Reachability analysis is active — entry point detection covers all major Python agent frameworks and the call graph traversal handles projects of any size. TypeScript/JavaScript entry point detection is stable.

The JSON output schema is stable at v1 — see [`docs/schema_v1.md`](docs/schema_v1.md) for the full field reference. Feedback, edge cases, and false positive reports are especially valuable — open an issue.
