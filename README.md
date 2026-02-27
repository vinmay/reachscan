# agent-scan

> Static capability analysis for Python AI code.
> Know what it can do before it does it.

---

## The problem

You're giving an LLM tools. Tools mean real-world access — files, shell, network, credentials.

Most developers add tools without a clear accounting of what permissions they're actually granting. The agent docs tell you what the tool is *for*. They don't tell you what it *can do*.

`agent-scan` is the accounting.

It analyzes Python code and reports the actual capabilities present: what the code can read, write, execute, send, and access. Not what the README says. What the code does.

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

## What it looks like

```text
Agent Capability Report
=======================

Target: ./my_agent

Capabilities
------------
  • Read local files
  • Send data to external servers
  • Execute shell commands
  • Access environment variables and secrets

Findings
--------
  [READ]    agent/tools/file_tool.py:42     open(path, 'r')
  [SEND]    agent/client.py:87              requests.post(self.endpoint, json=payload)
  [EXECUTE] agent/runner.py:23              subprocess.run(cmd, shell=True)
  [SECRETS] agent/config.py:15             os.environ['OPENAI_API_KEY']

Risk Analysis
-------------
  DATA EXPOSURE
    READ + SEND detected — local files may be transmitted externally

  SYSTEM MODIFICATION
    EXECUTE detected — shell commands can be run on the host machine
```

You get file paths and line numbers. Not just "this repo uses subprocess" — you get exactly where and how.

---

## Who needs this

**Agent developers** — audit your own code before shipping. Know exactly what you're granting the LLM access to, and where those grants live in your codebase.

**Security and platform teams** — you're deploying agents your developers wrote, or agents that use third-party frameworks. Before they hit production, run a scan. Get a fast, defensible answer to "what can this thing actually do?"

**Anyone integrating third-party tools** — tools, plugins, and MCP servers come with capabilities attached. Scan them *before* wiring them into your agent. `agent-scan https://github.com/some-org/some-tool` takes seconds and requires nothing installed on that repo.

**MCP server authors** — show your users exactly what your server can and cannot do. A clean scan result is a trust signal.

---

## It's not just for agents

The name is intentional but the scope is broader.

Any Python code that runs in an AI-adjacent context is a valid target — tool libraries, retrieval pipelines, memory modules, execution sandboxes. If an LLM can call it, you want to know what it can do.

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
agent-scan [target] [--json]
```

`target` accepts:

| Input | Example |
|---|---|
| Local path | `agent-scan .` |
| Local path, JSON output | `agent-scan ./my_agent --json` |
| GitHub repository URL | `agent-scan https://github.com/org/repo` |
| MCP HTTP endpoint | `agent-scan mcp+https://mcp.example.com` |

The GitHub URL path does a shallow clone — you don't need the repo checked out locally.

---

## Project direction

Phase 1 is visibility: static capability detection with low false positive rates, across any Python AI codebase.

The goal:

> Give AI systems a permission model they've never had.

---

## Status

Stable for Phase 1 capability detection. Rules and output format may evolve.
Feedback, edge cases, and false positive reports are especially valuable — open an issue.
