# agent-scan

> **Tells you what your AI agent can access, change, and send — before it does.**  
> Because giving an LLM a tool is giving it power.

---

## What is this?

`agent-scan` analyzes your agent code and prints the **real-world actions it is capable of performing**.

Instead of showing implementation details, it shows consequences.

Example:

```text
Agent Capability Report
=======================

Capabilities
------------
  • Read local files
  • Send data to external servers
  • Execute shell commands
  • Access environment variables

Risk Analysis
-------------
  DATA EXPOSURE
    Local files may be transmitted externally

  SYSTEM MODIFICATION
    Commands may be executed on the host machine
```

## What this is NOT

To avoid confusion:

- ❌ Not a vulnerability scanner  
- ❌ Not a linter  
- ❌ Not a dependency checker  
- ❌ Not a compliance tool  
- ❌ Not a prompt injection detector *(yet)*  

**It is a capability audit.**

Static analysis only: results are inferred from code patterns and do not prove runtime behavior or exploitability.

---

## Why this exists

Most developers give agents powerful tools without realizing the consequences.

An LLM with tools is no longer just generating text —  
it is a program acting on your system.

`agent-scan` makes those powers visible.

---

## Supported

Currently supports:

**Python agent frameworks**  
(Initially generic tool patterns — framework-agnostic detection)

**Capabilities detected (phase-1)**  
EXECUTE — ability to run shell commands or invoke system execution APIs  
READ — ability to read local files or file-like content  
WRITE — ability to create, modify, delete, or move files  
SEND — ability to make outbound network requests  
SECRETS — ability to access credentials, env vars, or secret managers  
DYNAMIC — ability to execute dynamically generated code or perform dynamic imports  
AUTONOMY — ability to schedule or run background tasks without explicit user approval

---

## Installation

### Option 1 — Recommended (install as a CLI tool)

Install using **pipx** so it runs globally but stays isolated:

```bash
pipx install git+https://github.com/vinmay/agent-scan.git
```

Then run:

```bash
agent-scan .
```

---

### Option 2 — Install from source (development)

```bash
git clone https://github.com/vinmay/agent-scan.git
cd agent-scan

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .[dev]
```

Run the example:

```bash
agent-scan examples/demo_agent
```

Demo agents include file, network, secrets, and dynamic execution patterns for static scanning in `examples/demo_agent/`.

---

### Option 3 — Run without installing

```bash
python -m agent_scan.cli examples/demo_agent
```

---

## Requirements

- Python 3.11+
- pip or pipx

> If `agent-scan` command is not found after installation, ensure your `pipx` or virtual environment binaries are on your PATH.

## Usage

agent-scan [target] [--json] [--rules=all|core]

`target` can be:
- local file/directory path
- GitHub repository URL (for example `https://github.com/org/repo`)
- MCP HTTP endpoint (prefix with `mcp+`, for example `mcp+https://mcp.example.com`)

### Examples

- agent-scan .
- agent-scan ./examples/demo_agent --json
- agent-scan https://github.com/openai/openai-python --json
- agent-scan mcp+https://mcp.example.com

---

## Project direction

This project starts as visibility.

Later phases:

- detect dangerous capability chains
- CI change detection
- runtime protection

The goal is simple:

> Give AI agents a permission system they never had.

---

## Status

Early prototype — rules and output will evolve quickly.
Feedback and weird edge cases are especially valuable.
