# agent-scan

> **Tells you what your AI agent can access, change, and send — before it does.**  
> Because giving an LLM a tool is giving it power.

---

## What is this?

`agent-scan` analyzes your agent code and prints the **real-world actions it is capable of performing**.

Instead of showing implementation details, it shows consequences.

Example:

Agent Capability Report
───────────────────────

This agent can:

• Read local files
• Send data to external servers
• Execute shell commands
• Access environment variables

Possible impact:
Local files and secrets could be transmitted externally.

---

## What this is NOT

To avoid confusion:

- ❌ Not a vulnerability scanner  
- ❌ Not a linter  
- ❌ Not a dependency checker  
- ❌ Not a compliance tool  
- ❌ Not a prompt injection detector *(yet)*  

**It is a capability audit.**

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

---

## Usage

agent-scan [path] [--json] [--rules=all|core]

### Examples

agent-scan .
agent-scan ./examples/demo-agent --json

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
