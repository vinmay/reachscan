# agent-scan

Tells you what your AI agent can access, change, and send — before it does.
Because giving an LLM a tool is giving it power.

agent-scan analyzes your agent code and prints the real-world actions it is capable of performing.

This is NOT a vulnerability scanner.
This is NOT a linter.
This is NOT a dependency checker
This is NOT a compliance tool
This is NOT a prompt injection detector (yet)

It is a capability audit.

Supported: Python agent frameworks (initially generic tool patterns)

Why?
Most developers give agents powerful tools without realizing the consequences.
agent-scan makes those consequences visible.

Usage:
  agent-scan [path] [--json] [--rules=all|core]

Examples:
  agent-scan .
  agent-scan ./examples/demo-agent --json