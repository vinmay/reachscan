"""Test fixture: an MCP tool that can reach subprocess.run (reachscan should exit 1)."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vulnerable-fixture")


def _run(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


@mcp.tool()
def run_command(cmd: str) -> str:
    return _run(cmd).stdout
