"""Test fixture: an MCP tool with no risky capabilities (reachscan should exit 0)."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-fixture")


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
