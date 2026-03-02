"""Tests for TypeScript/JavaScript entry point detection."""

import pytest
from pathlib import Path
from agent_scan.ts_entry_points import (
    detect_ts_entry_points,
    scan_ts_files,
    _is_excluded_ts_file,
)


# ---------------------------------------------------------------------------
# MCP server.tool("name", ...) — Priority 1
# ---------------------------------------------------------------------------

def test_mcp_tool_single():
    content = '''
const server = new Server({ name: "my-server", version: "1.0.0" });

server.tool("read_file", { path: z.string() }, async ({ path }) => {
    return fs.readFileSync(path, "utf-8");
});
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "read_file"
    assert r.pattern_type == "mcp_tool"
    assert r.confidence == 0.95
    assert r.lineno == 4


def test_mcp_tool_multiple():
    content = '''
server.tool("read_file", schema, handler1);
server.tool("write_file", schema, handler2);
server.tool("search_web", schema, handler3);
'''
    results = detect_ts_entry_points("tools.ts", content)
    names = [r.name for r in results]
    assert names == ["read_file", "write_file", "search_web"]
    assert all(r.pattern_type == "mcp_tool" for r in results)


def test_mcp_tool_single_quotes():
    content = "server.tool('execute_code', schema, handler);\n"
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "execute_code"


def test_mcp_tool_different_variable_names():
    """Variable name before .tool() doesn't have to be 'server'."""
    content = '''
mcp.tool("get_weather", schema, handler);
s.tool("send_email", schema, handler);
'''
    results = detect_ts_entry_points("tools.ts", content)
    names = [r.name for r in results]
    assert "get_weather" in names
    assert "send_email" in names


def test_mcp_tool_no_match_on_variable_first_arg():
    """Dynamic tool name (variable, not string literal) should not fire."""
    content = "server.tool(TOOL_NAME, schema, handler);\n"
    results = detect_ts_entry_points("tools.ts", content)
    assert results == []


# ---------------------------------------------------------------------------
# MCP server.tool( — name on next line — Priority 1b
# ---------------------------------------------------------------------------

def test_mcp_tool_name_on_next_line():
    """server.tool( with name on the very next line is detected."""
    content = '''\
server.tool(
    "web_search_exa",
    "Search the web for any topic",
    { query: z.string() },
    async ({ query }) => { return query; }
);
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "web_search_exa"
    assert results[0].pattern_type == "mcp_tool"
    assert results[0].confidence == 0.95
    assert results[0].lineno == 1


def test_mcp_tool_name_on_next_line_single_quotes():
    content = "server.tool(\n    'execute_code',\n    handler\n);\n"
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "execute_code"


def test_mcp_tool_name_on_next_line_variable_skipped():
    """Variable first arg with description on line 2 must NOT produce a false positive."""
    content = '''\
agent.server.tool(
    TOOLS.kv_namespace_create,
    'Create a new kv namespace',
    { title: z.string() },
    async (params) => {}
);
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert results == []


def test_mcp_tool_name_on_next_line_multiple():
    """Multiple multi-line tool registrations."""
    content = '''\
server.tool(
    "read_file",
    "Read a file",
    { path: z.string() },
    async ({ path }) => {}
);
server.tool(
    "write_file",
    "Write a file",
    { path: z.string(), content: z.string() },
    async ({ path, content }) => {}
);
'''
    results = detect_ts_entry_points("tools.ts", content)
    names = [r.name for r in results]
    assert "read_file" in names
    assert "write_file" in names


# ---------------------------------------------------------------------------
# MCP setRequestHandler — Priority 2
# ---------------------------------------------------------------------------

def test_mcp_set_request_handler():
    content = '''
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    // handle calls
});
'''
    results = detect_ts_entry_points("server.ts", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "CallToolRequestSchema"
    assert r.pattern_type == "mcp_handler"
    assert r.confidence == 0.80
    assert r.lineno == 2


def test_mcp_set_request_handler_list_tools():
    content = "server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));\n"
    results = detect_ts_entry_points("server.ts", content)
    assert len(results) == 1
    assert results[0].name == "ListToolsRequestSchema"


def test_mcp_both_handlers():
    content = '''
server.setRequestHandler(ListToolsRequestSchema, listHandler);
server.setRequestHandler(CallToolRequestSchema, callHandler);
'''
    results = detect_ts_entry_points("server.ts", content)
    assert len(results) == 2
    names = [r.name for r in results]
    assert "ListToolsRequestSchema" in names
    assert "CallToolRequestSchema" in names


def test_mcp_set_request_handler_schema_on_next_line():
    """Schema argument on the line after setRequestHandler( is detected."""
    content = '''\
server.setRequestHandler(
    ReadResourceRequestSchema,
    async (request) => {
        return context.readResource(request.params.uri);
    },
);
'''
    results = detect_ts_entry_points("server.ts", content)
    assert len(results) == 1
    assert results[0].name == "ReadResourceRequestSchema"
    assert results[0].pattern_type == "mcp_handler"
    assert results[0].lineno == 1


def test_mcp_set_request_handler_mixed_inline_and_multiline():
    """Mix of inline and multi-line setRequestHandler in the same file."""
    content = '''\
server.setRequestHandler(ListResourcesRequestSchema, async () => {});
server.setRequestHandler(
    ReadResourceRequestSchema,
    async (request) => {},
);
server.setRequestHandler(
    ListResourceTemplatesRequestSchema,
    async () => {},
);
'''
    results = detect_ts_entry_points("server.ts", content)
    names = {r.name for r in results}
    assert "ListResourcesRequestSchema" in names
    assert "ReadResourceRequestSchema" in names
    assert "ListResourceTemplatesRequestSchema" in names
    assert len(results) == 3


# ---------------------------------------------------------------------------
# MCP tool definition object — Priority 3
# ---------------------------------------------------------------------------

def test_mcp_tool_definition_inline():
    """name + description + inputSchema on adjacent lines."""
    content = '''\
const navigateSchema = {
    name: "playwright_navigate",
    description: "Navigate to a URL",
    inputSchema: {
        type: "object",
    },
};
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    r = results[0]
    assert r.name == "playwright_navigate"
    assert r.pattern_type == "mcp_tool_definition"
    assert r.confidence == 0.85
    assert r.lineno == 2


def test_mcp_tool_definition_multiple():
    """Multiple tool definitions in an array."""
    content = '''\
return [
    {
        name: "read_file",
        description: "Read a file",
        inputSchema: { type: "object" },
    },
    {
        name: "write_file",
        description: "Write a file",
        inputSchema: { type: "object" },
    },
];
'''
    results = detect_ts_entry_points("tools.ts", content)
    names = [r.name for r in results]
    assert "read_file" in names
    assert "write_file" in names
    assert all(r.pattern_type == "mcp_tool_definition" for r in results)


def test_mcp_tool_definition_no_fp_without_input_schema():
    """name + description but no inputSchema should not fire."""
    content = '''\
const serverInfo = {
    name: "my-server",
    description: "A server config",
};
'''
    results = detect_ts_entry_points("config.ts", content)
    assert results == []


def test_mcp_tool_definition_no_fp_without_description():
    """name + inputSchema but no description should not fire."""
    content = '''\
const schema = {
    name: "some_schema",
    inputSchema: { type: "object" },
};
'''
    results = detect_ts_entry_points("schema.ts", content)
    assert results == []


def test_mcp_tool_definition_tool_schema_typed():
    """ToolSchema<> typed variable — browserbase-style pattern."""
    content = '''\
const navigateSchema: ToolSchema<typeof NavigateInputSchema> = {
    name: "browserbase_navigate",
    description: "Navigate to a URL in the browser",
    inputSchema: NavigateInputSchema,
};
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "browserbase_navigate"
    assert results[0].pattern_type == "mcp_tool_definition"


# ---------------------------------------------------------------------------
# LangChain.js DynamicTool — Priority 4
# ---------------------------------------------------------------------------

def test_langchain_dynamic_tool_inline():
    """Name on the same line as the constructor."""
    content = 'const t = new DynamicTool({ name: "web_search", description: "...", func: handler });\n'
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "web_search"
    assert results[0].pattern_type == "langchain_tool"
    assert results[0].confidence == 0.85


def test_langchain_dynamic_structured_tool_inline():
    content = 'const t = new DynamicStructuredTool({ name: "calculator", schema: z.object({}), func: handler });\n'
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "calculator"


def test_langchain_dynamic_tool_multiline():
    """Name on a line following the constructor."""
    content = '''\
const searchTool = new DynamicTool({
    name: "web_search",
    description: "Search the internet for information.",
    func: async (input: string) => {
        return await search(input);
    },
});
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "web_search"
    assert results[0].lineno == 1  # line of the constructor call


def test_langchain_dynamic_tool_name_not_found():
    """DynamicTool where name isn't found within lookahead → 'unknown'."""
    content = '''\
const t = new DynamicTool({
    description: "A tool with no name property in range",
});
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1
    assert results[0].name == "unknown"


# ---------------------------------------------------------------------------
# server.registerTool() — MCP SDK v1.6+
# ---------------------------------------------------------------------------

def test_mcp_register_tool_inline():
    """server.registerTool("name", schema, handler) — name on same line."""
    content = 'server.registerTool("resolve-library-id", { description: "..." }, handler);\n'
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 1
    assert results[0].name == "resolve-library-id"
    assert results[0].pattern_type == "mcp_tool"
    assert results[0].confidence == 0.95


def test_mcp_register_tool_multiline():
    """server.registerTool( with name on the next line."""
    content = '''\
server.registerTool(
  "get-library-docs",
  { description: "Fetch docs" },
  handler
);
'''
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 1
    assert results[0].name == "get-library-docs"
    assert results[0].lineno == 1


def test_mcp_register_tool_multiple():
    """Multiple registerTool calls are each detected."""
    content = '''\
server.registerTool("tool-a", schema, handlerA);
server.registerTool("tool-b", schema, handlerB);
'''
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 2
    assert {r.name for r in results} == {"tool-a", "tool-b"}


def test_mcp_register_tool_no_match_variable_first_arg():
    """Dynamic name (variable) as first arg must not fire."""
    content = 'server.registerTool(TOOL_NAME, schema, handler);\n'
    results = detect_ts_entry_points("index.ts", content)
    assert results == []


# ---------------------------------------------------------------------------
# server.addTool() — FastMCP
# ---------------------------------------------------------------------------

def test_mcp_add_tool_multiline():
    """server.addTool({ name: 'x', ... }) — name on a following line."""
    content = '''\
server.addTool({
  name: 'firecrawl_scrape',
  description: 'Scrape content from a URL',
  parameters: z.object({ url: z.string() }),
  execute: async ({ url }) => fetch(url),
});
'''
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 1
    assert results[0].name == "firecrawl_scrape"
    assert results[0].pattern_type == "mcp_tool"
    assert results[0].confidence == 0.90


def test_mcp_add_tool_inline():
    """server.addTool with name: on same line as addTool(."""
    content = "server.addTool({ name: 'quick_tool', execute: handler });\n"
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 1
    assert results[0].name == "quick_tool"


def test_mcp_add_tool_multiple():
    """Multiple addTool calls are each detected."""
    content = '''\
server.addTool({
  name: 'tool_one',
  execute: handlerOne,
});
server.addTool({
  name: 'tool_two',
  execute: handlerTwo,
});
'''
    results = detect_ts_entry_points("index.ts", content)
    assert len(results) == 2
    assert {r.name for r in results} == {"tool_one", "tool_two"}


def test_mcp_add_tool_no_name_skipped():
    """addTool({}) with no name: property within lookahead → skipped (name='unknown')."""
    content = '''\
server.addTool({
  execute: handler,
});
'''
    results = detect_ts_entry_points("index.ts", content)
    # name would be "unknown" → should not be emitted
    assert results == []


# ---------------------------------------------------------------------------
# No false positives on plain TypeScript
# ---------------------------------------------------------------------------

def test_no_fp_plain_function():
    content = '''\
function greet(name: string): string {
    return `Hello, ${name}!`;
}
export { greet };
'''
    results = detect_ts_entry_points("util.ts", content)
    assert results == []


def test_no_fp_class_method():
    content = '''\
class MyService {
    async process(input: string) {
        return input.toUpperCase();
    }
}
'''
    results = detect_ts_entry_points("service.ts", content)
    assert results == []


def test_no_fp_tool_with_variable_first_arg():
    """Only string literal first args count for server.tool()."""
    content = "server.tool(toolConfig.name, toolConfig.schema, toolConfig.handler);\n"
    results = detect_ts_entry_points("tools.ts", content)
    assert results == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_no_duplicate_findings():
    """Same name at same line should not appear twice."""
    content = 'server.tool("read_file", schemaA, handlerA);\n'
    results = detect_ts_entry_points("tools.ts", content)
    assert len(results) == 1


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

def test_dts_excluded():
    assert _is_excluded_ts_file(Path("src/types.d.ts")) is True


def test_test_file_excluded():
    assert _is_excluded_ts_file(Path("src/tools.test.ts")) is True
    assert _is_excluded_ts_file(Path("src/tools.spec.ts")) is True


def test_min_js_excluded():
    assert _is_excluded_ts_file(Path("dist/bundle.min.js")) is True


def test_normal_ts_not_excluded():
    assert _is_excluded_ts_file(Path("src/tools.ts")) is False


def test_node_modules_excluded():
    assert _is_excluded_ts_file(Path("node_modules/some-pkg/index.ts")) is True


def test_dist_excluded():
    assert _is_excluded_ts_file(Path("dist/index.js")) is True


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def test_scan_ts_files_finds_tools(tmp_path):
    tools_file = tmp_path / "src" / "tools.ts"
    tools_file.parent.mkdir(parents=True)
    tools_file.write_text(
        'server.tool("get_data", schema, handler);\n'
        'server.tool("set_data", schema, handler);\n'
    )

    results = scan_ts_files(tmp_path)
    assert len(results) == 2
    names = {r.name for r in results}
    assert names == {"get_data", "set_data"}


def test_scan_ts_files_skips_node_modules(tmp_path):
    nm_file = tmp_path / "node_modules" / "pkg" / "index.ts"
    nm_file.parent.mkdir(parents=True)
    nm_file.write_text('server.tool("should_not_appear", schema, h);\n')

    src_file = tmp_path / "src" / "tools.ts"
    src_file.parent.mkdir(parents=True)
    src_file.write_text('server.tool("real_tool", schema, h);\n')

    results = scan_ts_files(tmp_path)
    names = {r.name for r in results}
    assert "real_tool" in names
    assert "should_not_appear" not in names


def test_scan_ts_files_skips_dts(tmp_path):
    dts_file = tmp_path / "src" / "index.d.ts"
    dts_file.parent.mkdir(parents=True)
    dts_file.write_text('server.tool("from_declaration", schema, h);\n')

    results = scan_ts_files(tmp_path)
    assert results == []


def test_scan_ts_files_empty_dir(tmp_path):
    results = scan_ts_files(tmp_path)
    assert results == []


def test_scan_single_ts_file(tmp_path):
    f = tmp_path / "tools.ts"
    f.write_text('server.tool("single_file_tool", schema, h);\n')
    results = scan_ts_files(f)
    assert len(results) == 1
    assert results[0].name == "single_file_tool"
