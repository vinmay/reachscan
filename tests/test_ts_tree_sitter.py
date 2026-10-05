"""Tests for the tree-sitter TS/JS parsing path and its regex fallback."""

from reachscan.ts_entry_points import count_ts_files, detect_ts_entry_points, scan_ts_files
from reachscan.ts_parser import grammar_for, parse_ts, string_value


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_grammar_selection_by_extension():
    assert grammar_for("a.ts") == "typescript"
    assert grammar_for("a.mts") == "typescript"
    assert grammar_for("a.cts") == "typescript"
    assert grammar_for("a.tsx") == "tsx"
    assert grammar_for("a.js") == "javascript"
    assert grammar_for("a.jsx") == "javascript"
    assert grammar_for("a.mjs") == "javascript"
    assert grammar_for("a.cjs") == "javascript"
    assert grammar_for("a.py") is None


def test_parse_clean_file():
    assert parse_ts("a.ts", "const x: number = 1;\n") is not None


def test_parse_syntax_error_returns_none():
    assert parse_ts("a.ts", "const = = ;;; function (\n") is None


def test_parse_jsx_needs_tsx_grammar():
    src = "const el = <div>hi</div>;\n"
    assert parse_ts("a.tsx", src) is not None
    assert parse_ts("a.jsx", src) is not None
    assert parse_ts("a.ts", src) is None  # JSX isn't valid in a plain .ts file


def test_parse_non_ts_extension_returns_none():
    assert parse_ts("a.py", "x = 1\n") is None


def test_string_value_rejects_template_substitution():
    tree = parse_ts("a.ts", "f(`plain`, `with-${x}`);\n")
    call = tree.root_node.named_children[0].named_children[0]
    args = call.child_by_field_name("arguments").named_children
    assert string_value(args[0]) == "plain"
    assert string_value(args[1]) is None


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------

def test_parse_failure_falls_back_to_regex_and_flags_results():
    content = 'server.tool("read_file", schema, handler);\nconst = = ;;;\n'
    results = detect_ts_entry_points("broken.ts", content)
    assert [r.name for r in results] == ["read_file"]
    assert all(r.fallback for r in results)


def test_clean_parse_results_are_not_flagged():
    results = detect_ts_entry_points("ok.ts", 'server.tool("read_file", schema, handler);\n')
    assert [r.fallback for r in results] == [False]


def test_fallback_flag_not_in_json_dict():
    content = 'server.tool("read_file", schema, handler);\nconst = = ;;;\n'
    ep = detect_ts_entry_points("broken.ts", content)[0]
    assert "fallback" not in ep.as_dict()


# ---------------------------------------------------------------------------
# JSX / TSX files
# ---------------------------------------------------------------------------

TSX_SOURCE = '''\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "ui", version: "1.0.0" });

server.tool("render_card", { title: z.string() }, async ({ title }) => {
  const el = <Card title={title} />;
  return { content: [{ type: "text", text: renderToString(el) }] };
});
'''


def test_tsx_file_detected_with_tree_sitter():
    results = detect_ts_entry_points("tools.tsx", TSX_SOURCE)
    assert [(r.name, r.lineno, r.fallback) for r in results] == [("render_card", 5, False)]


def test_jsx_in_plain_ts_file_falls_back():
    results = detect_ts_entry_points("tools.ts", TSX_SOURCE)
    assert [r.name for r in results] == ["render_card"]
    assert all(r.fallback for r in results)


def test_scan_includes_tsx_and_jsx(tmp_path):
    (tmp_path / "a.tsx").write_text(TSX_SOURCE)
    (tmp_path / "b.jsx").write_text('server.tool("from_jsx", {}, () => <b />);\n')
    (tmp_path / "c.test.tsx").write_text('server.tool("ignored", {}, () => 1);\n')
    names = sorted(ep.name for ep in scan_ts_files(tmp_path))
    assert names == ["from_jsx", "render_card"]
    assert count_ts_files(tmp_path) == 2


# ---------------------------------------------------------------------------
# Cases the AST handles that line-based regex did not
# ---------------------------------------------------------------------------

def test_chained_tool_call_on_next_line():
    content = '''\
server
  .tool("chained_tool", schema, handler);
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert [(r.name, r.lineno) for r in results] == [("chained_tool", 2)]


def test_name_two_lines_after_tool_call():
    content = '''\
server.tool(

  "spaced_out",
  schema,
  handler,
);
'''
    results = detect_ts_entry_points("tools.ts", content)
    assert [(r.name, r.lineno) for r in results] == [("spaced_out", 1)]


def test_backtick_tool_name_without_substitution():
    content = "server.registerTool(`list_items`, config, handler);\n"
    results = detect_ts_entry_points("tools.ts", content)
    assert [r.name for r in results] == ["list_items"]


def test_backtick_tool_name_with_substitution_skipped():
    content = "server.tool(`tool-${suffix}`, schema, handler);\n"
    assert detect_ts_entry_points("tools.ts", content) == []


def test_set_request_handler_with_namespaced_schema():
    content = "server.setRequestHandler(types.CallToolRequestSchema, async (req) => ({}));\n"
    results = detect_ts_entry_points("index.ts", content)
    assert [(r.name, r.pattern_type) for r in results] == [("CallToolRequestSchema", "mcp_handler")]


def test_commented_out_tool_not_detected():
    content = '''\
// server.tool("old_tool", schema, handler);
/* server.registerTool("older_tool", config, handler); */
const msg = 'server.tool("in_a_string", x, y)';
'''
    assert detect_ts_entry_points("tools.ts", content) == []


def test_tool_definition_fields_must_be_in_same_object():
    """name in one object, description/inputSchema in a neighbor: not a tool definition."""
    content = '''\
const info = {
    name: "my-server",
};
const other = {
    description: "unrelated",
    inputSchema: {},
};
'''
    assert detect_ts_entry_points("config.ts", content) == []


def test_tool_definition_on_one_line():
    content = 'const t = { name: "one_liner", description: "d", inputSchema: {} };\n'
    results = detect_ts_entry_points("tools.ts", content)
    assert [(r.name, r.pattern_type) for r in results] == [("one_liner", "mcp_tool_definition")]


def test_namespaced_dynamic_tool():
    content = 'const t = new tools.DynamicStructuredTool({ name: "ns_tool", func: f });\n'
    results = detect_ts_entry_points("tools.ts", content)
    assert [(r.name, r.pattern_type) for r in results] == [("ns_tool", "langchain_tool")]


def test_add_tool_with_quoted_name_key():
    content = 'server.addTool({ "name": "quoted_key", execute: run });\n'
    results = detect_ts_entry_points("index.ts", content)
    assert [r.name for r in results] == ["quoted_key"]


def test_results_in_source_order():
    content = '''\
server.tool("b_second", s, h);
server.tool("a_first_line_three", s, h);
'''
    content = 'server.tool("z_top", s, h);\n' + content
    results = detect_ts_entry_points("tools.ts", content)
    assert [r.name for r in results] == ["z_top", "b_second", "a_first_line_three"]
