"""T8: TypeScript call graph, tool handlers, and reachability."""

import json

from reachscan.scanner import scan_path

SDK = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'


def _write(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _states(report):
    return {
        e["finding"]["evidence"]: e["finding"]
        for e in report["findings"]
    }


def _scan(tmp_path, files):
    _write(tmp_path, files)
    return scan_path(tmp_path)


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------

def test_same_file_helper_chain_is_reachable(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
const server = new McpServer({ name: "d", version: "1" });
function inner(c: string) { return execSync(c); }
const outer = (c: string) => inner(c);
server.tool("run", {}, async ({ cmd }) => outer(cmd));
'''})
    f = _states(report)["child_process.execSync()"]
    assert f["reachability"] == "reachable"
    assert f["entry_point_name"] == "run"
    assert f["reachability_path"] == ["run", "outer", "inner"]
    locs = f["reachability_path_locations"]
    assert [loc["lineno"] for loc in locs] == [7, 6, 5]


def test_unreferenced_function_is_unreachable(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
import { writeFileSync } from "fs";
const server = new McpServer({ name: "d", version: "1" });
export function unused(c: string) { return execSync(c); }
server.tool("save", {}, async ({ p }) => { writeFileSync(p, "x"); return {}; });
'''})
    s = _states(report)
    assert s["child_process.execSync()"]["reachability"] == "unreachable"
    assert s["fs.writeFileSync()"]["reachability"] == "reachable"


def test_relative_imports_resolve_across_files(tmp_path):
    report = _scan(tmp_path, {
        "src/server.ts": SDK + '''
import { runIt } from "./lib/exec.js";
import save from "./lib/save";
import * as net from "./lib/net";
const server = new McpServer({ name: "d", version: "1" });
server.tool("run", {}, async ({ c }) => runIt(c));
server.tool("save", {}, async ({ p }) => save(p));
server.tool("ping", {}, async ({ u }) => net.ping(u));
''',
        "src/lib/exec.ts": 'import { execSync } from "child_process";\n'
                           'export function runIt(c: string) { return execSync(c); }\n',
        "src/lib/save.ts": 'import { writeFileSync } from "fs";\n'
                           'export default function save(p: string) { writeFileSync(p, "x"); }\n',
        "src/lib/net/index.ts": 'export async function ping(u: string) { return fetch(u); }\n',
    })
    s = _states(report)
    assert s["child_process.execSync()"]["entry_point_name"] == "run"
    assert s["child_process.execSync()"]["reachability_path"] == ["run", "runIt"]
    assert s["fs.writeFileSync()"]["reachability"] == "reachable"
    assert s["fs.writeFileSync()"]["reachability_path"] == ["save", "save"]
    assert s["fetch()"]["reachability_path"] == ["ping", "ping"]


def test_commonjs_require_resolves(tmp_path):
    report = _scan(tmp_path, {
        "server.js": SDK + '''
const { runIt } = require("./exec");
const server = new McpServer({ name: "d", version: "1" });
server.tool("run", {}, async ({ c }) => runIt(c));
''',
        "exec.js": 'const { execSync } = require("child_process");\n'
                   'function runIt(c) { return execSync(c); }\nmodule.exports = { runIt };\n',
    })
    assert _states(report)["child_process.execSync()"]["reachability"] == "reachable"


def test_this_method_calls_follow_the_class(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
class Tools {
  server = new McpServer({ name: "d", version: "1" });
  register() {
    this.server.tool("run", {}, async ({ c }) => this.runIt(c));
  }
  private runIt(c: string) { return this.shell(c); }
  private shell(c: string) { return execSync(c); }
}
'''})
    f = _states(report)["child_process.execSync()"]
    assert f["reachability_path"] == ["run", "Tools.runIt", "Tools.shell"]


def test_object_literal_methods(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
const server = new McpServer({ name: "d", version: "1" });
const helpers = {
  run(c: string) { return execSync(c); },
};
server.tool("run", {}, async ({ c }) => helpers.run(c));
'''})
    assert _states(report)["child_process.execSync()"]["reachability_path"] == ["run", "helpers.run"]


def test_dynamic_dispatch_adds_no_edge(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
const server = new McpServer({ name: "d", version: "1" });
const table: Record<string, (c: string) => unknown> = {};
export function shell(c: string) { return execSync(c); }
server.tool("run", {}, async ({ op, c }) => table[op](c));
'''})
    assert _states(report)["child_process.execSync()"]["reachability"] == "unreachable"


def test_traversal_depth_limit(tmp_path):
    chain = "\n".join(f"function f{i}() {{ return f{i + 1}(); }}" for i in range(10))
    report = _scan(tmp_path, {"server.ts": SDK + f'''
import {{ execSync }} from "child_process";
const server = new McpServer({{ name: "d", version: "1" }});
{chain}
function f10() {{ return execSync("ls"); }}
server.tool("deep", {{}}, async () => f0());
'''})
    assert _states(report)['child_process.execSync()']["reachability"] == "unreachable"


def test_setrequesthandler_and_dynamictool(tmp_path):
    report = _scan(tmp_path, {
        "low.ts": '''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "child_process";
const server = new Server({ name: "d", version: "1" }, {});
async function handleCall(req: any) { return execSync(req.params.arguments.c); }
server.setRequestHandler(CallToolRequestSchema, handleCall);
''',
        "lc.ts": '''
import { DynamicTool } from "@langchain/core/tools";
import { readFileSync } from "fs";
export const t = new DynamicTool({ name: "reader", description: "r", func: async (p) => readFileSync(p, "utf8") });
''',
    })
    s = _states(report)
    assert s["child_process.execSync()"]["entry_point_name"] == "CallToolRequestSchema"
    assert s["fs.readFileSync()"]["entry_point_name"] == "reader"


# ---------------------------------------------------------------------------
# Registration patterns T8 adds (each with a near miss)
# ---------------------------------------------------------------------------

def test_addtool_with_same_file_tool_object(tmp_path):
    report = _scan(tmp_path, {"server.ts": '''
import { FastMCP } from "fastmcp";
import { execSync } from "child_process";
const server = new FastMCP({ name: "d", version: "1.0.0" });
const runTool = { name: "run", description: "r", parameters: {}, execute: async (a: any) => execSync(a.c) };
server.addTool(runTool);
'''})
    f = _states(report)["child_process.execSync()"]
    assert f["entry_point_name"] == "run"
    assert "run" in {ep["name"] for ep in report["ts_entry_points"]}


def test_addtool_near_miss_unresolved_identifier(tmp_path):
    report = _scan(tmp_path, {"server.ts": '''
import { FastMCP } from "fastmcp";
import { execSync } from "child_process";
import { runTool } from "some-package";
const server = new FastMCP({ name: "d", version: "1.0.0" });
export const local = async (a: any) => execSync(a.c);
server.addTool(runTool);
'''})
    assert report["ts_entry_points"] == []
    assert _states(report)["child_process.execSync()"]["reachability"] == "no_entry_points"


def test_exported_tool_definitions_with_schema_key(tmp_path):
    report = _scan(tmp_path, {
        "tools/scrape.ts": '''
import { z } from "zod";
export const scrapeTool = {
  name: "scrape",
  description: "Scrape a page",
  schema: { url: z.string() },
  handler: async ({ url }: { url: string }) => fetch(url),
};
''',
        "server.ts": SDK + '''
import { scrapeTool } from "./tools/scrape";
const server = new McpServer({ name: "d", version: "1" });
for (const t of [scrapeTool]) server.tool(t.name, t.description, t.schema, t.handler);
''',
    })
    f = _states(report)["fetch()"]
    assert f["reachability"] == "reachable"
    assert f["entry_point_name"] == "scrape"


def test_tool_definition_near_miss_without_schema(tmp_path):
    report = _scan(tmp_path, {"lib.ts": '''
export const plugin = {
  name: "scrape",
  description: "Not a tool: no schema key",
  handler: async (url: string) => fetch(url),
};
'''})
    assert report["ts_entry_points"] == []


def test_project_registration_wrapper(tmp_path):
    report = _scan(tmp_path, {
        "register.ts": SDK + '''
export const server = new McpServer({ name: "d", version: "1" });
export function registerTool(def: any) {
  server.registerTool(def.name, { description: def.description }, def.execute);
}
''',
        "tools.ts": '''
import { registerTool } from "./register";
import { execSync } from "child_process";
registerTool({ name: "costs", description: "c", execute: async (a: any) => execSync(a.c) });
''',
    })
    f = _states(report)["child_process.execSync()"]
    assert f["entry_point_name"] == "costs"


def test_registration_wrapper_near_miss_not_calling_sdk(tmp_path):
    report = _scan(tmp_path, {
        "register.ts": 'export function registerTool(def: any) { console.log(def.name); }\n',
        "tools.ts": '''
import { registerTool } from "./register";
import { execSync } from "child_process";
registerTool({ name: "costs", description: "c", execute: async (a: any) => execSync(a.c) });
''',
    })
    assert report["ts_entry_points"] == []


def test_xmcp_file_based_tools(tmp_path):
    files = {
        "package.json": json.dumps({"dependencies": {"xmcp": "^0.1.0"}}),
        "src/tools/run.ts": '''
import { execSync } from "child_process";
export const metadata = { name: "run", description: "r" };
export default async function run({ c }: { c: string }) { return execSync(c); }
''',
    }
    report = _scan(tmp_path, files)
    f = _states(report)["child_process.execSync()"]
    assert f["entry_point_name"] == "run"


def test_xmcp_near_miss_without_dependency(tmp_path):
    report = _scan(tmp_path, {"src/tools/run.ts": '''
import { execSync } from "child_process";
export const metadata = { name: "run", description: "r" };
export default async function run({ c }: { c: string }) { return execSync(c); }
'''})
    assert report["ts_entry_points"] == []


def test_dynamic_name_registration_in_mcp_subclass(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
class Proxy extends McpServer {
  load(remoteTool: any) {
    this.tool(remoteTool.name, remoteTool.description, async (a: any) => execSync(a.c));
  }
}
'''})
    f = _states(report)["child_process.execSync()"]
    assert f["entry_point_name"] == "unknown"


def test_dynamic_name_near_miss_without_sdk(tmp_path):
    report = _scan(tmp_path, {"cli.ts": '''
import { execSync } from "child_process";
const program: any = {};
export function setup(cmd: any) { program.tool(cmd.name, async () => execSync("ls")); }
'''})
    assert report["ts_entry_points"] == []


def test_define_tool_handler_property(tmp_path):
    report = _scan(tmp_path, {"tools/issues.ts": '''
import { defineTool } from "../internal/tool";
export default defineTool({
  name: "list_issues",
  description: "List issues",
  inputSchema: {},
  async handler(params: any) { return fetch("https://api.example.com/issues"); },
});
'''})
    f = _states(report)["fetch()"]
    assert f["entry_point_name"] == "list_issues"
    assert f["reachability_path"] == ["list_issues"]


def test_method_call_on_unresolved_instance_is_unknown(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
import { writeFileSync } from "fs";
const server = new McpServer({ name: "d", version: "1" });
class ShellTool {
  run(c: string) { return execSync(c); }
}
class Unused {
  save(p: string) { writeFileSync(p, "x"); }
}
const tools: any[] = [new ShellTool()];
server.tool("run", {}, async ({ c }) => tools[0].run(c));
'''})
    s = _states(report)
    assert s["child_process.execSync()"]["reachability"] == "unknown"
    assert s["fs.writeFileSync()"]["reachability"] == "unreachable"


def test_constructor_calls_are_edges(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
const server = new McpServer({ name: "d", version: "1" });
class Runner {
  constructor(c: string) { execSync(c); }
}
server.tool("run", {}, async ({ c }) => { new Runner(c); return {}; });
'''})
    f = _states(report)["child_process.execSync()"]
    assert f["reachability_path"] == ["run", "Runner.constructor"]


def test_registration_through_cast_callee(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
import { execSync } from "child_process";
class Base {
  server: any;
  register() {
    (this.server.registerTool as unknown as Function)(this.name, {}, async (a: any) => execSync(a.c));
  }
}
'''})
    assert _states(report)["child_process.execSync()"]["entry_point_name"] == "unknown"


def test_wrapped_and_bound_handlers(tmp_path):
    report = _scan(tmp_path, {"server.ts": '''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "child_process";
import { writeFileSync } from "fs";
const server = new Server({ name: "d", version: "1" }, {});
const withTelemetry = (fn: any) => fn;
server.setRequestHandler(CallToolRequestSchema, withTelemetry(async (req: any) => execSync(req.c)));
class S {
  constructor(private srv: any) {}
  save(a: any) { writeFileSync(a.p, "x"); }
  init() { this.srv.tool("save", {}, this.save.bind(this)); }
}
'''})
    s = _states(report)
    assert s["child_process.execSync()"]["reachability"] == "reachable"
    assert s["fs.writeFileSync()"]["entry_point_name"] == "save"


def test_tool_name_from_constant_or_fallback(tmp_path):
    report = _scan(tmp_path, {"server.ts": SDK + '''
const name = "get-env";
export const registerA = (server: McpServer) => {
  server.registerTool(name, {}, async () => ({ content: [] }));
};
export function registerB(server: McpServer, toolName?: string) {
  server.tool(toolName || "web_search", "d", {}, async () => ({ content: [] }));
}
'''})
    assert {ep["name"] for ep in report["ts_entry_points"]} == {"get-env", "web_search"}


def test_handler_called_on_tool_objects_in_a_list_is_unknown(tmp_path):
    report = _scan(tmp_path, {
        "tools/drt.mjs": 'import { execSync } from "child_process";\n'
                         'export default { name: "drt", description: "d", handler: async (a) => execSync(a.c) };\n',
        "server.mjs": SDK + '''
import drt from "./tools/drt.mjs";
const TOOLS = [drt];
const server = new McpServer({ name: "d", version: "1" });
for (const tool of TOOLS) {
  server.registerTool(tool.name, {}, async (a) => tool.handler(a));
}
''',
    })
    assert _states(report)["child_process.execSync()"]["reachability"] == "unknown"
