# Changelog

All notable changes to reachscan are documented here. This project follows [Semantic Versioning](https://semver.org/). The JSON output schema has its own version (`schema_version`), documented in [`docs/schema_v1.md`](docs/schema_v1.md).

## [Unreleased]

### Added

- **TypeScript/JavaScript reachability.** TS findings now get the same reachability states as Python: each tool handler is an entry node, and a call graph follows direct calls within a file, relative imports (ESM including `./x.js` → `x.ts`, CommonJS `require`, namespace imports), `this.method()`, object-literal methods, constructors, and callbacks defined inside a function, for up to 8 hops. Reachable TS findings carry `entry_point_name`, `reachability_path`, and SARIF code flows. Code that only an unresolved method call could reach (`tool.execute()` on an instance or a tool object from a list) is `unknown`. Anything else not on a path is `unreachable`.
- **More TS tool registrations recognized:** `addTool(toolObject)` with a project tool object; tool-definition objects using `schema` / `parameters` / `args` and a `handler` / `execute` property or method (including `defineTool({...})`); objects passed to a project wrapper that calls `registerTool` / `tool` / `addTool`; xmcp file-based tools (projects depending on xmcp); handlers wrapped in a function call (`withTelemetry(async (req) => ...)`) or bound (`this.run.bind(this)`); and registrations with a computed name. These are reported with the name `unknown` unless the name is a same-file constant or has a `x || "literal"` fallback.

### Changed

- **Exit code:** reachable high-risk TS findings now produce exit code 1, as Python findings already did. TS-only projects that previously exited 0 may now fail CI. Combined risks for TS findings use reachable and module-level findings, not presence. On the phase-3 corpus: TS entry points go from 366 to 690. TS findings that were `unknown` or `no_entry_points` (1,252) are now 196 `reachable`, 900 `unreachable`, 152 `unknown`, and 4 `no_entry_points`. 16 repos move from exit 0 to 1, and 8 combined risks are added in 4 repos. Python results are unchanged.

### Fixed

- **Sends through clients returned by project helpers are detected again.** A project function that returns an HTTP client on every path (`requests.Session()`, the `requests` module, `httpx.Client()` / `AsyncClient()`, `aiohttp.ClientSession()`, `urllib3.PoolManager()`, directly or through a local variable) is treated as a client factory. Send methods called on its result (`with get_session() as s: s.post(...)`, `client = await make_client(); await client.get(...)`, `make_client().get(...)`) are reported as SEND at the call site. Resolution is one hop, configuration calls such as `mount` stay non-evidence, and helpers returning other types or mixed types don't count. This restores sends hidden since 0.3.1 stopped counting client construction as a send. On the phase-3 corpus: 4 sends restored (all reachable), nothing else changes, and one `openWorldHint` annotation mismatch reappears with the actual `post` call as its sink.
- **In-process HTTP clients and bare-import constructors aren't sends.** An httpx client built with `transport=ASGITransport(...)` / `WSGITransport(...)` / `MockTransport(...)` talks to an in-process app or mock, so it's no longer tracked as a network client (in the per-file detector or as a client factory). Constructors called through a bare import (`from httpx import AsyncClient` → `AsyncClient()`), and the transport objects themselves, are no longer SEND evidence, which completes the earlier client-construction fix. Requests made through real network clients are still detected. On the phase-3 corpus this removes 2 constructor findings; the sends they belonged to are still reported.

## [0.3.1] - 2026-10-05

### Changed

- **Lowlevel MCP dispatch linkage:** a `types.Tool` declaration is now also linked to its branch in the `call_tool` handler when the branch test is an `and` conjunction containing the tool-name comparison (e.g. `if name == "x" and arguments:`). `or` conditions and handler-object dispatch still aren't linked. On the phase-3 corpus, linked lowlevel tools go from 28 to 45 (unlinked 29 → 12); findings, combined risks, exit codes, and annotation mismatches are unchanged.

### Fixed

- **SEND precision:** creating or configuring an HTTP client is no longer reported as a network send. Client construction (`requests.Session()`, `httpx.Client()` / `AsyncClient()`, `aiohttp.ClientSession()`, `urllib3.PoolManager()`), `Session.mount(...)`, and adapters send nothing; requests made through those clients (`session.post(...)`, `client.get(...)`, `pool.request(...)`) are still detected. A URL literal also needs a host to count: a bare scheme prefix such as `"https://"` no longer turns a call into a send. On the phase-3 corpus this removes 43 findings in 5 repos, with no change to combined risks or exit codes. One side effect: sends made only through a client returned by a helper function are no longer visible, which is a known call-graph limitation.

## [0.3.0] - 2026-10-05

### Added

- **MCP annotation verification (Python).** reachscan reads the `ToolAnnotations` hints that MCP tools declare (FastMCP `@mcp.tool(annotations=...)` and lowlevel `types.Tool(...)`) and reports an **annotation mismatch** when a call path from that tool contradicts an explicit hint:
  - `readOnlyHint: true` + reachable WRITE, EXECUTE, or DYNAMIC (high);
  - `openWorldHint: false` + a reachable outbound HTTP, websocket, or raw socket connect (high). Socket connects to a literal loopback host (`localhost`, `127.0.0.0/8`, `::1`), calls into the project's own modules, database drivers, and other protocol clients don't count;
  - `destructiveHint: false` + a reachable delete, move/rename, or truncating write (medium).

  Every mismatch includes the call path from the tool to the contradicting code, and a contradiction without one isn't reported. Absent hints use the MCP spec's conservative defaults (schema 2026-07-28) and aren't checked. Hints that can't be resolved statically are skipped and listed under `--explain`. Lowlevel tools are linked to their branch in the `call_tool` handler for `if name == ...` / `match name:` dispatch. Mismatches appear in a new "Annotation Mismatches" section of the text report, in JSON, and in SARIF as rule `mcp-risk-mismatch`.
- **JSON schema 1.1** (additive): a top-level `annotation_mismatches` array and per-entry-point `annotations` / `declared_tools`. All v1 fields are unchanged. See [`docs/schema_v1.md`](docs/schema_v1.md).
- **TypeScript/JavaScript capability detection.** All seven capability classes are now detected in TS/JS code, with imports resolved first (ESM, CommonJS, `node:` prefixes, aliases), so `regex.exec()` or a local `exec` helper isn't mistaken for `child_process.exec`. TS call paths aren't traced yet: TS findings inside functions are reported as `unknown` (or `no_entry_points`), top-level code as `module_level`, and TS findings don't affect exit codes.
- **Tree-sitter parsing for TypeScript/JavaScript**, using prebuilt wheels (no Node.js needed). `.tsx` and `.jsx` files are now scanned. Entry point detection no longer matches inside comments or strings, and it finds registrations however they're formatted.
- **SARIF notification when entry points are missing.** When a language has findings but no detected entry points, the SARIF run carries a warning in `invocations[].toolExecutionNotifications` saying how many findings weren't shown.
- **Text report:** a combined risk that comes only from module-level code is labelled "from module-level code only", with the files listed.

### Changed

- **New runtime dependencies:** `tree-sitter`, `tree-sitter-typescript`, `tree-sitter-javascript` (pure pip wheels).
- The combined-risk presence fallback (used when no entry points were detected) is decided separately for Python and TypeScript/JavaScript findings. Python results are the same as in 0.2.0.
- README: a quick start by audience, setup for the Claude Code / Codex plugin, CI docs led by the [GitHub Action](https://github.com/marketplace/actions/reachscan), a "what works today" status table, and the call graph's known limitations.

### Known limitations

- The Python call graph doesn't resolve method calls on object instances (`obj.method()`, `self.client.method()`), chained attribute calls, `super()`, or inherited methods. Sinks reached only that way show as unreachable or unknown and can't produce annotation mismatches.

## [0.2.0] - 2026-10-05

### Added

- **SARIF 2.1.0 output** with `--sarif`, for GitHub code scanning and other SARIF tools. There is one rule per capability (`reachscan/EXECUTE`, ...) and one per combined risk (`reachscan/combined/remote_control`, ...). A reachable high-risk finding is an `error`, a reachable medium-risk finding is a `warning`, and everything else is a `note`. Each reachable finding includes a `codeFlow` that walks the call chain from the LLM entry point to the sink. `--sarif` can't be combined with `--json`, and exit codes are the same.
- `--sarif-include-unreachable`: by default, SARIF output contains only findings an LLM entry point can reach, plus code that runs at import. This flag adds unreachable, unknown, and no-entry-point findings.
- **Factory and constructor entry points**: tools registered through calls instead of decorators are now detected. This covers LlamaIndex (`FunctionTool.from_defaults`, `QueryEngineTool.from_defaults`), DSPy (`dspy.Tool`), OpenAI Swarm (`Agent(functions=[...])`), Google ADK (`Agent(tools=[...])`), and CAMEL (`FunctionTool`).
- **More agent frameworks**: entry point detection for Strands, Haystack, Agno/Phidata, MetaGPT, Marvin, Agency Swarm, and smolagents.
- **Network detection**: more `requests` and `httpx` methods, plus calls made through client objects (`requests.Session`, `httpx.Client`, `httpx.AsyncClient`, `aiohttp.ClientSession`).
- **src/ and monorepo layouts**: the call graph now resolves absolute imports of packages that live below the project root.

### Fixed

- **Combined risks fired on unreachable code.** Combined risks (such as Data Exfiltration = SEND + WRITE) were computed before the reachability pass, so they used every capability present in the repo. They now require each capability to be reachable or module-level. When no entry points are detected, they still fall back to every capability present.
- **Wrong function after a nested `def`**: code that follows a nested function inside an outer function was attributed to the nested function, which hid reachable findings such as `exec()` and `eval()` calls. Reachability now uses each function's end line to find the right enclosing scope.
- **Duplicate file findings**: `with open(...)` and `open(...)` on the same line are now reported once.
- **Secrets noise**: environment variables that look like configuration (`*_PORT`, `*_TIMEOUT`, ...) get lower confidence than credential-like ones (`*_KEY`, `*_TOKEN`, ...).

### Changed

- The text report ends with a link to the GitHub repo.

JSON output is unchanged. It is still schema v1.

## [0.1.1] - 2026-03-12

### Added

- `--explain`: shows the full call chain for each reachable finding in the text report.

## [0.1.0] - 2026-03-05

- First release.

[0.3.1]: https://github.com/vinmay/reachscan/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vinmay/reachscan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vinmay/reachscan/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/vinmay/reachscan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/vinmay/reachscan/releases/tag/v0.1.0
