# Changelog

All notable changes to reachscan are documented here. This project follows [Semantic Versioning](https://semver.org/). The JSON output schema has its own version (`schema_version`), documented in [`docs/schema_v1.md`](docs/schema_v1.md).

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

[0.2.0]: https://github.com/vinmay/reachscan/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/vinmay/reachscan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/vinmay/reachscan/releases/tag/v0.1.0
