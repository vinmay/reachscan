# reachscan JSON Schema v1

This document is the canonical reference for the `--json` output format introduced in reachscan v1.

The schema is **stable**: new fields may be added in future minor versions, but existing fields will not be removed or renamed without a major schema version bump.

**Schema 1.1** (reachscan 0.3.0) adds, without changing any v1 field:
- top-level [`annotation_mismatches`](#annotation-mismatch-object);
- optional `annotations` and `declared_tools` on [Python entry points](#python-entry-point-object).

Consumers that ignore unknown fields can read 1.1 reports unchanged.

---

## Top-level fields

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `schema_version` | `string` | Yes | `"1.2"` since reachscan 0.4.0 (`"1.1"` in 0.3.x, `"1"` before 0.3.0). Additive versions keep the major number |
| `generated_at` | `string` | Yes | UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`) |
| `reachscan_version` | `string` | Yes | Version of the reachscan package; `"unknown"` if not installed |
| `target` | `string` | Yes | The scan target as provided (path, URL, or `pypi:name==version`) |
| `source_type` | `string` | Yes | One of: `"local"`, `"github"`, `"mcp"`, `"pypi"` |
| `resolved_version` | `string\|null` | Yes | Resolved package version for PyPI targets; `null` for all other sources |
| `num_files_scanned` | `integer` | Yes | Number of Python files analyzed |
| `num_ts_files_scanned` | `integer` | Yes | Number of TypeScript/JavaScript files scanned for entry-point patterns |
| `entry_points_detected` | `integer` | Yes | Total LLM-callable entry points detected (`py_entry_points + ts_entry_points`) |
| `py_entry_points` | `array` | Yes | Python LLM entry points (see [Python entry point object](#python-entry-point-object)) |
| `ts_entry_points` | `array` | Yes | TypeScript/JavaScript entry points (see [TS entry point object](#typescript-entry-point-object)) |
| `capabilities` | `array<string>` | Yes | Sorted list of capability keys present across all findings (e.g. `["EXECUTE", "SEND"]`) |
| `risks` | `array` | Yes | Cross-capability risk inferences (see [Risk object](#risk-object)) |
| `findings` | `array` | Yes | All findings from all detectors (see [Finding wrapper](#finding-wrapper)) |
| `annotation_mismatches` | `array` | Yes (1.1) | MCP tool annotations contradicted by capabilities reachable from that tool (see [Annotation mismatch object](#annotation-mismatch-object)). Empty when there are none |
| `suppression_warnings` | `array` | Yes (1.2) | `reachscan:allow-*` comments that were ignored: `{file, lineno, message}` (no reason given, unknown capability, or no code after the comment). Empty when there are none |
| `other_languages` | `array` | Yes | Non-Python/TS languages detected when no Python files found (see [Language object](#language-object)) |
| `static_analysis_note` | `string` | Yes | Disclaimer: `"This report reflects code patterns. It does not prove runtime behavior or exploitability."` |

---

## Finding wrapper

Each element of `findings` is:

```json
{
  "detector": "shell_exec",
  "finding": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `detector` | `string` | Detector name: `shell_exec`, `network`, `file_access`, `secrets`, `dynamic_exec`, `autonomy` |
| `finding` | `object` | Finding detail (see [Finding object](#finding-object)) |

---

## Finding object

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `capability` | `string` | Yes | Capability key: `EXECUTE`, `SEND`, `READ`, `WRITE`, `SECRETS`, `DYNAMIC`, `AUTONOMY` |
| `evidence` | `string` | Yes | Code pattern that triggered the finding (e.g. `"subprocess.run()"`) |
| `file` | `string` | Yes | Source file path (relative to scan root) |
| `lineno` | `integer\|null` | Yes | Line number; `null` if not determinable |
| `confidence` | `float` | Yes | Detection confidence in `[0.0, 1.0]` |
| `risk_level` | `string` | Yes | One of: `"high"`, `"medium"`, `"low"`, `"info"` |
| `explanation` | `string` | Yes | Human-readable explanation of the capability |
| `impact` | `string` | Yes | Human-readable description of potential impact |
| `reachability` | `string` | Yes | Reachability state (see [Reachability values](#reachability-values)) |
| `entry_point_name` | `string\|null` | No | Name of the LLM entry point that can reach this finding (when `reachability == "reachable"`) |
| `reachability_path` | `array<string>\|null` | No | Call chain from entry point to finding (when `reachability == "reachable"`) |
| `reachability_path_truncated` | `boolean` | No | `true` if the call path was cut off at the traversal depth limit |
| `finding_id` | `string` | Yes | 12-character SHA-1 hex digest; stable for the same `(detector, file, lineno, evidence)` tuple |
| `finding_ref` | `string` | Yes | Human-readable `"detector:file:lineno:evidence"` string |
| `suppression` | `object` | No (1.2) | Present when an inline `reachscan:allow-<capability> <reason>` comment covers this finding: `{reason, line}` (`line` is the comment's line). Suppressed findings don't affect the exit code |

---

## Reachability values

| Value | Meaning |
|-------|---------|
| `reachable` | Confirmed on a call path from an LLM entry point |
| `unreachable` | Exists in the codebase, not reachable from any LLM entry point |
| `module_level` | Runs on import — executes when the module loads, not via a function call |
| `unknown` | Inside code that cannot be statically resolved (dynamic dispatch, parse failures) |
| `no_entry_points` | No LLM entry points were detected; full reachability analysis was not possible |

---

## Python entry point object

Each element of `py_entry_points`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Function name |
| `file` | `string` | Source file (relative to scan root) |
| `lineno` | `integer` | Line number of the entry point definition |
| `framework` | `string` | Detected framework (e.g. `"pydantic_ai"`, `"langchain"`, `"openai_agents"`) |
| `pattern` | `string` | Detection pattern used (e.g. `"decorator"`, `"class"`) |
| `confidence` | `float` | Framework attribution confidence in `[0.0, 1.0]` |
| `reachable_findings` | `array<string>` | Finding IDs reachable from this entry point |
| `annotations` | `object` | (1.1, MCP decorator tools only) Effective ToolAnnotations hints; see [Annotations object](#annotations-object) |
| `declared_tools` | `array` | (1.1, MCP lowlevel `list_tools` handlers only) `types.Tool` declarations: `{name, lineno, annotations}` |

### Annotations object

Spec defaults (MCP schema 2026-07-28) are applied: `readOnlyHint` false; `destructiveHint` true only when `readOnlyHint` is false; `idempotentHint` false; `openWorldHint` true.

| Field | Type | Description |
|-------|------|-------------|
| `declared` | `boolean` | An annotations argument was given (and wasn't `None`) |
| `unresolved_reference` | `boolean` | Annotations were passed by a reference that couldn't be resolved statically |
| `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` | `object` | `{"value": true \| false \| null, "source": "explicit" \| "default" \| "unresolvable"}`. Unresolvable values are `null` and never produce mismatches. snake_case spellings (`read_only_hint`) are unresolvable because their effect depends on the MCP SDK version |

---

## Annotation mismatch object

Each element of `annotation_mismatches` describes one false claim: an explicitly declared hint on one MCP tool, contradicted by a capability reachable from that tool. One object per (tool, rule); further contradicting call sites are listed in `additional_observations`. A contradiction without a call path from the tool is never reported.

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `string` | Always `"mcp-risk-mismatch"` (also the SARIF rule id) |
| `rule` | `string` | `read_only_contradicted` (readOnlyHint true + reachable WRITE/EXECUTE/DYNAMIC), `closed_world_contradicted` (openWorldHint false + a reachable outbound HTTP, websocket, or raw socket connect not to a literal loopback host; project-module calls, database drivers, and other protocol clients don't count), or `non_destructive_contradicted` (destructiveHint false, with readOnlyHint false, + reachable delete, move/rename, or truncating write) |
| `risk_level` | `string` | `"high"` for read_only, `"medium"` for closed_world and non_destructive (closed_world was `"high"` before 0.4.0) |
| `tool` | `string` | MCP tool name |
| `entry_point` | `object` | `{name, file, lineno, dispatch}`. `dispatch` is `"decorator"` (FastMCP) or `"lowlevel"` (a `types.Tool` linked to its branch in the `call_tool` handler) |
| `declared` | `object` | `{hint, value}`, e.g. `{"hint": "readOnlyHint", "value": true}` |
| `observed` | `object` | `{capability, evidence, file, lineno, finding_id}`, plus `send_kind` (`"HTTP"`, `"websocket"`, or `"socket"`) for `closed_world_contradicted`; `finding_id` matches an entry in `findings` |
| `reachability_path` | `array<string>` | Call chain from the tool's entry point to the function containing the sink |
| `additional_observations` | `array` | Other contradicting sinks for the same tool and rule: `{capability, evidence, file, lineno, finding_id, reachability_path}` |
| `message` | `string` | Human-readable summary |
| `mismatch_id` | `string` | 12-character stable id for (tool, entry point file, rule) |
| `suppression` | `object` | (1.2, optional) Present when a `reachscan:allow-mismatch <reason>` comment on the tool's declaration covers this mismatch: `{reason, line}`. A capability suppression on the sink doesn't suppress the mismatch. Suppressed mismatches don't affect the exit code |

---

## TypeScript entry point object

Each element of `ts_entry_points`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Tool/function name |
| `file` | `string` | Source file (relative to scan root) |
| `lineno` | `integer` | Line number |
| `framework` | `string` | Detection pattern: `"mcp_tool"`, `"langchain_tool"`, `"mcp_handler"`, `"mcp_tool_definition"` |
| `confidence` | `float` | Detection confidence in `[0.0, 1.0]` |

---

## Risk object

Each element of `risks`:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Risk identifier: `"data_exfiltration"`, `"remote_control"`, `"secret_leak"`, or `"destructive_agent"` |
| `title` | `string` | Human-readable title (e.g. `"Remote Control Risk"`) |
| `severity` | `string` | `"high"` |
| `why` | `string` | Why the combination is risky |
| `capabilities_triggered` | `array<string>` | Capability keys that triggered this risk |
| `includes_suppressed_findings` | `boolean` | (1.2, optional) Present and `true` when some of the risk's contributing findings are suppressed inline. Suppressed findings still count toward combined risks |
| `all_findings_suppressed` | `boolean` | (1.2, optional) With `includes_suppressed_findings`: `true` if every contributing finding is suppressed |
| `suppressed_findings` | `array` | (1.2, optional) The suppressed contributing findings: `{finding_id, capability, evidence, file, lineno, reason}` |

Combined risks don't affect the exit code.

---

## Language object

Each element of `other_languages` (populated only when no Python files were found):

| Field | Type | Description |
|-------|------|-------------|
| `language` | `string` | Language name (e.g. `"Go"`, `"Rust"`) |
| `count` | `integer` | Number of source files detected |

---

## Example

```json
{
  "schema_version": "1.1",
  "generated_at": "2025-10-01T14:23:00Z",
  "reachscan_version": "0.1.0",
  "target": "pypi:openai-agents==0.0.19",
  "source_type": "pypi",
  "resolved_version": "0.0.19",
  "num_files_scanned": 153,
  "entry_points_detected": 4,
  "py_entry_points": [],
  "ts_entry_points": [],
  "capabilities": ["EXECUTE", "SEND"],
  "risks": [],
  "findings": [
    {
      "detector": "shell_exec",
      "finding": {
        "capability": "EXECUTE",
        "evidence": "subprocess.run()",
        "file": "src/agents/tools.py",
        "lineno": 14,
        "confidence": 0.9,
        "risk_level": "high",
        "explanation": "This code can execute shell commands.",
        "impact": "An attacker with LLM access could run arbitrary commands.",
        "reachability": "reachable",
        "entry_point_name": "run_shell",
        "reachability_path": ["run_shell", "_exec"],
        "reachability_path_truncated": false,
        "finding_id": "abc123def456",
        "finding_ref": "shell_exec:src/agents/tools.py:14:subprocess.run()"
      }
    }
  ],
  "annotation_mismatches": [],
  "other_languages": [],
  "static_analysis_note": "This report reflects code patterns. It does not prove runtime behavior or exploitability."
}
```

---

## Exit codes

When using `--json` (or without it), the CLI exits with:

| Code | Meaning |
|------|---------|
| `0` | Scan complete, severity threshold not exceeded |
| `1` | Scan complete, ≥1 reachable finding or annotation mismatch meets the `--severity` threshold (suppressed ones excluded) |
| `2` | Scan failed (bad target, network error, unhandled exception) |

Use `--severity none` to always get exit code 0 (report-only mode).
