# reachscan JSON Schema v1

This document is the canonical reference for the `--json` output format introduced in reachscan v1.

The schema is **stable**: new fields may be added in future minor versions, but existing fields will not be removed or renamed without a major schema version bump.

---

## Top-level fields

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `schema_version` | `string` | Yes | Always `"1"` for this schema version |
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
| `id` | `string` | Risk identifier (e.g. `"secret_leak"`, `"destructive_agent"`) |
| `description` | `string` | Human-readable description of the combined-capability risk |
| `capabilities` | `array<string>` | Capability keys that triggered this risk |

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
  "schema_version": "1",
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
| `1` | Scan complete, ≥1 reachable finding exceeds `--severity` threshold |
| `2` | Scan failed (bad target, network error, unhandled exception) |

Use `--severity none` to always get exit code 0 (report-only mode).
