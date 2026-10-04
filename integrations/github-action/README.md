# reachscan GitHub Action

Runs [reachscan](https://github.com/vinmay/reachscan) on your AI agent or MCP server code. It reports what the code can execute, read, write, and send, and whether an LLM tool handler can reach it. Results go to the GitHub Security tab with the call chain for each reachable finding, and the job fails when a reachable finding meets your severity threshold.

## Minimal workflow

```yaml
name: reachscan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # needed to upload SARIF to code scanning

jobs:
  reachscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: vinmay/reachscan-action@v1
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan, relative to the workspace. |
| `severity` | `high` | Fail when a reachable finding meets this risk level: `high`, `medium`, or `none` (never fail). |
| `sarif` | `true` | Upload SARIF to GitHub code scanning. Set to `false` to only print the report and gate on the exit code. |
| `version` | `latest` | reachscan version from PyPI, such as `0.2.0`. Pin it for reproducible CI. Must be 0.2.0 or later, the first release with `--sarif`. |
| `category` | `reachscan` | Code scanning category. Use a different value for each run if you scan several paths in one workflow. |
| `python-version` | `3.12` | Python used to run reachscan (3.11 or later). |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | `0` clean, `1` reachable finding at or above `severity`, `2` scan failure. |
| `sarif-file` | Path to the SARIF file when `sarif` is `true`. |

## Examples

Report only, never fail the build:

```yaml
- uses: vinmay/reachscan-action@v1
  with:
    severity: none
```

Pin the version and scan a subdirectory:

```yaml
- uses: vinmay/reachscan-action@v1
  with:
    path: servers/my-mcp-server
    version: "0.2.0"
```

No code scanning (private repos without GitHub Advanced Security):

```yaml
- uses: vinmay/reachscan-action@v1
  with:
    sarif: "false"
```

## What gets uploaded

- One rule per capability (`reachscan/EXECUTE`, `reachscan/SEND`, ...) and one per combined risk (`reachscan/combined/remote_control`, ...).
- A reachable high-risk finding is an `error`, a reachable medium-risk finding is a `warning`, and everything else is a `note`.
- Only findings an LLM entry point can reach (plus code that runs at import) are uploaded, so the Security tab stays focused on what a prompt can trigger.

## How it works

1. Sets up Python with `actions/setup-python`.
2. Installs reachscan with `pipx`.
3. Runs `reachscan <path> --sarif --severity <severity>` and prints the text report to the job log.
4. Uploads the SARIF with `github/codeql-action/upload-sarif` (skipped if the scan itself failed).
5. Exits with reachscan's exit code.

reachscan is static analysis. It runs offline on your checkout and sends no code anywhere.
