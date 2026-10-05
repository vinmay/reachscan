"""Tests for TypeScript/JavaScript capability detection (positive and near-miss cases)."""

import json

import pytest

from reachscan.cli import main
from reachscan.reporters.json_reporter import json_report
from reachscan.reporters.sarif_reporter import build_sarif
from reachscan.reporters.text_reporter import human_report
from reachscan.scanner import scan_path
from reachscan.ts_capabilities import scan_ts_capabilities
from reachscan.ts_parser import parse_ts


def detect(src: str, filename: str = "mod.ts"):
    tree = parse_ts(filename, src)
    assert tree is not None, "fixture must parse"
    return [
        (r.finding.capability, r.finding.evidence, r.detector)
        for r in scan_ts_capabilities(filename, tree.root_node)
    ]


def caps(src: str, filename: str = "mod.ts"):
    return [(c, e) for c, e, _ in detect(src, filename)]


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "src",
    [
        'import { exec } from "child_process";\nexec(cmd);\n',
        'import { exec } from "node:child_process";\nexec(cmd);\n',
        'import { exec as run } from "child_process";\nrun(cmd);\n',
        'import * as cp from "child_process";\ncp.exec(cmd);\n',
        'import cp from "child_process";\ncp.exec(cmd);\n',
        'import cp = require("child_process");\ncp.exec(cmd);\n',
        'const cp = require("child_process");\ncp.exec(cmd);\n',
        'const { exec } = require("child_process");\nexec(cmd);\n',
        'const { exec: run } = require("node:child_process");\nrun(cmd);\n',
        'const run = require("child_process").exec;\nrun(cmd);\n',
        'require("child_process").exec(cmd);\n',
    ],
)
def test_import_forms_resolve_to_child_process(src):
    assert caps(src) == [("EXECUTE", "child_process.exec()")]


def test_type_only_import_is_not_a_binding():
    src = 'import type { exec } from "child_process";\nexec(cmd);\n'
    assert caps(src) == []


def test_unrelated_module_with_same_function_name():
    src = 'import { exec } from "./db";\nexec("SELECT 1");\n'
    assert caps(src) == []


# ---------------------------------------------------------------------------
# EXECUTE
# ---------------------------------------------------------------------------

def test_execute_positive():
    src = '''\
import { spawn, execFileSync, fork } from "child_process";
import { execa, execaSync } from "execa";
spawn("ls"); execFileSync("git", ["log"]); fork("./worker.js");
await execa("ls"); execaSync("pwd");
Bun.spawn(["ls"]);
'''
    assert [e for c, e in caps(src)] == [
        "child_process.spawn()", "child_process.execFileSync()", "child_process.fork()",
        "execa.execa()", "execa.execaSync()", "Bun.spawn()",
    ]
    assert all(c == "EXECUTE" for c, _ in caps(src))


def test_execute_near_miss_regex_and_db_exec():
    src = '''\
const re = /a+/;
re.exec(input);
/b/.exec(input);
db.exec("CREATE TABLE t (x)");
pattern.exec("x");
'''
    assert caps(src) == []


def test_execute_default_import_call():
    src = 'import execa from "execa";\nawait execa("ls");\n'
    assert caps(src) == [("EXECUTE", "execa()")]


# ---------------------------------------------------------------------------
# READ / WRITE
# ---------------------------------------------------------------------------

def test_fs_read_and_write_classification():
    src = '''\
import fs from "fs";
import { readFile, writeFile } from "fs/promises";
fs.readFileSync("a"); fs.createReadStream("a"); fs.readdirSync(".");
fs.writeFileSync("b", "x"); fs.appendFileSync("b", "y"); fs.unlinkSync("b");
fs.rmSync("d", { recursive: true }); fs.renameSync("a", "b"); fs.mkdirSync("d");
fs.copyFileSync("a", "b"); fs.createWriteStream("c");
await readFile("a"); await writeFile("b", "x");
'''
    result = caps(src)
    reads = [e for c, e in result if c == "READ"]
    writes = [e for c, e in result if c == "WRITE"]
    assert reads == ["fs.readFileSync()", "fs.createReadStream()", "fs.readdirSync()",
                     "fs/promises.readFile()"]
    assert writes == ["fs.writeFileSync()", "fs.appendFileSync()", "fs.unlinkSync()",
                      "fs.rmSync()", "fs.renameSync()", "fs.mkdirSync()",
                      "fs.copyFileSync()", "fs.createWriteStream()", "fs/promises.writeFile()"]


def test_fs_promises_via_property_and_named_import():
    src = '''\
import { promises as fsp } from "fs";
import * as fs from "node:fs";
await fsp.unlink("a");
await fs.promises.readFile("b");
'''
    assert caps(src) == [("WRITE", "fs/promises.unlink()"), ("READ", "fs/promises.readFile()")]


def test_fs_open_classified_by_flags():
    src = '''\
import fs from "fs";
fs.openSync("a");
fs.openSync("a", "r");
fs.openSync("a", "w");
fs.openSync("a", "r+");
fs.open("a", (err, fd) => {});
'''
    assert [c for c, _ in caps(src)] == ["READ", "READ", "WRITE", "WRITE", "READ"]


def test_fs_near_miss_other_modules_and_methods():
    src = '''\
import { readFile } from "./storage";
import fse from "memfs";
readFile("a");
fse.writeFileSync("b", "x");
cache.readFile("c");
fs.writeFileSync("d", "x");
'''
    # `fs` is never imported here, so fs.writeFileSync can't be resolved.
    assert caps(src) == []


# ---------------------------------------------------------------------------
# SEND
# ---------------------------------------------------------------------------

def test_send_positive():
    src = '''\
import axios from "axios";
import got from "got";
import https from "node:https";
import { request } from "undici";
import WebSocket from "ws";
const nodeFetch = require("node-fetch");
await fetch(url);
await axios.post(url, body);
await axios(url);
await got(url);
https.request(url);
await request(url);
new WebSocket(url);
await nodeFetch(url);
'''
    assert [e for c, e in caps(src)] == [
        "fetch()", "axios.post()", "axios()", "got()", "https.request()",
        "undici.request()", "new ws()", "node-fetch()",
    ]
    assert all(c == "SEND" for c, _ in caps(src))


def test_send_near_miss_shadowed_fetch_and_local_request():
    src = '''\
import { request } from "./api";
function call(fetch: (u: string) => Promise<unknown>) {
  return fetch("x");
}
request("/local");
client.get(url);
'''
    assert caps(src) == []


def test_send_net_and_global_websocket():
    src = '''\
import net from "net";
import dgram from "dgram";
net.connect(80, "example.com");
dgram.createSocket("udp4");
new WebSocket("wss://example.com");
'''
    assert [e for c, e in caps(src)] == ["net.connect()", "dgram.createSocket()", "new WebSocket()"]


# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------

def test_process_env_access_forms_and_confidence():
    src = '''\
const key = process.env.OPENAI_API_KEY;
const port = process.env["PORT"];
const { GITHUB_TOKEN, LOG_LEVEL: level } = process.env;
const other = process.env.SOMETHING;
'''
    tree = parse_ts("mod.ts", src)
    results = [(r.finding.evidence, r.finding.confidence)
               for r in scan_ts_capabilities("mod.ts", tree.root_node)]
    assert results == [
        ("process.env.OPENAI_API_KEY", 0.9),
        ("process.env.PORT", 0.7),  # bare PORT: config suffixes need "_" (same as Python)
        ("process.env.GITHUB_TOKEN", 0.9),
        ("process.env.LOG_LEVEL", 0.4),
        ("process.env.SOMETHING", 0.7),
    ]


def test_dotenv_and_keytar():
    src = '''\
import "dotenv/config";
import dotenv from "dotenv";
import keytar from "keytar";
dotenv.config();
await keytar.getPassword("svc", "user");
'''
    assert caps(src) == [
        ("SECRETS", "import 'dotenv/config'"),
        ("SECRETS", "dotenv.config()"),
        ("SECRETS", "keytar.getPassword()"),
    ]


def test_secrets_near_miss():
    src = '''\
const env = config.env.API_KEY;
const p = myprocess.env.TOKEN;
process.exit(1);
const cwd = process.cwd();
'''
    assert caps(src) == []


# ---------------------------------------------------------------------------
# DYNAMIC
# ---------------------------------------------------------------------------

def test_dynamic_positive():
    src = '''\
import vm from "node:vm";
eval(code);
new Function("a", code);
vm.runInNewContext(code, {});
new vm.Script(code);
const mod = await import(userPath);
const lib = require(name);
'''
    assert [e for c, e in caps(src)] == [
        "eval()", "new Function()", "vm.runInNewContext()", "new vm.Script()",
        "import() with non-literal specifier", "require() with non-literal specifier",
    ]
    assert all(c == "DYNAMIC" for c, _ in caps(src))


def test_dynamic_near_miss_literal_imports_and_method_named_eval():
    src = '''\
const a = await import("./plugin.js");
const b = require("lodash");
const c = await import(`./static.js`);
engine.eval(expr);
'''
    assert caps(src) == []


def test_dynamic_near_miss_literal_with_ts_cast():
    src = 'const p = await import("asciinema-player" as any);\n'
    assert caps(src) == []


def test_env_writes_are_not_secret_reads():
    src = '''\
delete process.env[key];
delete process.env.API_KEY;
process.env.NODE_ENV = "test";
process.env["TOKEN"] = saved;
'''
    assert caps(src) == []


def test_dynamic_near_miss_local_eval():
    src = '''\
function evaluate(eval: (s: string) => number) { return eval("1+1"); }
'''
    assert caps(src) == []


# ---------------------------------------------------------------------------
# AUTONOMY
# ---------------------------------------------------------------------------

def test_autonomy_positive():
    src = '''\
import cron from "node-cron";
import { CronJob } from "cron";
import Bree from "bree";
import { Agenda } from "agenda";
import { Worker } from "worker_threads";
setInterval(tick, 1000);
cron.schedule("* * * * *", job);
new CronJob("* * * * *", job);
new Bree({ jobs: [] });
new Agenda({ db: { address } });
new Worker("./w.js");
'''
    assert [e for c, e in caps(src)] == [
        "setInterval()", "node-cron.schedule()", "new cron.CronJob()",
        "new bree()", "new agenda.Agenda()", "new worker_threads.Worker()",
    ]
    assert all(c == "AUTONOMY" for c, _ in caps(src))


def test_autonomy_near_miss():
    src = '''\
setTimeout(tick, 1000);
scheduler.schedule(job);
new Worker("./w.js");
'''
    # setTimeout is one-shot; Worker isn't imported from worker_threads here.
    assert caps(src) == []


# ---------------------------------------------------------------------------
# Scope and file types
# ---------------------------------------------------------------------------

def test_module_level_vs_function_scope():
    src = '''\
import { execSync } from "child_process";
execSync("echo top");
export function run() { execSync("echo inside"); }
const handler = async () => { await fetch(url); };
class Tool { call() { return fetch(url); } }
'''
    tree = parse_ts("mod.ts", src)
    scopes = [(r.finding.lineno, r.in_function)
              for r in scan_ts_capabilities("mod.ts", tree.root_node)]
    assert scopes == [(2, False), (3, True), (4, True), (5, True)]


def test_javascript_and_jsx_files():
    js = 'const { exec } = require("child_process");\nexec(cmd);\n'
    jsx = 'import fs from "fs";\nconst El = () => <div>{fs.readFileSync("a")}</div>;\n'
    assert caps(js, "tool.js") == [("EXECUTE", "child_process.exec()")]
    assert caps(jsx, "view.jsx") == [("READ", "fs.readFileSync()")]


def test_detector_names_match_python_detectors():
    src = '''\
import { exec } from "child_process";
import fs from "fs";
exec(c); fetch(u); fs.readFileSync(p); fs.writeFileSync(p, d);
const k = process.env.API_KEY; eval(s); setInterval(f, 1);
'''
    detectors = {(c, d) for c, _, d in detect(src)}
    assert detectors == {
        ("EXECUTE", "shell_exec"), ("SEND", "network"), ("READ", "file_access"),
        ("WRITE", "file_access"), ("SECRETS", "secrets"), ("DYNAMIC", "dynamic_exec"),
        ("AUTONOMY", "autonomy"),
    }


# ---------------------------------------------------------------------------
# Scanner integration: text, JSON, SARIF
# ---------------------------------------------------------------------------

TS_SERVER = '''\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";

const apiKey = process.env.SERVICE_API_KEY;
const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
  return { content: [{ type: "text", text: execSync(cmd).toString() }] };
});
'''


@pytest.fixture
def ts_project(tmp_path):
    (tmp_path / "server.ts").write_text(TS_SERVER)
    return tmp_path


def _ts_findings(report):
    return {
        (e["finding"]["capability"], e["finding"]["evidence"]): e["finding"]
        for e in report["findings"]
    }


def test_scan_reports_ts_findings_with_states(ts_project):
    report = scan_path(ts_project)
    found = _ts_findings(report)
    execute = found[("EXECUTE", "child_process.execSync()")]
    secret = found[("SECRETS", "process.env.SERVICE_API_KEY")]
    assert execute["reachability"] == "unknown"     # inside a tool handler; TS paths not traced yet
    assert secret["reachability"] == "module_level"  # top-level code runs on import
    assert execute["risk_level"] == "high"
    assert execute["explanation"] and execute["finding_id"]
    assert set(report["capabilities"]) == {"EXECUTE", "SECRETS"}


def test_ts_function_findings_without_entry_points_are_no_entry_points(tmp_path):
    (tmp_path / "util.ts").write_text(
        'import { execSync } from "child_process";\nexport const run = (c: string) => execSync(c);\n'
    )
    report = scan_path(tmp_path)
    assert [e["finding"]["reachability"] for e in report["findings"]] == ["no_entry_points"]


def test_ts_findings_in_json(ts_project):
    report = json.loads(json_report(scan_path(ts_project)))
    assert report["schema_version"] == "1.1"
    evidence = {e["finding"]["evidence"] for e in report["findings"]}
    assert {"child_process.execSync()", "process.env.SERVICE_API_KEY"} <= evidence
    for e in report["findings"]:
        assert e["detector"] in {"shell_exec", "secrets"}
        assert "reachability_path_locations" not in e["finding"]
    assert "num_ts_files_unparsed" not in report  # internal only, schema unchanged


def test_ts_findings_in_sarif(ts_project):
    results = scan_path(ts_project)
    default = build_sarif(results)["runs"][0]["results"]
    full = build_sarif(results, include_unreachable=True)["runs"][0]["results"]
    rules = {r["ruleId"] for r in full}
    assert "reachscan/EXECUTE" in rules
    assert {r["ruleId"] for r in default} == {"reachscan/SECRETS"}  # module_level only
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in full}
    assert uris == {"server.ts"}


def test_ts_findings_in_text_report(ts_project):
    out = human_report(scan_path(ts_project))
    assert "child_process.execSync()" in out
    assert "UNKNOWN" in out
    assert "TypeScript call paths" in out


def test_ts_findings_do_not_change_exit_code_until_reachable(ts_project, capsys):
    with pytest.raises(SystemExit) as exc:
        main([str(ts_project), "--json"])
    assert exc.value.code == 0


def test_mixed_project_keeps_python_reachability(tmp_path):
    (tmp_path / "server.ts").write_text(TS_SERVER)
    (tmp_path / "helper.py").write_text("import subprocess\n\ndef run():\n    subprocess.run(['ls'])\n")
    report = scan_path(tmp_path)
    states = {
        (e["finding"]["file"].rsplit("/", 1)[-1], e["finding"]["capability"]):
            e["finding"]["reachability"]
        for e in report["findings"]
    }
    assert states[("helper.py", "EXECUTE")] == "no_entry_points"
    assert states[("server.ts", "EXECUTE")] == "unknown"
    out = human_report(report)
    # Python no_entry_points findings stay visible next to TS unknown findings.
    assert "subprocess.run()" in out
    assert "NO_ENTRY_POINTS" in out


def test_unparseable_ts_file_noted_in_text_report(tmp_path):
    (tmp_path / "broken.ts").write_text('import { exec } from "child_process";\nconst = = ;\n')
    report = scan_path(tmp_path)
    assert report["num_ts_files_unparsed"] == 1
    assert report["findings"] == []
    assert "couldn't be parsed" in human_report(report)
