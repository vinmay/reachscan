"""T8a: code only an unresolved method call could reach is unknown, not unreachable."""

import textwrap

import pytest

from reachscan.scanner import scan_path

LC = "from langchain_core.tools import BaseTool\nimport subprocess\nimport os\n"
FASTMCP = "from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('d')\n"
TS_SDK = ('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
          'import { execSync } from "child_process";\n'
          'const server = new McpServer({ name: "d", version: "1" });\n')


def _states(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(textwrap.dedent(text))
    report = scan_path(tmp_path)
    return {e["finding"]["evidence"]: e["finding"]["reachability"] for e in report["findings"]}


PY_CASES = {
    "self_attr_method": {"tool.py": LC + """
class Shell:
    def exec(self, c):
        subprocess.run(c)
class RunTool(BaseTool):
    name: str = "run"
    description: str = "r"
    def __init__(self):
        super().__init__()
        self.shell = Shell()
    def _run(self, c: str):
        return self.shell.exec(c)
"""},
    "local_instance_method": {"server.py": FASTMCP + """
class Shell:
    def exec(self, c):
        subprocess.run(c)
@mcp.tool()
def run(c: str):
    s = Shell()
    s.exec(c)
"""},
    "inherited_method": {"base.py": "import subprocess\nclass ShellMixin:\n    def _shell(self, c):\n        subprocess.run(c)\n",
                         "tool.py": LC + """
from base import ShellMixin
class RunTool(ShellMixin, BaseTool):
    name: str = "run"
    description: str = "r"
    def _run(self, c: str):
        return self._shell(c)
"""},
    "super_method": {"tool.py": LC + """
class Base(BaseTool):
    name: str = "base"
    description: str = "b"
    def _shell(self, c):
        subprocess.run(c)
class RunTool(Base):
    name: str = "run"
    description: str = "r"
    def _shell(self, c):
        return super()._shell(c)
    def _run(self, c: str):
        return self._shell(c)
"""},
}


@pytest.mark.parametrize("case", sorted(PY_CASES))
def test_python_unresolved_method_call_is_unknown(tmp_path, case):
    assert _states(tmp_path, PY_CASES[case])["subprocess.run()"] == "unknown"


def test_python_unknown_follows_onward_calls(tmp_path):
    states = _states(tmp_path, {"server.py": FASTMCP + """
class Shell:
    def exec(self, c):
        return self._really(c)
    def _really(self, c):
        subprocess.run(c)
@mcp.tool()
def run(c: str):
    Shell().exec(c)
"""})
    assert states["subprocess.run()"] == "unknown"


def test_python_unrelated_method_stays_unreachable(tmp_path):
    states = _states(tmp_path, {"server.py": FASTMCP + """
class Shell:
    def exec(self, c):
        return c
    def wipe(self, p):
        subprocess.run(["rm", p])
@mcp.tool()
def run(c: str):
    Shell().exec(c)
"""})
    assert states["subprocess.run()"] == "unreachable"


def test_python_external_module_calls_add_no_candidates(tmp_path):
    states = _states(tmp_path, {"server.py": FASTMCP + """
import os.path
class Paths:
    def join(self, p):
        subprocess.run(["touch", p])
@mcp.tool()
def run(c: str):
    return os.path.join("a", c) + "".join([c])
"""})
    assert states["subprocess.run()"] == "unreachable"


TS_CASES = {
    "inherited_same_file": TS_SDK + """
class Base { protected shell(c: string) { return execSync(c); } }
class Tools extends Base {
  register() { server.tool("run", {}, async ({ c }) => this.shell(c)); }
}
""",
    "super_method": TS_SDK + """
class Base { shell(c: string) { return execSync(c); } }
class Tools extends Base {
  shell(c: string) { return super.shell(c); }
  register() { server.tool("run", {}, async ({ c }) => this.shell(c)); }
}
""",
}


@pytest.mark.parametrize("case", sorted(TS_CASES))
def test_ts_inherited_and_super_are_unknown(tmp_path, case):
    assert _states(tmp_path, {"server.ts": TS_CASES[case]})["child_process.execSync()"] == "unknown"


def test_ts_inherited_cross_file_is_unknown(tmp_path):
    states = _states(tmp_path, {
        "base.ts": 'import { execSync } from "child_process";\n'
                   'export class Base { protected shell(c: string) { return execSync(c); } }\n',
        "server.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
                     'import { Base } from "./base";\n'
                     'const server = new McpServer({ name: "d", version: "1" });\n'
                     'class Tools extends Base {\n'
                     '  register() { server.tool("run", {}, async ({ c }) => this.shell(c)); }\n'
                     '}\n',
    })
    assert states["child_process.execSync()"] == "unknown"
