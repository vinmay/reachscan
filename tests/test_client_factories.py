"""Tests for SEND evidence through HTTP clients returned by project helpers (T11e)."""

import textwrap
from pathlib import Path

from reachscan.detectors.client_factories import scan_client_factory_sends
from reachscan.scanner import scan_path


def _write(root: Path, files: dict) -> Path:
    for name, src in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(src), encoding="utf-8")
    return root


def _sends(root: Path):
    files = sorted(p for p in root.rglob("*.py"))
    return sorted(
        (Path(f.file).name, f.lineno, f.evidence) for f in scan_client_factory_sends(files, root)
    )


AWSLABS_HELPERS = '''\
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_requests_session() -> requests.Session:
    retry_strategy = Retry(total=3, backoff_factor=1)
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
'''


def test_awslabs_shape_cross_file(tmp_path):
    """Helper returns a configured Session; the caller posts through it."""
    _write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/helpers.py": AWSLABS_HELPERS,
        "pkg/server.py": '''\
            from pkg.helpers import get_requests_session

            ENDPOINT = "https://example.com/suggest"

            def suggest(query):
                with get_requests_session() as session:
                    response = session.post(ENDPOINT, json={"query": query}, timeout=30)
                    return response.json()
            ''',
    })
    assert _sends(tmp_path) == [
        ("server.py", 7, "requests.Session.post (client from get_requests_session())"),
    ]


def test_configuration_calls_stay_non_evidence(tmp_path):
    """The #34 fix holds: mount/headers/close on a factory client aren't sends."""
    _write(tmp_path, {"m.py": AWSLABS_HELPERS + '''

def configure():
    s = get_requests_session()
    s.mount("https://", object())
    s.headers.update({"X": "1"})
    s.close()
'''})
    assert _sends(tmp_path) == []


def test_direct_call_on_factory_result(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import httpx

        def make_client():
            return httpx.Client(timeout=5)

        def fetch(url):
            return make_client().get(url)
        '''})
    assert _sends(tmp_path) == [("m.py", 7, "httpx.Client.get (client from make_client())")]


def test_async_factory_with_await_and_local_variable(tmp_path):
    _write(tmp_path, {"m.py": '''\
        from httpx import AsyncClient

        async def make_client():
            client = AsyncClient(headers={"User-Agent": "x"})
            return client

        async def fetch(url):
            client = await make_client()
            return await client.post(url, json={})
        '''})
    assert _sends(tmp_path) == [("m.py", 9, "httpx.AsyncClient.post (client from make_client())")]


def test_async_with_and_module_attribute_import(tmp_path):
    _write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/clients.py": '''\
            import aiohttp

            def session():
                return aiohttp.ClientSession()
            ''',
        "pkg/tool.py": '''\
            from pkg import clients

            async def run(url):
                async with clients.session() as s:
                    async with s.get(url) as resp:
                        return await resp.text()
            ''',
    })
    assert _sends(tmp_path) == [("tool.py", 5, "aiohttp.ClientSession.get (client from session())")]


def test_urllib3_pool_manager_request(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import urllib3

        def pool():
            return urllib3.PoolManager()

        def go(url):
            p = pool()
            p.clear()
            return p.request("GET", url)
        '''})
    assert _sends(tmp_path) == [("m.py", 9, "urllib3.PoolManager.request (client from pool())")]


def test_factory_returning_requests_module(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import requests

        def http():
            return requests

        def go(url):
            return http().get(url)
        '''})
    assert _sends(tmp_path) == [("m.py", 7, "requests.get (client from http())")]


# ---------------------------------------------------------------------------
# Near-misses
# ---------------------------------------------------------------------------

def test_helper_returning_dict_is_not_a_factory(tmp_path):
    _write(tmp_path, {"m.py": '''\
        def load_config():
            return {"get": 1, "post": 2}

        def use():
            cfg = load_config()
            return cfg.get("get"), cfg.post if False else None
        '''})
    assert _sends(tmp_path) == []


def test_helper_returning_custom_class_is_not_a_factory(tmp_path):
    _write(tmp_path, {"m.py": '''\
        class Mailbox:
            def post(self, msg):
                return msg

        def make_mailbox():
            return Mailbox()

        def use():
            box = make_mailbox()
            return box.post("hi")
        '''})
    assert _sends(tmp_path) == []


def test_mixed_return_types_do_not_count(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import requests

        def maybe_session(offline):
            if offline:
                return {}
            return requests.Session()

        def use(url):
            s = maybe_session(False)
            return s.get(url)
        '''})
    assert _sends(tmp_path) == []


def test_variable_with_mixed_assignments_does_not_count(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import requests

        def maybe_session(offline):
            s = requests.Session()
            if offline:
                s = None
            return s

        def use(url):
            return maybe_session(False).get(url)
        '''})
    assert _sends(tmp_path) == []


def test_function_that_can_fall_off_the_end_is_not_a_factory(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import requests

        def session_or_none(flag):
            if flag:
                return requests.Session()

        def use(url):
            return session_or_none(True).get(url)
        '''})
    assert _sends(tmp_path) == []


def test_one_hop_only(tmp_path):
    """A helper returning another helper's client isn't followed."""
    _write(tmp_path, {"m.py": '''\
        import requests

        def base():
            return requests.Session()

        def wrapper():
            return base()

        def use(url):
            return wrapper().get(url)
        '''})
    assert _sends(tmp_path) == []


def test_generator_context_manager_out_of_scope(tmp_path):
    _write(tmp_path, {"m.py": '''\
        import contextlib
        import requests

        @contextlib.contextmanager
        def session():
            s = requests.Session()
            yield s

        def use(url):
            with session() as s:
                return s.get(url)
        '''})
    assert _sends(tmp_path) == []


# ---------------------------------------------------------------------------
# End to end: the restored send feeds reachability and annotation mismatches
# ---------------------------------------------------------------------------

def test_open_world_mismatch_uses_restored_send(tmp_path):
    _write(tmp_path, {
        "helpers.py": AWSLABS_HELPERS,
        "server.py": '''\
            from mcp.server.fastmcp import FastMCP
            from mcp.types import ToolAnnotations
            from helpers import get_requests_session

            ENDPOINT = "https://example.com/suggest"
            mcp = FastMCP("x")

            @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
            def suggest(query: str):
                with get_requests_session() as session:
                    return session.post(ENDPOINT, json={"q": query}).json()
            ''',
    })
    report = scan_path(tmp_path)
    sends = [e["finding"] for e in report["findings"] if e["finding"]["capability"] == "SEND"]
    assert [(Path(f["file"]).name, f["lineno"], f["reachability"]) for f in sends] == [
        ("server.py", 11, "reachable"),
    ]
    (m,) = report["annotation_mismatches"]
    assert m["rule"] == "closed_world_contradicted"
    assert m["observed"]["send_kind"] == "HTTP"
    assert m["observed"]["evidence"] == "requests.Session.post (client from get_requests_session())"
    assert m["reachability_path"] == ["suggest"]


def test_no_duplicate_when_per_file_detector_already_flags_the_line(tmp_path):
    """A literal URL lets the per-file detector flag the call; the factory pass adds nothing."""
    _write(tmp_path, {
        "helpers.py": AWSLABS_HELPERS,
        "server.py": '''\
            from helpers import get_requests_session

            def suggest(query):
                with get_requests_session() as session:
                    return session.post("https://example.com/suggest", json={"q": query})
            ''',
    })
    report = scan_path(tmp_path)
    sends = [e["finding"] for e in report["findings"] if e["finding"]["capability"] == "SEND"]
    assert [(Path(f["file"]).name, f["lineno"]) for f in sends] == [("server.py", 5)]
