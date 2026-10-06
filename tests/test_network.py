from reachscan.detectors.network import scan_file


def test_requests_detect():
    src = 'import requests\nrequests.post("https://example.com/api", json={"a":1})'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "SEND" for f in findings)


def test_mcp_server_transport_not_flagged():
    """MCP server-side transports (StreamableHTTPSessionManager, SseServerTransport)
    must not be flagged as outbound network — they are server plumbing, not clients."""
    src = '''\
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.sse import SseServerTransport

manager = StreamableHTTPSessionManager(app=app, event_store=None)
sse = SseServerTransport("/messages/")
'''
    findings = scan_file("server.py", src)
    assert findings == [], f"Unexpected findings: {[f.evidence for f in findings]}"


def test_real_outbound_http_still_detected():
    """True outbound HTTP calls must still fire even after MCP suppression."""
    src = '''\
import requests
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

manager = StreamableHTTPSessionManager(app=app, event_store=None)
resp = requests.get("https://api.example.com/data")
'''
    findings = scan_file("server.py", src)
    assert any(f.evidence == "requests.get" for f in findings)
    # The transport should NOT appear
    assert not any("StreamableHTTP" in f.evidence for f in findings)

# ---------------------------------------------------------------------------
# Non-sending calls: client construction, adapters, mount, session config
# ---------------------------------------------------------------------------

def _send_evidence(src):
    return sorted(f.evidence for f in scan_file("demo.py", src) if f.capability == "SEND")


def test_session_configuration_is_not_send():
    """The awslabs shape: a helper that builds and configures a session sends nothing."""
    src = '''
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def get_requests_session():
    retry_strategy = Retry(total=3, backoff_factor=1)
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "x"})
    return session
'''
    assert _send_evidence(src) == []


def test_client_constructors_alone_are_not_send():
    src = '''
import httpx
import aiohttp
import urllib3

a = httpx.Client(timeout=10)
b = httpx.AsyncClient()
c = aiohttp.ClientSession()
d = urllib3.PoolManager()
'''
    assert _send_evidence(src) == []


def test_verb_calls_through_clients_are_still_send():
    src = '''
import requests
import httpx
import urllib3

session = requests.Session()
session.post(url, json={})

with httpx.Client() as client:
    client.get(url)

pool = urllib3.PoolManager()
pool.request("GET", url)
'''
    assert _send_evidence(src) == [
        "httpx.Client.get", "requests.Session.post", "urllib3.PoolManager.request",
    ]


def test_scheme_only_literal_is_not_a_request_url():
    src = '''
import requests
registry.get("https://")
registry.get("http://")
'''
    assert _send_evidence(src) == []


def test_literal_url_with_host_still_flags_verb_calls():
    src = '''
client.get("https://api.example.com/v1/items")
'''
    assert _send_evidence(src) == ["client.get -> https://api.example.com/v1/items"]


def test_mount_with_full_url_is_not_send():
    src = '''
import requests
session = requests.Session()
session.mount("https://internal.example.com/", adapter)
'''
    assert _send_evidence(src) == []


def test_constructor_via_bare_import_is_not_send():
    """Completes #34: `from httpx import AsyncClient; AsyncClient()` creates a client, sends nothing."""
    src = '''
from httpx import AsyncClient, Client
from requests import Session

a = AsyncClient(timeout=5)
b = Client()
c = Session()
'''
    assert _send_evidence(src) == []


def test_in_process_transport_client_is_not_tracked():
    """basic-memory shape: an httpx client over ASGITransport talks to an in-process app."""
    src = '''
import httpx
from httpx import ASGITransport

async def call(app):
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/memory", json={})
    local = httpx.Client(transport=httpx.MockTransport(handler))
    local.get("/x")
'''
    assert _send_evidence(src) == []


def test_network_transport_client_still_tracked():
    src = '''
import httpx

client = httpx.Client(transport=httpx.HTTPTransport(retries=3))
client.get(url)
'''
    assert _send_evidence(src) == ["httpx.Client.get"]
