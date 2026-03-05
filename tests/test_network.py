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