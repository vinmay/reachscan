# examples/demo-agent/network_agent.py
"""
Demo agent showing multiple network call styles.

This file exists to exercise static detectors; the scanner should flag
calls to requests, urllib, socket, httpx, and websockets patterns.

Run manually (will perform real requests) only if you understand the effects:
    python examples/demo-agent/network_agent.py
"""

import requests
import urllib.request
import socket

# Optional additional imports demonstrating different libraries (not executed by default)
try:
    import httpx
except Exception:
    httpx = None

try:
    import aiohttp
except Exception:
    aiohttp = None

try:
    import websockets
except Exception:
    websockets = None


def requests_example():
    # simple requests call (literal URL -> should be flagged)
    resp = requests.get("https://example.com/api/health")
    return resp.status_code


def requests_post_example(data: dict):
    # POST with json payload (likely exfiltration candidate)
    resp = requests.post("https://example.com/submit", json=data)
    return resp.ok


def urllib_example():
    # urllib.request usage
    with urllib.request.urlopen("https://example.com/hello") as fh:
        return fh.read(64)


def socket_example():
    # low-level socket usage
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(2.0)
        s.connect(("example.com", 80))
        s.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        return s.recv(128)
    finally:
        s.close()


def httpx_example():
    # optional: httpx usage (if installed)
    if httpx is None:
        return None
    with httpx.Client() as c:
        r = c.get("https://example.com/")
        return r.status_code


async def aiohttp_example():
    # async example — not run by default
    if aiohttp is None:
        return None
    async with aiohttp.ClientSession() as session:
        async with session.get("https://example.com/async") as resp:
            return await resp.text()


async def websockets_example():
    # websockets example — not run by default
    if websockets is None:
        return None
    uri = "wss://echo.websocket.org"
    async with websockets.connect(uri) as ws:
        await ws.send("hello")
        return await ws.recv()


if __name__ == "__main__":
    print("Running network demo functions (these will make external network calls).")
    print("requests_example:", requests_example())
    print("requests_post_example:", requests_post_example({"x": 1}))
    print("urllib_example:", urllib_example()[:60])
    print("socket_example:", socket_example()[:60])
    if httpx:
        print("httpx_example:", httpx_example())
    else:
        print("httpx not installed; skipping httpx example.")
    print("Done.")