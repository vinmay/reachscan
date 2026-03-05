"""
Resolve scan targets from local paths, GitHub URLs, MCP HTTP endpoints, or PyPI packages.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import zipfile
from urllib.parse import urlparse
from urllib.request import urlopen, Request


@dataclass
class ResolvedTarget:
    local_path: Path
    display_target: str
    source_type: str
    resolved_version: Optional[str] = field(default=None)


ProgressCallback = Callable[[str, Optional[int], str], None]


def _is_github_url(target: str) -> bool:
    parsed = urlparse(target)
    host = (parsed.netloc or "").lower()
    return parsed.scheme in {"http", "https"} and "github.com" in host


def _is_mcp_http_endpoint(target: str) -> bool:
    return target.startswith("mcp+http://") or target.startswith("mcp+https://")


def _to_mcp_http_url(target: str) -> str:
    if target.startswith("mcp+http://"):
        return "http://" + target[len("mcp+http://") :]
    if target.startswith("mcp+https://"):
        return "https://" + target[len("mcp+https://") :]
    return target


def _is_pypi_target(target: str) -> bool:
    """Return True when target uses the explicit pypi: scheme."""
    return target.startswith("pypi:")


def _parse_pypi_target(target: str) -> tuple[str, Optional[str]]:
    """
    Strip the 'pypi:' prefix and split 'name==version' into (name, version).
    Bare name (no version specifier) returns (name, None).

    Examples:
        'pypi:requests'          → ('requests', None)
        'pypi:requests==2.31.0'  → ('requests', '2.31.0')
    """
    spec = target[len("pypi:"):]
    if "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip()
    return spec.strip(), None


def _safe_tar_members(tar: tarfile.TarFile):
    """Yield only safe tar members, skipping absolute paths, traversal, and symlinks."""
    for member in tar.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            continue
        if member.issym() or member.islnk():
            continue
        yield member


def _fetch_pypi_package(
    name: str,
    version: Optional[str],
    out_dir: Path,
    progress_callback: Optional[ProgressCallback] = None,
) -> str:
    """
    Query PyPI, download the best available artifact, extract it into out_dir,
    and return the resolved version string.

    Prefers sdist (.tar.gz) over wheel (.whl) so the full source tree is present.
    Falls back to wheel when no sdist is available.
    """
    if version:
        api_url = f"https://pypi.org/pypi/{name}/{version}/json"
    else:
        api_url = f"https://pypi.org/pypi/{name}/json"

    if progress_callback:
        progress_callback("pypi_download", 0, f"Fetching metadata for {name}")

    try:
        with urlopen(api_url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if version:
                raise RuntimeError(
                    f"PyPI: '{name}=={version}' not found. "
                    "Check the package name and version."
                ) from e
            raise RuntimeError(
                f"PyPI: package '{name}' not found. Check the package name."
            ) from e
        raise RuntimeError(f"PyPI API error for '{name}': HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error contacting PyPI: {e}") from e

    resolved_version: str = data["info"]["version"]
    urls: List[Dict] = data.get("urls", [])

    # Prefer sdist, fall back to any wheel
    artifact = None
    for u in urls:
        if u.get("packagetype") == "sdist":
            artifact = u
            break
    if artifact is None:
        for u in urls:
            if u.get("packagetype") == "bdist_wheel":
                artifact = u
                break
    if artifact is None:
        raise RuntimeError(
            f"PyPI: no downloadable sdist or wheel found for '{name}=={resolved_version}'."
        )

    download_url: str = artifact["url"]
    filename: str = artifact["filename"]

    if progress_callback:
        progress_callback("pypi_download", 30, f"Downloading {filename}")

    try:
        with urlopen(download_url, timeout=60) as resp:
            archive_bytes = resp.read()
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to download '{filename}': {e}") from e

    if progress_callback:
        progress_callback("pypi_download", 70, f"Extracting {filename}")

    archive_data = io.BytesIO(archive_bytes)

    if filename.endswith((".tar.gz", ".tar.bz2", ".tgz")):
        mode = "r:gz" if filename.endswith((".tar.gz", ".tgz")) else "r:bz2"
        try:
            with tarfile.open(fileobj=archive_data, mode=mode) as tar:
                tar.extractall(path=out_dir, members=_safe_tar_members(tar))
        except tarfile.TarError as e:
            raise RuntimeError(f"Failed to extract '{filename}': {e}") from e
    elif filename.endswith((".whl", ".zip")):
        try:
            with zipfile.ZipFile(archive_data) as zf:
                for member in zf.namelist():
                    member_path = Path(member)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        continue
                    zf.extract(member, path=out_dir)
        except zipfile.BadZipFile as e:
            raise RuntimeError(f"Failed to extract '{filename}': {e}") from e
    else:
        raise RuntimeError(f"Unrecognised archive format: '{filename}'.")

    if progress_callback:
        progress_callback("pypi_download", 100, "Done")

    return resolved_version


def _safe_python_filename(uri: str, idx: int) -> str:
    parsed = urlparse(uri)
    name = Path(parsed.path).name or f"resource_{idx}.py"
    if not name.endswith(".py"):
        name = f"{name}.py"
    digest = hashlib.sha1(uri.encode("utf-8")).hexdigest()[:8]
    return f"{idx:04d}_{digest}_{name}"


def _jsonrpc_request(endpoint: str, payload: Dict) -> Dict:
    body = json.dumps(payload).encode("utf-8")
    req = Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urlopen(req, timeout=15) as resp:
        data = resp.read().decode("utf-8")
    return json.loads(data)


def _mcp_initialize(endpoint: str) -> None:
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "reachscan", "version": "0.1.0"},
        },
    }
    try:
        _jsonrpc_request(endpoint, init_payload)
        _jsonrpc_request(
            endpoint,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
    except Exception:
        # Some servers don't require or support explicit initialize in simple deployments.
        pass


def _list_mcp_resources(endpoint: str) -> List[Dict]:
    resources: List[Dict] = []
    cursor: Optional[str] = None
    req_id = 10
    while True:
        params = {"cursor": cursor} if cursor else {}
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "resources/list",
            "params": params,
        }
        req_id += 1
        resp = _jsonrpc_request(endpoint, payload)
        result = resp.get("result") or {}
        resources.extend(result.get("resources", []))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return resources


def _read_mcp_resource(endpoint: str, uri: str, req_id: int) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "resources/read",
        "params": {"uri": uri},
    }
    resp = _jsonrpc_request(endpoint, payload)
    result = resp.get("result") or {}
    contents = result.get("contents") or []
    text_parts: List[str] = []
    for item in contents:
        text = item.get("text")
        if isinstance(text, str):
            text_parts.append(text)
    return "\n".join(text_parts)


def _materialize_mcp_endpoint(endpoint: str, out_dir: Path) -> None:
    _mcp_initialize(endpoint)
    resources = _list_mcp_resources(endpoint)
    py_resources = []
    for r in resources:
        uri = str(r.get("uri", ""))
        mime = str(r.get("mimeType", ""))
        if uri.endswith(".py") or mime in {"text/x-python", "application/x-python-code"}:
            py_resources.append(r)

    if not py_resources:
        raise RuntimeError("MCP endpoint returned no Python resources to scan.")

    for idx, resource in enumerate(py_resources, start=1):
        uri = str(resource.get("uri", ""))
        text = _read_mcp_resource(endpoint, uri, req_id=1000 + idx)
        if not text.strip():
            continue
        filename = _safe_python_filename(uri, idx)
        (out_dir / filename).write_text(text, encoding="utf-8")


def _clone_github_repo(
    url: str,
    out_dir: Path,
    progress_callback: Optional[ProgressCallback] = None,
) -> None:
    if progress_callback:
        progress_callback("github_clone", 0, "Starting clone")

    proc = subprocess.Popen(
        ["git", "clone", "--progress", "--depth", "1", url, str(out_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    percent_re = re.compile(r"(Receiving objects|Resolving deltas):\s+(\d+)%")
    last_percent: Optional[int] = None
    stderr_lines: List[str] = []

    assert proc.stderr is not None
    for raw_line in proc.stderr:
        line = raw_line.strip()
        stderr_lines.append(line)
        match = percent_re.search(line)
        if match:
            stage = match.group(1)
            percent = int(match.group(2))
            last_percent = percent
            if progress_callback:
                progress_callback("github_clone", percent, stage)

    returncode = proc.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(
            returncode=returncode,
            cmd=proc.args,
            output="",
            stderr="\n".join(stderr_lines),
        )

    if progress_callback:
        progress_callback("github_clone", max(last_percent or 0, 100), "Clone complete")


@contextmanager
def resolve_target(
    target: str | Path,
    progress_callback: Optional[ProgressCallback] = None,
) -> Iterator[ResolvedTarget]:
    if isinstance(target, Path):
        p = target.resolve()
        yield ResolvedTarget(local_path=p, display_target=str(p), source_type="local")
        return

    target_str = str(target).strip()
    maybe_local = Path(target_str)
    if maybe_local.exists():
        p = maybe_local.resolve()
        yield ResolvedTarget(local_path=p, display_target=str(p), source_type="local")
        return

    tmp_root = Path(tempfile.mkdtemp(prefix="reachscan_remote_"))
    try:
        if _is_github_url(target_str):
            work = tmp_root / "github_repo"
            _clone_github_repo(target_str, work, progress_callback=progress_callback)
            yield ResolvedTarget(local_path=work, display_target=target_str, source_type="github")
            return

        if _is_mcp_http_endpoint(target_str):
            work = tmp_root / "mcp_resources"
            work.mkdir(parents=True, exist_ok=True)
            endpoint = _to_mcp_http_url(target_str)
            _materialize_mcp_endpoint(endpoint, work)
            yield ResolvedTarget(local_path=work, display_target=target_str, source_type="mcp")
            return

        if _is_pypi_target(target_str):
            work = tmp_root / "pypi_package"
            work.mkdir(parents=True, exist_ok=True)
            name, version = _parse_pypi_target(target_str)
            resolved_version = _fetch_pypi_package(
                name, version, work, progress_callback=progress_callback
            )
            yield ResolvedTarget(
                local_path=work,
                display_target=target_str,
                source_type="pypi",
                resolved_version=resolved_version,
            )
            return

        raise FileNotFoundError(
            f"Target '{target_str}' is not a local path and is not a supported remote target."
        )
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
