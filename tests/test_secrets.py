import pytest
from reachscan.detectors.secrets import scan_file

def test_os_environ_get():
    src = 'import os\nval = os.environ.get("API_KEY")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "SECRETS" for f in findings)
    assert any("API_KEY" in f.evidence for f in findings)

def test_os_getenv():
    src = 'import os\nval = os.getenv("TOKEN")'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "SECRETS" for f in findings)
    assert any("TOKEN" in f.evidence or "os.getenv" in f.evidence for f in findings)

def test_dotenv_load():
    src = 'from dotenv import load_dotenv\nload_dotenv()'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "SECRETS" for f in findings)

def test_os_environ_subscript():
    src = 'import os\nval = os.environ["DB_PASSWORD"]'
    findings = scan_file("demo.py", src)
    assert any("DB_PASSWORD" in f.evidence for f in findings)

def test_boto3_secretsmanager_get_secret_value():
    src = 'import boto3\nclient = boto3.client("secretsmanager")\nclient.get_secret_value("my-secret")'
    findings = scan_file("demo.py", src)
    assert any("get_secret_value" in f.evidence for f in findings)

def test_gcp_secretmanager_access():
    src = 'from google.cloud import secretmanager\nclient = secretmanager.SecretManagerServiceClient()\nclient.access_secret_version("projects/p/secrets/s/versions/1")'
    findings = scan_file("demo.py", src)
    assert any("access_secret_version" in f.evidence for f in findings)

def test_azure_keyvault_get_secret():
    src = 'from azure.keyvault.secrets import SecretClient\nclient = SecretClient("vault-url", None)\nclient.get_secret("my-secret")'
    findings = scan_file("demo.py", src)
    assert any("get_secret" in f.evidence for f in findings)


# ---------------------------------------------------------------------------
# Non-secret env var suppression
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "MARKITDOWN_MCP_SERVER_PORT",
    "APP_HOST",
    "REQUEST_TIMEOUT",
    "APP_DEBUG",
    "APP_LOG_LEVEL",
    "WORKER_THREADS",
    "APP_MODE",
    "SERVER_ENV",
    "BASE_URL",
])
def test_non_secret_env_vars_suppressed(key):
    """Env vars with obviously non-secret suffixes must not produce SECRETS findings."""
    src = f'import os\nval = os.getenv("{key}", "default")\n'
    findings = scan_file("server.py", src)
    assert findings == [], f"Expected no findings for {key!r}, got {findings}"


def test_non_secret_suppressed_environ_subscript():
    """os.environ[PORT_KEY] with known non-secret suffix is suppressed."""
    src = 'import os\nport = os.environ["SERVER_PORT"]\n'
    findings = scan_file("server.py", src)
    assert findings == []


def test_real_secret_still_detected_after_suppression():
    """Genuine secrets (API_KEY, TOKEN, PASSWORD) must not be suppressed."""
    src = 'import os\nkey = os.getenv("MY_API_KEY")\n'
    findings = scan_file("server.py", src)
    assert any("MY_API_KEY" in f.evidence for f in findings)


def test_bearer_token_still_detected():
    """ND_MCP_BEARER_TOKEN should still fire (BEARER_TOKEN suffix not suppressed)."""
    src = 'import os\ntok = os.environ.get("ND_MCP_BEARER_TOKEN")\n'
    findings = scan_file("server.py", src)
    assert any("ND_MCP_BEARER_TOKEN" in f.evidence for f in findings)
