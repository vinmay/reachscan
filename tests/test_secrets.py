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
    "MAX_BATCH_SIZE",
    "RETRY_LIMIT",
    "POLL_INTERVAL",
    "FEATURE_ENABLED",
])
def test_config_env_vars_low_confidence(key):
    """Env vars with config-like suffixes should get low confidence (0.4)."""
    src = f'import os\nval = os.getenv("{key}", "default")\n'
    findings = scan_file("server.py", src)
    assert len(findings) == 1, f"Expected 1 finding for {key!r}, got {len(findings)}"
    assert findings[0].confidence == 0.4, f"Expected confidence 0.4 for {key!r}"


def test_config_environ_subscript_low_confidence():
    """os.environ[PORT_KEY] with known config suffix gets low confidence."""
    src = 'import os\nport = os.environ["SERVER_PORT"]\n'
    findings = scan_file("server.py", src)
    assert len(findings) == 1
    assert findings[0].confidence == 0.4


def test_credential_env_vars_high_confidence():
    """Genuine secrets (API_KEY, TOKEN, PASSWORD) get high confidence (0.9)."""
    src = 'import os\nkey = os.getenv("MY_API_KEY")\n'
    findings = scan_file("server.py", src)
    assert any("MY_API_KEY" in f.evidence for f in findings)
    assert findings[0].confidence == 0.9


def test_bearer_token_still_detected():
    """ND_MCP_BEARER_TOKEN should fire with high confidence (_TOKEN suffix)."""
    src = 'import os\ntok = os.environ.get("ND_MCP_BEARER_TOKEN")\n'
    findings = scan_file("server.py", src)
    assert any("ND_MCP_BEARER_TOKEN" in f.evidence for f in findings)
    assert findings[0].confidence == 0.9


def test_ambiguous_env_var_medium_confidence():
    """Env var without clear config or credential pattern gets 0.7."""
    src = 'import os\nval = os.getenv("DATABASE_CONNECTION")\n'
    findings = scan_file("server.py", src)
    assert len(findings) == 1
    assert findings[0].confidence == 0.7
