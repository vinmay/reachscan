from agent_scan.detectors.secrets import scan_file

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
