"""
Demo agent showing secrets/credentials access patterns.
This file is designed to be *scanned* (statically) by agent-scan.

It does not execute any secret retrieval by default; functions are not called.
"""

import os

# Basic environment variable access (common secret source)
API_KEY = os.getenv("API_KEY")
DB_PASSWORD = os.environ["DB_PASSWORD"]

# Optional libraries for secrets management
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

try:
    import boto3
except Exception:
    boto3 = None

try:
    from google.cloud import secretmanager
except Exception:
    secretmanager = None

try:
    from azure.keyvault.secrets import SecretClient
except Exception:
    SecretClient = None


def dotenv_example():
    if load_dotenv is None:
        return None
    # loads secrets from .env file
    return load_dotenv()


def aws_secrets_manager_example():
    if boto3 is None:
        return None
    client = boto3.client("secretsmanager")
    # retrieve a secret by name
    return client.get_secret_value("my-secret")


def gcp_secret_manager_example():
    if secretmanager is None:
        return None
    client = secretmanager.SecretManagerServiceClient()
    # access a specific secret version
    return client.access_secret_version("projects/p/secrets/s/versions/1")


def azure_keyvault_example():
    if SecretClient is None:
        return None
    client = SecretClient("https://example.vault.azure.net/", None)
    # retrieve secret by name
    return client.get_secret("my-secret")


if __name__ == "__main__":
    print("This demo file is meant for static scanning only.")
