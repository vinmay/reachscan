"""
Secrets access capability detector.

Detects common patterns that indicate access to secrets or credentials:
- os.environ[...] or os.environ.get(...)
- os.getenv(...)
- dotenv.load_dotenv(...)
- decouple.config(...)
- keyring.get_password(...)
- AWS Secrets Manager (boto3, aws_secretsmanager_cache)
- GCP Secret Manager (google.cloud.secretmanager)
- Azure Key Vault (azure.keyvault.secrets)

Returns CapabilityFinding(capability="SECRETS", evidence=..., file=..., lineno=..., confidence=...)
"""
import ast
from typing import List
from .base import CapabilityFinding
from .registry import register_detector

# Known secret access call patterns: (module, attr) -> evidence label
SECRET_CALL_ATTRS = {
    ("os", "getenv"): "os.getenv",
    ("os", "environ.get"): "os.environ.get",
    ("dotenv", "load_dotenv"): "dotenv.load_dotenv",
    ("dotenv.main", "load_dotenv"): "dotenv.load_dotenv",
    ("decouple", "config"): "decouple.config",
    ("keyring", "get_password"): "keyring.get_password",
    ("aws_secretsmanager_cache", "SecretCache"): "aws_secretsmanager_cache.SecretCache",
    ("google.cloud.secretmanager", "SecretManagerServiceClient"): "google.cloud.secretmanager.SecretManagerServiceClient",
    ("azure.keyvault.secrets", "SecretClient"): "azure.keyvault.secrets.SecretClient",
}

# If these names are imported directly, treat as secrets access
SECRET_FUNC_NAMES = {
    "getenv",
    "load_dotenv",
    "config",
    "get_password",
    "get_secret_value",
    "get_secret",
    "access_secret_version",
}

@register_detector("secrets")
def scan_file(path: str, content: str) -> List[CapabilityFinding]:
    findings: List[CapabilityFinding] = []
    try:
        tree = ast.parse(content)
    except Exception:
        return findings

    # collect imports mapping: alias -> full module
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                fullname = f"{module}.{alias.name}" if module else alias.name
                imports[alias.asname or alias.name] = fullname

    def resolve_name(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            parts.reverse()
            if not parts:
                return None
            first = parts[0]
            mapped = imports.get(first, first)
            return ".".join([mapped] + parts[1:]) if parts[1:] else mapped
        return None

    def const_str(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def arg_const_str(call_node, index=0):
        if call_node.args and len(call_node.args) > index:
            return const_str(call_node.args[index])
        return None

    # Detect os.environ[...] style access
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            value = node.value
            resolved = resolve_name(value)
            if resolved in {"os.environ", "environ"}:
                key_name = None
                # Python 3.11+: slice is expression; for older, may be ast.Index
                slc = node.slice
                if isinstance(slc, ast.Index):  # pragma: no cover - py<3.9
                    slc = slc.value
                key_name = const_str(slc)
                evidence = f"{resolved}[...]"
                if key_name:
                    evidence = f"{resolved}[{key_name!r}]"
                findings.append(CapabilityFinding(
                    capability="SECRETS",
                    evidence=evidence,
                    file=path,
                    lineno=getattr(node, "lineno", None),
                    confidence=0.9,
                ))

    # Detect call sites
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                resolved = resolve_name(func)
                if resolved:
                    # Normalize environ.get to a single key
                    if resolved.startswith("os.environ") and resolved.endswith("get"):
                        resolved = "os.environ.get"
                    # Try to annotate env var name when constant
                    env_key = None
                    if resolved in {"os.environ.get", "os.getenv"}:
                        env_key = arg_const_str(node, 0)
                    for (mod, attr), label in SECRET_CALL_ATTRS.items():
                        if resolved == f"{mod}.{attr}":
                            evidence = label
                            if env_key:
                                evidence = f"{label}({env_key!r})"
                            findings.append(CapabilityFinding(
                                capability="SECRETS",
                                evidence=evidence,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.9,
                            ))
                            break
                    else:
                        # Handle boto3 client('secretsmanager').get_secret_value(...)
                        if resolved.endswith("get_secret_value"):
                            secret_id = arg_const_str(node, 0)
                            evidence = "get_secret_value"
                            if secret_id:
                                evidence = f"get_secret_value({secret_id!r})"
                            findings.append(CapabilityFinding(
                                capability="SECRETS",
                                evidence=evidence,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.85,
                            ))
                        # Handle Azure SecretClient.get_secret(...)
                        if resolved.endswith("get_secret"):
                            secret_name = arg_const_str(node, 0)
                            evidence = "get_secret"
                            if secret_name:
                                evidence = f"get_secret({secret_name!r})"
                            findings.append(CapabilityFinding(
                                capability="SECRETS",
                                evidence=evidence,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.85,
                            ))
                        # Handle GCP Secret Manager access_secret_version(...)
                        if resolved.endswith("access_secret_version"):
                            secret_ver = arg_const_str(node, 0)
                            evidence = "access_secret_version"
                            if secret_ver:
                                evidence = f"access_secret_version({secret_ver!r})"
                            findings.append(CapabilityFinding(
                                capability="SECRETS",
                                evidence=evidence,
                                file=path,
                                lineno=getattr(node, "lineno", None),
                                confidence=0.85,
                            ))
            elif isinstance(func, ast.Name):
                name = func.id
                full = imports.get(name)
                if name in SECRET_FUNC_NAMES or (full and any(full.endswith(f".{n}") for n in SECRET_FUNC_NAMES)):
                    # annotate getenv/config/get_secret with constant key if possible
                    key = arg_const_str(node, 0)
                    evidence = full or name
                    if key and name in {"getenv", "config", "get_secret", "access_secret_version", "get_secret_value"}:
                        evidence = f"{evidence}({key!r})"
                    findings.append(CapabilityFinding(
                        capability="SECRETS",
                        evidence=evidence,
                        file=path,
                        lineno=getattr(node, "lineno", None),
                        confidence=0.85,
                    ))

    # Deduplicate by (evidence, lineno)
    seen = set()
    unique: List[CapabilityFinding] = []
    for f in findings:
        key = (f.evidence, f.lineno)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique
