"""Helpers to attach user-facing explanations and impacts to detector findings."""

from typing import Any, Dict

from reachscan.reachability import REACHABILITY_FIELDS

CAPABILITY_DETAILS: Dict[str, Dict[str, str]] = {
    "EXECUTE": {
        "risk_level": "high",
        "explanation": "This code can execute shell or interpreter commands on the host.",
        "impact": "A malicious prompt could run destructive commands, install malware, or alter the environment.",
    },
    "SEND": {
        "risk_level": "high",
        "explanation": "This code can send data over the network to external services.",
        "impact": "Sensitive local data could be transmitted to untrusted endpoints.",
    },
    "READ": {
        "risk_level": "medium",
        "explanation": "This code can read local files from the filesystem.",
        "impact": "Private files may be exposed to later processing or exfiltration.",
    },
    "WRITE": {
        "risk_level": "high",
        "explanation": "This code can write, modify, move, or delete files.",
        "impact": "An unsafe prompt could tamper with project files or remove important data.",
    },
    "SECRETS": {
        "risk_level": "high",
        "explanation": "This code accesses secrets or credential sources.",
        "impact": "Credentials may be disclosed and used for unauthorized access.",
    },
    "DYNAMIC": {
        "risk_level": "high",
        "explanation": "This code performs dynamic execution or runtime code loading.",
        "impact": "Untrusted input could become executable code, increasing compromise risk.",
    },
    "AUTONOMY": {
        "risk_level": "medium",
        "explanation": "This code can schedule or continue actions without direct user interaction.",
        "impact": "Risky behavior may repeat in the background after the initiating prompt.",
    },
}

DEFAULT_DETAILS = {
    "risk_level": "medium",
    "explanation": "This code exposes a potentially sensitive capability.",
    "impact": "If abused, this behavior can expand the blast radius of prompt injection.",
}


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a normalized finding with explanation, impact, and risk_level populated.

    Existing fields provided by detectors are preserved.
    """
    capability = finding.get("capability")
    detail = CAPABILITY_DETAILS.get(capability, DEFAULT_DETAILS)
    enriched = dict(finding)

    # Detectors currently emit CapabilityFinding defaults (None/"medium").
    # Replace missing/default values with capability-specific metadata.
    if not enriched.get("explanation"):
        enriched["explanation"] = detail["explanation"]
    if not enriched.get("impact"):
        enriched["impact"] = detail["impact"]

    current_risk = enriched.get("risk_level")
    if not current_risk or str(current_risk).lower() == "medium":
        enriched["risk_level"] = detail["risk_level"]

    # Reachability fields — None until the reachability analysis pass runs.
    # These are always present in the schema so downstream tooling can rely
    # on the keys existing. The reachability pass writes the real values.
    for field_name in REACHABILITY_FIELDS:
        enriched.setdefault(field_name, None)

    # Finding ID fields — None here, overwritten by scanner.py immediately
    # after enrichment using make_finding_id(). Defined as defaults so the
    # schema is complete even in unit tests that call enrich_finding() directly.
    enriched.setdefault("finding_id", None)   # compact SHA-1 hash
    enriched.setdefault("finding_ref", None)  # human-readable label

    return enriched
