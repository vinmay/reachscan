"""Multi-capability reasoning for higher-level behavioral risks."""

from typing import Any, Dict, Iterable, List, Set


def _capability_set(findings: Iterable[Dict[str, Any]]) -> Set[str]:
    return {f.get("capability") for f in findings if f.get("capability")}


def _has_destructive_write(findings: Iterable[Dict[str, Any]]) -> bool:
    destructive_tokens = ("remove", "unlink", "rename", "replace", "delete")
    for finding in findings:
        if finding.get("capability") != "WRITE":
            continue
        evidence = str(finding.get("evidence", "")).lower()
        if any(token in evidence for token in destructive_tokens):
            return True
    return False


def analyze_combined_capabilities(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Infer higher-level risks by combining capabilities across findings.
    """
    caps = _capability_set(findings)
    risks: List[Dict[str, Any]] = []

    def add_risk(
        risk_id: str,
        title: str,
        severity: str,
        why: str,
        required_capabilities: Set[str],
    ) -> None:
        risks.append(
            {
                "id": risk_id,
                "title": title,
                "severity": severity,
                "why": why,
                "capabilities_triggered": sorted(required_capabilities),
            }
        )

    if {"SEND", "WRITE"}.issubset(caps):
        add_risk(
            "data_exfiltration",
            "Data Exfiltration Risk",
            "high",
            "The code can both access/change local files and send data externally.",
            {"SEND", "WRITE"},
        )

    if {"EXECUTE", "SEND"}.issubset(caps):
        add_risk(
            "remote_control",
            "Remote Control Risk",
            "high",
            "The code can execute commands and communicate over the network.",
            {"EXECUTE", "SEND"},
        )

    if {"READ", "SEND"}.issubset(caps):
        add_risk(
            "secret_leak",
            "Secret Leakage Risk",
            "high",
            "The code can read local files and transmit their contents externally.",
            {"READ", "SEND"},
        )

    if {"EXECUTE", "WRITE"}.issubset(caps) and _has_destructive_write(findings):
        add_risk(
            "destructive_agent",
            "Destructive Agent Risk",
            "high",
            "The code can execute commands and perform destructive file actions.",
            {"EXECUTE", "WRITE"},
        )

    return risks
