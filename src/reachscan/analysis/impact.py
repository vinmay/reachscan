"""Multi-capability reasoning for higher-level behavioral risks."""

from typing import Any, Dict, Iterable, List, Set


_COUNTED_STATES = {"reachable", "module_level"}
_UNEVALUATED_STATES = {None, "no_entry_points"}
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs")


def finding_language(finding: Dict[str, Any]) -> str:
    """"ts" for TypeScript/JavaScript files, "python" otherwise (including no file)."""
    file = str(finding.get("file") or "").lower()
    return "ts" if file.endswith(_TS_SUFFIXES) else "python"


def risk_counted_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the findings that count toward combined risks.

    A finding counts if its reachability is "reachable" or "module_level"
    (module-level code runs unconditionally). When no finding of a language
    carries an evaluated reachability state (all are missing/None or
    "no_entry_points"), every finding of that language counts by presence.

    The presence fallback is decided separately for Python and for
    TypeScript/JavaScript findings, so TS states in a mixed project don't
    switch off the fallback for Python findings (or the other way round).
    """
    by_language: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_language.setdefault(finding_language(f), []).append(f)
    counted: List[Dict[str, Any]] = []
    for group in by_language.values():
        evaluated = any(f.get("reachability") not in _UNEVALUATED_STATES for f in group)
        if evaluated:
            counted.extend(f for f in group if f.get("reachability") in _COUNTED_STATES)
        else:
            counted.extend(group)
    return counted


def _reachable_capability_set(findings: Iterable[Dict[str, Any]]) -> Set[str]:
    """Capabilities with at least one finding that counts toward combined risks."""
    return {f["capability"] for f in risk_counted_findings(findings) if f.get("capability")}


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
    caps = _reachable_capability_set(findings)
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
