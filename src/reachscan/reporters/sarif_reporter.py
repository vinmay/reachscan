"""SARIF 2.1.0 output for reachscan reports.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub code scanning notes: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from reachscan.analysis.finding_enrichment import CAPABILITY_DETAILS
from reachscan.analysis.impact import finding_language
from reachscan.schema import _get_tool_version

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/vinmay/reachscan"
SRCROOT = "%SRCROOT%"

# Findings in these states are reported by default. Everything else (unreachable,
# unknown, no_entry_points) needs --sarif-include-unreachable, so the GitHub
# Security tab only shows what an LLM entry point can actually trigger.
DEFAULT_STATES = frozenset({"reachable", "module_level"})

# Mirrors the combined-capability rules in reachscan.analysis.impact.
COMBINED_RULES: Dict[str, Dict[str, Any]] = {
    "data_exfiltration": {
        "name": "DataExfiltration",
        "title": "Data Exfiltration Risk",
        "description": "The code can both access/change local files and send data externally.",
        "severity": "high",
    },
    "remote_control": {
        "name": "RemoteControl",
        "title": "Remote Control Risk",
        "description": "The code can execute commands and communicate over the network.",
        "severity": "high",
    },
    "secret_leak": {
        "name": "SecretLeakage",
        "title": "Secret Leakage Risk",
        "description": "The code can read local files and transmit their contents externally.",
        "severity": "high",
    },
    "destructive_agent": {
        "name": "DestructiveAgent",
        "title": "Destructive Agent Risk",
        "description": "The code can execute commands and perform destructive file actions.",
        "severity": "high",
    },
}

# GitHub maps security-severity scores to critical/high/medium/low.
_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "3.0", "info": "1.0"}
_REACHABLE_LEVELS = {"high": "error", "medium": "warning"}


def _capability_rule_id(capability: str) -> str:
    return f"reachscan/{capability}"


def _combined_rule_id(risk_id: str) -> str:
    return f"reachscan/combined/{risk_id}"


def _level(risk_level: Optional[str], reachability: Optional[str]) -> str:
    """Reachable high → error, reachable medium → warning, everything else → note."""
    if reachability != "reachable":
        return "note"
    return _REACHABLE_LEVELS.get(str(risk_level or "").lower(), "note")


def _build_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for capability, detail in CAPABILITY_DETAILS.items():
        risk = detail["risk_level"]
        rules.append(
            {
                "id": _capability_rule_id(capability),
                "name": capability.capitalize(),
                "shortDescription": {"text": f"{capability} capability"},
                "fullDescription": {"text": detail["explanation"]},
                "help": {"text": f"{detail['explanation']} {detail['impact']}"},
                "helpUri": INFORMATION_URI,
                "defaultConfiguration": {"level": _REACHABLE_LEVELS.get(risk, "note")},
                "properties": {
                    "tags": ["security", "reachscan", capability.lower()],
                    "security-severity": _SECURITY_SEVERITY.get(risk, "5.0"),
                },
            }
        )
    for risk_id, rule in COMBINED_RULES.items():
        rules.append(
            {
                "id": _combined_rule_id(risk_id),
                "name": rule["name"],
                "shortDescription": {"text": rule["title"]},
                "fullDescription": {"text": rule["description"]},
                "help": {"text": rule["description"]},
                "helpUri": INFORMATION_URI,
                "defaultConfiguration": {"level": _REACHABLE_LEVELS.get(rule["severity"], "note")},
                "properties": {
                    "tags": ["security", "reachscan", "combined-risk"],
                    "security-severity": _SECURITY_SEVERITY.get(rule["severity"], "5.0"),
                },
            }
        )
    return rules


def _scan_root(results: Dict[str, Any]) -> Optional[Path]:
    """Absolute local scan root, or None for remote targets (paths already relative)."""
    if results.get("source_type", "local") != "local":
        return None
    target = Path(str(results.get("target", "."))).resolve()
    return target.parent if target.is_file() else target


class _Locator:
    """Builds SARIF artifact locations relative to the scan root."""

    def __init__(self, root: Optional[Path]):
        self.root = root

    def uri(self, file: str) -> Dict[str, Any]:
        path = Path(file)
        if path.is_absolute():
            if self.root is not None:
                try:
                    rel = path.resolve().relative_to(self.root)
                    return {"uri": PurePosixPath(rel).as_posix(), "uriBaseId": SRCROOT}
                except ValueError:
                    pass
            return {"uri": path.as_uri()}
        return {"uri": PurePosixPath(path).as_posix(), "uriBaseId": SRCROOT}

    def physical(self, file: str, lineno: Optional[int]) -> Dict[str, Any]:
        loc: Dict[str, Any] = {"artifactLocation": self.uri(file)}
        if isinstance(lineno, int) and lineno > 0:
            loc["region"] = {"startLine": lineno}
        return loc


def _message(finding: Dict[str, Any], detector: str) -> str:
    capability = finding.get("capability")
    evidence = finding.get("evidence")
    state = finding.get("reachability")
    if state == "reachable":
        text = (
            f"{capability} via {evidence} is reachable from LLM entry point "
            f"'{finding.get('entry_point_name')}'."
        )
        path = finding.get("reachability_path") or []
        if path:
            text += f" Call chain: {' -> '.join(path)}."
    elif state == "module_level":
        text = f"{capability} via {evidence} runs at module import time."
    else:
        text = f"{capability} via {evidence} ({state or 'unknown'} from LLM entry points)."
    impact = finding.get("impact")
    if impact:
        text += f" {impact}"
    return text


def _code_flow(finding: Dict[str, Any], locator: _Locator) -> Optional[Dict[str, Any]]:
    """One threadFlowLocation per function hop, then the sink itself."""
    hops = finding.get("reachability_path_locations") or []
    if not hops:
        return None
    thread_locations = []
    for i, hop in enumerate(hops):
        label = "LLM entry point" if i == 0 else "calls"
        thread_locations.append(
            {
                "location": {
                    "physicalLocation": locator.physical(hop["file"], hop.get("lineno")),
                    "message": {"text": f"{label} {hop['function']}"},
                },
                "nestingLevel": i,
                "executionOrder": i,
            }
        )
    thread_locations.append(
        {
            "location": {
                "physicalLocation": locator.physical(finding.get("file", ""), finding.get("lineno")),
                "message": {"text": f"{finding.get('capability')} via {finding.get('evidence')}"},
            },
            "nestingLevel": len(hops),
            "executionOrder": len(hops),
        }
    )
    return {
        "message": {"text": f"Call chain from entry point '{finding.get('entry_point_name')}'"},
        "threadFlows": [{"locations": thread_locations}],
    }


def _finding_result(
    item: Dict[str, Any], locator: _Locator, rule_index: Dict[str, int]
) -> Dict[str, Any]:
    finding = item.get("finding", {})
    detector = item.get("detector", "unknown")
    capability = finding.get("capability", "UNKNOWN")
    rule_id = _capability_rule_id(capability)
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _level(finding.get("risk_level"), finding.get("reachability")),
        "message": {"text": _message(finding, detector)},
        "locations": [
            {"physicalLocation": locator.physical(finding.get("file", ""), finding.get("lineno"))}
        ],
        "properties": {
            "detector": detector,
            "capability": capability,
            "evidence": finding.get("evidence"),
            "riskLevel": finding.get("risk_level"),
            "reachability": finding.get("reachability"),
            "confidence": finding.get("confidence"),
            "entryPoint": finding.get("entry_point_name"),
            "reachabilityPath": finding.get("reachability_path"),
            "reachabilityPathTruncated": bool(finding.get("reachability_path_truncated")),
            "findingId": finding.get("finding_id"),
        },
    }
    if rule_id in rule_index:
        result["ruleIndex"] = rule_index[rule_id]
    if finding.get("finding_id"):
        result["partialFingerprints"] = {"reachscanFindingId/v1": finding["finding_id"]}
    flow = _code_flow(finding, locator)
    if flow:
        result["codeFlows"] = [flow]
    return result


def _pick_anchor(findings: List[Dict[str, Any]], capability: str) -> Optional[Dict[str, Any]]:
    """Best finding to locate a combined risk on: reachable, then module_level, then any."""
    candidates = [f for f in findings if f.get("capability") == capability]
    for state in ("reachable", "module_level"):
        for f in candidates:
            if f.get("reachability") == state:
                return f
    return candidates[0] if candidates else None


def _risk_result(
    risk: Dict[str, Any],
    findings: List[Dict[str, Any]],
    locator: _Locator,
    rule_index: Dict[str, int],
) -> Optional[Dict[str, Any]]:
    capabilities = risk.get("capabilities_triggered") or []
    anchors = [a for a in (_pick_anchor(findings, c) for c in capabilities) if a]
    if not anchors:
        return None  # GitHub code scanning requires a location
    all_reachable = len(anchors) == len(capabilities) and all(
        a.get("reachability") == "reachable" for a in anchors
    )
    level = _REACHABLE_LEVELS.get(risk.get("severity", ""), "note") if all_reachable else "note"
    rule_id = _combined_rule_id(risk.get("id", "unknown"))
    primary, related = anchors[0], anchors[1:]
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": f"{risk.get('title', risk.get('id'))}: {risk.get('why', '')} "
            f"Capabilities: {', '.join(capabilities)}."
        },
        "locations": [
            {"physicalLocation": locator.physical(primary.get("file", ""), primary.get("lineno"))}
        ],
        "properties": {
            "riskId": risk.get("id"),
            "severity": risk.get("severity"),
            "capabilities": capabilities,
            "allCapabilitiesReachable": all_reachable,
        },
    }
    if rule_id in rule_index:
        result["ruleIndex"] = rule_index[rule_id]
    if related:
        result["relatedLocations"] = [
            {
                "id": i,
                "physicalLocation": locator.physical(f.get("file", ""), f.get("lineno")),
                "message": {"text": f"{f.get('capability')} via {f.get('evidence')}"},
            }
            for i, f in enumerate(related, start=1)
        ]
    return result


_LANGUAGE_LABELS = {"python": "Python", "ts": "TypeScript/JavaScript"}
_ENTRY_POINT_KEYS = {"python": "py_entry_points", "ts": "ts_entry_points"}


def _no_entry_point_notifications(
    results: Dict[str, Any], omitted_by_language: Dict[str, int]
) -> List[Dict[str, Any]]:
    """One warning per language that has hidden findings but no detected entry points.

    Without entry points, reachability isn't evaluated for that language, so
    its findings are left out of the default SARIF results. The notification
    says so, so an empty Security tab isn't mistaken for a clean scan.
    """
    notifications = []
    for language, label in _LANGUAGE_LABELS.items():
        hidden = omitted_by_language.get(language, 0)
        if hidden == 0 or results.get(_ENTRY_POINT_KEYS[language]):
            continue
        notifications.append({
            "level": "warning",
            "message": {
                "text": (
                    f"No entry points detected for {label}; reachability not evaluated; "
                    f"{hidden} findings not shown. Use --sarif-include-unreachable "
                    "to include them."
                )
            },
            "descriptor": {"id": "reachscan/no-entry-points"},
            "properties": {"language": language, "findingsNotShown": hidden},
        })
    return notifications


def build_sarif(results: Dict[str, Any], include_unreachable: bool = False) -> Dict[str, Any]:
    """Convert scanner output to a SARIF 2.1.0 log dict."""
    rules = _build_rules()
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}
    root = _scan_root(results)
    locator = _Locator(root)

    items = results.get("findings", [])
    all_findings = [item.get("finding", {}) for item in items]
    sarif_results: List[Dict[str, Any]] = []
    omitted = 0
    omitted_by_language: Dict[str, int] = {}
    for item in items:
        state = item.get("finding", {}).get("reachability")
        if not include_unreachable and state not in DEFAULT_STATES:
            omitted += 1
            language = finding_language(item.get("finding", {}))
            omitted_by_language[language] = omitted_by_language.get(language, 0) + 1
            continue
        sarif_results.append(_finding_result(item, locator, rule_index))

    for risk in results.get("risks", []):
        risk_result = _risk_result(risk, all_findings, locator, rule_index)
        if risk_result:
            sarif_results.append(risk_result)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "reachscan",
                "version": _get_tool_version(),
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": sarif_results,
        "invocations": [{"executionSuccessful": True}],
        "properties": {
            "target": results.get("target", ""),
            "sourceType": results.get("source_type", "local"),
            "entryPointsDetected": len(results.get("py_entry_points", []))
            + len(results.get("ts_entry_points", [])),
            "includeUnreachable": include_unreachable,
            "omittedFindings": omitted,
        },
    }
    notifications = _no_entry_point_notifications(results, omitted_by_language)
    if notifications:
        run["invocations"][0]["toolExecutionNotifications"] = notifications
    if root is not None:
        run["originalUriBaseIds"] = {SRCROOT: {"uri": root.as_uri() + "/"}}
    return {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


def sarif_report(results: Dict[str, Any], include_unreachable: bool = False) -> str:
    """Return a pretty-printed SARIF 2.1.0 JSON string."""
    return json.dumps(build_sarif(results, include_unreachable), indent=2, ensure_ascii=False)
