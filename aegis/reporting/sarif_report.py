from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote
from typing import Any

from aegis import __version__
from aegis.checks import ALL_CHECKS
from aegis.models import Finding, Severity, Status

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_ALERT_STATUSES = {Status.FAIL, Status.WARN, Status.ERROR}
_SEVERITY_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}
_CHECK_IDS = {check.check_id for check in ALL_CHECKS}


def load_location_map(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read SARIF location map: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("SARIF location map root must be a JSON object")

    locations: dict[str, dict[str, Any]] = {}
    for raw_check_id, entry in payload.items():
        if not isinstance(raw_check_id, str):
            raise ValueError("SARIF location map keys must be Aegis check IDs")
        check_id = raw_check_id.upper()
        if check_id not in _CHECK_IDS:
            raise ValueError(f"Unknown Aegis check ID in SARIF location map: {raw_check_id}")
        if check_id in locations:
            raise ValueError(f"Duplicate Aegis check ID in SARIF location map: {check_id}")
        if not isinstance(entry, dict):
            raise ValueError(f"SARIF location for {check_id} must be an object")
        uri = entry.get("uri")
        line = entry.get("line")
        if not isinstance(uri, str) or not uri:
            raise ValueError(f"SARIF location for {check_id} requires a repository-relative POSIX URI")
        decoded_uri = uri
        for _ in range(3):
            decoded_uri = unquote(decoded_uri)
        if "\\" in decoded_uri or ":" in decoded_uri or "?" in decoded_uri or "#" in decoded_uri or any(ord(char) < 0x20 for char in decoded_uri):
            raise ValueError(f"SARIF location for {check_id} requires a repository-relative POSIX URI")
        segments = decoded_uri.split("/")
        if decoded_uri.startswith("/") or any(part in {"", ".", ".."} for part in segments):
            raise ValueError(f"SARIF location for {check_id} must stay within the repository root")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError(f"SARIF location for {check_id}.line must be a positive integer")
        locations[check_id] = {"uri": uri, "line": line}
    return locations


def _result_level(finding: Finding) -> str:
    if finding.status == Status.WARN:
        return "warning"
    return _SEVERITY_LEVEL[finding.severity]


def _rule(finding: Finding) -> dict[str, Any]:
    short_description = finding.title[:1024]
    full_description = (finding.why or finding.title)[:1024]
    tags = list(dict.fromkeys(["security", finding.module.lower(), *(tag.lower() for tag in finding.tags)]))[:20]
    rule: dict[str, Any] = {
        "id": finding.check_id,
        "name": finding.title[:255],
        "shortDescription": {"text": short_description},
        "fullDescription": {"text": full_description},
        "defaultConfiguration": {"level": _SEVERITY_LEVEL[finding.severity]},
        "help": {
            "text": finding.remediation or finding.why or finding.title,
            "markdown": f"{finding.why or finding.title}\n\n**Suggested remediation:** {finding.remediation or 'Review the host policy and evidence.'}",
        },
        "properties": {
            "tags": tags,
            "precision": "medium",
            "security-severity": f"{_SECURITY_SEVERITY[finding.severity]:.1f}",
            "aegis.module": finding.module,
            "aegis.severity": finding.severity.value,
        },
    }
    for reference in finding.references:
        if isinstance(reference, str) and reference.startswith(("https://", "http://")):
            rule["helpUri"] = reference
            break
    return rule


def _result(finding: Finding, rule_index: int, location: dict[str, Any] | None) -> dict[str, Any]:
    message = [f"{finding.title} ({finding.status.value}/{finding.severity.value})."]
    if finding.current:
        message.append(f"Current: {finding.current}")
    if finding.expected:
        message.append(f"Expected: {finding.expected}")
    if finding.why:
        message.append(f"Why: {finding.why}")
    if finding.remediation:
        message.append(f"Suggested remediation: {finding.remediation}")
    if finding.evidence:
        message.append("Evidence: " + "; ".join(finding.evidence))

    properties: dict[str, Any] = {
        "aegis.status": finding.status.value,
        "aegis.severity": finding.severity.value,
        "aegis.module": finding.module,
        "aegis.scored": finding.scored,
        "aegis.tags": finding.tags,
    }
    if finding.current:
        properties["aegis.current"] = finding.current
    if finding.expected:
        properties["aegis.expected"] = finding.expected
    if finding.remediation:
        properties["aegis.remediation"] = finding.remediation

    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index,
        "level": _result_level(finding),
        "kind": "review" if finding.status == Status.WARN else "fail",
        "message": {"text": "\n".join(message)},
        "properties": properties,
    }
    if location is not None:
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": location["uri"]},
                "region": {"startLine": location["line"]},
            }
        }]
    return result


def render_sarif(
    findings: list[Finding],
    *,
    platform: str | None = None,
    profile: str | None = None,
    locations: dict[str, dict[str, Any]] | None = None,
) -> str:
    actionable = [finding for finding in findings if finding.status in _ALERT_STATUSES]
    if locations is not None:
        missing = sorted({finding.check_id for finding in actionable} - locations.keys())
        if missing:
            raise ValueError("SARIF location map is missing active findings: " + ", ".join(missing))

    unique_findings: dict[str, Finding] = {}
    for finding in actionable:
        unique_findings.setdefault(finding.check_id, finding)
    rule_ids = sorted(unique_findings)
    rule_indexes = {check_id: index for index, check_id in enumerate(rule_ids)}
    rules = [_rule(unique_findings[check_id]) for check_id in rule_ids]
    results = [
        _result(finding, rule_indexes[finding.check_id], locations.get(finding.check_id) if locations is not None else None)
        for finding in actionable
    ]
    run_properties: dict[str, str] = {}
    if platform is not None:
        run_properties["aegis.platform"] = platform
    if profile is not None:
        run_properties["aegis.profile"] = profile
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "Aegis Linux Hardening",
            "semanticVersion": __version__,
            "rules": rules,
        }},
        "automationDetails": {"id": "aegis-host-audit"},
        "invocations": [{"executionSuccessful": True}],
        "results": results,
    }
    if run_properties:
        run["properties"] = run_properties
    payload = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"