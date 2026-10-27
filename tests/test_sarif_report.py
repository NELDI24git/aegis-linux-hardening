import json
from pathlib import Path

import pytest

from aegis.models import Finding, Severity, Status
from aegis.reporting.sarif_report import load_location_map, render_sarif


def finding(check_id="SSH-001", status=Status.FAIL, severity=Severity.HIGH):
    return Finding(
        check_id, "Root SSH login is disabled", "ssh", status, severity,
        "PermitRootLogin yes", "PermitRootLogin no", "Direct root login increases impact.",
        "Set PermitRootLogin no after validating access.", evidence=["/etc/ssh/sshd_config:1"],
        tags=["authentication"],
    )


def test_sarif_emits_actionable_findings_and_stable_rule_metadata():
    payload = json.loads(render_sarif([
        finding(),
        finding("SSH-002", Status.WARN, Severity.MEDIUM),
        finding("SSH-003", Status.PASS, Severity.LOW),
        finding("SSH-004", Status.EXEMPT, Severity.CRITICAL),
    ], platform="Ubuntu test", profile="bastion"))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["properties"] == {"aegis.platform": "Ubuntu test", "aegis.profile": "bastion"}
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["SSH-001", "SSH-002"]
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "SSH-001"
    assert run["results"][1]["level"] == "warning"
    assert "Suggested remediation" in run["results"][0]["message"]["text"]
    assert "locations" not in run["results"][0]


def test_sarif_location_map_produces_repo_relative_locations(tmp_path: Path):
    path = tmp_path / "locations.json"
    path.write_text(json.dumps({"ssh-001": {"uri": "infra/sshd.conf", "line": 12}}), encoding="utf-8")
    locations = load_location_map(path)
    payload = json.loads(render_sarif([finding()], locations=locations))
    assert payload["runs"][0]["results"][0]["locations"] == [{
        "physicalLocation": {
            "artifactLocation": {"uri": "infra/sshd.conf"},
            "region": {"startLine": 12},
        }
    }]


def test_sarif_github_mapping_must_cover_active_findings():
    with pytest.raises(ValueError, match="missing active findings"):
        render_sarif([finding()], locations={})


@pytest.mark.parametrize("uri", ["../outside", "/absolute/file", "C:/file", "infra\\file", "infra//file", "%2e%2e/outside", "%252e%252e/outside", "infra%2f..%2fsecret"])
def test_sarif_location_map_rejects_non_repository_paths(tmp_path: Path, uri: str):
    path = tmp_path / "locations.json"
    path.write_text(json.dumps({"SSH-001": {"uri": uri, "line": 1}}), encoding="utf-8")
    with pytest.raises(ValueError, match="repository-relative|repository root"):
        load_location_map(path)
