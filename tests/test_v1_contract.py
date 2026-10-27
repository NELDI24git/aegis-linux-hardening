from __future__ import annotations

import aegis
import aegis.engine.remediation as remediation
from aegis.baseline import BASELINE_SCHEMA_VERSION
from aegis.engine.transaction import MANIFEST_SCHEMA
from aegis.eventlog import EVENT_SCHEMA_VERSION
from aegis.exitcodes import (
    AUDIT_THRESHOLD,
    DRIFT_DETECTED,
    INTEGRITY_FAILED,
    OK,
    PREFLIGHT_FAILED,
    REMEDIATION_FAILED,
    RUNTIME_ROLLBACK_FAILED,
    SNAPSHOT_CHANGES,
    USAGE_OR_INPUT,
)
from aegis.integrity import SIGNATURE_SCHEMA_VERSION
from aegis.policy import POLICY_SCHEMA_VERSION
from aegis.reporting.json_report import REPORT_SCHEMA_VERSION
from aegis.reporting.sarif_report import SARIF_VERSION


def test_v1_release_and_machine_format_versions_are_pinned() -> None:
    assert aegis.__version__ == "1.1.0"
    assert POLICY_SCHEMA_VERSION == 3
    assert REPORT_SCHEMA_VERSION == 2
    assert BASELINE_SCHEMA_VERSION == 2
    assert MANIFEST_SCHEMA == 3
    assert EVENT_SCHEMA_VERSION == 1
    assert SIGNATURE_SCHEMA_VERSION == 2
    assert SARIF_VERSION == "2.1.0"


def test_v1_automation_exit_code_meanings_are_pinned() -> None:
    assert {
        "success": OK,
        "input": USAGE_OR_INPUT,
        "drift": DRIFT_DETECTED,
        "audit_threshold": AUDIT_THRESHOLD,
        "runtime_rollback": RUNTIME_ROLLBACK_FAILED,
        "integrity": INTEGRITY_FAILED,
        "preflight": PREFLIGHT_FAILED,
        "remediation": REMEDIATION_FAILED,
        "snapshot_changes": SNAPSHOT_CHANGES,
    } == {
        "success": 0,
        "input": 2,
        "drift": 3,
        "audit_threshold": 4,
        "runtime_rollback": 5,
        "integrity": 6,
        "preflight": 7,
        "remediation": 8,
        "snapshot_changes": 9,
    }


def test_v1_cli_keeps_existing_audit_options() -> None:
    from aegis.cli import build_parser

    args = build_parser().parse_args(
        ["audit", "--profile", "web-server", "--json", "report.json", "--fail-on", "high"]
    )
    assert args.command == "audit"
    assert args.profile == "web-server"
    assert args.json_path == "report.json"
    assert args.fail_on == "high"


def test_legacy_ssh_remediation_entry_point_delegates(monkeypatch) -> None:
    expected = "transaction-123"
    calls = []

    def fake_apply(ctx, check_ids, *, dry_run=False):
        calls.append((ctx, check_ids, dry_run))
        return expected

    monkeypatch.setattr(remediation, "apply_fixes", fake_apply)
    result = remediation.apply_ssh_fixes("context", ["SSH-001"], dry_run=True)

    assert result == expected
    assert calls == [("context", ["SSH-001"], True)]
