from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from aegis.cli import main
from aegis.exitcodes import INTEGRITY_FAILED, OK, SNAPSHOT_CHANGES, USAGE_OR_INPUT
from aegis.integrity import generate_key
from aegis.snapshots import compare_snapshots, load_snapshot_data


def finding(check_id: str, status: str, *, current: str = "observed", severity: str = "HIGH", evidence: list[str] | None = None):
    return {
        "check_id": check_id,
        "title": f"Control {check_id}",
        "status": status,
        "severity": severity,
        "current": current,
        "expected": "secure",
        "evidence": evidence or [],
    }


def snapshot(findings: list[dict], *, host_id: str | None = "node-1", scope: dict | None = None):
    return {
        "schema_version": 1,
        "snapshot_id": str(uuid.uuid4()),
        "created_at": "2026-10-27T12:00:00+00:00",
        "aegis_version": "1.1.0",
        "platform": "Test Linux 1",
        "profile": "general",
        "host_id": host_id,
        "policy_sha256": None,
        "scope": scope or {"module": "ssh", "tags": []},
        "findings": findings,
    }


def write_ssh_config(root: Path, *, root_login: str, password_auth: str) -> None:
    path = root / "etc/ssh/sshd_config"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"PermitRootLogin {root_login}\nPasswordAuthentication {password_auth}\nMaxAuthTries 4\n",
        encoding="utf-8",
    )


def test_diff_classifies_added_resolved_regressed_changed_removed_and_unchanged():
    before = snapshot([
        finding("SSH-001", "FAIL"),
        finding("SSH-002", "PASS"),
        finding("SSH-003", "WARN", evidence=["old evidence"]),
        finding("SSH-005", "WARN", severity="LOW"),
        finding("ACC-001", "INFO"),
        finding("KERN-001", "PASS"),
    ])
    after = snapshot([
        finding("SSH-001", "PASS"),
        finding("SSH-002", "FAIL"),
        finding("SSH-003", "WARN", evidence=["new evidence"]),
        finding("SSH-005", "WARN", severity="HIGH"),
        finding("KERN-001", "PASS"),
        finding("SSH-004", "FAIL"),
    ])

    diff = compare_snapshots(before, after)

    assert [item["check_id"] for item in diff.added] == ["SSH-004"]
    assert [item["check_id"] for item in diff.resolved] == ["SSH-001"]
    assert [item["check_id"] for item in diff.regressed] == ["SSH-002", "SSH-005"]
    assert [item["check_id"] for item in diff.changed] == ["SSH-003"]
    assert [item["check_id"] for item in diff.removed] == ["ACC-001"]
    assert diff.unchanged == 1
    assert diff.has_changes
    assert diff.to_dict()["summary"]["regressed"] == 2


def test_diff_refuses_different_hosts_and_scopes():
    base = snapshot([finding("SSH-001", "PASS")])
    other_host = snapshot([finding("SSH-001", "PASS")], host_id="node-2")
    other_scope = snapshot([finding("SSH-001", "PASS")], scope={"module": None, "tags": []})

    with pytest.raises(ValueError, match="host IDs differ"):
        compare_snapshots(base, other_host)
    with pytest.raises(ValueError, match="scopes differ"):
        compare_snapshots(base, other_scope)


def test_snapshot_validation_rejects_duplicate_ids_and_unknown_schema():
    duplicate = snapshot([finding("SSH-001", "PASS"), finding("SSH-001", "FAIL")])
    with pytest.raises(ValueError, match="duplicates"):
        load_snapshot_data(json.dumps(duplicate).encode())

    unsupported = snapshot([])
    unsupported["schema_version"] = 99
    with pytest.raises(ValueError, match="Unsupported snapshot schema"):
        load_snapshot_data(json.dumps(unsupported).encode())


def test_cli_creates_snapshot_and_reports_changes(tmp_path: Path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    write_ssh_config(root, root_login="yes", password_auth="yes")
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"

    assert main(["--root", str(root), "snapshot", "create", str(before), "--module", "ssh", "--host-id", "node-1"]) == OK
    before_payload = json.loads(before.read_text(encoding="utf-8"))
    assert before_payload["schema_version"] == 1
    assert before_payload["host_id"] == "node-1"
    assert before_payload["findings"]
    capsys.readouterr()

    write_ssh_config(root, root_login="no", password_auth="no")
    assert main(["--root", str(root), "snapshot", "create", str(after), "--module", "ssh", "--host-id", "node-1"]) == OK
    capsys.readouterr()
    result = main(["--root", str(root), "snapshot", "diff", str(before), str(after), "--json"])
    output = capsys.readouterr().out
    assert result == SNAPSHOT_CHANGES
    payload = json.loads(output)
    assert payload["summary"]["changed"] >= 1
    assert payload["summary"]["has_changes"] is True


def test_cli_snapshot_creation_refuses_overwrite_without_force(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    output = tmp_path / "snapshot.json"
    args = ["--root", str(root), "snapshot", "create", str(output), "--module", "ssh"]

    assert main(args) == OK
    previous = output.read_bytes()
    assert main(args) == USAGE_OR_INPUT
    assert output.read_bytes() == previous
    assert main([*args, "--force"]) == OK
    assert output.read_bytes() != previous


def test_signed_snapshots_fail_closed_and_verify_before_diff(tmp_path: Path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    key = tmp_path / "integrity.key"
    generate_key(key)
    snapshot_path = tmp_path / "signed.json"

    assert main([
        "--root", str(root), "snapshot", "create", str(snapshot_path),
        "--module", "ssh", "--host-id", "node-1", "--sign-key", str(key),
    ]) == OK
    capsys.readouterr()
    assert main([
        "snapshot", "diff", str(snapshot_path), str(snapshot_path), "--require-signature", "--json",
    ]) == INTEGRITY_FAILED
    capsys.readouterr()
    assert main([
        "snapshot", "diff", str(snapshot_path), str(snapshot_path), "--verify-key", str(key),
        "--require-signature", "--json",
    ]) == OK
    assert json.loads(capsys.readouterr().out)["summary"]["has_changes"] is False

    snapshot_path.write_bytes(snapshot_path.read_bytes() + b" ")
    assert main([
        "snapshot", "diff", str(snapshot_path), str(snapshot_path), "--verify-key", str(key),
    ]) == INTEGRITY_FAILED
