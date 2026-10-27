import json
from pathlib import Path

from aegis.context import SystemContext
from aegis.policy import Policy, example_policy, migrate_policy_dict, validate_policy_dict


def test_v3_example_is_valid():
    assert validate_policy_dict(example_policy()) == []


def test_legacy_policy_migrates_to_v3():
    migrated = migrate_policy_dict({
        "allowed_public_ports": [22, 443],
        "allowed_privileged_files": ["/usr/local/bin/helper"],
    })
    assert migrated["schema_version"] == 3
    assert migrated["network"]["allowed_public_ports"] == [22, 443]
    assert migrated["privilege"]["allowed_suid_sgid"] == ["/usr/local/bin/helper"]


def test_v2_policy_migrates_to_v3():
    migrated = migrate_policy_dict({
        "schema_version": 2,
        "host_role": "web-server",
        "network": {"allowed_public_ports": [22, 80, 443]},
        "privilege": {"allowed_suid_sgid": []},
        "ssh": {"admin_users": ["admin"], "expected_password_authentication": "disabled"},
    })
    assert migrated["schema_version"] == 3
    assert migrated["profile"] == "web-server"


def test_invalid_explicit_policy_is_not_silently_accepted(tmp_path: Path):
    target = tmp_path / "etc/aegis"
    target.mkdir(parents=True)
    (target / "policy.json").write_text(json.dumps({"schema_version": 3, "profile": "general", "network": {"allowed_public_ports": [70000]}}))
    policy = Policy.load(SystemContext(tmp_path))
    assert policy.explicit
    assert not policy.valid
    assert policy.validation_errors


def test_exception_requires_reason_and_expiry():
    raw = example_policy()
    raw["exceptions"] = [{"check_id": "SSH-001", "reason": "x", "expires_at": "not-a-date"}]
    errors = validate_policy_dict(raw)
    assert any("rationale" in error for error in errors)
    assert any("YYYY-MM-DD" in error for error in errors)
