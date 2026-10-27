import json
from pathlib import Path

from aegis.context import SystemContext
from aegis.engine.audit import run_audit
from aegis.models import Status
from aegis.profiles import get_profile


def _write(root: Path, path: str, text: str):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_minimal_profile_is_smaller_control_pack(tmp_path: Path):
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    _write(tmp_path, "/etc/shadow", "root:*:20000:0:99999:7:::\n")
    general = run_audit(SystemContext(tmp_path), profile="general")
    minimal = run_audit(SystemContext(tmp_path), profile="minimal")
    assert len(minimal) < len(general)
    assert all(get_profile("minimal").check_enabled(check_id=f.check_id, module=f.module) for f in minimal)


def test_active_exception_becomes_exempt_without_becoming_pass(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    _write(tmp_path, "/etc/aegis/policy.json", json.dumps({
        "schema_version": 3,
        "profile": "general",
        "network": {}, "privilege": {}, "ssh": {}, "controls": {},
        "exceptions": [{"check_id": "SSH-001", "reason": "Temporary break-glass compatibility window", "expires_at": "2999-12-31", "ticket": "SEC-1"}],
    }))
    findings = run_audit(SystemContext(tmp_path), module="ssh")
    finding = next(f for f in findings if f.check_id == "SSH-001")
    assert finding.status == Status.EXEMPT
    assert finding.original_status == Status.FAIL
    assert not finding.scored
    assert finding.exception_ticket == "SEC-1"


def test_expired_exception_is_ignored(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    _write(tmp_path, "/etc/aegis/policy.json", json.dumps({
        "schema_version": 3,
        "profile": "general",
        "network": {}, "privilege": {}, "ssh": {}, "controls": {},
        "exceptions": [{"check_id": "SSH-001", "reason": "Old migration exception", "expires_at": "2000-01-01"}],
    }))
    finding = next(f for f in run_audit(SystemContext(tmp_path), module="ssh") if f.check_id == "SSH-001")
    assert finding.status == Status.FAIL
    assert any("expired exception ignored" in item for item in finding.evidence)


def test_semantic_tag_filter_selects_authentication_controls(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    findings = run_audit(SystemContext(tmp_path), profile="general", tags={"authentication"})
    assert findings
    assert all("authentication" in f.tags for f in findings)
    assert {f.module for f in findings} <= {"ssh", "accounts", "pam"}


def test_cli_profile_replaces_inherited_ports_but_not_explicit_override(tmp_path: Path):
    _write(tmp_path, "/etc/aegis/policy.json", json.dumps({
        "schema_version": 3, "profile": "web-server", "network": {}, "privilege": {}, "ssh": {}, "controls": {}, "exceptions": []
    }))
    ctx = SystemContext(tmp_path)
    run_audit(ctx, module="network", profile="bastion")
    from aegis.policy import Policy
    assert Policy.load(ctx).allowed_public_ports == {22}

    tmp2 = tmp_path / "explicit"
    _write(tmp2, "/etc/aegis/policy.json", json.dumps({
        "schema_version": 3, "profile": "web-server", "network": {"allowed_public_ports": [22, 8443]}, "privilege": {}, "ssh": {}, "controls": {}, "exceptions": []
    }))
    ctx2 = SystemContext(tmp2)
    run_audit(ctx2, module="network", profile="bastion")
    assert Policy.load(ctx2).allowed_public_ports == {22, 8443}
