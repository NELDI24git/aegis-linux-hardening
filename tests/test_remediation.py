from pathlib import Path

from aegis.context import SystemContext
from aegis.engine.remediation import apply_fixes, preflight_fixes
from aegis.engine.transaction import rollback_transaction


def _write(root: Path, path: str, text: str):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_cross_domain_fake_root_transaction_and_rollback(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n")
    _write(tmp_path, "/proc/sys/kernel/randomize_va_space", "0\n")
    ctx = SystemContext(tmp_path)

    preflight = preflight_fixes(ctx, ["SSH-001", "KERN-001"])
    assert preflight.ok

    txid = apply_fixes(ctx, ["SSH-001", "KERN-001"])
    assert txid
    assert ctx.exists("/etc/ssh/sshd_config.d/00-aegis-hardening.conf")
    assert ctx.exists("/etc/sysctl.d/90-aegis-hardening.conf")

    result = rollback_transaction(ctx, txid)
    assert result.runtime_ok
    assert not ctx.exists("/etc/ssh/sshd_config.d/00-aegis-hardening.conf")
    assert not ctx.exists("/etc/sysctl.d/90-aegis-hardening.conf")


def test_lockout_sensitive_preflight_requires_live_host(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
    result = preflight_fixes(SystemContext(tmp_path), ["SSH-002"])
    assert not result.ok
    assert any("live target host" in message for message in result.messages)
