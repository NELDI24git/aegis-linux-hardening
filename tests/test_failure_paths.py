from pathlib import Path

import pytest

from aegis.context import SystemContext
from aegis.engine.remediation import RemediationError, apply_fixes
from aegis.engine.runtime import RuntimeActionResult


def _write(root: Path, path: str, text: str):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_mixed_domain_failure_rolls_back_every_prepared_file(tmp_path: Path, monkeypatch):
    _write(tmp_path, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n")
    _write(tmp_path, "/proc/sys/kernel/randomize_va_space", "0\n")
    ctx = SystemContext(tmp_path)

    monkeypatch.setattr("aegis.engine.remediation.validate_sshd", lambda *a, **k: RuntimeActionResult("sshd", True, ["ok"]))
    monkeypatch.setattr("aegis.engine.remediation.apply_sysctl_values", lambda *a, **k: RuntimeActionResult("sysctl", False, ["injected failure"]))

    with pytest.raises(RemediationError, match="transaction rolled back"):
        apply_fixes(ctx, ["SSH-001", "KERN-001"])

    assert not ctx.exists("/etc/ssh/sshd_config.d/00-aegis-hardening.conf")
    assert not ctx.exists("/etc/sysctl.d/90-aegis-hardening.conf")
