from pathlib import Path

from aegis.checks.ssh import SSHMaxAuthTriesCheck, SSHRootLoginCheck
from aegis.context import SystemContext
from aegis.models import Status


def make_config(root: Path, text: str):
    p = root / "etc/ssh"
    p.mkdir(parents=True)
    (p / "sshd_config").write_text(text, encoding="utf-8")


def test_fallback_parser_detects_root_login(tmp_path: Path):
    make_config(tmp_path, "PermitRootLogin yes\nMaxAuthTries 6\n")
    finding = SSHRootLoginCheck().run(SystemContext(tmp_path))
    assert finding.status == Status.FAIL


def test_fallback_parser_warns_when_value_looks_compliant_but_is_not_authoritative(tmp_path: Path):
    make_config(tmp_path, "PermitRootLogin no\nMaxAuthTries 4\n")
    root = SSHRootLoginCheck().run(SystemContext(tmp_path))
    tries = SSHMaxAuthTriesCheck().run(SystemContext(tmp_path))
    assert root.status == Status.WARN
    assert tries.status == Status.WARN
