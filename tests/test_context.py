from pathlib import Path

import pytest

from aegis.context import SystemContext


def test_fake_root_maps_posix_paths_on_any_host(tmp_path: Path):
    ctx = SystemContext(tmp_path)
    assert ctx.path("/etc/ssh/sshd_config") == tmp_path / "etc" / "ssh" / "sshd_config"
    with pytest.raises(ValueError, match="absolute POSIX"):
        ctx.path("etc/ssh/sshd_config")
    with pytest.raises(ValueError, match="traversal"):
        ctx.path("/etc/../shadow")
