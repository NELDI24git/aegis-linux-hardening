import os
from pathlib import Path

import pytest

from aegis.checks.filesystem import ShadowPermissionsCheck
from aegis.context import SystemContext
from aegis.models import Status


@pytest.mark.skipif(os.name != "posix", reason="Unix ownership and mode bits are unavailable on Windows")
def test_shadow_0640_shadow_group_is_accepted(tmp_path: Path):
    etc = tmp_path / "etc"
    etc.mkdir()
    shadow = etc / "shadow"
    shadow.write_text("root:*:0:0:99999:7:::\n", encoding="utf-8")
    os.chmod(shadow, 0o640)
    gid = shadow.stat().st_gid
    (etc / "group").write_text(f"shadow:x:{gid}:\n", encoding="utf-8")
    result = ShadowPermissionsCheck().run(SystemContext(tmp_path))
    # UID ownership is inherited from the test runner. Root CI normally passes;
    # non-root development environments should still exercise the group-mode logic.
    if shadow.stat().st_uid == 0:
        assert result.status == Status.PASS
    else:
        assert result.status == Status.FAIL
