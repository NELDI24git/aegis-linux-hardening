from pathlib import Path

from aegis.checks.accounts import ExtraUIDZeroCheck
from aegis.context import SystemContext
from aegis.models import Status


def test_extra_uid_zero_detected(tmp_path: Path):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/tmp:/bin/sh\n",
        encoding="utf-8",
    )
    result = ExtraUIDZeroCheck().run(SystemContext(tmp_path))
    assert result.status == Status.FAIL
    assert "backdoor" in result.current
