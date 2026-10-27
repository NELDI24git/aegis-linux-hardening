import os
from pathlib import Path

import pytest

from aegis.context import SystemContext
from aegis.inventory.privileged import collect_privileged_files


@pytest.mark.skipif(os.name != "posix", reason="SUID bits are a Unix filesystem feature")
def test_fake_root_finds_suid_file(tmp_path: Path):
    binary = tmp_path / "usr/local/bin/helper"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o4755)
    files, _ = collect_privileged_files(SystemContext(tmp_path))
    assert any(f.path == "/usr/local/bin/helper" and f.suid for f in files)
