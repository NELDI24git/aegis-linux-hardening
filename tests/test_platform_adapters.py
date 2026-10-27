from pathlib import Path

from aegis.context import SystemContext
from aegis.platform import detect_platform
from aegis.platforms import get_platform_adapter


def _os_release(root: Path, text: str):
    path = root / "etc/os-release"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")


def test_ubuntu_selects_debian_adapter(tmp_path: Path):
    _os_release(tmp_path, 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n')
    ctx = SystemContext(tmp_path)
    assert detect_platform(ctx).distro_id == "ubuntu"
    assert get_platform_adapter(ctx).family == "debian"


def test_rocky_selects_rpm_adapter(tmp_path: Path):
    _os_release(tmp_path, 'NAME="Rocky Linux"\nID=rocky\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.5"\n')
    ctx = SystemContext(tmp_path)
    assert get_platform_adapter(ctx).family == "rpm"
