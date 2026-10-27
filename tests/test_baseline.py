from pathlib import Path

from aegis.baseline import compare_baseline, create_baseline
from aegis.context import SystemContext


def write_socket_fixture(root: Path, port: int) -> None:
    fixture = root / "var/lib/aegis/fixtures"
    fixture.mkdir(parents=True, exist_ok=True)
    (fixture / "ss.txt").write_text(f"tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\n", encoding="utf-8")


def test_baseline_detects_new_socket(tmp_path: Path):
    write_socket_fixture(tmp_path, 22)
    ctx = SystemContext(tmp_path)
    baseline = tmp_path / "baseline.json"
    create_baseline(ctx, baseline)

    write_socket_fixture(tmp_path, 8080)
    ctx = SystemContext(tmp_path)  # new run = new cache
    drift = compare_baseline(ctx, baseline)
    assert drift.has_drift
    assert any(":8080" in item for item in drift.added_sockets)
