from pathlib import Path

from aegis.baseline import compare_baseline_data
from aegis.cli import main
from aegis.context import SystemContext
from aegis.exitcodes import INTEGRITY_FAILED, OK, USAGE_OR_INPUT
from aegis.integrity import generate_key


def test_signed_baseline_requires_verification_and_checks_bytes(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    baseline = tmp_path / "host.json"
    key = tmp_path / "integrity.key"
    generate_key(key)

    assert main(["--root", str(root), "baseline", "create", str(baseline), "--sign-key", str(key)]) == OK
    assert main(["--root", str(root), "baseline", "compare", str(baseline)]) == INTEGRITY_FAILED
    assert main(["--root", str(root), "baseline", "compare", str(baseline), "--verify-key", str(key), "--require-signature"]) == OK

    baseline.write_bytes(baseline.read_bytes() + b" ")
    assert main(["--root", str(root), "baseline", "compare", str(baseline), "--verify-key", str(key)]) == INTEGRITY_FAILED


def test_unsigned_baseline_can_be_required_to_have_signature(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    baseline = tmp_path / "host.json"
    assert main(["--root", str(root), "baseline", "create", str(baseline)]) == OK
    assert main(["--root", str(root), "baseline", "compare", str(baseline), "--require-signature"]) == INTEGRITY_FAILED


def test_baseline_creation_refuses_implicit_overwrite(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    baseline = tmp_path / "host.json"
    assert main(["--root", str(root), "baseline", "create", str(baseline)]) == OK
    before = baseline.read_bytes()
    assert main(["--root", str(root), "baseline", "create", str(baseline)]) == USAGE_OR_INPUT
    assert baseline.read_bytes() == before
    assert main(["--root", str(root), "baseline", "create", str(baseline), "--force"]) == OK


def test_malformed_baseline_records_are_rejected(tmp_path: Path):
    try:
        compare_baseline_data(SystemContext(tmp_path), b'{"schema_version": 2, "sockets": "invalid", "privileged_files": []}')
    except ValueError as exc:
        assert "must be arrays" in str(exc)
    else:
        raise AssertionError("malformed baseline was accepted")


def test_failed_signed_baseline_create_keeps_existing_artifacts(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    baseline = tmp_path / "host.json"
    key = tmp_path / "short.key"
    key.write_bytes(b"short")
    before = b"preserve this existing baseline"
    baseline.write_bytes(before)

    result = main(["--root", str(root), "baseline", "create", str(baseline), "--sign-key", str(key), "--force"])
    assert result == INTEGRITY_FAILED
    assert baseline.read_bytes() == before
