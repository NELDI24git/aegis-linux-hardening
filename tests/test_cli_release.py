import json
from pathlib import Path

from aegis.cli import main
from aegis.exitcodes import AUDIT_THRESHOLD, INTEGRITY_FAILED, OK, USAGE_OR_INPUT


def _write(root: Path, path: str, text: str):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_cli_integrity_round_trip(tmp_path: Path):
    key = tmp_path / "key"
    target = tmp_path / "artifact"
    target.write_text("hello", encoding="utf-8")
    assert main(["integrity", "keygen", str(key)]) == OK
    assert main(["integrity", "sign", str(target), "--key", str(key)]) == OK
    assert main(["integrity", "verify", str(target), "--key", str(key)]) == OK
    target.write_text("tampered", encoding="utf-8")
    assert main(["integrity", "verify", str(target), "--key", str(key)]) == INTEGRITY_FAILED


def test_cli_fail_on_uses_stable_exit_code(tmp_path: Path):
    _write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
    assert main(["--root", str(tmp_path), "audit", "--module", "ssh", "--fail-on", "high"]) == AUDIT_THRESHOLD


def test_cli_writes_sarif_with_explicit_github_locations(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 6\n")
    sarif = tmp_path / "audit.sarif"
    locations = tmp_path / "sarif-locations.json"
    locations.write_text(json.dumps({
        f"SSH-{number:03d}": {"uri": "infra/sshd_config", "line": number}
        for number in range(1, 7)
    }), encoding="utf-8")

    result = main([
        "--root", str(root), "audit", "--module", "ssh", "--sarif", str(sarif),
        "--sarif-location-map", str(locations),
    ])
    assert result == OK
    payload = json.loads(sarif.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
    assert all(item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "infra/sshd_config"
               for item in payload["runs"][0]["results"])


def test_cli_rejects_colliding_report_paths(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    output = tmp_path / "same.json"
    assert main(["--root", str(root), "audit", "--json", str(output), "--sarif", str(output)]) == USAGE_OR_INPUT
