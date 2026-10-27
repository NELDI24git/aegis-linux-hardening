import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

import pytest

from aegis.integrity import generate_key, sign_file, verify_file


def test_hmac_integrity_detects_tampering(tmp_path: Path):
    target = tmp_path / "report.json"
    key = tmp_path / "integrity.key"
    target.write_text('{"ok": true}\n', encoding="utf-8")
    generate_key(key)
    sign_file(target, key)
    assert verify_file(target, key).ok
    target.write_text('{"ok": false}\n', encoding="utf-8")
    result = verify_file(target, key)
    assert not result.ok
    assert "HMAC" in result.message


def test_key_is_not_overwritten_without_force(tmp_path: Path):
    key = tmp_path / "integrity.key"
    generate_key(key)
    before = key.read_bytes()
    try:
        generate_key(key)
    except ValueError:
        pass
    else:
        raise AssertionError("expected overwrite refusal")
    assert key.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="mode-bit key permissions are a POSIX guarantee")
def test_integrity_key_rejects_broad_permissions(tmp_path: Path):
    target = tmp_path / "report"
    key = tmp_path / "key"
    target.write_text("data", encoding="utf-8")
    generate_key(key)
    key.chmod(0o644)
    try:
        sign_file(target, key)
    except ValueError as exc:
        assert "permissions" in str(exc)
    else:
        raise AssertionError("expected broad-permission key rejection")


def test_signature_is_bound_to_target_filename(tmp_path: Path):
    target = tmp_path / "report.json"
    renamed = tmp_path / "renamed.json"
    key = tmp_path / "integrity.key"
    target.write_text("{}", encoding="utf-8")
    generate_key(key)
    signature = sign_file(target, key)
    shutil.copyfile(target, renamed)
    shutil.copyfile(signature, renamed.with_name(renamed.name + ".sig"))
    result = verify_file(renamed, key)
    assert not result.ok
    assert "different target filename" in result.message


def test_signature_hmac_binds_target_name_even_if_sidecar_is_edited(tmp_path: Path):
    target = tmp_path / "report.json"
    renamed = tmp_path / "renamed.json"
    key = tmp_path / "integrity.key"
    target.write_text("{}", encoding="utf-8")
    generate_key(key)
    signature = sign_file(target, key)
    shutil.copyfile(target, renamed)
    payload = json.loads(signature.read_text(encoding="utf-8"))
    payload["target_name"] = renamed.name
    renamed.with_name(renamed.name + ".sig").write_text(json.dumps(payload), encoding="utf-8")
    result = verify_file(renamed, key)
    assert not result.ok
    assert "HMAC verification failed" in result.message


def test_legacy_signature_schema_remains_verifiable(tmp_path: Path):
    target = tmp_path / "legacy.json"
    key = tmp_path / "integrity.key"
    target.write_text("legacy", encoding="utf-8")
    generate_key(key)
    key_bytes = key.read_bytes()
    digest = hmac.new(key_bytes, target.read_bytes(), hashlib.sha256).hexdigest()
    signature = {
        "schema_version": 1,
        "algorithm": "HMAC-SHA256",
        "target_name": target.name,
        "digest": digest,
    }
    target.with_name(target.name + ".sig").write_text(json.dumps(signature), encoding="utf-8")
    assert verify_file(target, key).ok


def test_signature_rejects_boolean_schema_version(tmp_path: Path):
    target = tmp_path / "report.json"
    key = tmp_path / "integrity.key"
    target.write_text("{}", encoding="utf-8")
    generate_key(key)
    signature = sign_file(target, key)
    payload = json.loads(signature.read_text(encoding="utf-8"))
    payload["schema_version"] = True
    signature.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_file(target, key)
    assert not result.ok
    assert "unsupported signature schema" in result.message
