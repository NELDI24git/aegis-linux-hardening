from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aegis.fileio import atomic_write_bytes, atomic_write_text

SIGNATURE_SCHEMA_VERSION = 2


class IntegrityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    message: str


def generate_key(path: str | Path, *, force: bool = False) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    if force:
        atomic_write_bytes(target, key, mode=0o600)
        return target
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise IntegrityError(f"refusing to overwrite existing integrity key: {target}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(target, 0o600)
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return target


def _read_key(path: str | Path) -> bytes:
    target = Path(path)
    if target.is_symlink():
        raise IntegrityError("refusing to use a symlink as an integrity key")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise IntegrityError(f"cannot safely open integrity key: {exc}") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise IntegrityError("integrity key must be a regular file")
        if os.name == "posix" and info.st_mode & 0o077:
            raise IntegrityError("integrity key permissions are too broad; require mode 0600 or stricter")
        key = stream.read()
    if len(key) < 32:
        raise IntegrityError("integrity key must contain at least 32 bytes")
    return key


def _hmac_file(path: Path, key: bytes, target_name: str) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(b"AEGIS-SIGNATURE-v2\x00")
    digest.update(target_name.encode("utf-8"))
    digest.update(b"\x00")
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hmac_bytes(data: bytes, key: bytes, target_name: str) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(b"AEGIS-SIGNATURE-v2\x00")
    digest.update(target_name.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(data)
    return digest.hexdigest()


def signature_path(path: str | Path) -> Path:
    target = Path(path)
    return target.with_name(target.name + ".sig")


def sign_file(
    path: str | Path,
    key_path: str | Path,
    *,
    signature: str | Path | None = None,
    target_name: str | None = None,
) -> Path:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise IntegrityError(f"cannot sign missing, non-regular, or symlink file: {target}")
    key = _read_key(key_path)
    signed_name = target_name or target.name
    if not signed_name or signed_name in {".", ".."} or "/" in signed_name or "\\" in signed_name:
        raise IntegrityError("signature target name must be a plain filename")
    sig_path = Path(signature) if signature else signature_path(target)
    payload = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "algorithm": "HMAC-SHA256",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_name": signed_name,
        "digest": _hmac_file(target, key, signed_name),
    }
    atomic_write_text(sig_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return sig_path


def verify_bytes(
    data: bytes,
    target_name: str,
    key_path: str | Path,
    *,
    signature: str | Path,
) -> VerificationResult:
    sig_path = Path(signature)
    if sig_path.is_symlink():
        return VerificationResult(False, "refusing to use a symlink as a signature file")
    if not sig_path.is_file():
        return VerificationResult(False, f"signature file missing: {sig_path}")
    try:
        payload = json.loads(sig_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return VerificationResult(False, "signature root must be a JSON object")
        schema = payload.get("schema_version")
        if not isinstance(schema, int) or isinstance(schema, bool) or schema not in {1, SIGNATURE_SCHEMA_VERSION} or payload.get("algorithm") != "HMAC-SHA256":
            return VerificationResult(False, "unsupported signature schema or algorithm")
        if payload.get("target_name") != target_name:
            return VerificationResult(False, "signature is bound to a different target filename")
        expected = payload.get("digest")
        if not isinstance(expected, str) or len(expected) != 64:
            return VerificationResult(False, "signature digest is malformed")
        key = _read_key(key_path)
        if schema == 1:
            actual = hmac.new(key, data, hashlib.sha256).hexdigest()
        else:
            actual = _hmac_bytes(data, key, target_name)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IntegrityError) as exc:
        return VerificationResult(False, str(exc))
    if not hmac.compare_digest(expected, actual):
        return VerificationResult(False, "HMAC verification failed; file or signature/key does not match")
    return VerificationResult(True, f"HMAC-SHA256 verified for {target_name}")


def verify_file(
    path: str | Path,
    key_path: str | Path,
    *,
    signature: str | Path | None = None,
) -> VerificationResult:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        return VerificationResult(False, f"target file missing, non-regular, or symlink: {target}")
    try:
        data = target.read_bytes()
    except OSError as exc:
        return VerificationResult(False, str(exc))
    return verify_bytes(data, target.name, key_path, signature=signature or signature_path(target))