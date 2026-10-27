from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.context import SystemContext
from aegis.engine.runtime import RuntimeActionResult, execute_rollback_action


MANIFEST_SCHEMA = 3


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class BackupEntry:
    path: str
    existed: bool
    backup_name: str | None
    before_sha256: str | None = None
    after_sha256: str | None = None


@dataclass(slots=True)
class TransactionManifest:
    schema_version: int
    transaction_id: str
    created_at: str
    description: str
    entries: list[BackupEntry]
    runtime_actions: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class RollbackResult:
    restored: list[str]
    runtime_results: list[RuntimeActionResult] = field(default_factory=list)

    @property
    def runtime_ok(self) -> bool:
        return all(result.ok for result in self.runtime_results)


class Transaction:
    def __init__(
        self,
        ctx: SystemContext,
        state_dir: str | Path = "/var/lib/aegis",
        *,
        description: str = "Aegis configuration change",
    ) -> None:
        self.ctx = ctx
        self.state_dir = Path(state_dir) if ctx.is_real_system else ctx.path(state_dir)
        self.transaction_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        self.tx_dir = self.state_dir / "backups" / self.transaction_id
        self.entries: list[BackupEntry] = []
        self.runtime_actions: list[dict[str, Any]] = []
        self.description = description

    def backup(self, absolute_path: str) -> None:
        if any(entry.path == absolute_path for entry in self.entries):
            return
        src = self.ctx.path(absolute_path)
        self.tx_dir.mkdir(parents=True, exist_ok=True)
        if src.exists():
            if not src.is_file():
                raise ValueError(f"Transactional backup currently supports regular files only: {absolute_path}")
            backup_name = absolute_path.strip("/").replace("/", "__") or "root"
            dst = self.tx_dir / backup_name
            shutil.copy2(src, dst)
            self.entries.append(BackupEntry(absolute_path, True, backup_name, _sha256(src)))
        else:
            self.entries.append(BackupEntry(absolute_path, False, None, None))

    def add_runtime_action(self, kind: str, *, before: dict[str, str], after: dict[str, str]) -> None:
        self.runtime_actions.append({"kind": kind, "before": dict(before), "after": dict(after)})

    def commit_manifest(self) -> None:
        self.tx_dir.mkdir(parents=True, exist_ok=True)
        for entry in self.entries:
            entry.after_sha256 = _sha256(self.ctx.path(entry.path))
        manifest = TransactionManifest(
            MANIFEST_SCHEMA,
            self.transaction_id,
            datetime.now(timezone.utc).isoformat(),
            self.description,
            self.entries,
            self.runtime_actions,
        )
        payload = {
            "schema_version": manifest.schema_version,
            "transaction_id": manifest.transaction_id,
            "created_at": manifest.created_at,
            "description": manifest.description,
            "entries": [asdict(e) for e in manifest.entries],
            "runtime_actions": manifest.runtime_actions,
        }
        (self.tx_dir / "manifest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def atomic_write(self, absolute_path: str, content: str, mode: int = 0o644) -> None:
        target = self.ctx.path(absolute_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".aegis-", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_name, mode)
            os.replace(tmp_name, target)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)


def _load_manifest(ctx: SystemContext, transaction_id: str, state_dir: str | Path = "/var/lib/aegis") -> tuple[Path, dict[str, Any]]:
    base = Path(state_dir) if ctx.is_real_system else ctx.path(state_dir)
    tx_dir = base / "backups" / transaction_id
    manifest_path = tx_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Transaction {transaction_id!r} not found")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema = manifest.get("schema_version", 1)
    if not isinstance(schema, int) or schema > MANIFEST_SCHEMA:
        raise ValueError(f"Unsupported transaction manifest schema {schema!r}")
    return tx_dir, manifest


def list_transactions(ctx: SystemContext, state_dir: str | Path = "/var/lib/aegis") -> list[dict[str, str]]:
    base = Path(state_dir) if ctx.is_real_system else ctx.path(state_dir)
    backup_dir = base / "backups"
    if not backup_dir.is_dir():
        return []
    rows: list[dict[str, str]] = []
    for tx_dir in sorted(backup_dir.iterdir(), reverse=True):
        manifest_path = tx_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append({
            "transaction_id": str(manifest.get("transaction_id", tx_dir.name)),
            "created_at": str(manifest.get("created_at", "unknown")),
            "description": str(manifest.get("description", "legacy transaction")),
        })
    return rows


def rollback_transaction(
    ctx: SystemContext,
    transaction_id: str,
    state_dir: str | Path = "/var/lib/aegis",
    *,
    force: bool = False,
    restore_runtime: bool = True,
) -> RollbackResult:
    tx_dir, manifest = _load_manifest(ctx, transaction_id, state_dir)
    restored: list[str] = []

    # First pass: detect conflicts and verify backups before touching anything.
    for entry in manifest.get("entries", []):
        target = ctx.path(entry["path"])
        current_hash = _sha256(target)
        before_hash = entry.get("before_sha256")
        after_hash = entry.get("after_sha256")
        original_missing = not bool(entry.get("existed"))
        already_original = (original_missing and not target.exists()) or (before_hash is not None and current_hash == before_hash)
        expected_post_state = after_hash == current_hash

        if not force and after_hash is not None and not expected_post_state and not already_original:
            raise ValueError(
                f"Refusing rollback: {entry['path']} changed after transaction {transaction_id}. "
                "Review the file or use --force to overwrite the newer state."
            )

        if entry.get("existed"):
            src = tx_dir / entry["backup_name"]
            if not src.is_file():
                raise ValueError(f"Backup payload missing for {entry['path']}")
            if before_hash is not None and _sha256(src) != before_hash:
                raise ValueError(f"Backup integrity check failed for {entry['path']}")

    # Second pass: restore only after the entire transaction passed preflight.
    for entry in manifest.get("entries", []):
        target = ctx.path(entry["path"])
        if entry.get("existed"):
            src = tx_dir / entry["backup_name"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
        elif target.exists():
            target.unlink()
        restored.append(entry["path"])

    runtime_results: list[RuntimeActionResult] = []
    if restore_runtime:
        # Reverse order mirrors transactional unwind when multiple domains were changed.
        for action in reversed(manifest.get("runtime_actions", [])):
            runtime_results.append(execute_rollback_action(ctx, action))

    return RollbackResult(restored, runtime_results)
