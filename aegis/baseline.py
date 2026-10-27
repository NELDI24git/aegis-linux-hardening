from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis import __version__
from aegis.context import SystemContext
from aegis.fileio import atomic_write_text
from aegis.inventory.privileged import PrivilegedFile, collect_privileged_files
from aegis.inventory.sockets import ListeningSocket, collect_listening_sockets
from aegis.platform import detect_platform
from aegis.policy import Policy

BASELINE_SCHEMA_VERSION = 2


@dataclass(slots=True)
class BaselineDrift:
    added_sockets: list[str]
    removed_sockets: list[str]
    added_privileged_files: list[str]
    removed_privileged_files: list[str]
    changed_privileged_files: list[str]

    @property
    def has_drift(self) -> bool:
        return any((self.added_sockets, self.removed_sockets, self.added_privileged_files, self.removed_privileged_files, self.changed_privileged_files))


def _socket_record(item: ListeningSocket) -> dict[str, object]:
    return {"protocol": item.protocol, "address": item.address, "port": item.port, "process": item.process}


def _privileged_record(item: PrivilegedFile) -> dict[str, object]:
    return {"path": item.path, "mode": item.mode, "uid": item.uid, "gid": item.gid, "package": item.package}


def create_baseline(ctx: SystemContext, output: str | Path) -> None:
    sockets, socket_source = collect_listening_sockets(ctx)
    privileged, privileged_source = collect_privileged_files(ctx)
    platform = detect_platform(ctx)
    policy = Policy.load(ctx)
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "aegis_version": __version__,
        "platform": platform.display,
        "profile": policy.profile if policy.valid else "unknown",
        "sources": {"sockets": socket_source, "privileged_files": privileged_source},
        "sockets": [_socket_record(x) for x in sockets],
        "privileged_files": [_privileged_record(x) for x in privileged],
    }
    atomic_write_text(output, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _socket_key(record: dict[str, object]) -> tuple[object, ...]:
    return (record.get("protocol"), record.get("address"), record.get("port"), record.get("process"))


def _socket_display(record: dict[str, object]) -> str:
    return f"{record.get('protocol')} {record.get('address')}:{record.get('port')} process={record.get('process') or 'unknown'}"


def _privileged_display(record: dict[str, object]) -> str:
    mode = record.get("mode")
    mode_text = oct(mode) if isinstance(mode, int) and not isinstance(mode, bool) else str(mode)
    return f"{record.get('path')} mode={mode_text} uid={record.get('uid')} gid={record.get('gid')} package={record.get('package') or 'unowned/unknown'}"


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_baseline_record(payload: dict[str, Any]) -> None:
    sockets = payload.get("sockets")
    privileged = payload.get("privileged_files")
    if not isinstance(sockets, list) or not isinstance(privileged, list):
        raise ValueError("Baseline sockets and privileged_files must be arrays")

    seen_socket_keys: set[tuple[object, ...]] = set()
    for index, record in enumerate(sockets):
        prefix = f"Baseline sockets[{index}]"
        if not isinstance(record, dict):
            raise ValueError(f"{prefix} must be an object")
        if not _is_nonempty_string(record.get("protocol")) or not _is_nonempty_string(record.get("address")):
            raise ValueError(f"{prefix} requires non-empty protocol and address strings")
        port = record.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"{prefix}.port must be an integer from 1 to 65535")
        process = record.get("process")
        if process is not None and not isinstance(process, str):
            raise ValueError(f"{prefix}.process must be a string or null")
        key = (record["protocol"], record["address"], port, process)
        if key in seen_socket_keys:
            raise ValueError(f"{prefix} duplicates another socket record")
        seen_socket_keys.add(key)

    seen_privileged_paths: set[str] = set()
    for index, record in enumerate(privileged):
        prefix = f"Baseline privileged_files[{index}]"
        if not isinstance(record, dict) or not _is_nonempty_string(record.get("path")):
            raise ValueError(f"{prefix} requires a non-empty path string")
        record_path = record["path"]
        if not record_path.startswith("/") or ".." in Path(record_path).parts:
            raise ValueError(f"{prefix}.path must be an absolute host path")
        if record_path in seen_privileged_paths:
            raise ValueError(f"{prefix}.path duplicates another privileged-file record")
        seen_privileged_paths.add(record_path)
        mode = record.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
            raise ValueError(f"{prefix}.mode must be an integer from 0 to 0o7777")
        for field in ("uid", "gid"):
            value = record.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{prefix}.{field} must be a non-negative integer")
        package = record.get("package")
        if package is not None and not isinstance(package, str):
            raise ValueError(f"{prefix}.package must be a string or null")


def _load_baseline_data(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid baseline JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Baseline root must be a JSON object")
    schema = payload.get("schema_version")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema not in {1, BASELINE_SCHEMA_VERSION}:
        raise ValueError(f"Unsupported baseline schema version {schema!r}")
    _validate_baseline_record(payload)
    return payload


def _load_baseline(path: str | Path) -> dict[str, Any]:
    return _load_baseline_data(Path(path).read_bytes())


def compare_baseline_data(ctx: SystemContext, data: bytes) -> BaselineDrift:
    payload = _load_baseline_data(data)
    current_sockets, _ = collect_listening_sockets(ctx)
    current_privileged, _ = collect_privileged_files(ctx)
    old_sockets = {_socket_key(x): x for x in payload["sockets"]}
    new_records = [_socket_record(x) for x in current_sockets]
    new_sockets = {_socket_key(x): x for x in new_records}
    added_sockets = [_socket_display(new_sockets[k]) for k in sorted(new_sockets.keys() - old_sockets.keys(), key=str)]
    removed_sockets = [_socket_display(old_sockets[k]) for k in sorted(old_sockets.keys() - new_sockets.keys(), key=str)]
    old_priv = {str(x["path"]): x for x in payload["privileged_files"]}
    new_priv_records = [_privileged_record(x) for x in current_privileged]
    new_priv = {str(x["path"]): x for x in new_priv_records}
    added_priv = [_privileged_display(new_priv[k]) for k in sorted(new_priv.keys() - old_priv.keys())]
    removed_priv = [_privileged_display(old_priv[k]) for k in sorted(old_priv.keys() - new_priv.keys())]
    changed_priv: list[str] = []
    for path in sorted(old_priv.keys() & new_priv.keys()):
        before, after = old_priv[path], new_priv[path]
        if (before.get("mode"), before.get("uid"), before.get("gid"), before.get("package")) != (after.get("mode"), after.get("uid"), after.get("gid"), after.get("package")):
            changed_priv.append(f"{path}: {_privileged_display(before)} -> {_privileged_display(after)}")
    return BaselineDrift(added_sockets, removed_sockets, added_priv, removed_priv, changed_priv)


def compare_baseline(ctx: SystemContext, baseline_path: str | Path) -> BaselineDrift:
    return compare_baseline_data(ctx, Path(baseline_path).read_bytes())


def render_drift(drift: BaselineDrift) -> str:
    sections = [
        ("Added listening sockets", drift.added_sockets), ("Removed listening sockets", drift.removed_sockets),
        ("Added SUID/SGID files", drift.added_privileged_files), ("Removed SUID/SGID files", drift.removed_privileged_files),
        ("Changed SUID/SGID metadata", drift.changed_privileged_files),
    ]
    lines = ["AEGIS BASELINE DRIFT", "=" * 78]
    for title, values in sections:
        lines.extend(["", title])
        lines.extend((f"  + {v}" for v in values) if values else ["  none"])
    lines.extend(["", "DRIFT DETECTED" if drift.has_drift else "NO DRIFT DETECTED"])
    return "\n".join(lines)