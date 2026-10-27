from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis import __version__
from aegis.context import SystemContext
from aegis.engine.audit import run_audit
from aegis.models import Severity, Status
from aegis.platform import detect_platform
from aegis.policy import DEFAULT_POLICY_PATH, Policy

SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_DIFF_SCHEMA_VERSION = 1
_VALID_STATUSES = {item.value for item in Status}
_VALID_SEVERITIES = {item.value for item in Severity}
_ADVERSE_STATUSES = {Status.FAIL.value, Status.ERROR.value, Status.WARN.value}
_POSITIVE_STATUSES = {Status.PASS.value, Status.INFO.value}
_STATUS_RISK = {Status.PASS.value: 0, Status.INFO.value: 0, Status.EXEMPT.value: 1, Status.WARN.value: 1, Status.FAIL.value: 2, Status.ERROR.value: 3}
_SEVERITY_RISK = {Severity.INFO.value: 0, Severity.LOW.value: 1, Severity.MEDIUM.value: 2, Severity.HIGH.value: 3, Severity.CRITICAL.value: 4}


def create_snapshot(
    ctx: SystemContext,
    *,
    module: str | None = None,
    profile: str | None = None,
    tags: set[str] | None = None,
    host_id: str | None = None,
) -> dict[str, Any]:
    if host_id is not None:
        host_id = host_id.strip()
        if not host_id or len(host_id) > 128 or any(ord(char) < 32 for char in host_id):
            raise ValueError("host ID must contain 1 to 128 printable characters")

    selected_tags = sorted({tag.strip().lower() for tag in (tags or set()) if tag.strip()})
    findings = run_audit(ctx, module, profile=profile, tags=set(selected_tags))
    platform = detect_platform(ctx)
    policy = Policy.load(ctx)
    selected_profile = profile or (policy.profile if policy.explicit and policy.valid else "general")

    policy_path = ctx.path(DEFAULT_POLICY_PATH)
    policy_sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest() if policy_path.is_file() else None
    payload: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "aegis_version": __version__,
        "platform": platform.display,
        "profile": selected_profile,
        "host_id": host_id,
        "policy_sha256": policy_sha256,
        "scope": {"module": module, "tags": selected_tags},
        "findings": [finding.to_dict() for finding in sorted(findings, key=lambda item: item.check_id)],
    }
    _validate_snapshot_payload(payload)
    return payload


def render_snapshot(payload: dict[str, Any]) -> str:
    _validate_snapshot_payload(payload)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_snapshot_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Snapshot root must be a JSON object")
    schema = payload.get("schema_version")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(f"Unsupported snapshot schema version {schema!r}")
    for field in ("snapshot_id", "created_at", "aegis_version", "platform", "profile"):
        if not _nonempty_string(payload.get(field)):
            raise ValueError(f"Snapshot {field} must be a non-empty string")
    try:
        snapshot_id = uuid.UUID(payload["snapshot_id"])
    except (ValueError, AttributeError) as exc:
        raise ValueError("Snapshot snapshot_id must be a UUID") from exc
    if str(snapshot_id) != payload["snapshot_id"]:
        raise ValueError("Snapshot snapshot_id must use canonical UUID form")
    try:
        created_at = datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Snapshot created_at must be an ISO 8601 timestamp") from exc
    if created_at.tzinfo is None:
        raise ValueError("Snapshot created_at must include a timezone")

    host_id = payload.get("host_id")
    if host_id is not None and (not _nonempty_string(host_id) or len(host_id) > 128 or any(ord(char) < 32 for char in host_id)):
        raise ValueError("Snapshot host_id must be null or a printable string up to 128 characters")
    policy_hash = payload.get("policy_sha256")
    if policy_hash is not None and (not isinstance(policy_hash, str) or re.fullmatch(r"[0-9a-f]{64}", policy_hash) is None):
        raise ValueError("Snapshot policy_sha256 must be null or a lowercase SHA-256 hex digest")

    scope = payload.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("Snapshot scope must be an object")
    module = scope.get("module")
    if module is not None and not _nonempty_string(module):
        raise ValueError("Snapshot scope.module must be null or a non-empty string")
    tags = scope.get("tags")
    if not isinstance(tags, list) or any(not _nonempty_string(tag) for tag in tags):
        raise ValueError("Snapshot scope.tags must be an array of non-empty strings")
    if len(tags) != len(set(tags)):
        raise ValueError("Snapshot scope.tags must not contain duplicates")

    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Snapshot findings must be an array")
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        prefix = f"Snapshot findings[{index}]"
        if not isinstance(finding, dict):
            raise ValueError(f"{prefix} must be an object")
        check_id = finding.get("check_id")
        if not _nonempty_string(check_id):
            raise ValueError(f"{prefix}.check_id must be a non-empty string")
        if check_id in seen:
            raise ValueError(f"{prefix}.check_id duplicates another finding")
        seen.add(check_id)
        if not _nonempty_string(finding.get("title")):
            raise ValueError(f"{prefix}.title must be a non-empty string")
        if finding.get("status") not in _VALID_STATUSES:
            raise ValueError(f"{prefix}.status is unsupported")
        if finding.get("severity") not in _VALID_SEVERITIES:
            raise ValueError(f"{prefix}.severity is unsupported")
        for field in ("current", "expected"):
            if not isinstance(finding.get(field), str):
                raise ValueError(f"{prefix}.{field} must be a string")
        evidence = finding.get("evidence")
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise ValueError(f"{prefix}.evidence must be an array of strings")
    return payload


def load_snapshot_data(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid snapshot JSON: {exc}") from exc
    return _validate_snapshot_payload(payload)


def load_snapshot(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if target.is_symlink():
        raise ValueError(f"refusing to read a symlink snapshot: {target}")
    return load_snapshot_data(target.read_bytes())


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _change(check_id: str, before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    reference = after or before or {}
    return {"check_id": check_id, "title": reference.get("title", check_id), "before": before, "after": after}


@dataclass(slots=True)
class SnapshotDiff:
    before: dict[str, Any]
    after: dict[str, Any]
    added: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    regressed: list[dict[str, Any]]
    changed: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    unchanged: int
    metadata_changes: dict[str, dict[str, object]]
    warnings: list[str]

    @property
    def has_changes(self) -> bool:
        return any((self.added, self.resolved, self.regressed, self.changed, self.removed))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SNAPSHOT_DIFF_SCHEMA_VERSION,
            "before": {key: self.before.get(key) for key in ("snapshot_id", "created_at", "host_id", "platform", "profile", "aegis_version")},
            "after": {key: self.after.get(key) for key in ("snapshot_id", "created_at", "host_id", "platform", "profile", "aegis_version")},
            "summary": {
                "added": len(self.added), "resolved": len(self.resolved), "regressed": len(self.regressed),
                "changed": len(self.changed), "removed": len(self.removed), "unchanged": self.unchanged,
                "has_changes": self.has_changes,
            },
            "metadata_changes": self.metadata_changes,
            "warnings": self.warnings,
            "changes": {
                "added": self.added, "resolved": self.resolved, "regressed": self.regressed,
                "changed": self.changed, "removed": self.removed,
            },
        }


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> SnapshotDiff:
    _validate_snapshot_payload(before)
    _validate_snapshot_payload(after)
    if _canonical(before["scope"]) != _canonical(after["scope"]):
        raise ValueError("Snapshot scopes differ; compare snapshots created with the same module and tags")
    before_host, after_host = before.get("host_id"), after.get("host_id")
    if before_host != after_host and (before_host is not None or after_host is not None):
        raise ValueError("Snapshot host IDs differ; refusing to compare different or unidentified hosts")

    old = {finding["check_id"]: finding for finding in before["findings"]}
    new = {finding["check_id"]: finding for finding in after["findings"]}
    added: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged = 0
    for check_id in sorted(old.keys() | new.keys()):
        previous, current = old.get(check_id), new.get(check_id)
        if previous is None:
            added.append(_change(check_id, None, current))
        elif current is None:
            removed.append(_change(check_id, previous, None))
        elif _canonical(previous) == _canonical(current):
            unchanged += 1
        else:
            old_status, new_status = previous["status"], current["status"]
            entry = _change(check_id, previous, current)
            severity_increased = _SEVERITY_RISK[current["severity"]] > _SEVERITY_RISK[previous["severity"]]
            status_worsened = _STATUS_RISK[new_status] > _STATUS_RISK[old_status]
            if old_status in _ADVERSE_STATUSES and new_status in _POSITIVE_STATUSES:
                resolved.append(entry)
            elif new_status in _ADVERSE_STATUSES and (status_worsened or severity_increased):
                regressed.append(entry)
            else:
                changed.append(entry)

    metadata_changes: dict[str, dict[str, object]] = {}
    for field in ("aegis_version", "platform", "profile", "policy_sha256"):
        if before.get(field) != after.get(field):
            metadata_changes[field] = {"before": before.get(field), "after": after.get(field)}
    warnings = []
    if before_host is None:
        warnings.append("Host identity was not supplied; confirm both snapshots belong to the same host.")
    return SnapshotDiff(before, after, added, resolved, regressed, changed, removed, unchanged, metadata_changes, warnings)


def render_snapshot_diff(diff: SnapshotDiff) -> str:
    data = diff.to_dict()
    summary = data["summary"]
    lines = [
        "AEGIS SNAPSHOT DIFF",
        "=" * 78,
        f"Before: {diff.before['created_at']} ({diff.before['snapshot_id']})",
        f"After:  {diff.after['created_at']} ({diff.after['snapshot_id']})",
        f"Host:   {diff.before.get('host_id') or 'unspecified'}",
        "",
        "Findings: " + ", ".join(
            f"{label} {summary[key]}" for key, label in (
                ("added", "added"), ("resolved", "resolved"), ("regressed", "regressed"),
                ("changed", "changed"), ("removed", "removed"), ("unchanged", "unchanged"),
            )
        ),
    ]
    for field, values in diff.metadata_changes.items():
        lines.append(f"Metadata {field}: {values['before']!r} -> {values['after']!r}")
    for warning in diff.warnings:
        lines.append(f"WARN: {warning}")
    groups = (
        ("Added checks", diff.added, "+"), ("Resolved findings", diff.resolved, "RESOLVED"),
        ("Regressed findings", diff.regressed, "REGRESSION"), ("Other changes", diff.changed, "CHANGED"),
        ("Removed checks", diff.removed, "REMOVED"),
    )
    for title, items, marker in groups:
        if not items:
            continue
        lines.extend(["", title])
        for item in items:
            before_item, after_item = item["before"], item["after"]
            status = ""
            if before_item and after_item:
                status = f" {before_item['status']} -> {after_item['status']}"
            elif after_item:
                status = f" {after_item['status']}"
            elif before_item:
                status = f" {before_item['status']}"
            lines.append(f"  [{marker}] {item['check_id']}{status} {item['title']}")
            if before_item and after_item:
                for field in ("severity", "current", "expected", "exception_reason", "exception_expires_at", "exception_ticket", "evidence"):
                    if before_item.get(field) != after_item.get(field):
                        lines.append(f"      {field}: {before_item.get(field)!r} -> {after_item.get(field)!r}")
    lines.extend(["", "CHANGES DETECTED" if diff.has_changes else "NO FINDING CHANGES"])
    return "\n".join(lines)
