from __future__ import annotations

from dataclasses import dataclass

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


@dataclass(slots=True)
class Mount:
    source: str
    target: str
    fstype: str
    options: set[str]


def _decode_mount_field(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")


def read_mounts(ctx: SystemContext) -> list[Mount]:
    path = "/proc/self/mounts"
    if not ctx.exists(path):
        path = "/proc/mounts"
    if not ctx.exists(path):
        return []
    mounts: list[Mount] = []
    for line in ctx.read_text(path).splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mounts.append(Mount(_decode_mount_field(parts[0]), _decode_mount_field(parts[1]), parts[2], set(parts[3].split(","))))
    return mounts


def _mount_for(mounts: list[Mount], target: str) -> Mount | None:
    matches = [m for m in mounts if target == m.target or target.startswith(m.target.rstrip("/") + "/")]
    return max(matches, key=lambda m: len(m.target), default=None)


class DevShmOptionsCheck(Check):
    check_id = "MNT-001"
    module = "mounts"
    title = "/dev/shm restricts device, privilege, and executable semantics"

    def run(self, ctx: SystemContext) -> Finding:
        mount = _mount_for(read_mounts(ctx), "/dev/shm")
        if mount is None:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.MEDIUM,
                "/dev/shm mount not found", "nodev,nosuid,noexec where compatible",
                "Shared memory is commonly writable by many users and benefits from restrictive mount semantics.",
                "Review the target host mount table.", scored=False,
            )
        required = {"nodev", "nosuid", "noexec"}
        missing = sorted(required - mount.options)
        return Finding(
            self.check_id, self.title, self.module,
            Status.FAIL if missing else Status.PASS,
            Severity.MEDIUM,
            f"{mount.target} options={','.join(sorted(mount.options))}",
            "nodev,nosuid,noexec",
            "Restrictive shared-memory mount options reduce abuse of a globally writable execution/storage area.",
            "Add missing options after checking application compatibility.",
            auto_fix=False,
            evidence=[f"missing={','.join(missing)}"] if missing else [],
        )


class TmpOptionsCheck(Check):
    check_id = "MNT-002"
    module = "mounts"
    title = "/tmp mount hardening reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        mounts = read_mounts(ctx)
        mount = _mount_for(mounts, "/tmp")
        if mount is None:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "/tmp mount not found", "temporary storage strategy reviewed",
                "World-writable temporary storage is a common boundary for local attacks.",
                "Review the target host mount strategy.", scored=False,
            )
        if mount.target != "/tmp":
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                f"/tmp resides on {mount.target} ({mount.fstype})", "separate/restricted /tmp where justified by threat model",
                "Mount flags on a shared root filesystem cannot be tightened for /tmp without a separate mount.",
                "Treat this as architecture guidance rather than an automatic failure.", scored=False,
            )
        required = {"nodev", "nosuid"}
        missing = sorted(required - mount.options)
        return Finding(
            self.check_id, self.title, self.module,
            Status.WARN if missing else Status.PASS,
            Severity.LOW,
            f"/tmp options={','.join(sorted(mount.options))}",
            "nodev,nosuid on a separate /tmp mount where compatible",
            "Restrictive temporary-storage semantics can reduce several local abuse paths.",
            "Add missing options only after compatibility review; noexec is intentionally not required by this generic rule.",
            auto_fix=False,
            evidence=[f"missing={','.join(missing)}"] if missing else [],
            scored=False,
        )


CHECKS = [DevShmOptionsCheck(), TmpOptionsCheck()]
