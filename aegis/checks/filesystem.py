from __future__ import annotations

import stat

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


def _group_name(ctx: SystemContext, gid: int) -> str | None:
    if not ctx.exists("/etc/group"):
        return None
    for line in ctx.read_text("/etc/group").splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            try:
                candidate = int(parts[2])
            except ValueError:
                continue
            if candidate == gid:
                return parts[0]
    return None


class ShadowPermissionsCheck(Check):
    check_id = "FS-001"
    module = "filesystem"
    title = "/etc/shadow permissions restrict unauthorized access"

    def run(self, ctx: SystemContext) -> Finding:
        p = ctx.path("/etc/shadow")
        if not p.exists():
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.HIGH,
                "/etc/shadow not found", "root-owned; no world access; no unauthorized group write/execute",
                "The shadow file contains password hashes and other sensitive account data.",
                "Investigate the missing shadow file.", False, scored=False,
            )
        st = p.stat()
        mode = stat.S_IMODE(st.st_mode)
        group = _group_name(ctx, st.st_gid)
        world_bits = mode & 0o007
        dangerous_group_bits = mode & 0o030  # group write or execute
        group_read = bool(mode & 0o040)
        group_read_authorized = (not group_read) or group == "shadow"
        owner_ok = st.st_uid == 0
        risky = bool(world_bits or dangerous_group_bits or not group_read_authorized or not owner_ok)
        evidence = [f"uid={st.st_uid}", f"gid={st.st_gid} ({group or 'unknown'})", f"mode={oct(mode)}"]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.FAIL if risky else Status.PASS,
            Severity.HIGH,
            ", ".join(evidence),
            "owner root; no world access; optional group-read only for the shadow group",
            "Excessive permissions can expose password hashes or allow unauthorized modification.",
            "Restore ownership and permissions according to the distribution's shadow-file policy; Debian-family systems commonly use root:shadow with 0640 or stricter.",
            auto_fix=False,
            evidence=evidence,
        )


class PasswdWritableCheck(Check):
    check_id = "FS-002"
    module = "filesystem"
    title = "/etc/passwd is root-owned and not group/world writable"

    def run(self, ctx: SystemContext) -> Finding:
        p = ctx.path("/etc/passwd")
        if not p.exists():
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.CRITICAL,
                "/etc/passwd not found", "root-owned and not group/world writable",
                "The passwd database is fundamental to local account identity.",
                "Investigate the missing passwd file.", False, scored=False,
            )
        st = p.stat()
        mode = stat.S_IMODE(st.st_mode)
        risky = bool(mode & 0o022) or st.st_uid != 0
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.FAIL if risky else Status.PASS,
            Severity.CRITICAL,
            f"mode={oct(mode)} uid={st.st_uid} gid={st.st_gid}",
            "owner UID 0; no group/world write bits",
            "Unauthorized writes to /etc/passwd can enable account tampering or privilege escalation.",
            "Restore root ownership and remove group/world write permissions, then investigate how the state was introduced.",
            auto_fix=False,
        )


CHECKS = [ShadowPermissionsCheck(), PasswdWritableCheck()]
