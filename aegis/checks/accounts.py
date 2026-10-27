from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


class ExtraUIDZeroCheck(Check):
    check_id = "ACC-001"
    module = "accounts"
    title = "No additional UID 0 accounts"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.exists("/etc/passwd"):
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.HIGH,
                "/etc/passwd not found", "Only root has UID 0",
                "UID 0 grants superuser privileges.",
                "Investigate why /etc/passwd is unavailable.", False,
            )
        uid0: list[str] = []
        for line in ctx.read_text("/etc/passwd").splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid0.append(parts[0])
        extras = [u for u in uid0 if u != "root"]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.FAIL if extras else Status.PASS,
            Severity.CRITICAL if extras else Severity.HIGH,
            f"UID 0 accounts: {', '.join(uid0) if uid0 else 'none'}",
            "Only root has UID 0",
            "Any account with UID 0 has full superuser privileges regardless of its username.",
            "Review unexpected UID 0 accounts and assign appropriate non-zero UIDs.",
            auto_fix=False,
        )


CHECKS = [ExtraUIDZeroCheck()]


class EmptyPasswordHashCheck(Check):
    check_id = "ACC-002"
    module = "accounts"
    title = "No local account has an empty password hash"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.exists("/etc/shadow"):
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.CRITICAL,
                "/etc/shadow not found", "no empty password fields",
                "An empty password field can permit passwordless local authentication depending on PAM configuration.",
                "Investigate the account database.", auto_fix=False, scored=False,
            )
        if ctx.is_real_system and not ctx.is_root:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.CRITICAL,
                "root privileges required to inspect /etc/shadow", "no empty password fields",
                "The shadow database must be read to establish whether empty password hashes exist.",
                "Re-run the accounts audit with sudo.", scored=False,
            )
        empty: list[str] = []
        for line in ctx.read_text("/etc/shadow").splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty.append(parts[0])
        return Finding(
            self.check_id, self.title, self.module,
            Status.FAIL if empty else Status.PASS,
            Severity.CRITICAL,
            "accounts with empty password field: " + (", ".join(empty) if empty else "none"),
            "none",
            "Empty password fields can create a direct authentication weakness on systems that permit null passwords.",
            "Lock the affected account or set a strong authentication method, then review PAM null-password behavior.",
            auto_fix=False,
            evidence=empty,
        )


CHECKS.append(EmptyPasswordHashCheck())
