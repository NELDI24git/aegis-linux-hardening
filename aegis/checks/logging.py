from __future__ import annotations

import re

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


def _journald_storage(ctx: SystemContext) -> str | None:
    paths = ["/etc/systemd/journald.conf"]
    dropin_dir = ctx.path("/etc/systemd/journald.conf.d")
    if dropin_dir.is_dir():
        paths.extend("/etc/systemd/journald.conf.d/" + p.name for p in sorted(dropin_dir.glob("*.conf")))
    value = None
    for path in paths:
        if not ctx.exists(path):
            continue
        for raw in ctx.read_text(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"(?i)^Storage\s*=\s*(\S+)", line)
            if match:
                value = match.group(1).lower()
    return value


class PersistentJournalCheck(Check):
    check_id = "LOG-001"
    module = "logging"
    title = "System logs survive reboot"

    def run(self, ctx: SystemContext) -> Finding:
        storage = _journald_storage(ctx)
        persistent_dir = ctx.path("/var/log/journal").is_dir()
        persistent = storage == "persistent" or (storage in {None, "auto"} and persistent_dir)
        return Finding(
            self.check_id, self.title, self.module,
            Status.PASS if persistent else Status.WARN,
            Severity.MEDIUM,
            f"journald Storage={storage or 'default/auto'}, /var/log/journal={'present' if persistent_dir else 'absent'}",
            "persistent logs or an equivalent remote logging pipeline",
            "Volatile-only logs can erase useful incident evidence at reboot.",
            "Enable persistent journald storage or document an equivalent reliable remote logging design.",
            auto_fix=False,
            scored=False,
        )


class AuditdCheck(Check):
    check_id = "LOG-002"
    module = "logging"
    title = "Linux audit service state reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.is_real_system:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "runtime service state unavailable under fake root", "audit service active when required",
                "Linux Audit can provide security-relevant event trails for high-assurance or compliance-sensitive hosts.",
                "Run on the target host.", scored=False,
            )
        installed = bool(ctx.which("auditctl"))
        if not installed:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "auditd not installed", "auditd or equivalent telemetry when required by policy",
                "Not every minimal host requires auditd, but systems with stronger forensic/compliance requirements often do.",
                "Decide based on host threat model and telemetry requirements.", scored=False,
            )
        if not ctx.which("systemctl"):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "systemctl unavailable", "auditd active", "Audit telemetry should be reliably collected.",
                "Verify auditd using the platform service manager.", scored=False,
            )
        result = ctx.run(["systemctl", "is-active", "auditd.service"])
        active = result.returncode == 0 and result.stdout.strip() == "active"
        return Finding(
            self.check_id, self.title, self.module,
            Status.PASS if active else Status.WARN,
            Severity.MEDIUM,
            f"auditd={result.stdout.strip() or result.stderr.strip()}",
            "active when installed/required",
            "An installed but inactive audit service can create a false sense of telemetry coverage.",
            "Start/enable auditd after validating rules and storage capacity.", auto_fix=False,
            scored=installed,
        )


CHECKS = [PersistentJournalCheck(), AuditdCheck()]
