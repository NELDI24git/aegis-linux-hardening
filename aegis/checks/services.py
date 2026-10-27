from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


def _systemd_active(ctx: SystemContext, units: tuple[str, ...]) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    if not ctx.is_real_system or not ctx.which("systemctl"):
        return False, evidence
    for unit in units:
        result = ctx.run(["systemctl", "is-active", unit])
        state = result.stdout.strip() or result.stderr.strip()
        evidence.append(f"{unit}: {state}")
        if result.returncode == 0 and state == "active":
            return True, evidence
    return False, evidence


class Fail2BanCheck(Check):
    check_id = "SVC-001"
    module = "services"
    title = "Fail2Ban state reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.is_real_system:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "runtime service state unavailable under fake root", "Fail2Ban active when required by exposure policy",
                "Rate-limiting repeated authentication failures can reduce brute-force noise, but Fail2Ban is not mandatory on every host.",
                "Run the check on the target host and decide based on exposed authentication services.",
                scored=False,
            )

        installed = bool(ctx.which("fail2ban-client"))
        active, evidence = _systemd_active(ctx, ("fail2ban.service", "fail2ban"))
        if active:
            status, current = Status.PASS, "installed and active"
        elif installed:
            status, current = Status.WARN, "installed but inactive"
        else:
            status, current = Status.INFO, "not installed"

        return Finding(
            self.check_id,
            self.title,
            self.module,
            status,
            Severity.LOW,
            current,
            "active when internet-exposed password authentication or other brute-forceable services require it",
            "Fail2Ban can provide useful rate-limiting defense in depth, but key-only SSH and upstream controls may make it unnecessary.",
            "Review authentication exposure first; configure jails only for services that exist on this host.",
            auto_fix=False,
            evidence=evidence,
            scored=installed,
        )


CHECKS = [Fail2BanCheck()]
