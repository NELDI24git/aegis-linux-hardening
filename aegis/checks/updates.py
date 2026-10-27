from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status
from aegis.platforms import get_platform_adapter


class AutomaticSecurityUpdatesCheck(Check):
    check_id = "UPD-001"
    module = "updates"
    title = "Automatic security updates are configured"

    def run(self, ctx: SystemContext) -> Finding:
        adapter = get_platform_adapter(ctx)
        state = adapter.automatic_updates_state(ctx)
        if not state.authoritative or state.enabled is None:
            return Finding(
                self.check_id,
                self.title,
                self.module,
                Status.INFO,
                Severity.MEDIUM,
                state.current,
                state.expected,
                "Timely security updates reduce exposure to publicly known vulnerabilities.",
                "Configure the distribution's supported automatic-update mechanism after defining maintenance windows, reboot behavior, and recovery expectations.",
                auto_fix=False,
                evidence=state.evidence,
                scored=False,
            )
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.PASS if state.enabled else Status.FAIL,
            Severity.MEDIUM,
            state.current,
            state.expected,
            "Automatic security updates reduce patch latency on systems that may otherwise be maintained inconsistently.",
            "Enable the platform's automatic update mechanism only after defining maintenance windows, reboot behavior, and rollback/recovery expectations.",
            auto_fix=False,
            evidence=state.evidence,
        )


class RebootRequiredCheck(Check):
    check_id = "UPD-002"
    module = "updates"
    title = "No pending security-maintenance reboot"

    def run(self, ctx: SystemContext) -> Finding:
        required = ctx.exists("/var/run/reboot-required")
        packages: list[str] = []
        if ctx.exists("/var/run/reboot-required.pkgs"):
            packages = [line.strip() for line in ctx.read_text("/var/run/reboot-required.pkgs").splitlines() if line.strip()]

        # /var/run/reboot-required is Debian-family convention. Other platforms
        # are left advisory until their reboot-needed adapter is implemented.
        adapter = get_platform_adapter(ctx)
        if adapter.family != "debian":
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.MEDIUM,
                f"reboot marker adapter not implemented for {adapter.family}",
                "no pending reboot required to finish maintenance",
                "Some security fixes do not become fully effective until affected kernels or long-running services are restarted.",
                "Review platform-specific reboot requirements after updates.",
                auto_fix=False, scored=False,
            )

        return Finding(
            self.check_id, self.title, self.module,
            Status.WARN if required else Status.PASS,
            Severity.MEDIUM,
            "reboot required" if required else "no reboot marker",
            "no pending reboot required to finish maintenance",
            "Some security fixes do not become fully effective until affected kernels or long-running services are restarted.",
            "Schedule a controlled reboot if required, considering availability and rollback procedures.",
            auto_fix=False,
            evidence=packages[:50],
            scored=False,
        )


CHECKS = [AutomaticSecurityUpdatesCheck(), RebootRequiredCheck()]
