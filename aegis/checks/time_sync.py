from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


class TimeSynchronizationCheck(Check):
    check_id = "TIME-001"
    module = "time"
    title = "System clock synchronization is active"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.is_real_system or not ctx.which("timedatectl"):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "timedatectl state unavailable", "synchronized system clock",
                "Reliable timestamps are important for authentication protocols, logs, and incident correlation.",
                "Verify NTP/chrony/systemd-timesyncd on the target host.", scored=False,
            )
        result = ctx.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        value = result.stdout.strip().lower()
        if result.returncode != 0:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                result.stderr.strip() or "unable to query synchronization", "synchronized system clock",
                "Reliable timestamps are important for security telemetry and protocols.",
                "Verify the active time synchronization service.", scored=False,
            )
        synced = value == "yes"
        return Finding(
            self.check_id, self.title, self.module,
            Status.PASS if synced else Status.WARN,
            Severity.LOW,
            f"NTPSynchronized={value}", "yes",
            "Clock drift can break time-sensitive authentication and make forensic timelines unreliable.",
            "Enable and troubleshoot the host's approved NTP implementation.", auto_fix=False,
            scored=False,
        )


CHECKS = [TimeSynchronizationCheck()]
