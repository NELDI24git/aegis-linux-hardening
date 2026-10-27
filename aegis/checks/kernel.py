from __future__ import annotations

from dataclasses import dataclass

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


def _proc_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def _read_int(ctx: SystemContext, key: str) -> int | None:
    path = _proc_path(key)
    if not ctx.exists(path):
        return None
    try:
        return int(ctx.read_text(path).strip())
    except (OSError, ValueError):
        return None


@dataclass(slots=True)
class IntegerSysctlCheck(Check):
    check_id: str
    title: str
    key: str
    expected_text: str
    severity: Severity
    minimum: int | None = None
    exact: int | None = None
    why_text: str = ""
    remediation_text: str = ""
    module: str = "kernel"

    def run(self, ctx: SystemContext) -> Finding:
        value = _read_int(ctx, self.key)
        if value is None:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, self.severity,
                f"{self.key}=unavailable", self.expected_text,
                self.why_text, "Review on a standard Linux host.", scored=False,
            )
        passed = (value == self.exact) if self.exact is not None else (self.minimum is not None and value >= self.minimum)
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.PASS if passed else Status.FAIL,
            self.severity,
            f"{self.key}={value}",
            self.expected_text,
            self.why_text,
            self.remediation_text,
            auto_fix=True,
            references=["Linux kernel sysctl documentation"],
        )


CHECKS = [
    IntegerSysctlCheck(
        "KERN-001", "Full address-space randomization enabled", "kernel.randomize_va_space", "kernel.randomize_va_space=2",
        Severity.HIGH, exact=2,
        why_text="Full ASLR increases uncertainty for many memory-corruption exploitation techniques.",
        remediation_text="Set kernel.randomize_va_space=2 through a managed sysctl configuration after compatibility review.",
    ),
    IntegerSysctlCheck(
        "KERN-002", "Kernel pointer exposure restricted", "kernel.kptr_restrict", "kernel.kptr_restrict>=1",
        Severity.MEDIUM, minimum=1,
        why_text="Restricting kernel pointer visibility reduces information useful for kernel exploitation.",
        remediation_text="Set kernel.kptr_restrict to at least 1 unless debugging requirements justify otherwise.",
    ),
    IntegerSysctlCheck(
        "KERN-003", "Unprivileged kernel log access restricted", "kernel.dmesg_restrict", "kernel.dmesg_restrict=1",
        Severity.MEDIUM, exact=1,
        why_text="Kernel logs can expose addresses, device state, and other information useful to local attackers.",
        remediation_text="Set kernel.dmesg_restrict=1 unless unprivileged dmesg access is an explicit operational requirement.",
    ),
    IntegerSysctlCheck(
        "KERN-004", "Protected hardlinks enabled", "fs.protected_hardlinks", "fs.protected_hardlinks=1",
        Severity.MEDIUM, exact=1,
        why_text="Protected hardlinks reduce classes of link-based privilege escalation in shared writable directories.",
        remediation_text="Set fs.protected_hardlinks=1.",
    ),
    IntegerSysctlCheck(
        "KERN-005", "Protected symlinks enabled", "fs.protected_symlinks", "fs.protected_symlinks=1",
        Severity.MEDIUM, exact=1,
        why_text="Protected symlinks reduce link-following attacks in sticky world-writable directories.",
        remediation_text="Set fs.protected_symlinks=1.",
    ),
]
