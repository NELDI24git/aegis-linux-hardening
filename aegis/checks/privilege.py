from __future__ import annotations

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.inventory.privileged import collect_privileged_files
from aegis.models import Finding, Severity, Status
from aegis.policy import Policy
from aegis.platforms import get_platform_adapter


class WritablePrivilegedBinaryCheck(Check):
    check_id = "PRIV-001"
    module = "privilege"
    title = "SUID/SGID executables are not group/world writable"

    def run(self, ctx: SystemContext) -> Finding:
        files, source = collect_privileged_files(ctx)
        risky = [f for f in files if f.group_or_world_writable]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.FAIL if risky else Status.PASS,
            Severity.CRITICAL,
            f"{len(risky)} writable privileged executable(s) ({source})",
            "0 writable SUID/SGID executables",
            "A writable SUID/SGID executable can allow an unprivileged user to replace or modify code that later executes with elevated effective credentials.",
            "Immediately review ownership and permissions, restore the file from a trusted package/source, and investigate how it became writable.",
            auto_fix=False,
            evidence=[f.display() for f in risky[:50]],
        )


class UnownedPrivilegedBinaryCheck(Check):
    check_id = "PRIV-002"
    module = "privilege"
    title = "Unexpected privileged executables are reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        files, source = collect_privileged_files(ctx)
        if not files:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                f"no inventory available or no privileged files ({source})", "privileged files attributable to trusted packages or explicit policy",
                "Custom or unexplained privileged executables deserve manual review because they expand local privilege-escalation attack surface.",
                "Review on the target host.", scored=False,
            )
        policy = Policy.load(ctx)
        if policy.explicit and not policy.valid:
            return Finding(
                self.check_id, self.title, self.module, Status.ERROR, Severity.MEDIUM,
                "invalid /etc/aegis/policy.json", "valid privilege allowlist policy",
                "A malformed allowlist makes provenance classification unreliable.",
                "Run `aegis policy validate /etc/aegis/policy.json` and fix the reported schema errors.",
                auto_fix=False, evidence=policy.validation_errors, scored=False,
            )
        adapter = get_platform_adapter(ctx)
        if ctx.is_real_system and not adapter.package_provenance_available(ctx):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                f"package ownership unavailable for adapter={adapter.family}",
                "privileged files attributable to trusted packages or explicit policy",
                "Package provenance is needed before Aegis can distinguish expected distribution binaries from custom privileged executables.",
                "Use the inventory for manual review or install/enable the platform package database tools.",
                auto_fix=False, evidence=[f.display() for f in files[:50]], scored=False,
            )
        unowned = [f for f in files if f.package is None and f.path not in policy.allowed_privileged_files]
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.WARN if unowned else Status.PASS,
            Severity.HIGH,
            f"{len(unowned)} unowned/unapproved privileged executable(s) ({source})",
            "all SUID/SGID executables owned by trusted packages or explicitly allowlisted",
            "Privileged binaries outside package management can be legitimate, but they require stronger provenance and change-control scrutiny.",
            "Verify each file's origin and necessity. Remove the privilege bit or binary only after confirming it is not required; otherwise add the exact path to Aegis policy.",
            auto_fix=False,
            evidence=[f.display() for f in unowned[:50]],
        )


class PrivilegedInventoryCheck(Check):
    check_id = "PRIV-003"
    module = "privilege"
    title = "Privileged executable inventory collected"

    def run(self, ctx: SystemContext) -> Finding:
        files, source = collect_privileged_files(ctx)
        return Finding(
            self.check_id,
            self.title,
            self.module,
            Status.INFO,
            Severity.INFO,
            f"{len(files)} SUID/SGID executable(s) ({source})",
            "inventory retained for review/baselining",
            "Knowing which binaries carry elevated execution semantics makes later drift detection possible.",
            "Use `aegis inventory suid` to inspect the full list.",
            auto_fix=False,
            evidence=[f.display() for f in files[:30]],
            scored=False,
        )


CHECKS = [WritablePrivilegedBinaryCheck(), UnownedPrivilegedBinaryCheck(), PrivilegedInventoryCheck()]
