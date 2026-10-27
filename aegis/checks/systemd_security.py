from __future__ import annotations

import os
import stat
from pathlib import Path

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


class SystemdAnalyzeSecurityCheck(Check):
    check_id = "SYS-001"
    module = "systemd"
    title = "systemd service hardening exposure inventoried"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.is_real_system or not ctx.which("systemd-analyze"):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.INFO,
                "systemd-analyze runtime inventory unavailable", "review service sandboxing where systemd is used",
                "systemd sandboxing directives can reduce the impact of a compromised daemon, but exposure scores are role-dependent and are not vulnerabilities by themselves.",
                "Run on a systemd host and review high-exposure network-facing or custom services in context.",
                auto_fix=False, scored=False,
            )

        result = ctx.run(["systemd-analyze", "security", "--no-pager", "--no-legend"], timeout=45)
        if result.returncode != 0:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.INFO,
                f"systemd-analyze failed: {result.stderr.strip() or result.returncode}",
                "service hardening inventory available",
                "The analyzer is an advisory source for service sandboxing opportunities.",
                "Run `systemd-analyze security <unit>` manually for important services.",
                auto_fix=False, scored=False,
            )

        scored: list[tuple[float, str]] = []
        for raw in result.stdout.splitlines():
            parts = raw.split()
            if len(parts) < 2 or not parts[0].endswith(".service"):
                continue
            try:
                exposure = float(parts[1])
            except ValueError:
                continue
            scored.append((exposure, raw.strip()))
        scored.sort(reverse=True, key=lambda item: item[0])
        worst = scored[:20]
        return Finding(
            self.check_id, self.title, self.module, Status.INFO, Severity.INFO,
            f"{len(scored)} service exposure score(s) parsed",
            "high-value services reviewed for appropriate sandboxing",
            "A high systemd exposure score can identify missing sandboxing opportunities, but some services legitimately require broad privileges.",
            "Review the highest-exposure custom and network-facing services; do not apply sandboxing directives without compatibility testing.",
            auto_fix=False,
            evidence=[line for _score, line in worst],
            scored=False,
        )


class WritableCustomUnitCheck(Check):
    check_id = "SYS-002"
    module = "systemd"
    title = "Custom systemd unit files are not group/world writable"

    def run(self, ctx: SystemContext) -> Finding:
        base = ctx.path("/etc/systemd/system")
        if not base.is_dir():
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                "/etc/systemd/system unavailable", "custom unit files not group/world writable",
                "Writable privileged service definitions can allow command execution as the service account, frequently root.",
                "Review on a systemd host.", auto_fix=False, scored=False,
            )

        risky: list[str] = []
        inspected = 0
        for root, dirs, files in os.walk(base):
            # Drop-in directories are relevant too, but symlinked units are
            # package/reference links and should be assessed at their target.
            for name in files:
                if not (name.endswith(".service") or name.endswith(".conf")):
                    continue
                path = Path(root) / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                inspected += 1
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o022:
                    display_path = "/" + str(path.relative_to(ctx.root_dir)) if not ctx.is_real_system else str(path)
                    risky.append(f"{display_path} mode={oct(mode)} uid={st.st_uid} gid={st.st_gid}")

        return Finding(
            self.check_id, self.title, self.module,
            Status.FAIL if risky else Status.PASS,
            Severity.CRITICAL,
            f"{len(risky)} writable custom unit/drop-in file(s) out of {inspected} inspected",
            "0 group/world-writable service unit or drop-in files under /etc/systemd/system",
            "An unprivileged modification to a root-run service definition can become a direct privilege-escalation path when the unit starts or reloads.",
            "Restore ownership and permissions from a trusted source, review recent changes, and reload systemd only after investigating unexpected modifications.",
            auto_fix=False,
            evidence=risky[:50],
        )


CHECKS = [SystemdAnalyzeSecurityCheck(), WritableCustomUnitCheck()]
