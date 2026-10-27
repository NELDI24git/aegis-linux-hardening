from __future__ import annotations

import re

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status


def _fallback_parse_sshd_config(ctx: SystemContext) -> dict[str, str]:
    """Best-effort parser used only when `sshd -T` is unavailable.

    It intentionally ignores Match blocks and complex OpenSSH precedence.
    Findings produced from this fallback are therefore WARN rather than PASS.
    """
    path = "/etc/ssh/sshd_config"
    if not ctx.exists(path):
        return {}

    values: dict[str, str] = {}
    in_match = False
    for raw in ctx.read_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"(?i)^match\s+", line):
            in_match = True
            continue
        if in_match:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip()
        values.setdefault(key, value)
    return values


def effective_sshd_config(ctx: SystemContext) -> tuple[dict[str, str], bool, str]:
    if ctx.which("sshd"):
        result = ctx.run(["sshd", "-T"])
        if result.returncode == 0:
            values: dict[str, str] = {}
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    values[parts[0].lower()] = parts[1].strip()
            return values, True, "sshd -T"
        return _fallback_parse_sshd_config(ctx), False, f"sshd -T failed: {result.stderr.strip()}"
    return _fallback_parse_sshd_config(ctx), False, "sshd not available; fallback parser used"


class SSHRootLoginCheck(Check):
    check_id = "SSH-001"
    module = "ssh"
    title = "Direct root SSH login disabled"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        value = cfg.get("permitrootlogin", "unknown").lower()
        passed = value == "no"
        if passed and authoritative:
            status = Status.PASS
        elif passed:
            status = Status.WARN
        else:
            status = Status.FAIL
        return Finding(
            self.check_id,
            self.title,
            self.module,
            status,
            Severity.HIGH,
            f"PermitRootLogin={value} ({source})",
            "PermitRootLogin=no",
            "Direct remote root login removes an identity boundary and increases the impact of credential compromise.",
            "Disable direct root SSH login and use a named administrative account with sudo.",
            auto_fix=True,
        )


class SSHPasswordAuthCheck(Check):
    check_id = "SSH-002"
    module = "ssh"
    title = "SSH password authentication disabled"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        value = cfg.get("passwordauthentication", "unknown").lower()
        passed = value == "no"
        status = Status.PASS if passed and authoritative else (Status.WARN if passed else Status.FAIL)
        return Finding(
            self.check_id,
            self.title,
            self.module,
            status,
            Severity.MEDIUM,
            f"PasswordAuthentication={value} ({source})",
            "PasswordAuthentication=no",
            "Disabling password authentication reduces exposure to password spraying and brute-force attacks.",
            "Verify working key-based access for an administrator, then disable SSH password authentication.",
            auto_fix=True,
        )


class SSHMaxAuthTriesCheck(Check):
    check_id = "SSH-003"
    module = "ssh"
    title = "SSH authentication attempts limited"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        raw = cfg.get("maxauthtries", "unknown")
        try:
            value = int(raw)
        except ValueError:
            value = None
        passed = value is not None and value <= 4
        status = Status.PASS if passed and authoritative else (Status.WARN if passed else Status.FAIL)
        return Finding(
            self.check_id,
            self.title,
            self.module,
            status,
            Severity.LOW,
            f"MaxAuthTries={raw} ({source})",
            "MaxAuthTries<=4",
            "A lower authentication-attempt limit reduces the number of guesses available per connection.",
            "Set MaxAuthTries to 4 or lower after checking compatibility with your authentication flow.",
            auto_fix=True,
        )


CHECKS = [SSHRootLoginCheck(), SSHPasswordAuthCheck(), SSHMaxAuthTriesCheck()]


class SSHPermitEmptyPasswordsCheck(Check):
    check_id = "SSH-004"
    module = "ssh"
    title = "SSH empty-password authentication disabled"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        value = cfg.get("permitemptypasswords", "unknown").lower()
        passed = value == "no"
        status = Status.PASS if passed and authoritative else (Status.WARN if passed else Status.FAIL)
        return Finding(
            self.check_id, self.title, self.module, status, Severity.CRITICAL,
            f"PermitEmptyPasswords={value} ({source})", "PermitEmptyPasswords=no",
            "Allowing SSH authentication for accounts with empty passwords can create a direct remote-access weakness.",
            "Set PermitEmptyPasswords no and investigate any local account with an empty password field.",
            auto_fix=True,
        )


class SSHHostbasedAuthCheck(Check):
    check_id = "SSH-005"
    module = "ssh"
    title = "SSH host-based authentication disabled"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        value = cfg.get("hostbasedauthentication", "unknown").lower()
        passed = value == "no"
        status = Status.PASS if passed and authoritative else (Status.WARN if passed else Status.FAIL)
        return Finding(
            self.check_id, self.title, self.module, status, Severity.MEDIUM,
            f"HostbasedAuthentication={value} ({source})", "HostbasedAuthentication=no",
            "Host-based trust is unnecessary on most modern servers and expands the trust boundary when enabled.",
            "Disable host-based authentication unless the environment explicitly relies on it.",
            auto_fix=True,
        )


class SSHIgnoreRhostsCheck(Check):
    check_id = "SSH-006"
    module = "ssh"
    title = "Legacy rhosts trust ignored"

    def run(self, ctx: SystemContext) -> Finding:
        cfg, authoritative, source = effective_sshd_config(ctx)
        value = cfg.get("ignorerhosts", "unknown").lower()
        passed = value == "yes"
        status = Status.PASS if passed and authoritative else (Status.WARN if passed else Status.FAIL)
        return Finding(
            self.check_id, self.title, self.module, status, Severity.MEDIUM,
            f"IgnoreRhosts={value} ({source})", "IgnoreRhosts=yes",
            "Legacy rhosts-style trust relationships create weak implicit authentication boundaries.",
            "Set IgnoreRhosts yes unless a documented legacy dependency requires otherwise.",
            auto_fix=True,
        )


CHECKS.extend([SSHPermitEmptyPasswordsCheck(), SSHHostbasedAuthCheck(), SSHIgnoreRhostsCheck()])
