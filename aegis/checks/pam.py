from __future__ import annotations

import re

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status
from aegis.platform import detect_platform


class PAMPasswordQualityCheck(Check):
    check_id = "PAM-001"
    module = "pam"
    title = "PAM password-quality control is present"

    def run(self, ctx: SystemContext) -> Finding:
        platform = detect_platform(ctx)
        if platform.distro_id not in {"debian", "ubuntu", "linuxmint", "pop"}:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                f"platform={platform.distro_id}", "distribution-appropriate password-quality control",
                "Password-quality controls can reduce weak local password choices where passwords remain in use.",
                "A PAM adapter for this distribution is not implemented yet.", scored=False,
            )
        path = "/etc/pam.d/common-password"
        if not ctx.exists(path):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                f"{path} unavailable", "pam_pwquality or pam_passwdqc configured when local passwords are used",
                "Password-quality controls can reduce weak local password choices.",
                "Review the host's authentication stack.", scored=False,
            )
        text = ctx.read_text(path)
        modules = []
        if re.search(r"\bpam_pwquality\.so\b", text):
            modules.append("pam_pwquality")
        if re.search(r"\bpam_passwdqc\.so\b", text):
            modules.append("pam_passwdqc")
        return Finding(
            self.check_id, self.title, self.module,
            Status.PASS if modules else Status.WARN,
            Severity.LOW,
            "configured modules: " + (", ".join(modules) if modules else "none detected"),
            "password-quality module present when password authentication is part of the host policy",
            "Weak password selection increases guessing risk where passwords are accepted.",
            "Configure a supported password-quality module only if local/password authentication is actually part of the system design.",
            auto_fix=False,
            scored=False,
        )


class PAMLockoutCheck(Check):
    check_id = "PAM-002"
    module = "pam"
    title = "Repeated authentication failure control reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        paths = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
        texts = []
        for path in paths:
            if ctx.exists(path):
                texts.append(ctx.read_text(path))
        if not texts:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.LOW,
                "PAM authentication files unavailable", "lockout/rate-limiting policy reviewed",
                "Authentication throttling can slow online guessing but may also create denial-of-service risk if configured carelessly.",
                "Review the platform authentication stack.", scored=False,
            )
        combined = "\n".join(texts)
        modules = []
        for name in ("pam_faillock.so", "pam_tally2.so"):
            if name in combined:
                modules.append(name)
        return Finding(
            self.check_id, self.title, self.module,
            Status.PASS if modules else Status.INFO,
            Severity.LOW,
            "controls: " + (", ".join(modules) if modules else "no PAM lockout module detected"),
            "an explicit authentication failure/rate-limiting strategy",
            "Brute-force resistance should be deliberate and balanced against account-lockout denial-of-service risk.",
            "Use PAM lockout, Fail2Ban, upstream rate limiting, key-only SSH, or another documented control appropriate to the host.",
            auto_fix=False,
            scored=False,
        )


CHECKS = [PAMPasswordQualityCheck(), PAMLockoutCheck()]
