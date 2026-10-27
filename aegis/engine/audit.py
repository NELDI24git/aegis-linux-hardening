from __future__ import annotations

from datetime import datetime, timezone

from aegis.checks import ALL_CHECKS
from aegis.context import SystemContext
from aegis.models import Finding, Severity, Status
from aegis.policy import Policy
from aegis.profiles import get_profile


def _apply_exception(finding: Finding, policy: Policy) -> Finding:
    exception = policy.exception_for(finding.check_id)
    if exception is None:
        return finding
    if exception.active():
        finding.original_status = finding.status
        finding.status = Status.EXEMPT
        finding.scored = False
        finding.exception_reason = exception.reason
        finding.exception_expires_at = exception.expires_at
        finding.exception_ticket = exception.ticket
        finding.evidence.append(f"exception: {exception.reason}")
        finding.evidence.append(f"exception expires: {exception.expires_at}")
        if exception.ticket:
            finding.evidence.append(f"exception ticket: {exception.ticket}")
    else:
        finding.evidence.append(f"expired exception ignored (expired {exception.expires_at})")
    return finding


def run_audit(
    ctx: SystemContext,
    module: str | None = None,
    *,
    profile: str | None = None,
    tags: set[str] | None = None,
) -> list[Finding]:
    policy = Policy.load(ctx)
    selected_profile = profile or (policy.profile if policy.explicit and policy.valid else "general")
    selected = get_profile(selected_profile)  # validate explicit CLI profile
    if profile is not None:
        # CLI profile changes built-in role defaults while retaining explicit local overrides.
        if not policy.explicit:
            policy.profile = selected_profile
            policy.allowed_public_ports = set(selected.default_public_ports)
            policy.explicit = True
        else:
            policy.profile = selected_profile
            if not policy.allowed_public_ports_explicit:
                policy.allowed_public_ports = set(selected.default_public_ports)
        ctx.cache["aegis.policy"] = policy
    wanted_tags = {tag.lower() for tag in (tags or set())}
    checks = []
    for check in ALL_CHECKS:
        if module is not None and check.module != module:
            continue
        enabled = policy.control_enabled(check.check_id, check.module) if profile is None else get_profile(selected_profile).check_enabled(check_id=check.check_id, module=check.module)
        if not enabled:
            continue
        effective_tags = set(check.effective_tags())
        if wanted_tags and not (wanted_tags & {x.lower() for x in effective_tags}):
            continue
        checks.append(check)

    findings: list[Finding] = []
    for check in checks:
        try:
            finding = check.run(ctx)
            finding.tags = check.effective_tags()
            findings.append(_apply_exception(finding, policy))
        except Exception as exc:  # one broken check must not abort the entire audit
            finding = Finding(
                check.check_id, check.title, check.module, Status.ERROR, Severity.MEDIUM,
                f"{type(exc).__name__}: {exc}", "check completes successfully",
                "An incomplete check means Aegis could not establish this control's state.",
                "Re-run with verbose output, inspect host prerequisites, and report a reproducible Aegis bug if the problem persists.",
                auto_fix=False, scored=False, tags=check.effective_tags(),
            )
            findings.append(_apply_exception(finding, policy))
    return findings


def check_by_id(check_id: str):
    wanted = check_id.upper()
    for check in ALL_CHECKS:
        if check.check_id.upper() == wanted:
            return check
    return None
