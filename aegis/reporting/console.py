from __future__ import annotations

from collections import Counter

from aegis.engine.scoring import score_details
from aegis.models import Finding, Status

SYMBOL = {
    Status.PASS: "[PASS]",
    Status.FAIL: "[FAIL]",
    Status.WARN: "[WARN]",
    Status.INFO: "[INFO]",
    Status.ERROR: "[ERR ]",
    Status.EXEMPT: "[EXEM]",
}


def render_console(findings: list[Finding], platform_name: str | None = None, *, verbose: bool = False, profile: str | None = None) -> str:
    lines = ["AEGIS SECURITY AUDIT"]
    if platform_name:
        lines.append(platform_name)
    if profile:
        lines.append(f"Profile: {profile}")
    lines.append("=" * 78)
    current_module = None
    for f in findings:
        if f.module != current_module:
            current_module = f.module
            lines.extend(["", current_module.upper()])
        scored = "" if f.scored else " [advisory]"
        lines.append(f"{SYMBOL[f.status]} {f.check_id:<8} {f.title} [{f.severity.value}]{scored}")
        if f.status != Status.PASS or verbose:
            lines.append(f"         current:  {f.current}")
            lines.append(f"         expected: {f.expected}")
        if f.status == Status.EXEMPT:
            origin = f.original_status.value if f.original_status else "unknown"
            lines.append(f"         exception: original={origin}; expires={f.exception_expires_at or 'unknown'}")
            lines.append(f"                    {f.exception_reason or 'no rationale'}")
            if f.exception_ticket:
                lines.append(f"                    ticket={f.exception_ticket}")
        if verbose and f.evidence:
            lines.append("         evidence:")
            for item in f.evidence[:20]:
                lines.append(f"           - {item}")
            if len(f.evidence) > 20:
                lines.append(f"           ... {len(f.evidence) - 20} more")
        if verbose and f.status in {Status.FAIL, Status.WARN, Status.ERROR}:
            lines.append(f"         why:      {f.why}")
            lines.append(f"         action:   {f.remediation}")

    counts = Counter(f.status.value for f in findings)
    score = score_details(findings)
    lines.extend([
        "", "-" * 78,
        f"PASS {counts['PASS']}  FAIL {counts['FAIL']}  WARN {counts['WARN']}  INFO {counts['INFO']}  ERROR {counts['ERROR']}  EXEMPT {counts['EXEMPT']}",
        f"Security score: {score.score}/100 ({score.scored_findings} scored checks)",
    ])
    return "\n".join(lines)
