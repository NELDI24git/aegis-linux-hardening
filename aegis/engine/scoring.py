from __future__ import annotations

from dataclasses import dataclass

from aegis.models import Finding, Severity, Status

WEIGHTS = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 3, Severity.HIGH: 7, Severity.CRITICAL: 12}
STATUS_CREDIT = {Status.PASS: 1.0, Status.WARN: 0.5, Status.ERROR: 0.25, Status.FAIL: 0.0}


@dataclass(slots=True)
class ScoreDetails:
    score: int
    earned: float
    possible: float
    scored_findings: int


def score_details(findings: list[Finding]) -> ScoreDetails:
    earned = possible = 0.0
    count = 0
    for finding in findings:
        if not finding.scored or finding.status in {Status.INFO, Status.EXEMPT}:
            continue
        weight = WEIGHTS[finding.severity]
        if weight <= 0:
            continue
        possible += weight
        earned += weight * STATUS_CREDIT.get(finding.status, 0.0)
        count += 1
    score = 100 if possible == 0 else round((earned / possible) * 100)
    return ScoreDetails(max(0, min(100, score)), earned, possible, count)


def security_score(findings: list[Finding]) -> int:
    return score_details(findings).score
