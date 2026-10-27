from aegis.engine.scoring import security_score
from aegis.models import Finding, Severity, Status


def f(status, severity, *, scored=True):
    return Finding("X", "x", "test", status, severity, "", "", "", "", scored=scored)


def test_clean_score_is_100():
    assert security_score([f(Status.PASS, Severity.CRITICAL)]) == 100


def test_score_is_normalized_by_severity_weight():
    findings = [
        f(Status.PASS, Severity.HIGH),
        f(Status.FAIL, Severity.MEDIUM),
    ]
    assert security_score(findings) == 70


def test_advisory_findings_do_not_change_score():
    findings = [
        f(Status.PASS, Severity.HIGH),
        f(Status.FAIL, Severity.CRITICAL, scored=False),
    ]
    assert security_score(findings) == 100
