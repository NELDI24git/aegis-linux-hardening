from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"
    ERROR = "ERROR"
    EXEMPT = "EXEMPT"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    module: str
    status: Status
    severity: Severity
    current: str
    expected: str
    why: str
    remediation: str
    auto_fix: bool = False
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    scored: bool = True
    tags: list[str] = field(default_factory=list)
    original_status: Status | None = None
    exception_reason: str | None = None
    exception_expires_at: str | None = None
    exception_ticket: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        if self.original_status is not None:
            data["original_status"] = self.original_status.value
        return data
