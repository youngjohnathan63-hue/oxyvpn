"""Scanner data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self):
        return _RANK[self]

    @property
    def penalty(self):
        return _PENALTY[self]


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
         Severity.HIGH: 3, Severity.CRITICAL: 4}
_PENALTY = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 4,
            Severity.HIGH: 8, Severity.CRITICAL: 15}


class Status(str, Enum):
    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    severity: Severity
    status: Status
    summary: str
    details: list = field(default_factory=list)
    remediation: str = ""
    evidence: str = ""

    @property
    def counts(self):
        return self.status in (Status.WARN, Status.FAIL, Status.ERROR)

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "summary": self.summary,
            "details": self.details,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class ScanReport:
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0
    host: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def issues(self):
        return [f for f in self.findings if f.counts]

    @property
    def counts(self):
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.issues:
            out[finding.severity.value] += 1
        return out

    @property
    def score(self):
        penalty = sum(f.severity.penalty for f in self.issues)
        return max(0, min(100, 100 - penalty))

    @property
    def grade(self):
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 55:
            return "D"
        return "F"

    def by_category(self):
        out = {}
        for finding in self.findings:
            out.setdefault(finding.category, []).append(finding)
        return out

    def to_dict(self):
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration, 2),
            "host": self.host,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }

    @staticmethod
    def now():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")