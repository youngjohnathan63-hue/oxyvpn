"""Scan orchestration."""

from __future__ import annotations

import threading
import time

from . import (checks_accounts, checks_files, checks_hardening,
               checks_network, checks_persistence, checks_system)
from .models import ScanReport

MODULES = [
    ("System", checks_system),
    ("Hardening", checks_hardening),
    ("Persistence", checks_persistence),
    ("Network", checks_network),
    ("Files", checks_files),
    ("Accounts", checks_accounts),
]


def total_checks():
    return sum(len(module.CHECKS) for _, module in MODULES)


class Scanner:
    def __init__(self, on_progress=None, on_finding=None):
        self.on_progress = on_progress
        self.on_finding = on_finding
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self) -> ScanReport:
        report = ScanReport(started_at=ScanReport.now())
        try:
            report.host = checks_system.host_info()
        except Exception as exc:
            report.errors.append("host info: %s" % exc)

        total = total_checks()
        done = 0

        for category, module in MODULES:
            for check_id, title, func in module.CHECKS:
                if self._cancel.is_set():
                    break
                done += 1
                if self.on_progress:
                    self.on_progress(done, total, category, title)
                try:
                    finding = func(report.host) if func.__code__.co_argcount else func()
                except Exception as exc:
                    from .models import Finding, Severity, Status
                    finding = Finding(check_id, title, category, Severity.LOW,
                                      Status.ERROR, "Check raised: %s" % exc)
                    report.errors.append("%s: %s" % (check_id, exc))
                report.findings.append(finding)
                if self.on_finding:
                    self.on_finding(finding)

        report.finished_at = ScanReport.now()
        report.duration = time.time() - _epoch(report.started_at)
        return report


def _epoch(stamp):
    try:
        return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return time.time()