from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


SEVERITY_RANK = {
    "none": 0,
    "info": 1,
    "low": 2,
    "moderate": 3,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "unknown": 4,
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    lowered = value.strip().lower()
    if lowered == "moderate":
        return "medium"
    if lowered in SEVERITY_RANK:
        return lowered
    return "unknown"


def severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_RANK[normalize_severity(value)] >= SEVERITY_RANK[normalize_severity(threshold)]


@dataclass(frozen=True)
class Finding:
    ecosystem: str
    package: str
    severity: str
    advisory: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    title: str = ""
    url: str = ""
    source: str = ""


@dataclass
class AuditTarget:
    id: str
    ecosystem: str
    manifest: Path
    working_dir: Path
    command: list[str]
    parser: Callable[["AuditTarget", str, str], list[Finding]]
    alternative_commands: list[list[str]] = field(default_factory=list)
    report_path: Path | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class AuditExecution:
    target: AuditTarget
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    findings: list[Finding]
    failed: bool = False
    error: str = ""


@dataclass
class AuditSummary:
    executions: list[AuditExecution]

    @property
    def findings(self) -> list[Finding]:
        return [finding for execution in self.executions for finding in execution.findings]

    @property
    def failed_executions(self) -> list[AuditExecution]:
        return [execution for execution in self.executions if execution.failed]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for finding in self.findings:
            counts[normalize_severity(finding.severity)] += 1
        return counts


JsonValue = dict[str, Any] | list[Any]
