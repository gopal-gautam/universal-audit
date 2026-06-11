from __future__ import annotations

import json
from dataclasses import asdict

from .models import AuditSummary


def format_table(summary: AuditSummary) -> str:
    lines: list[str] = []
    for execution in summary.executions:
        status = "failed" if execution.failed else "ok"
        lines.append(f"{execution.target.ecosystem}: {execution.target.manifest} ({status})")
        if execution.error:
            lines.append(f"  error: {execution.error}")
        for note in execution.target.notes:
            lines.append(f"  note: {note}")
        for finding in execution.findings:
            advisory = f" [{finding.advisory}]" if finding.advisory else ""
            version = f" {finding.installed_version}" if finding.installed_version else ""
            title = f" - {finding.title}" if finding.title else ""
            lines.append(f"  {finding.severity.upper():8} {finding.package}{version}{advisory}{title}")
        if not execution.findings and not execution.failed:
            lines.append("  no vulnerabilities reported")
    if not lines:
        lines.append("No supported dependency manifests found.")

    counts = summary.counts_by_severity()
    lines.append("")
    lines.append(
        "Summary: "
        + ", ".join(f"{severity}={count}" for severity, count in counts.items() if count)
        if any(counts.values())
        else "Summary: no vulnerabilities reported"
    )
    return "\n".join(lines)


def format_json(summary: AuditSummary) -> str:
    payload = {
        "summary": summary.counts_by_severity(),
        "executions": [
            {
                "ecosystem": execution.target.ecosystem,
                "manifest": str(execution.target.manifest),
                "command": execution.command,
                "returncode": execution.returncode,
                "failed": execution.failed,
                "error": execution.error,
                "findings": [asdict(finding) for finding in execution.findings],
            }
            for execution in summary.executions
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
