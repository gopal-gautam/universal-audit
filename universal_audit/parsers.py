from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AuditTarget, Finding, normalize_severity


def parse_json_object(text: str) -> Any:
    text = text.strip()
    if not text:
        return {}
    return json.loads(text)


def parse_npm(target: AuditTarget, stdout: str, stderr: str) -> list[Finding]:
    data = parse_json_object(stdout)
    vulnerabilities = data.get("vulnerabilities", {}) if isinstance(data, dict) else {}
    findings: list[Finding] = []
    for package, vulnerability in vulnerabilities.items():
        severity = normalize_severity(vulnerability.get("severity"))
        via = vulnerability.get("via", [])
        advisory_id = ""
        title = vulnerability.get("title", "")
        url = vulnerability.get("url", "")
        if isinstance(via, list):
            advisory = next((item for item in via if isinstance(item, dict)), {})
            advisory_id = str(advisory.get("source", "") or advisory.get("id", ""))
            title = title or str(advisory.get("title", ""))
            url = url or str(advisory.get("url", ""))
        findings.append(
            Finding(
                ecosystem=target.ecosystem,
                package=str(package),
                severity=severity,
                advisory=advisory_id,
                installed_version=str(vulnerability.get("range", "")),
                fixed_version=str(vulnerability.get("fixAvailable", "")),
                title=title,
                url=url,
                source=str(target.manifest),
            )
        )
    return findings


def parse_pip_audit(target: AuditTarget, stdout: str, stderr: str) -> list[Finding]:
    data = parse_json_object(stdout)
    dependencies = data.get("dependencies", data) if isinstance(data, dict) else data
    findings: list[Finding] = []
    if not isinstance(dependencies, list):
        return findings
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        package = str(dependency.get("name", ""))
        version = str(dependency.get("version", ""))
        for vulnerability in dependency.get("vulns", []):
            if not isinstance(vulnerability, dict):
                continue
            aliases = vulnerability.get("aliases") or []
            advisory = str(vulnerability.get("id", "") or (aliases[0] if aliases else ""))
            findings.append(
                Finding(
                    ecosystem=target.ecosystem,
                    package=package,
                    severity="unknown",
                    advisory=advisory,
                    installed_version=version,
                    fixed_version=", ".join(vulnerability.get("fix_versions", [])),
                    title=str(vulnerability.get("description", ""))[:180],
                    source=str(target.manifest),
                )
            )
    return findings


def parse_composer(target: AuditTarget, stdout: str, stderr: str) -> list[Finding]:
    data = parse_json_object(stdout)
    findings: list[Finding] = []
    advisories = data.get("advisories", {}) if isinstance(data, dict) else {}
    for package, package_advisories in advisories.items():
        if isinstance(package_advisories, dict):
            iterable = package_advisories.values()
        else:
            iterable = package_advisories
        for advisory in iterable:
            if not isinstance(advisory, dict):
                continue
            findings.append(
                Finding(
                    ecosystem=target.ecosystem,
                    package=str(package),
                    severity=normalize_severity(advisory.get("severity")),
                    advisory=str(advisory.get("cve", "") or advisory.get("advisoryId", "") or advisory.get("id", "")),
                    title=str(advisory.get("title", "")),
                    url=str(advisory.get("link", "") or advisory.get("url", "")),
                    source=str(target.manifest),
                )
            )
    return findings


def parse_dotnet(target: AuditTarget, stdout: str, stderr: str) -> list[Finding]:
    data = parse_json_object(stdout)
    findings: list[Finding] = []
    projects = data.get("projects", []) if isinstance(data, dict) else []
    for project in projects:
        for framework in project.get("frameworks", []):
            package_groups = [
                framework.get("topLevelPackages", []),
                framework.get("transitivePackages", []),
            ]
            for packages in package_groups:
                for package in packages:
                    for vulnerability in package.get("vulnerabilities", []):
                        findings.append(
                            Finding(
                                ecosystem=target.ecosystem,
                                package=str(package.get("id", "")),
                                severity=normalize_severity(vulnerability.get("severity")),
                                advisory=str(vulnerability.get("advisoryurl", "") or vulnerability.get("advisoryUrl", "")),
                                installed_version=str(package.get("resolvedVersion", "")),
                                url=str(vulnerability.get("advisoryurl", "") or vulnerability.get("advisoryUrl", "")),
                                source=str(target.manifest),
                            )
                        )
    return findings


def parse_dependency_check(target: AuditTarget, stdout: str, stderr: str) -> list[Finding]:
    report_text = stdout
    if target.report_path and target.report_path.exists():
        report_text = target.report_path.read_text(encoding="utf-8")
    data = parse_json_object(report_text)
    dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
    findings: list[Finding] = []
    for dependency in dependencies:
        package = dependency.get("fileName", "") or dependency.get("filePath", "")
        for vulnerability in dependency.get("vulnerabilities", []):
            cvss = vulnerability.get("cvssv3", {}) or vulnerability.get("cvssv2", {})
            severity = vulnerability.get("severity") or cvss.get("baseSeverity")
            findings.append(
                Finding(
                    ecosystem=target.ecosystem,
                    package=str(package),
                    severity=normalize_severity(str(severity)),
                    advisory=str(vulnerability.get("name", "")),
                    title=str(vulnerability.get("description", ""))[:180],
                    url=_first_reference_url(vulnerability),
                    source=str(target.manifest),
                )
            )
    return findings


def _first_reference_url(vulnerability: dict[str, Any]) -> str:
    references = vulnerability.get("references", [])
    if isinstance(references, list) and references:
        first = references[0]
        if isinstance(first, dict):
            return str(first.get("url", ""))
    return ""


def read_report_if_needed(path: Path | None) -> str:
    if path and path.exists():
        return path.read_text(encoding="utf-8")
    return ""
