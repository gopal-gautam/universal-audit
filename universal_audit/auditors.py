from __future__ import annotations

from pathlib import Path

from .discovery import DiscoveryOptions, is_requirement_file, iter_project_files
from .models import AuditTarget
from .parsers import parse_composer, parse_dependency_check, parse_dotnet, parse_npm, parse_pip_audit


def discover_targets(options: DiscoveryOptions, include_dev: bool) -> list[AuditTarget]:
    files = iter_project_files(options.root, options.max_depth)
    targets: list[AuditTarget] = []
    targets.extend(_discover_npm(files, include_dev))
    targets.extend(_discover_python(files, options))
    targets.extend(_discover_composer(files, include_dev))
    targets.extend(_discover_dotnet(files))
    targets.extend(_discover_java(files))
    return _dedupe_targets(targets)


def _discover_npm(files: list[Path], include_dev: bool) -> list[AuditTarget]:
    targets: list[AuditTarget] = []
    for manifest in files:
        if manifest.name != "package.json":
            continue
        command = ["npm", "audit", "--json"]
        if not include_dev:
            command.append("--omit=dev")
        targets.append(
            AuditTarget(
                id=f"npm:{manifest.parent}",
                ecosystem="npm",
                manifest=manifest,
                working_dir=manifest.parent,
                command=command,
                parser=parse_npm,
            )
        )
    return targets


def _discover_python(files: list[Path], options: DiscoveryOptions) -> list[AuditTarget]:
    targets: list[AuditTarget] = []
    explicit_requirements = tuple(path.resolve() for path in options.requirements)
    requirement_files = {path.resolve() for path in files if is_requirement_file(path)}
    requirement_files.update(explicit_requirements)
    for requirement in sorted(requirement_files):
        targets.append(
            AuditTarget(
                id=f"python-requirements:{requirement}",
                ecosystem="python",
                manifest=requirement,
                working_dir=requirement.parent,
                command=["pip-audit", "-r", str(requirement), "--format=json"],
                parser=parse_pip_audit,
            )
        )
    for manifest in files:
        if manifest.name == "pyproject.toml" or (manifest.name.startswith("pylock.") and manifest.name.endswith(".toml")):
            targets.append(
                AuditTarget(
                    id=f"python-project:{manifest.parent}",
                    ecosystem="python",
                    manifest=manifest,
                    working_dir=manifest.parent,
                    command=["pip-audit", str(manifest.parent), "--format=json"],
                    parser=parse_pip_audit,
                )
            )
    return targets


def _discover_composer(files: list[Path], include_dev: bool) -> list[AuditTarget]:
    targets: list[AuditTarget] = []
    composer_json_dirs = {path.parent for path in files if path.name == "composer.json"}
    composer_lock_dirs = {path.parent for path in files if path.name == "composer.lock"}
    for directory in sorted(composer_json_dirs | composer_lock_dirs):
        manifest = directory / ("composer.lock" if directory in composer_lock_dirs else "composer.json")
        command = ["composer", "audit", "--format=json"]
        if (directory / "composer.lock").exists():
            command.append("--locked")
        if not include_dev:
            command.append("--no-dev")
        targets.append(
            AuditTarget(
                id=f"composer:{directory}",
                ecosystem="composer",
                manifest=manifest,
                working_dir=directory,
                command=command,
                parser=parse_composer,
            )
        )
    return targets


def _discover_dotnet(files: list[Path]) -> list[AuditTarget]:
    manifests = [
        path
        for path in files
        if path.suffix.lower() in {".sln", ".csproj", ".fsproj", ".vbproj"}
    ]
    return [
        AuditTarget(
            id=f"dotnet:{manifest}",
            ecosystem="dotnet",
            manifest=manifest,
            working_dir=manifest.parent,
            command=[
                "dotnet",
                "package",
                "list",
                "--project",
                str(manifest),
                "--include-transitive",
                "--vulnerable",
                "--format",
                "json",
            ],
            alternative_commands=[
                [
                    "dotnet",
                    "list",
                    str(manifest),
                    "package",
                    "--include-transitive",
                    "--vulnerable",
                    "--format",
                    "json",
                ]
            ],
            parser=parse_dotnet,
        )
        for manifest in manifests
    ]


def _discover_java(files: list[Path]) -> list[AuditTarget]:
    targets: list[AuditTarget] = []
    for manifest in files:
        if manifest.name == "pom.xml":
            report = manifest.parent / "target" / "dependency-check-report.json"
            targets.append(
                AuditTarget(
                    id=f"maven:{manifest}",
                    ecosystem="maven",
                    manifest=manifest,
                    working_dir=manifest.parent,
                    command=[
                        "mvn",
                        "org.owasp:dependency-check-maven:check",
                        "-Dformat=JSON",
                        "-DfailBuildOnCVSS=11",
                    ],
                    parser=parse_dependency_check,
                    report_path=report,
                    notes=["First run can take several minutes while OWASP Dependency-Check downloads NVD data."],
                )
            )
        if manifest.name in {"build.gradle", "build.gradle.kts"}:
            out_dir = manifest.parent / ".universal-audit" / "dependency-check"
            targets.append(
                AuditTarget(
                    id=f"gradle:{manifest}",
                    ecosystem="gradle",
                    manifest=manifest,
                    working_dir=manifest.parent,
                    command=[
                        "dependency-check",
                        "--project",
                        manifest.parent.name,
                        "--scan",
                        str(manifest.parent),
                        "--format",
                        "JSON",
                        "--out",
                        str(out_dir),
                        "--failOnCVSS",
                        "11",
                    ],
                    parser=parse_dependency_check,
                    report_path=out_dir / "dependency-check-report.json",
                    notes=["Requires the OWASP Dependency-Check CLI to be installed."],
                )
            )
    return targets


def _dedupe_targets(targets: list[AuditTarget]) -> list[AuditTarget]:
    seen: set[str] = set()
    deduped: list[AuditTarget] = []
    for target in targets:
        if target.id not in seen:
            seen.add(target.id)
            deduped.append(target)
    return deduped
