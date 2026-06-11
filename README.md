# Universal Audit

[![Tests](https://github.com/gopal-gautam/universal-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/gopal-gautam/universal-audit/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/universal-audit.svg)](https://pypi.org/project/universal-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Universal Audit is an open source command line tool that detects dependency manifests in a project and runs the right package security audit for each ecosystem.

The goal is similar to `npm audit`, but across languages and frameworks:

- JavaScript and Node.js: `package.json` -> `npm audit --json`
- Python: `requirements*.txt` or explicit files -> `pip-audit -r ... --format json`
- Python projects: `pyproject.toml` / `pylock.*.toml` -> `pip-audit . --format json`
- PHP and Laravel: `composer.json` / `composer.lock` -> `composer audit --format json`
- .NET and C#: `.sln`, `.csproj`, `.fsproj`, `.vbproj` -> `dotnet package list --include-transitive --vulnerable --format json`
- Java Maven: `pom.xml` -> OWASP Dependency-Check Maven plugin
- Java Gradle: `build.gradle` / `build.gradle.kts` -> OWASP Dependency-Check CLI

Universal Audit does not maintain a vulnerability database. It delegates to mature ecosystem tools and normalizes their output into one report.

## Install for development

```bash
python -m pip install -e .
```

After the first PyPI release, users can install Universal Audit with:

```bash
python -m pip install universal-audit
```

## Usage

Scan the current project:

```bash
universal-audit
```

Scan another directory:

```bash
universal-audit /path/to/project
```

Pass Python requirement files when they are not named conventionally:

```bash
universal-audit --requirements api/requirements-prod.txt --requirements worker/constraints.txt
```

Emit JSON for CI:

```bash
universal-audit --format json --fail-on high
```

Preview what would run without executing audit tools:

```bash
universal-audit --dry-run
```

Run the local test suite:

```bash
python -m unittest discover -s tests -v
```

## Exit Codes

- `0`: No vulnerabilities at or above the selected `--fail-on` threshold.
- `1`: Vulnerabilities were found at or above the selected threshold.
- `2`: No audit could be completed because tools failed, manifests were unsupported, or no manifests were found.

Some ecosystem tools do not expose vulnerability severity in their JSON output. Universal Audit displays those findings as `UNKNOWN` and treats them as high risk for exit-code thresholding.

## Required ecosystem tools

Universal Audit expects the native audit tools to be installed when a matching ecosystem is detected.

| Ecosystem | Tool |
| --- | --- |
| JavaScript / Node.js | `npm` |
| Python | `pip-audit` |
| PHP / Laravel | `composer` |
| .NET / C# | `dotnet` SDK |
| Java Maven | `mvn` |
| Java Gradle | `dependency-check` CLI |

The first Java audit with OWASP Dependency-Check can take several minutes because it downloads and prepares vulnerability data from NVD.

## Current Scope

This is an MVP focused on dependency vulnerability scanning. It does not do static code analysis, license policy checks, malware sandboxing, or secret scanning.

Supported discovery is intentionally conservative:

- ignores dependency/build directories such as `node_modules`, `vendor`, `.venv`, `target`, `bin`, and `obj`
- scans up to a configurable depth with `--max-depth`
- allows manual Python requirement files with `--requirements`

## Research Notes

The initial adapters are based on the official audit surfaces for each ecosystem:

- npm documents `npm audit --json` and severity thresholds.
- `pip-audit` supports requirements files, local projects, JSON output, and exits with `1` when vulnerabilities are found.
- Composer supports `composer audit --format json` for installed or locked packages.
- Microsoft documents `dotnet package list --include-transitive --vulnerable --format json`; .NET 9 and earlier use the older `dotnet list package` command order.
- OWASP Dependency-Check is the practical Java baseline for Maven, Gradle, and CLI dependency vulnerability reports.

## License

MIT

## Contributing and Security

- See `CONTRIBUTING.md` for development setup and pull request guidelines.
- See `SECURITY.md` for vulnerability reporting.
- See `docs/PUBLISHING.md` for the PyPI release process.
