# Security Policy

## Supported Versions

Universal Audit is currently pre-1.0. Security fixes are provided for the latest released version.

## Reporting a Vulnerability

Please do not open a public issue for a vulnerability in Universal Audit itself.

Use GitHub private vulnerability reporting if it is enabled for the repository, or contact a project maintainer privately. Include:

- affected version or commit
- operating system and Python version
- steps to reproduce
- expected impact
- any suggested fix or mitigation

## Scope

Universal Audit delegates vulnerability detection to ecosystem tools such as `npm audit`, `pip-audit`, `composer audit`, `dotnet`, and OWASP Dependency-Check. If a report is inaccurate because of an upstream vulnerability feed or package manager behavior, report it to the upstream ecosystem tool or advisory source.

## Disclosure

Maintainers will acknowledge valid reports, investigate impact, prepare a fix where appropriate, and publish release notes once users can upgrade.
