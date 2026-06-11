from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .auditors import discover_targets
from .discovery import DiscoveryOptions
from .formatters import format_json, format_table
from .models import AuditSummary, severity_at_least
from .runner import run_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="universal-audit",
        description="Run dependency vulnerability audits across multiple package ecosystems.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory to scan.")
    parser.add_argument(
        "--requirements",
        action="append",
        default=[],
        help="Additional Python requirements file to audit. Can be passed multiple times.",
    )
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format.")
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "moderate", "high", "critical"],
        default="high",
        help="Exit with code 1 when findings meet or exceed this severity.",
    )
    parser.add_argument("--include-dev", action="store_true", help="Include development dependencies where supported.")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum directory depth for manifest discovery.")
    parser.add_argument("--timeout", type=int, default=600, help="Per-auditor timeout in seconds.")
    parser.add_argument("--dry-run", action="store_true", help="Print detected audit commands without running them.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    requirements = tuple(Path(item).resolve() for item in args.requirements)
    options = DiscoveryOptions(root=root, max_depth=args.max_depth, requirements=requirements)
    targets = discover_targets(options, include_dev=args.include_dev)

    if args.dry_run:
        if not targets:
            print("No supported dependency manifests found.")
            return 2
        for target in targets:
            command = " ".join(target.command)
            print(f"{target.ecosystem}: {target.manifest}")
            print(f"  {command}")
            for alternative in target.alternative_commands:
                print(f"  fallback: {' '.join(alternative)}")
        return 0

    executions = [run_target(target, timeout=args.timeout) for target in targets]
    summary = AuditSummary(executions=executions)
    output = format_json(summary) if args.format == "json" else format_table(summary)
    print(output)

    if not targets or summary.failed_executions:
        return 2
    if args.fail_on != "none" and any(severity_at_least(finding.severity, args.fail_on) for finding in summary.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
