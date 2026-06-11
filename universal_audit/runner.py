from __future__ import annotations

import subprocess

from .models import AuditExecution, AuditTarget


def run_target(target: AuditTarget, timeout: int) -> AuditExecution:
    commands = [target.command, *target.alternative_commands]
    last_execution: AuditExecution | None = None
    for command in commands:
        execution = _run_command(target, command, timeout)
        if not execution.failed:
            return execution
        last_execution = execution
    assert last_execution is not None
    return last_execution


def _run_command(target: AuditTarget, command: list[str], timeout: int) -> AuditExecution:
    try:
        completed = subprocess.run(
            command,
            cwd=target.working_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return AuditExecution(
            target=target,
            command=command,
            returncode=127,
            stdout="",
            stderr=str(exc),
            findings=[],
            failed=True,
            error=f"Required tool not found: {command[0]}",
        )
    except subprocess.TimeoutExpired as exc:
        return AuditExecution(
            target=target,
            command=command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            findings=[],
            failed=True,
            error=f"Timed out after {timeout} seconds",
        )

    try:
        findings = target.parser(target, completed.stdout, completed.stderr)
    except Exception as exc:  # noqa: BLE001 - parser failures should be reported, not crash the CLI.
        return AuditExecution(
            target=target,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            findings=[],
            failed=True,
            error=f"Could not parse {target.ecosystem} audit output: {exc}",
        )

    if completed.returncode not in {0, 1} and not findings:
        return AuditExecution(
            target=target,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            findings=findings,
            failed=True,
            error=(completed.stderr or completed.stdout or "Audit command failed").strip(),
        )

    return AuditExecution(
        target=target,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        findings=findings,
    )
