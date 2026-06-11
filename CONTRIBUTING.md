# Contributing to Universal Audit

Thanks for helping improve Universal Audit.

## Development Setup

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

On macOS or Linux, activate the virtual environment with:

```bash
source .venv/bin/activate
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Check the CLI

```bash
python -m universal_audit.cli --dry-run
```

## Contribution Guidelines

- Keep adapters small and ecosystem-specific.
- Prefer official package manager audit commands over custom vulnerability logic.
- Add parser tests for every new output format.
- Do not commit generated files such as `dist/`, `.egg-info/`, `__pycache__/`, or `.universal-audit/`.
- Keep public CLI behavior documented in `README.md`.

## Pull Request Checklist

- Tests pass locally.
- New functionality has tests.
- Documentation is updated when CLI behavior changes.
- The change is scoped to the issue or feature being addressed.
