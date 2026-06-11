# Publishing Universal Audit to PyPI

These steps prepare and publish `universal-audit` so users can install it with:

```bash
python -m pip install universal-audit
```

## Recommended: GitHub Trusted Publishing

Trusted Publishing is the preferred PyPI release flow because it avoids storing long-lived PyPI API tokens in GitHub.

1. Create accounts on PyPI and TestPyPI.
2. Push this repository to GitHub.
3. On PyPI, create a pending trusted publisher for the project:
   - Project name: `universal-audit`
   - Owner: `gopal-gautam`
   - Repository name: `universal-audit`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
4. Optional but recommended: create the same trusted publisher on TestPyPI using environment `testpypi`.
5. In GitHub repository settings, create environments named `pypi` and `testpypi`. Add required reviewers if you want manual approval before publishing.
6. Update the version in `pyproject.toml` and `universal_audit/__init__.py`.
7. Commit the release:

```bash
git add .
git commit -m "Release 0.1.0"
git tag v0.1.0
git push origin main --tags
```

8. Create a GitHub release from tag `v0.1.0`.
9. The `Publish to PyPI` GitHub Actions workflow will build and upload the package.

## Manual TestPyPI Smoke Test

Use this flow before the first real PyPI release if you want to test the package manually.

```bash
python -m pip install --upgrade pip build twine
python -m build
python -m twine check dist/*
python -m twine upload --repository testpypi dist/*
```

Then install from TestPyPI:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ universal-audit
universal-audit --help
```

## Manual PyPI Upload

Trusted Publishing is preferred. If you must publish manually:

1. Create a PyPI API token scoped to the `universal-audit` project.
2. Build and validate the distributions:

```bash
python -m pip install --upgrade pip build twine
python -m build
python -m twine check dist/*
```

3. Upload to PyPI:

```bash
python -m twine upload dist/*
```

When prompted, use `__token__` as the username and paste the API token as the password.

## Release Checklist

- `python -m unittest discover -s tests -v` passes.
- `python -m universal_audit.cli --dry-run` works.
- `README.md` and `CHANGELOG.md` are up to date.
- Version is updated in `pyproject.toml` and `universal_audit/__init__.py`.
- `python -m build` produces both `.tar.gz` and `.whl` files in `dist/`.
- `python -m twine check dist/*` passes.
