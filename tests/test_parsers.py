import json
import tempfile
import unittest
from pathlib import Path

from universal_audit.models import AuditTarget, severity_at_least
from universal_audit.parsers import parse_composer, parse_dotnet, parse_npm, parse_pip_audit


def target(tmp_path: Path, ecosystem: str) -> AuditTarget:
    manifest = tmp_path / "manifest"
    manifest.write_text("", encoding="utf-8")
    return AuditTarget(
        id=ecosystem,
        ecosystem=ecosystem,
        manifest=manifest,
        working_dir=tmp_path,
        command=["noop"],
        parser=lambda _target, _stdout, _stderr: [],
    )


class ParserTests(unittest.TestCase):
    def test_parse_npm_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            payload = {
                "vulnerabilities": {
                    "minimist": {
                        "severity": "high",
                        "range": "<1.2.6",
                        "via": [{"source": 123, "title": "prototype pollution", "url": "https://example.test"}],
                    }
                }
            }

            findings = parse_npm(target(tmp_path, "npm"), json.dumps(payload), "")

            self.assertEqual(findings[0].package, "minimist")
            self.assertEqual(findings[0].severity, "high")

    def test_parse_pip_audit_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            payload = [{"name": "flask", "version": "0.5", "vulns": [{"id": "PYSEC-1", "fix_versions": ["1.0"]}]}]

            findings = parse_pip_audit(target(tmp_path, "python"), json.dumps(payload), "")

            self.assertEqual(findings[0].package, "flask")
            self.assertEqual(findings[0].advisory, "PYSEC-1")

    def test_parse_composer_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            payload = {"advisories": {"vendor/pkg": [{"cve": "CVE-1", "severity": "critical", "title": "bad"}]}}

            findings = parse_composer(target(tmp_path, "composer"), json.dumps(payload), "")

            self.assertEqual(findings[0].package, "vendor/pkg")
            self.assertEqual(findings[0].severity, "critical")

    def test_parse_dotnet_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            payload = {
                "projects": [
                    {
                        "frameworks": [
                            {
                                "topLevelPackages": [
                                    {
                                        "id": "Newtonsoft.Json",
                                        "resolvedVersion": "1.0",
                                        "vulnerabilities": [{"severity": "High", "advisoryurl": "https://example.test"}],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }

            findings = parse_dotnet(target(tmp_path, "dotnet"), json.dumps(payload), "")

            self.assertEqual(findings[0].package, "Newtonsoft.Json")
            self.assertEqual(findings[0].severity, "high")

    def test_unknown_severity_fails_high_threshold(self) -> None:
        self.assertTrue(severity_at_least("unknown", "high"))
        self.assertFalse(severity_at_least("unknown", "critical"))


if __name__ == "__main__":
    unittest.main()
