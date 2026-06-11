import tempfile
import unittest
from pathlib import Path

from universal_audit.auditors import discover_targets
from universal_audit.discovery import DiscoveryOptions


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")


class DiscoveryTests(unittest.TestCase):
    def test_discovers_supported_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            touch(tmp_path / "package.json")
            touch(tmp_path / "requirements.txt")
            touch(tmp_path / "composer.json")
            touch(tmp_path / "app.csproj")
            touch(tmp_path / "pom.xml")
            touch(tmp_path / "build.gradle")

            targets = discover_targets(DiscoveryOptions(root=tmp_path, max_depth=2), include_dev=True)

            ecosystems = {target.ecosystem for target in targets}
            self.assertLessEqual({"npm", "python", "composer", "dotnet", "maven", "gradle"}, ecosystems)

    def test_ignores_dependency_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            touch(tmp_path / "node_modules" / "leftpad" / "package.json")
            touch(tmp_path / "vendor" / "package" / "composer.json")

            targets = discover_targets(DiscoveryOptions(root=tmp_path, max_depth=4), include_dev=True)

            self.assertEqual(targets, [])

    def test_adds_explicit_requirements_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            requirements = tmp_path / "deploy" / "prod.txt"
            touch(requirements)

            targets = discover_targets(
                DiscoveryOptions(root=tmp_path, max_depth=1, requirements=(requirements,)),
                include_dev=True,
            )

            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].command[:3], ["pip-audit", "-r", str(requirements.resolve())])


if __name__ == "__main__":
    unittest.main()
