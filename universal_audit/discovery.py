from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "vendor",
    "target",
    "build",
    "dist",
    "bin",
    "obj",
}


@dataclass(frozen=True)
class DiscoveryOptions:
    root: Path
    max_depth: int
    requirements: tuple[Path, ...] = ()


def iter_project_files(root: Path, max_depth: int) -> list[Path]:
    root = root.resolve()
    found: list[Path] = []

    def walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(directory.iterdir(), key=lambda item: (item.is_file(), item.name.lower()))
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name not in IGNORED_DIRS:
                    walk(entry, depth + 1)
            elif entry.is_file():
                found.append(entry)

    walk(root, 0)
    return found


def is_requirement_file(path: Path) -> bool:
    name = path.name.lower()
    return name == "requirements.txt" or (name.startswith("requirements-") and name.endswith(".txt"))
