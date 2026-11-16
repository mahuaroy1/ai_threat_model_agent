"""Safe, bounded discovery of files to analyze.

Discovery never follows symbolic links, skips dependency and VCS folders,
and enforces size and count limits so a hostile repository cannot exhaust
memory or escape the scan root.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ScanError

LOGGER = logging.getLogger(__name__)

SKIPPED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", "env", ".env.d", "node_modules", "__pycache__",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "site-packages",
        "dist", "build", ".idea", ".vscode", ".eggs",
    }
)
CONFIG_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties"})


@dataclass(frozen=True)
class SourceFile:
    """A file selected for analysis."""

    path: Path
    relative_path: str  # POSIX style, relative to the scan root
    kind: str  # "python" or "config"

    def read_text(self) -> str:
        """Read the file as UTF-8, replacing undecodable bytes."""
        return self.path.read_text(encoding="utf-8", errors="replace")


def classify(path: Path) -> str | None:
    """Return ``"python"``, ``"config"``, or ``None`` if the file is not relevant."""
    name = path.name.lower()
    if path.suffix == ".py":
        return "python"
    if name.startswith(".env") or path.suffix.lower() in CONFIG_SUFFIXES:
        return "config"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "config"
    return None


def discover_files(root: Path, *, max_file_bytes: int, max_files: int) -> tuple[list[SourceFile], list[str]]:
    """Walk ``root`` and return the files to analyze plus non-fatal warnings.

    Raises:
        ScanError: If ``root`` is not an existing directory.
    """
    root = root.resolve()
    if not root.is_dir():
        raise ScanError(f"Scan target is not a directory: {root}")

    files: list[SourceFile] = []
    warnings: list[str] = []

    def _on_walk_error(error: OSError) -> None:
        message = f"Cannot read directory {error.filename}: {error.strerror}"
        LOGGER.warning(message)
        warnings.append(message)

    for directory, subdirectories, filenames in os.walk(root, onerror=_on_walk_error, followlinks=False):
        # Prune in place so os.walk does not descend into skipped folders.
        subdirectories[:] = sorted(
            name for name in subdirectories
            if name not in SKIPPED_DIRECTORIES and not name.endswith(".egg-info")
        )
        for filename in sorted(filenames):
            path = Path(directory, filename)
            kind = classify(path)
            if kind is None:
                continue
            relative = path.relative_to(root).as_posix()
            try:
                if path.is_symlink():
                    LOGGER.debug("Skipping symlink %s", relative)
                    continue
                size = path.stat().st_size
            except OSError as error:
                warnings.append(f"Cannot stat {relative}: {error.strerror}")
                continue
            if size > max_file_bytes:
                warnings.append(f"Skipped {relative}: {size} bytes exceeds limit of {max_file_bytes}")
                continue
            if len(files) >= max_files:
                warnings.append(f"File limit of {max_files} reached; remaining files were not scanned")
                LOGGER.warning(warnings[-1])
                return files, warnings
            files.append(SourceFile(path=path, relative_path=relative, kind=kind))

    LOGGER.info("Discovered %d files under %s", len(files), root)
    return files, warnings
