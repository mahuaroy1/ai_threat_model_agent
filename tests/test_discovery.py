"""File discovery: classification, skipped folders, limits, and symlinks."""

import os
import unittest
from pathlib import Path

from ai_threat_model.discovery import classify, discover_files
from ai_threat_model.errors import ScanError
from tests.helpers import TempDirTestCase, write_project

LIMITS = {"max_file_bytes": 10_000, "max_files": 100}


class ClassifyTests(unittest.TestCase):
    def test_classification(self) -> None:
        self.assertEqual(classify(Path("agent.py")), "python")
        self.assertEqual(classify(Path(".env.local")), "config")
        self.assertEqual(classify(Path("requirements-dev.txt")), "config")
        self.assertEqual(classify(Path("langgraph.json")), "config")
        self.assertIsNone(classify(Path("README.md")))
        self.assertIsNone(classify(Path("notes.txt")))


class DiscoverTests(TempDirTestCase):
    def test_skips_dependency_and_vcs_folders(self) -> None:
        write_project(self.tmp, {
            "app/agent.py": "x = 1\n",
            "node_modules/pkg/index.py": "x = 1\n",
            ".venv/lib/site.py": "x = 1\n",
            ".git/config.json": "{}\n",
            "pkg.egg-info/setup.cfg": "[x]\n",
            "README.md": "# readme\n",
        })
        files, warnings = discover_files(self.tmp, **LIMITS)
        self.assertEqual([f.relative_path for f in files], ["app/agent.py"])
        self.assertEqual(warnings, [])

    def test_large_files_are_skipped_with_warning(self) -> None:
        write_project(self.tmp, {"big.py": "x = 1\n" * 100, "small.py": "x = 1\n"})
        files, warnings = discover_files(self.tmp, max_file_bytes=50, max_files=100)
        self.assertEqual([f.relative_path for f in files], ["small.py"])
        self.assertTrue(any("big.py" in warning for warning in warnings))

    def test_file_count_limit(self) -> None:
        write_project(self.tmp, {f"m{i}.py": "x = 1\n" for i in range(5)})
        files, warnings = discover_files(self.tmp, max_file_bytes=10_000, max_files=3)
        self.assertEqual(len(files), 3)
        self.assertTrue(any("File limit" in warning for warning in warnings))

    def test_symlinks_are_not_followed(self) -> None:
        outside = self.tmp / "outside"
        project = self.tmp / "project"
        write_project(outside, {"secret.py": "x = 1\n"})
        write_project(project, {"app.py": "x = 1\n"})
        try:
            os.symlink(outside / "secret.py", project / "linked.py")
            os.symlink(outside, project / "linked_dir", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is not permitted on this system")
        files, _ = discover_files(project, **LIMITS)
        self.assertEqual([f.relative_path for f in files], ["app.py"])

    def test_missing_root_raises(self) -> None:
        with self.assertRaises(ScanError):
            discover_files(self.tmp / "missing", **LIMITS)


if __name__ == "__main__":
    unittest.main()
