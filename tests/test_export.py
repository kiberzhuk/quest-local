import tempfile
import unittest
from pathlib import Path

from export_source import ROOT, TOP_LEVEL, source_files


class ExportTests(unittest.TestCase):
    def test_real_source_list_excludes_artifacts(self):
        names = [path.relative_to(ROOT).as_posix() for path in source_files()]
        self.assertIn("app.py", names)
        self.assertIn("LICENSE", names)
        self.assertIn(".github/workflows/tests.yml", names)
        for name in names:
            self.assertFalse(any(part in name.split("/") for part in
                                 (".venv", "__pycache__", "test-apk", "exports")))
            self.assertNotIn(Path(name).suffix, (".apk", ".p12", ".log", ".out", ".pyc"))

    def test_unlisted_root_files_are_never_added(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in TOP_LEVEL:
                (root / name).write_text("placeholder", encoding="utf-8")
            for name in ("token.json", "account.txt", "debug.py", "dump.xml", "adbkey"):
                (root / name).write_text("must not publish", encoding="utf-8")
            self.assertEqual({p.name for p in source_files(root)}, set(TOP_LEVEL))

    def test_missing_required_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                list(source_files(Path(directory)))
