"""Tests for copy utilities."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cursor_mover.copying import copy_tree_with_progress


class CopyingTest(unittest.TestCase):
    def test_copy_tree_with_progress_copies_files_and_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "src"
            dst = tmp_path / "dst"

            (src / "a").mkdir(parents=True)
            (src / "empty").mkdir(parents=True)
            (src / "a" / "b").mkdir(parents=True)

            (src / "root.txt").write_bytes(b"hello")
            (src / "a" / "b" / "nested.bin").write_bytes(b"\x00\x01\x02")

            stats = copy_tree_with_progress(src_dir=src, dst_dir=dst, desc="test")
            self.assertTrue((dst / "root.txt").exists())
            self.assertTrue((dst / "a" / "b" / "nested.bin").exists())
            self.assertTrue((dst / "empty").is_dir())

            self.assertEqual((dst / "root.txt").read_bytes(), b"hello")
            self.assertEqual((dst / "a" / "b" / "nested.bin").read_bytes(), b"\x00\x01\x02")

            self.assertEqual(stats.files_copied, 2)
            self.assertGreaterEqual(stats.dirs_created, 1)
            self.assertGreater(stats.bytes_copied, 0)
            self.assertGreaterEqual(stats.duration_s, 0.0)

            # * Sanity: dst tree has exactly the same number of files.
            dst_files = sum(len(files) for _, _, files in os.walk(dst))
            self.assertEqual(dst_files, 2)

