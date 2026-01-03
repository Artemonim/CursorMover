"""Unit tests for file URI conversion helpers."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from cursor_mover.workspace_uri import folder_uri_to_path, path_to_folder_uri


class WorkspaceUriTest(unittest.TestCase):
    def test_roundtrip_path_to_folder_uri(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()

            uri = path_to_folder_uri(folder)
            self.assertTrue(uri.startswith("file:///"))

            roundtrip = folder_uri_to_path(uri).resolve()
            self.assertEqual(roundtrip, folder)

            if sys.platform.startswith("win"):
                # * Example: file:///c%3A/Users/...
                self.assertRegex(uri, r"^file:///[a-z]%3A/")

    def test_folder_uri_to_path_rejects_non_file_uri(self) -> None:
        with self.assertRaises(ValueError):
            folder_uri_to_path("https://example.com/not-a-file-uri")

