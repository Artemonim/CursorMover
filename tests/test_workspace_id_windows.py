"""Tests for workspace id computation (Windows only)."""

from __future__ import annotations

import hashlib
import os
import tempfile
import sys
import unittest
from pathlib import Path

from cursor_mover.workspace_id import compute_folder_workspace_id
from cursor_mover.workspace_storage import find_workspace_storage_id_for_folder


@unittest.skipUnless(sys.platform.startswith("win"), "Windows-only test")
class WorkspaceIdWindowsTest(unittest.TestCase):
    def test_workspace_id_is_hash_of_reported_components(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            result = compute_folder_workspace_id(folder)

            hasher = hashlib.md5()
            hasher.update(result.fs_path_for_hash.encode("utf-8"))
            hasher.update(result.stat_salt.encode("utf-8"))
            self.assertEqual(result.workspace_id, hasher.hexdigest())

            # * Workspace IDs are MD5 hex digests.
            self.assertEqual(len(result.workspace_id), 32)
            self.assertEqual(result.workspace_id, result.workspace_id.lower())

            # * Cursor/VS Code uses a lower-cased drive letter and backslashes on Windows.
            drive, _ = os.path.splitdrive(result.fs_path_for_hash)
            self.assertTrue(drive and drive[0].islower())
            self.assertIn("\\", result.fs_path_for_hash)

    def test_computed_id_matches_existing_workspace_storage_when_provided(self) -> None:
        cursor_user_dir_raw = os.environ.get("CURSOR_MOVER_TEST_CURSOR_USER_DIR", "").strip()
        workspace_path_raw = os.environ.get("CURSOR_MOVER_TEST_WORKSPACE_PATH", "").strip()
        if not cursor_user_dir_raw or not workspace_path_raw:
            self.skipTest(
                "Integration test disabled. Set CURSOR_MOVER_TEST_CURSOR_USER_DIR and "
                "CURSOR_MOVER_TEST_WORKSPACE_PATH to enable."
            )

        cursor_user_dir = Path(cursor_user_dir_raw).resolve()
        workspace_path = Path(workspace_path_raw).resolve()

        found = find_workspace_storage_id_for_folder(cursor_user_dir, workspace_path)
        self.assertIsNotNone(found, "Expected a workspaceStorage entry for the provided workspace path.")

        computed = compute_folder_workspace_id(workspace_path).workspace_id
        self.assertEqual(found, computed)

