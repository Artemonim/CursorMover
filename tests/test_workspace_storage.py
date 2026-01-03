"""Unit tests for `workspaceStorage` discovery helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cursor_mover.workspace_storage import find_workspace_storage_id_for_folder, iter_workspace_storage_entries
from cursor_mover.workspace_uri import path_to_folder_uri


class WorkspaceStorageTest(unittest.TestCase):
    def test_iter_workspace_storage_entries_parses_workspace_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()

            cursor_user_dir = tmp_path / "Cursor" / "User"
            root = cursor_user_dir / "workspaceStorage"
            root.mkdir(parents=True)

            workspace_folder = tmp_path / "workspace"
            workspace_folder.mkdir()
            folder_uri = path_to_folder_uri(workspace_folder)

            good = root / "aaa"
            good.mkdir()
            (good / "workspace.json").write_text(json.dumps({"folder": folder_uri}), encoding="utf-8")

            bad_json = root / "bbb"
            bad_json.mkdir()
            (bad_json / "workspace.json").write_text("{bad json", encoding="utf-8")

            no_meta = root / "ccc"
            no_meta.mkdir()

            entries = {e.workspace_id: e for e in iter_workspace_storage_entries(cursor_user_dir)}
            self.assertEqual(set(entries.keys()), {"aaa", "bbb", "ccc"})

            self.assertEqual(entries["aaa"].folder_uri, folder_uri)
            self.assertIsNone(entries["bbb"].folder_uri)
            self.assertIsNone(entries["ccc"].meta_path)

            found = find_workspace_storage_id_for_folder(cursor_user_dir, workspace_folder)
            self.assertEqual(found, "aaa")

