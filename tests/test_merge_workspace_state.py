"""Integration-style tests for workspace DB merge.

These tests create temporary SQLite DBs with the tables used by Cursor's
workspaceStorage `state.vscdb` and validate that `merge_workspace_state`:
  - inserts missing keys from sources;
  - merges composer.composerData;
  - writes a backup of the original destination DB.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cursor_mover.merge import merge_workspace_state


def _create_workspace_db(path: Path, *, itemtable: dict[str, bytes], disk_kv: dict[str, bytes]) -> None:
    con = sqlite3.connect(path.as_posix())
    try:
        cur = con.cursor()
        cur.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
        cur.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")

        for key, value in itemtable.items():
            cur.execute("INSERT INTO ItemTable(key, value) VALUES (?, ?)", (key, value))
        for key, value in disk_kv.items():
            cur.execute("INSERT INTO cursorDiskKV(key, value) VALUES (?, ?)", (key, value))

        con.commit()
    finally:
        con.close()


def _read_itemtable_value(db_path: Path, key: str) -> bytes | None:
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        row = cur.execute("SELECT value FROM ItemTable WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        val = row[0]
        if isinstance(val, memoryview):
            return val.tobytes()
        if isinstance(val, bytes):
            return val
        return str(val).encode("utf-8")
    finally:
        con.close()


class MergeWorkspaceStateTest(unittest.TestCase):
    def test_merge_inserts_missing_keys_and_merges_composer_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            dst = tmp_path / "dst.state.vscdb"
            src1 = tmp_path / "src1.state.vscdb"
            src2 = tmp_path / "src2.state.vscdb"

            dst_composer = {
                "allComposers": [
                    {"composerId": "a", "lastUpdatedAt": 10, "name": "A"},
                    {"composerId": "b", "lastUpdatedAt": 5, "name": "B"},
                ],
                "selectedComposerIds": ["a"],
            }
            src1_composer = {
                "allComposers": [
                    {"composerId": "b", "lastUpdatedAt": 7, "name": "B2"},
                    {"composerId": "c", "lastUpdatedAt": 3, "name": "C"},
                ]
            }

            _create_workspace_db(
                dst,
                itemtable={
                    "composer.composerData": json.dumps(dst_composer).encode("utf-8"),
                    "k1": b"v1",
                },
                disk_kv={"d1": b"x"},
            )
            _create_workspace_db(
                src1,
                itemtable={
                    # * Duplicate should be ignored.
                    "k1": b"v1-dup",
                    "k2": b"v2",
                    "composer.composerData": json.dumps(src1_composer).encode("utf-8"),
                },
                disk_kv={"d2": b"y"},
            )
            _create_workspace_db(
                src2,
                itemtable={"k3": b"v3"},
                disk_kv={
                    # * Duplicate should be ignored.
                    "d2": b"y-dup",
                    "d3": b"z",
                },
            )

            result = merge_workspace_state(dst_db_path=dst, src_db_paths=[src1, src2])

            self.assertTrue(result.backup_path.exists())
            self.assertEqual(result.inserted_itemtable_keys, 2)  # k2 + k3
            self.assertEqual(result.inserted_cursordiskkv_keys, 2)  # d2 + d3
            self.assertEqual(result.composer_ids_before, 2)
            self.assertEqual(result.composer_ids_after, 3)

            # * Destination keeps original key and gains new keys.
            self.assertEqual(_read_itemtable_value(dst, "k1"), b"v1")
            self.assertEqual(_read_itemtable_value(dst, "k2"), b"v2")
            self.assertEqual(_read_itemtable_value(dst, "k3"), b"v3")

            merged_raw = _read_itemtable_value(dst, "composer.composerData")
            self.assertIsNotNone(merged_raw)
            merged = json.loads(merged_raw.decode("utf-8"))
            ids = {c["composerId"] for c in merged.get("allComposers", [])}
            self.assertEqual(ids, {"a", "b", "c"})

            # * b should come from src1 (newer lastUpdatedAt).
            b_item = next(c for c in merged["allComposers"] if c["composerId"] == "b")
            self.assertEqual(b_item["name"], "B2")

            # * Backup contains the pre-merge payload.
            backup_raw = _read_itemtable_value(result.backup_path, "composer.composerData")
            self.assertIsNotNone(backup_raw)
            backup = json.loads(backup_raw.decode("utf-8"))
            backup_ids = {c["composerId"] for c in backup.get("allComposers", [])}
            self.assertEqual(backup_ids, {"a", "b"})

