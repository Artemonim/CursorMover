"""Merge chat-related workspace storage state between workspaceStorage entries.

This module operates on the *workspace* DB (`workspaceStorage/<id>/state.vscdb`).
It does not touch `globalStorage/state.vscdb`.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from cursor_mover.locks import WorkspaceStorageLockedError, assert_paths_unlocked


@dataclass(frozen=True, slots=True)
class MergeResult:
    """Summary of a merge operation."""

    sources: tuple[Path, ...]
    destination: Path
    inserted_itemtable_keys: int
    inserted_cursordiskkv_keys: int
    composer_ids_before: int
    composer_ids_after: int
    backup_path: Path


def merge_workspace_state(
    *,
    dst_db_path: Path,
    src_db_paths: Sequence[Path],
) -> MergeResult:
    """Merges chat-related state from `src_db_paths` into `dst_db_path`.

    Strategy:
      - Create a consistent temporary copy of the destination DB via sqlite backup.
      - Insert missing keys from sources (ItemTable + cursorDiskKV).
      - Merge `composer.composerData` (registry of composers/chats) by `composerId`.
      - Run `PRAGMA integrity_check`.
      - Swap the merged DB into place, keeping a backup of the original.

    Args:
        dst_db_path: Destination `state.vscdb` path.
        src_db_paths: Source `state.vscdb` paths.

    Returns:
        MergeResult.

    Raises:
        FileNotFoundError: If destination DB or any source DB does not exist.
        WorkspaceStorageLockedError: If destination/source DBs appear locked.
        RuntimeError: If the merged DB fails integrity check.
    """
    dst_db_path = dst_db_path.resolve()
    if not dst_db_path.exists():
        raise FileNotFoundError(dst_db_path)

    resolved_srcs = tuple(p.resolve() for p in src_db_paths)
    for p in resolved_srcs:
        if not p.exists():
            raise FileNotFoundError(p)

    # * SQLite can keep state in WAL/SHM files; treat them as part of the lock set.
    lock_targets: list[Path] = []
    for db in [dst_db_path, *resolved_srcs]:
        lock_targets.append(db)
        lock_targets.append(db.with_name(db.name + "-wal"))
        lock_targets.append(db.with_name(db.name + "-shm"))
    assert_paths_unlocked(lock_targets)

    ts = time.strftime("%Y%m%d-%H%M%S")
    tmp_db = dst_db_path.with_name(f"{dst_db_path.name}.merge-tmp-{ts}")
    backup_db = dst_db_path.with_name(f"{dst_db_path.name}.premerge-{ts}")

    # * Create a consistent copy of dst into tmp using sqlite backup API.
    src_con = sqlite3.connect(f"file:{dst_db_path.as_posix()}?mode=ro", uri=True)
    try:
        tmp_con = sqlite3.connect(tmp_db.as_posix())
        try:
            src_con.backup(tmp_con)
        finally:
            tmp_con.close()
    finally:
        src_con.close()

    inserted_item = 0
    inserted_disk = 0

    dst_con = sqlite3.connect(tmp_db.as_posix())
    try:
        dst_cur = dst_con.cursor()
        _ensure_tables_exist(dst_cur)

        dst_item_keys = {k for (k,) in dst_cur.execute("SELECT key FROM ItemTable")}
        dst_disk_keys = {k for (k,) in dst_cur.execute("SELECT key FROM cursorDiskKV")}

        dst_composer = read_kv(dst_cur, table="ItemTable", key="composer.composerData")
        composer_ids_before = len(composer_ids_from_composer_data(dst_composer))

        src_composer_values: list[bytes | None] = []

        for src_db in resolved_srcs:
            src_con = sqlite3.connect(f"file:{src_db.as_posix()}?mode=ro", uri=True)
            try:
                src_cur = src_con.cursor()
                _ensure_tables_exist(src_cur)

                src_composer_values.append(
                    read_kv(src_cur, table="ItemTable", key="composer.composerData")
                )

                for key, value in src_cur.execute("SELECT key, value FROM ItemTable"):
                    if key in dst_item_keys:
                        continue
                    dst_cur.execute("INSERT INTO ItemTable(key, value) VALUES (?, ?)", (key, value))
                    dst_item_keys.add(key)
                    inserted_item += 1

                for key, value in src_cur.execute("SELECT key, value FROM cursorDiskKV"):
                    if key in dst_disk_keys:
                        continue
                    dst_cur.execute("INSERT INTO cursorDiskKV(key, value) VALUES (?, ?)", (key, value))
                    dst_disk_keys.add(key)
                    inserted_disk += 1
            finally:
                src_con.close()

        merged_composer = _merge_composer_data(dst_composer, src_composer_values)
        if merged_composer is not None:
            dst_cur.execute(
                "INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)",
                ("composer.composerData", merged_composer),
            )
            composer_ids_after = len(composer_ids_from_composer_data(merged_composer))
        else:
            composer_ids_after = composer_ids_before

        check = dst_cur.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {check[0] if check else 'unknown'}")

        dst_con.commit()
    finally:
        dst_con.close()

    # * Swap into place.
    shutil.move(dst_db_path, backup_db)
    shutil.move(tmp_db, dst_db_path)

    return MergeResult(
        sources=resolved_srcs,
        destination=dst_db_path,
        inserted_itemtable_keys=inserted_item,
        inserted_cursordiskkv_keys=inserted_disk,
        composer_ids_before=composer_ids_before,
        composer_ids_after=composer_ids_after,
        backup_path=backup_db,
    )


def _ensure_tables_exist(cur: sqlite3.Cursor) -> None:
    # * The workspace DB uses ItemTable + cursorDiskKV (Cursor-specific).
    cur.execute(
        "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value BLOB)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)"
    )


def read_kv(cur: sqlite3.Cursor, *, table: str, key: str) -> bytes | None:
    row = cur.execute(f"SELECT value FROM {table} WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    val = row[0]
    if isinstance(val, memoryview):
        return val.tobytes()
    if isinstance(val, bytes):
        return val
    return str(val).encode("utf-8")


def composer_ids_from_composer_data(raw: bytes | None) -> set[str]:
    if not raw:
        return set()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return set()
    composers = payload.get("allComposers")
    if not isinstance(composers, list):
        return set()
    ids: set[str] = set()
    for item in composers:
        if isinstance(item, dict):
            cid = item.get("composerId")
            if isinstance(cid, str):
                ids.add(cid)
    return ids


def _merge_composer_data(dst: bytes | None, src_values: Iterable[bytes | None]) -> bytes | None:
    """Merges composer.composerData payloads by composerId."""
    # * Collect all payloads that parse as JSON objects with allComposers list.
    payloads: list[dict] = []
    for raw in [dst, *src_values]:
        if not raw:
            continue
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("allComposers"), list):
            payloads.append(parsed)

    if not payloads:
        return None

    base = payloads[0]
    merged: dict[str, dict] = {}
    for p in payloads:
        for item in p.get("allComposers", []):
            if not isinstance(item, dict):
                continue
            cid = item.get("composerId")
            if not isinstance(cid, str):
                continue
            prev = merged.get(cid)
            if prev is None:
                merged[cid] = item
                continue
            # * Prefer the most recently updated item.
            prev_ts = prev.get("lastUpdatedAt")
            new_ts = item.get("lastUpdatedAt")
            if isinstance(prev_ts, (int, float)) and isinstance(new_ts, (int, float)):
                if new_ts > prev_ts:
                    merged[cid] = item
            elif prev_ts is None and new_ts is not None:
                merged[cid] = item

    # * Sort by lastUpdatedAt (desc), fallback to createdAt.
    def sort_key(item: dict) -> int:
        ts = item.get("lastUpdatedAt")
        if isinstance(ts, (int, float)):
            return int(ts)
        ts = item.get("createdAt")
        if isinstance(ts, (int, float)):
            return int(ts)
        return 0

    merged_list = sorted(merged.values(), key=sort_key, reverse=True)
    base["allComposers"] = merged_list

    # * Keep selection/focus from base (destination).
    return json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

