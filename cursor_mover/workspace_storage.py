"""Workspace storage discovery and manipulation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from cursor_mover.cursor_paths import workspace_storage_root
from cursor_mover.workspace_uri import path_to_folder_uri


@dataclass(frozen=True, slots=True)
class WorkspaceStorageEntry:
    """Represents one `workspaceStorage/<id>` directory."""

    workspace_id: str
    storage_dir: Path
    meta_path: Path | None
    folder_uri: str | None
    workspace_config_uri: str | None


def iter_workspace_storage_entries(cursor_user_dir: Path) -> Iterator[WorkspaceStorageEntry]:
    """Iterates `workspaceStorage/*` entries and parses their `workspace.json`."""
    root = workspace_storage_root(cursor_user_dir)
    if not root.exists():
        return

    for child in root.iterdir():
        if not child.is_dir():
            continue
        workspace_id = child.name
        meta = child / "workspace.json"
        if not meta.exists():
            yield WorkspaceStorageEntry(
                workspace_id=workspace_id,
                storage_dir=child,
                meta_path=None,
                folder_uri=None,
                workspace_config_uri=None,
            )
            continue

        folder_uri = None
        workspace_uri = None
        try:
            payload = json.loads(meta.read_text(encoding="utf-8"))
            folder_uri = payload.get("folder")
            workspace_uri = payload.get("workspace")
        except (OSError, json.JSONDecodeError):
            # ! Malformed metadata should not crash discovery.
            pass

        yield WorkspaceStorageEntry(
            workspace_id=workspace_id,
            storage_dir=child,
            meta_path=meta,
            folder_uri=folder_uri,
            workspace_config_uri=workspace_uri,
        )


def find_workspace_storage_id_for_folder(cursor_user_dir: Path, folder_path: Path) -> str | None:
    """Finds an existing workspaceStorage id for a folder workspace by folder URI."""
    folder_uri = path_to_folder_uri(folder_path)
    for entry in iter_workspace_storage_entries(cursor_user_dir):
        if entry.folder_uri == folder_uri:
            return entry.workspace_id
    return None


def workspace_storage_dir(cursor_user_dir: Path, workspace_id: str) -> Path:
    """Returns `<Cursor User dir>/workspaceStorage/<workspace_id>`."""
    return workspace_storage_root(cursor_user_dir) / workspace_id


def workspace_db_paths(storage_dir: Path) -> Iterable[Path]:
    """Returns a set of database-related files to lock-check/copy."""
    # * Cursor uses SQLite for workspace state; WAL files may appear while running.
    yield storage_dir / "state.vscdb"
    yield storage_dir / "state.vscdb-wal"
    yield storage_dir / "state.vscdb-shm"

