"""Workspace ID computation compatible with Cursor/VS Code workspaceStorage layout.

Cursor stores per-workspace data in:

  <Cursor User dir>/workspaceStorage/<workspace_id>/

Where `workspace_id` is derived from the workspace location.

Important:
  The ID for a folder workspace is NOT derived from the `file:///...` URI string.
  It's derived from the filesystem path and platform-specific stat metadata:

  - Windows: md5(fsPath + birthtimeMs)
  - macOS:   md5(fsPath + birthtimeMs)
  - Linux:   md5(fsPath + inode)
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class WorkspaceIdResult:
    """Computed workspace id along with components used for hashing."""

    workspace_id: str
    fs_path_for_hash: str
    stat_salt: str


def compute_folder_workspace_id(path: Path) -> WorkspaceIdResult:
    """Computes the workspaceStorage id for a folder workspace path.

    Args:
        path: Folder path of the workspace (must exist).

    Returns:
        WorkspaceIdResult containing the computed id and inputs used.

    Raises:
        FileNotFoundError: If the path does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(resolved)
    if not resolved.is_dir():
        raise NotADirectoryError(resolved)

    stat = os.stat(resolved)
    fs_path = _normalize_fs_path_for_hash(resolved)
    salt = _stat_salt_for_platform(stat)

    hasher = hashlib.md5()
    hasher.update(fs_path.encode("utf-8"))
    hasher.update(salt.encode("utf-8"))
    return WorkspaceIdResult(
        workspace_id=hasher.hexdigest(),
        fs_path_for_hash=fs_path,
        stat_salt=salt,
    )


def _normalize_fs_path_for_hash(path: Path) -> str:
    # * This replicates `URI.fsPath` normalization used by the app:
    # * - Windows drive letter becomes lower-case
    # * - Windows uses backslashes
    if sys.platform.startswith("win"):
        p = str(path)
        drive, rest = os.path.splitdrive(p)
        if drive and len(drive) >= 2 and drive[1] == ":":
            drive = drive[0].lower() + drive[1:]
        return (drive + rest).replace("/", "\\")

    return path.as_posix()


def _stat_salt_for_platform(stat: os.stat_result) -> str:
    # * Linux: inode is stable for rename on same filesystem and matches upstream logic.
    if sys.platform.startswith("linux"):
        return str(stat.st_ino)

    # * Windows/macOS: use "birthtime" milliseconds.
    birth_s = getattr(stat, "st_birthtime", None)
    if birth_s is None:
        # * On Windows, Python exposes creation time as st_ctime.
        birth_s = stat.st_ctime

    birth_ms = int(birth_s * 1000)
    return str(birth_ms)

