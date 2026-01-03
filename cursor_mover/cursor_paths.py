"""Helpers to locate Cursor user data directories across platforms.

This module avoids any external dependencies to keep the tool portable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def default_cursor_user_dir() -> Path:
    """Returns the default Cursor `User` directory for the current OS.

    Returns:
        Absolute path to `.../Cursor/User`.

    Raises:
        RuntimeError: If the OS is not recognized or required env vars are missing.
    """
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError("APPDATA is not set; cannot locate Cursor User dir.")
        return Path(appdata) / "Cursor" / "User"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User"

    # * Assume Linux / other Unix-like.
    return Path.home() / ".config" / "Cursor" / "User"


def workspace_storage_root(cursor_user_dir: Path) -> Path:
    """Returns `workspaceStorage` directory under Cursor User dir."""
    return cursor_user_dir / "workspaceStorage"


def global_storage_dir(cursor_user_dir: Path) -> Path:
    """Returns `globalStorage` directory under Cursor User dir."""
    return cursor_user_dir / "globalStorage"

