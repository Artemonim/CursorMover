"""File URI encoding/decoding compatible with Cursor workspace metadata."""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlparse


def path_to_folder_uri(path: Path) -> str:
    """Converts a filesystem path to a `file:///...` URI string used by Cursor.

    The output is intended to match what Cursor writes into `workspaceStorage/*/workspace.json`.
    On Windows, the drive letter is lower-cased and `:` is percent-encoded as `%3A`.

    Args:
        path: Absolute or relative filesystem path.

    Returns:
        A `file:///...` URI string.

    Raises:
        ValueError: If `path` is not absolute after resolution.
    """
    resolved = path.resolve()
    if sys.platform.startswith("win"):
        # * Example: G:\GitHub\CursorMover -> file:///g%3A/GitHub/CursorMover
        drive = resolved.drive
        if not drive or len(drive) < 2 or drive[1] != ":":
            raise ValueError(f"Expected a drive path, got: {resolved}")
        drive_letter = drive[0].lower()
        # PurePosix-like string: "G:/GitHub/CursorMover"
        posix = resolved.as_posix()
        # Strip "G:" prefix.
        suffix = posix[2:]
        # Ensure suffix starts with a slash.
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return "file:///" + drive_letter + "%3A" + quote(suffix, safe="/")

    # * POSIX: /home/user/proj -> file:///home/user/proj
    posix_path = resolved.as_posix()
    if not posix_path.startswith("/"):
        raise ValueError(f"Expected an absolute POSIX path, got: {posix_path}")
    return "file://" + quote(posix_path, safe="/")


def folder_uri_to_path(folder_uri: str) -> Path:
    """Best-effort conversion from a `file:///...` folder URI to a filesystem path.

    Args:
        folder_uri: A `file://` URI.

    Returns:
        Path corresponding to the URI.

    Raises:
        ValueError: If the URI is not a `file` URI.
    """
    parsed = urlparse(folder_uri)
    if parsed.scheme != "file":
        raise ValueError(f"Expected file URI, got: {folder_uri}")

    raw_path = unquote(parsed.path)
    if sys.platform.startswith("win"):
        # * /g:/GitHub/CursorMover -> g:\GitHub\CursorMover
        if raw_path.startswith("/") and len(raw_path) >= 4 and raw_path[2] == ":":
            raw_path = raw_path[1:]
        return Path(raw_path.replace("/", "\\"))

    return Path(raw_path)

