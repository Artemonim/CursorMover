"""Cross-platform checks for file locks.

This module is intentionally conservative: if we cannot prove the file is
available, we treat it as "locked" and abort the operation.
"""

from __future__ import annotations

import errno
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class WorkspaceStorageLockedError(RuntimeError):
    """Raised when workspace storage files appear to be in-use/locked."""


@dataclass(frozen=True, slots=True)
class LockedPath:
    """Represents a locked path detected by the lock probe."""

    path: Path
    reason: str


def assert_paths_unlocked(paths: Iterable[Path]) -> None:
    """Raises if any of the provided paths are locked/in use.

    Args:
        paths: Paths to check.

    Raises:
        WorkspaceStorageLockedError: If one or more paths are locked.
    """
    locked = [lp for lp in (probe_path_lock(p) for p in paths) if lp is not None]
    if not locked:
        return

    details = "\n".join(f"- {lp.path}: {lp.reason}" for lp in locked)
    raise WorkspaceStorageLockedError(
        "Workspace storage appears to be locked by another process.\n"
        "Close Cursor (and any other app using these files) and retry.\n"
        f"Locked paths:\n{details}"
    )


def probe_path_lock(path: Path) -> LockedPath | None:
    """Returns lock info if a path is locked, else None.

    Notes:
        - If the path does not exist, it's treated as unlocked (nothing to lock).
        - On Windows we use CreateFile with shareMode=0 to detect any open handle.
        - On POSIX we use `fcntl.lockf` exclusive lock (non-blocking).
    """
    if not path.exists():
        return None

    if sys.platform.startswith("win"):
        return _probe_windows_share_none(path)

    return _probe_posix_lockf(path)


def _probe_posix_lockf(path: Path) -> LockedPath | None:
    # * This uses advisory locks compatible with SQLite's fcntl locking model.
    import fcntl  # pylint: disable=import-outside-toplevel

    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:  # noqa: PERF203 - we need errno
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return LockedPath(path=path, reason=f"posix lockf denied (errno={exc.errno})")
            return LockedPath(path=path, reason=f"posix lockf error (errno={exc.errno})")
        return None
    finally:
        os.close(fd)


def _probe_windows_share_none(path: Path) -> LockedPath | None:
    # * CreateFileW shareMode=0 fails if ANY handle is already open (sharing violation).
    import ctypes  # pylint: disable=import-outside-toplevel
    from ctypes import wintypes  # pylint: disable=import-outside-toplevel

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    create_file_w = kernel32.CreateFileW
    create_file_w.argtypes = [
        wintypes.LPCWSTR,  # lpFileName
        wintypes.DWORD,  # dwDesiredAccess
        wintypes.DWORD,  # dwShareMode
        wintypes.LPVOID,  # lpSecurityAttributes
        wintypes.DWORD,  # dwCreationDisposition
        wintypes.DWORD,  # dwFlagsAndAttributes
        wintypes.HANDLE,  # hTemplateFile
    ]
    create_file_w.restype = wintypes.HANDLE

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    share_none = 0x00000000
    open_existing = 3
    file_attribute_normal = 0x00000080
    invalid_handle_value = wintypes.HANDLE(-1).value

    handle = create_file_w(
        str(path),
        generic_read,
        share_none,
        None,
        open_existing,
        file_attribute_normal,
        None,
    )
    if handle == invalid_handle_value:
        winerr = ctypes.get_last_error()
        # * 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION
        if winerr in (32, 33):
            return LockedPath(path=path, reason=f"windows sharing/lock violation (winerr={winerr})")
        return LockedPath(path=path, reason=f"windows CreateFileW failed (winerr={winerr})")

    try:
        return None
    finally:
        close_handle(handle)

