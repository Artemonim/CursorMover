"""Unit tests for lock detection helpers."""

from __future__ import annotations

import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path

from cursor_mover.locks import WorkspaceStorageLockedError, assert_paths_unlocked, probe_path_lock


def _posix_lock_file(path_raw: str, ready: multiprocessing.Event, stop: multiprocessing.Event) -> None:
    # * Run in a separate process to ensure fcntl locks are not owned by the parent process.
    import fcntl  # pylint: disable=import-outside-toplevel
    import os  # pylint: disable=import-outside-toplevel

    fd = os.open(path_raw, os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX)
        ready.set()
        stop.wait(5.0)
    finally:
        os.close(fd)


class LocksTest(unittest.TestCase):
    def test_probe_path_lock_returns_none_for_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.txt"
            self.assertIsNone(probe_path_lock(missing))

    def test_probe_path_lock_detects_locked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "locked.txt"
            path.write_text("x", encoding="utf-8")

            if sys.platform.startswith("win"):
                # * On Windows, CreateFileW with shareMode=0 must fail while any handle is open.
                fh = path.open("rb")
                try:
                    self.assertIsNotNone(probe_path_lock(path))
                finally:
                    fh.close()
                return

            # * POSIX: fcntl locks are per-process, so we lock in a separate process.
            ready = multiprocessing.Event()
            stop = multiprocessing.Event()
            proc = multiprocessing.Process(
                target=_posix_lock_file,
                args=(str(path), ready, stop),
            )
            proc.start()
            try:
                self.assertTrue(ready.wait(5.0), "Expected lock-holder process to acquire lock.")
                self.assertIsNotNone(probe_path_lock(path))
            finally:
                stop.set()
                proc.join(timeout=5.0)
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=5.0)

    def test_assert_paths_unlocked_raises_for_locked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "locked.txt"
            path.write_text("x", encoding="utf-8")

            if sys.platform.startswith("win"):
                fh = path.open("rb")
                try:
                    with self.assertRaises(WorkspaceStorageLockedError):
                        assert_paths_unlocked([path])
                finally:
                    fh.close()
                return

            ready = multiprocessing.Event()
            stop = multiprocessing.Event()
            proc = multiprocessing.Process(
                target=_posix_lock_file,
                args=(str(path), ready, stop),
            )
            proc.start()
            try:
                self.assertTrue(ready.wait(5.0), "Expected lock-holder process to acquire lock.")
                with self.assertRaises(WorkspaceStorageLockedError):
                    assert_paths_unlocked([path])
            finally:
                stop.set()
                proc.join(timeout=5.0)
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=5.0)

