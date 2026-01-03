"""Filesystem copy utilities with progress reporting."""

from __future__ import annotations

import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cursor_mover.console import info

try:
    from tqdm import tqdm  # type: ignore
except ImportError:  # pragma: no cover
    tqdm = None


@dataclass(frozen=True, slots=True)
class CopyPlan:
    """Planned copy operation for a directory tree."""

    dirs: tuple[Path, ...]
    files: tuple[Path, ...]
    total_bytes: int


@dataclass(frozen=True, slots=True)
class CopyStats:
    """Statistics for a completed copy operation."""

    files_copied: int
    dirs_created: int
    bytes_copied: int
    duration_s: float

    @property
    def bytes_per_second(self) -> float:
        if self.duration_s <= 0:
            return 0.0
        return self.bytes_copied / self.duration_s


def build_copy_plan(src_dir: Path) -> CopyPlan:
    """Builds a copy plan (directory list, file list, and total size)."""
    src_dir = src_dir.resolve()

    dirs: list[Path] = []
    files: list[Path] = []
    total_bytes = 0

    for root, dirnames, filenames in os.walk(src_dir):
        root_path = Path(root)
        rel_root = root_path.relative_to(src_dir)
        dirs.append(rel_root)

        # * Ensure a stable order for deterministic progress output.
        dirnames.sort()
        filenames.sort()

        for filename in filenames:
            rel_file = rel_root / filename
            files.append(rel_file)
            try:
                total_bytes += (src_dir / rel_file).stat().st_size
            except OSError:
                # ! If we cannot stat, still attempt to copy; size is unknown.
                pass

    return CopyPlan(dirs=tuple(dirs), files=tuple(files), total_bytes=total_bytes)


def copy_tree_with_progress(
    *,
    src_dir: Path,
    dst_dir: Path,
    desc: str,
    chunk_size: int = 4 * 1024 * 1024,
) -> CopyStats:
    """Copies a directory tree with a progress bar.

    Args:
        src_dir: Source directory.
        dst_dir: Destination directory (must not exist).
        desc: Progress bar label.
        chunk_size: Chunk size for streaming file copy.

    Returns:
        CopyStats.

    Raises:
        FileExistsError: If destination exists.
    """
    src_dir = src_dir.resolve()
    dst_dir = dst_dir.resolve()

    if dst_dir.exists():
        raise FileExistsError(dst_dir)

    info(f"{desc}: scanning files...")
    plan = _build_copy_plan_with_optional_progress(src_dir=src_dir, desc=desc)
    start = time.perf_counter()

    info(f"{desc}: scan complete (files={len(plan.files)}, dirs={len(plan.dirs)})")
    info(f"{desc}: preparing destination...")
    dst_dir.mkdir(parents=True, exist_ok=False)
    for rel_dir in plan.dirs:
        (dst_dir / rel_dir).mkdir(parents=True, exist_ok=True)

    if tqdm is None or not _is_progress_enabled():
        if tqdm is None and sys.stderr.isatty():
            print(
                "WARNING: tqdm is not installed; progress bars are disabled. "
                "Install requirements.txt (or use the project's venv).",
                file=sys.stderr,
            )
        info(f"{desc}: copying files...")
        for rel_file in plan.files:
            _copy_file_streaming(
                src=src_dir / rel_file,
                dst=dst_dir / rel_file,
                chunk_size=chunk_size,
                progress=None,
            )
    else:
        total = plan.total_bytes if plan.total_bytes > 0 else None
        info(f"{desc}: copying files...")
        with tqdm(
            total=total,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=desc,
            leave=True,
        ) as pbar:
            for rel_file in plan.files:
                _copy_file_streaming(
                    src=src_dir / rel_file,
                    dst=dst_dir / rel_file,
                    chunk_size=chunk_size,
                    progress=pbar,
                )

    duration_s = time.perf_counter() - start
    bytes_copied = _safe_sum_sizes(src_dir, plan.files)
    return CopyStats(
        files_copied=len(plan.files),
        dirs_created=len(plan.dirs),
        bytes_copied=bytes_copied,
        duration_s=duration_s,
    )


def _safe_sum_sizes(src_dir: Path, rel_files: Iterable[Path]) -> int:
    total = 0
    for rel_file in rel_files:
        try:
            total += (src_dir / rel_file).stat().st_size
        except OSError:
            pass
    return total


def _copy_file_streaming(
    *,
    src: Path,
    dst: Path,
    chunk_size: int,
    progress,
) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    with src.open("rb") as rfh, dst.open("wb") as wfh:
        while True:
            chunk = rfh.read(chunk_size)
            if not chunk:
                break
            wfh.write(chunk)
            copied += len(chunk)
            if progress is not None:
                progress.update(len(chunk))

    # * Preserve timestamps and other metadata.
    shutil.copystat(src, dst, follow_symlinks=True)

    # * If total size was unknown (stat failed) we still advance progress by copied bytes.
    if progress is not None and copied == 0:
        progress.update(0)


def _is_progress_enabled() -> bool:
    # * tqdm writes to stderr by default.
    return sys.stderr.isatty()


def _build_copy_plan_with_optional_progress(*, src_dir: Path, desc: str) -> CopyPlan:
    if tqdm is None or not _is_progress_enabled():
        return build_copy_plan(src_dir)

    with tqdm(
        total=None,
        unit="file",
        desc=f"{desc} (scan)",
        leave=False,
    ) as scan:
        # * Force initial render to avoid a "silent" gap before first update.
        scan.update(0)
        src_dir = src_dir.resolve()

        dirs: list[Path] = []
        files: list[Path] = []
        total_bytes = 0

        for root, dirnames, filenames in os.walk(src_dir):
            root_path = Path(root)
            rel_root = root_path.relative_to(src_dir)
            dirs.append(rel_root)

            # * Ensure a stable order for deterministic progress output.
            dirnames.sort()
            filenames.sort()

            for filename in filenames:
                rel_file = rel_root / filename
                files.append(rel_file)
                scan.update(1)
                try:
                    total_bytes += (src_dir / rel_file).stat().st_size
                except OSError:
                    # ! If we cannot stat, still attempt to copy; size is unknown.
                    pass

        return CopyPlan(dirs=tuple(dirs), files=tuple(files), total_bytes=total_bytes)

