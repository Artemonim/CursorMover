"""CLI for CursorMover."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import time
from pathlib import Path

from cursor_mover.console import error, info, success, warn
from cursor_mover.copying import CopyStats, copy_tree_with_progress
from cursor_mover.cursor_paths import default_cursor_user_dir
from cursor_mover.locks import WorkspaceStorageLockedError, assert_paths_unlocked
from cursor_mover.merge import MergeResult, merge_workspace_state
from cursor_mover.prompts import is_interactive, prompt_choice, prompt_yes_no
from cursor_mover.tui import run_tui
from cursor_mover.workspace_id import compute_folder_workspace_id
from cursor_mover.workspace_storage import (
    iter_workspace_storage_entries,
    find_workspace_storage_id_for_folder,
    workspace_db_paths,
    workspace_storage_dir,
)
from cursor_mover.workspace_uri import path_to_folder_uri


def main(argv: list[str] | None = None) -> int:
    try:
        if argv is None:
            argv = sys.argv[1:]
        if not argv and is_interactive():
            tui_cfg = run_tui()
            if tui_cfg is None:
                return 0
            argv = _tui_config_to_argv(tui_cfg)

        parser = argparse.ArgumentParser(prog="cursor-mover")
        parser.add_argument(
            "--cursor-user-dir",
            type=Path,
            default=None,
            help="Override Cursor User directory (default: auto-detect).",
        )

        sub = parser.add_subparsers(dest="cmd", required=True)

        doctor = sub.add_parser("doctor", help="Show derived workspace ids and Cursor storage mapping.")
        doctor.add_argument("--path", type=Path, required=True, help="Workspace folder path.")

        merge_cmd = sub.add_parser(
            "merge",
            help="Merge chat state from other workspaceStorage entries for the same folder URI into the current one.",
        )
        merge_cmd.add_argument("--path", type=Path, required=True, help="Workspace folder path to merge into.")
        merge_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts.",
        )
        merge_cmd.add_argument(
            "--delete-sources",
            action="store_true",
            help="Delete merged source workspaceStorage folders after successful merge.",
        )

        copy_cmd = sub.add_parser("copy", help="Copy a workspace folder and clone its Cursor chat history (mode C).")
        copy_cmd.add_argument("--src", type=Path, required=True, help="Source folder.")
        copy_cmd.add_argument("--dst", type=Path, required=True, help="Destination folder.")
        copy_cmd.add_argument(
            "--overwrite-dst",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination folder if it already exists.",
        )
        copy_cmd.add_argument(
            "--overwrite-workspace-storage",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination workspaceStorage/<id> if it already exists.",
        )
        copy_cmd.add_argument(
            "--merge-workspace-storage",
            action="store_true",
            help=(
                "If destination workspaceStorage/<id> already exists, merge source chat state into it "
                "(preserve any destination chats) instead of overwriting."
            ),
        )
        copy_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts (overwrite/unsafe).",
        )
        copy_cmd.add_argument(
            "--unsafe-db",
            "-UnsafeDB",
            "--unlock",
            "-Unlock",
            dest="unsafe_db",
            action="store_true",
            help="Ignore workspaceStorage DB lock check (unsafe; may copy inconsistent state).",
        )

        move_cmd = sub.add_parser(
            "move", help="Move a workspace folder and migrate its Cursor chat history (mode C)."
        )
        move_cmd.add_argument("--src", type=Path, required=True, help="Source folder.")
        move_cmd.add_argument("--dst", type=Path, required=True, help="Destination folder.")
        move_cmd.add_argument(
            "--overwrite-dst",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination folder if it already exists.",
        )
        move_cmd.add_argument(
            "--overwrite-workspace-storage",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination workspaceStorage/<id> if it already exists.",
        )
        move_cmd.add_argument(
            "--merge-workspace-storage",
            action="store_true",
            help=(
                "If destination workspaceStorage/<id> already exists, merge source chat state into it "
                "(preserve any destination chats) instead of overwriting."
            ),
        )
        move_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts (overwrite/unsafe).",
        )
        move_cmd.add_argument(
            "--unsafe-db",
            "-UnsafeDB",
            "--unlock",
            "-Unlock",
            dest="unsafe_db",
            action="store_true",
            help="Ignore workspaceStorage DB lock check (unsafe; may copy inconsistent state).",
        )

        args = parser.parse_args(argv)
        cursor_user_dir = args.cursor_user_dir or default_cursor_user_dir()

        try:
            if args.cmd == "doctor":
                _cmd_doctor(cursor_user_dir, args.path)
                return 0
            if args.cmd == "merge":
                _cmd_merge(
                    cursor_user_dir=cursor_user_dir,
                    path=args.path,
                    assume_yes=args.yes,
                    delete_sources=args.delete_sources,
                )
                return 0
            if args.cmd == "copy":
                _cmd_copy_mode_c(
                    cursor_user_dir=cursor_user_dir,
                    src=args.src,
                    dst=args.dst,
                    overwrite_dst=args.overwrite_dst,
                    overwrite_workspace_storage=args.overwrite_workspace_storage,
                    merge_workspace_storage=args.merge_workspace_storage,
                    unsafe_db=args.unsafe_db,
                    assume_yes=args.yes,
                )
                return 0
            if args.cmd == "move":
                _cmd_move_mode_c(
                    cursor_user_dir=cursor_user_dir,
                    src=args.src,
                    dst=args.dst,
                    overwrite_dst=args.overwrite_dst,
                    overwrite_workspace_storage=args.overwrite_workspace_storage,
                    merge_workspace_storage=args.merge_workspace_storage,
                    unsafe_db=args.unsafe_db,
                    assume_yes=args.yes,
                )
                return 0
        except WorkspaceStorageLockedError as exc:
            error(str(exc))
            return 2
        except (FileExistsError, FileNotFoundError, PermissionError, NotADirectoryError, ValueError) as exc:
            error(str(exc))
            return 2
        except OSError as exc:
            # * Handle common Windows "invalid path" user input.
            if getattr(exc, "winerror", None) == 123:
                error(str(exc))
                return 2
            raise

        raise RuntimeError(f"Unhandled command: {args.cmd}")
    except KeyboardInterrupt:
        # * Handle Ctrl+C gracefully in all interactive stages (TUI prompts, copying, etc.).
        print(file=sys.stderr, flush=True)
        warn("Interrupted by user (Ctrl+C).")
        return 130


def _cmd_doctor(cursor_user_dir: Path, folder: Path) -> None:
    folder = folder.resolve()
    folder_uri = path_to_folder_uri(folder)
    computed = compute_folder_workspace_id(folder)
    found_ids = sorted(
        {e.workspace_id for e in iter_workspace_storage_entries(cursor_user_dir) if e.folder_uri == folder_uri}
    )
    found_str = ", ".join(found_ids) if found_ids else "None"

    info(f"Cursor User dir: {cursor_user_dir}")
    info(f"Folder: {folder}")
    info(f"Folder URI: {folder_uri}")
    info(f"WorkspaceStorage ids (found by workspace.json): {found_str}")
    info(f"WorkspaceStorage id (computed): {computed.workspace_id}")
    info(f"Computed fsPath: {computed.fs_path_for_hash}")
    info(f"Computed stat salt: {computed.stat_salt}")

    if found_ids and computed.workspace_id not in found_ids:
        warn(
            "Computed workspaceStorage id does not match ids found by workspace.json. "
            "Cursor may create a new workspaceStorage entry for this folder."
        )
        warn("If chats appear missing, open the folder once in Cursor, then run merge to consolidate.")
        warn(f"Suggested fix (after opening once): python -m cursor_mover merge --path \"{folder}\"")

    if len(found_ids) > 1:
        warn("Multiple workspaceStorage entries found for this folder URI. Chat history may appear split.")
        warn(f"Suggested fix: python -m cursor_mover merge --path \"{folder}\"")

    lock_storage: Path | None = None
    computed_storage = workspace_storage_dir(cursor_user_dir, computed.workspace_id)
    if computed_storage.exists():
        lock_storage = computed_storage
    elif found_ids:
        lock_storage = workspace_storage_dir(cursor_user_dir, found_ids[0])

    if lock_storage is not None:
        dbs = list(workspace_db_paths(lock_storage))
        try:
            assert_paths_unlocked(dbs)
        except WorkspaceStorageLockedError as exc:
            error("LOCK CHECK: FAILED\n" + str(exc))
            return
        success("LOCK CHECK: OK")


def _cmd_merge(
    *,
    cursor_user_dir: Path,
    path: Path,
    assume_yes: bool,
    delete_sources: bool,
) -> None:
    folder = path.resolve()
    folder_uri = path_to_folder_uri(folder)
    dst_id = compute_folder_workspace_id(folder).workspace_id
    dst_storage = workspace_storage_dir(cursor_user_dir, dst_id)
    dst_db = dst_storage / "state.vscdb"

    if not dst_storage.exists():
        raise FileNotFoundError(
            "Destination workspaceStorage folder does not exist. "
            "Open the folder once in Cursor or run copy/move first."
        )

    # * Find other workspaceStorage entries that refer to the same folder URI.
    sources: list[Path] = []
    for entry in iter_workspace_storage_entries(cursor_user_dir):
        if entry.folder_uri != folder_uri:
            continue
        if entry.workspace_id == dst_id:
            continue
        candidate = entry.storage_dir / "state.vscdb"
        if candidate.exists():
            sources.append(candidate)

    if not sources:
        info("Nothing to merge: no other workspaceStorage entries found for this folder URI.")
        return

    # * Require unlocked DBs; merging writes and needs safe file swaps.
    _require_unlocked_for_merge(dst_db, sources)

    result = merge_workspace_state(dst_db_path=dst_db, src_db_paths=sources)
    success("OK")
    info(f"Merged sources: {len(result.sources)}")
    info(
        "Inserted keys: ItemTable="
        + str(result.inserted_itemtable_keys)
        + " cursorDiskKV="
        + str(result.inserted_cursordiskkv_keys)
    )
    info(f"Composer entries: {result.composer_ids_before} -> {result.composer_ids_after}")
    info(f"Backup: {result.backup_path}")

    if delete_sources:
        if not assume_yes and is_interactive():
            if not prompt_yes_no("Delete merged source workspaceStorage folders?", default=False):
                return
        for src_db in result.sources:
            _robust_rmtree(src_db.parent)
        info("Deleted merged source workspaceStorage folders.")


def _require_unlocked_for_merge(dst_db: Path, src_dbs: list[Path]) -> None:
    # * SQLite can keep state in WAL/SHM files; treat them as part of the lock set.
    lock_targets: list[Path] = []
    for db in [dst_db, *src_dbs]:
        lock_targets.append(db)
        lock_targets.append(db.with_name(db.name + "-wal"))
        lock_targets.append(db.with_name(db.name + "-shm"))

    try:
        assert_paths_unlocked(lock_targets)
        return
    except WorkspaceStorageLockedError as exc:
        if not is_interactive():
            raise

        while True:
            choice = prompt_choice(
                "Workspace DB appears locked. Close Cursor and retry?",
                {"r": "Retry lock check", "a": "Abort"},
                default="r",
            )
            if choice == "a":
                raise exc
            try:
                assert_paths_unlocked(lock_targets)
                return
            except WorkspaceStorageLockedError:
                continue

def _cmd_copy_mode_c(
    *,
    cursor_user_dir: Path,
    src: Path,
    dst: Path,
    overwrite_dst: bool | None,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    unsafe_db: bool,
    assume_yes: bool,
) -> None:
    src = _normalize_workspace_path(src, role="Source", must_exist=True)
    dst_input = _normalize_workspace_path(dst, role="Destination", must_exist=False)
    dst_container, dst = _resolve_destination_folder(src=src, dst_input=dst_input)
    if dst_container != dst and not dst_container.exists():
        dst_container.mkdir(parents=True, exist_ok=True)
    if dst == src:
        raise ValueError("Destination resolves to the same folder as Source. Choose a different destination.")
    info(f"Resolved destination: {dst}")

    src_ws_id = _require_existing_workspace_storage_id(cursor_user_dir, src)
    src_storage_dir = workspace_storage_dir(cursor_user_dir, src_ws_id)
    unsafe_db = _handle_workspace_db_lock_dialog(
        src_storage_dir=src_storage_dir,
        unsafe_db=unsafe_db,
        assume_yes=assume_yes,
    )

    _handle_overwrite_folder_dialog(dst, overwrite_dst=overwrite_dst, assume_yes=assume_yes)

    workspace_copy_stats = copy_tree_with_progress(
        src_dir=src,
        dst_dir=dst,
        desc="Copy workspace",
    )

    dst_ws_id = compute_folder_workspace_id(dst).workspace_id
    dst_storage_dir = workspace_storage_dir(cursor_user_dir, dst_ws_id)
    dst_folder_uri = path_to_folder_uri(dst)
    storage_copy_stats: CopyStats | None = None
    storage_merge_result: MergeResult | None = None
    if dst_storage_dir.exists():
        action = _resolve_existing_workspace_storage_action(
            dst_storage_dir=dst_storage_dir,
            overwrite_workspace_storage=overwrite_workspace_storage,
            merge_workspace_storage=merge_workspace_storage,
            assume_yes=assume_yes,
        )
        if action == "merge":
            storage_merge_result = _merge_workspace_storage_db(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
            )
            _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
        else:
            storage_copy_stats = _clone_workspace_storage(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
                dst_folder_uri=dst_folder_uri,
                overwrite=True,
                assume_yes=assume_yes,
            )
    else:
        storage_copy_stats = _clone_workspace_storage(
            src_storage_dir=src_storage_dir,
            dst_storage_dir=dst_storage_dir,
            dst_folder_uri=dst_folder_uri,
            overwrite=overwrite_workspace_storage,
            assume_yes=assume_yes,
        )

    success("OK")
    info(f"Copied workspace: {src} -> {dst}")
    if storage_merge_result is not None:
        info(f"Merged workspaceStorage DB: {src_ws_id} -> {dst_ws_id}")
        info(
            "Inserted keys: ItemTable="
            + str(storage_merge_result.inserted_itemtable_keys)
            + " cursorDiskKV="
            + str(storage_merge_result.inserted_cursordiskkv_keys)
        )
        info(
            f"Composer entries: {storage_merge_result.composer_ids_before} -> "
            f"{storage_merge_result.composer_ids_after}"
        )
        info(f"Backup: {storage_merge_result.backup_path}")
    else:
        info(f"Cloned workspaceStorage: {src_ws_id} -> {dst_ws_id}")
    _print_copy_stats("Workspace files", workspace_copy_stats)
    if storage_copy_stats is not None:
        _print_copy_stats("WorkspaceStorage", storage_copy_stats)


def _cmd_move_mode_c(
    *,
    cursor_user_dir: Path,
    src: Path,
    dst: Path,
    overwrite_dst: bool | None,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    unsafe_db: bool,
    assume_yes: bool,
) -> None:
    src = _normalize_workspace_path(src, role="Source", must_exist=True)
    dst_input = _normalize_workspace_path(dst, role="Destination", must_exist=False)
    dst_container, dst = _resolve_destination_folder(src=src, dst_input=dst_input)
    if dst_container != dst and not dst_container.exists():
        dst_container.mkdir(parents=True, exist_ok=True)
    if dst == src:
        raise ValueError("Destination resolves to the same folder as Source. Choose a different destination.")
    info(f"Resolved destination: {dst}")

    src_ws_id = _require_existing_workspace_storage_id(cursor_user_dir, src)
    src_storage_dir = workspace_storage_dir(cursor_user_dir, src_ws_id)
    unsafe_db = _handle_workspace_db_lock_dialog(
        src_storage_dir=src_storage_dir,
        unsafe_db=unsafe_db,
        assume_yes=assume_yes,
    )

    _handle_overwrite_folder_dialog(dst, overwrite_dst=overwrite_dst, assume_yes=assume_yes)

    shutil.move(src, dst)

    dst_ws_id = compute_folder_workspace_id(dst).workspace_id
    dst_storage_dir = workspace_storage_dir(cursor_user_dir, dst_ws_id)
    dst_folder_uri = path_to_folder_uri(dst)
    storage_copy_stats: CopyStats | None = None
    storage_merge_result: MergeResult | None = None
    if dst_storage_dir.exists():
        action = _resolve_existing_workspace_storage_action(
            dst_storage_dir=dst_storage_dir,
            overwrite_workspace_storage=overwrite_workspace_storage,
            merge_workspace_storage=merge_workspace_storage,
            assume_yes=assume_yes,
        )
        if action == "merge":
            storage_merge_result = _merge_workspace_storage_db(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
            )
            _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
        else:
            storage_copy_stats = _clone_workspace_storage(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
                dst_folder_uri=dst_folder_uri,
                overwrite=True,
                assume_yes=assume_yes,
            )
    else:
        storage_copy_stats = _clone_workspace_storage(
            src_storage_dir=src_storage_dir,
            dst_storage_dir=dst_storage_dir,
            dst_folder_uri=dst_folder_uri,
            overwrite=overwrite_workspace_storage,
            assume_yes=assume_yes,
        )

    success("OK")
    info(f"Moved workspace: {src} -> {dst}")
    if storage_merge_result is not None:
        info(f"Merged workspaceStorage DB: {src_ws_id} -> {dst_ws_id}")
        info(
            "Inserted keys: ItemTable="
            + str(storage_merge_result.inserted_itemtable_keys)
            + " cursorDiskKV="
            + str(storage_merge_result.inserted_cursordiskkv_keys)
        )
        info(
            f"Composer entries: {storage_merge_result.composer_ids_before} -> "
            f"{storage_merge_result.composer_ids_after}"
        )
        info(f"Backup: {storage_merge_result.backup_path}")
    else:
        info(f"Cloned workspaceStorage: {src_ws_id} -> {dst_ws_id}")
    if storage_copy_stats is not None:
        _print_copy_stats("WorkspaceStorage", storage_copy_stats)


def _require_existing_workspace_storage_id(cursor_user_dir: Path, folder: Path) -> str:
    found = find_workspace_storage_id_for_folder(cursor_user_dir, folder)
    if found:
        return found
    # ! Fallback: compute id (works only if folder stat matches existing id).
    computed = compute_folder_workspace_id(folder).workspace_id
    if workspace_storage_dir(cursor_user_dir, computed).exists():
        return computed
    raise FileNotFoundError(
        "No workspaceStorage entry found for this folder. "
        "Open the folder once in Cursor, then retry."
    )


def _resolve_existing_workspace_storage_action(
    *,
    dst_storage_dir: Path,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    assume_yes: bool,
) -> str:
    """Resolves how to handle an existing destination workspaceStorage directory."""
    if merge_workspace_storage:
        if overwrite_workspace_storage is not None:
            raise ValueError(
                "Do not combine --merge-workspace-storage with "
                "--overwrite-workspace-storage/--no-overwrite-workspace-storage."
            )
        return "merge"

    if overwrite_workspace_storage is True:
        return "overwrite"

    if overwrite_workspace_storage is False:
        raise FileExistsError(
            f"workspaceStorage exists: {dst_storage_dir}. "
            "Overwriting is disabled. Use --merge-workspace-storage or --overwrite-workspace-storage."
        )

    # * overwrite_workspace_storage is None.
    if assume_yes or not is_interactive():
        raise FileExistsError(
            f"workspaceStorage exists: {dst_storage_dir}. "
            "Specify --merge-workspace-storage or --overwrite-workspace-storage."
        )

    choice = prompt_choice(
        "Destination workspaceStorage already exists. What next?",
        {
            "m": "Merge source chats into existing destination (recommended)",
            "o": "Overwrite destination workspaceStorage (delete and replace)",
            "a": "Abort",
        },
        default="m",
    )
    if choice == "m":
        return "merge"
    if choice == "o":
        return "overwrite"
    raise FileExistsError(f"Aborted by user due to existing workspaceStorage: {dst_storage_dir}")


def _write_workspace_storage_meta(storage_dir: Path, folder_uri: str) -> None:
    """Writes/updates workspaceStorage `workspace.json` to match the folder URI."""
    meta = storage_dir / "workspace.json"
    meta.write_text('{\n  "folder": "' + folder_uri + '"\n}', encoding="utf-8")


def _merge_workspace_storage_db(*, src_storage_dir: Path, dst_storage_dir: Path) -> MergeResult:
    """Merges workspace DB chat state from src into existing dst."""
    src_db = (src_storage_dir / "state.vscdb").resolve()
    dst_db = (dst_storage_dir / "state.vscdb").resolve()
    if not src_db.exists():
        raise FileNotFoundError(src_db)
    if not dst_db.exists():
        raise FileNotFoundError(dst_db)

    # * Merging writes and swaps the destination DB file; it must be unlocked.
    _require_unlocked_for_merge(dst_db, [src_db])
    return merge_workspace_state(dst_db_path=dst_db, src_db_paths=[src_db])


def _clone_workspace_storage(
    *,
    src_storage_dir: Path,
    dst_storage_dir: Path,
    dst_folder_uri: str,
    overwrite: bool | None,
    assume_yes: bool,
) -> CopyStats:
    _handle_overwrite_folder_dialog(
        dst_storage_dir, overwrite_dst=overwrite, assume_yes=assume_yes, label="workspaceStorage"
    )

    stats = copy_tree_with_progress(
        src_dir=src_storage_dir,
        dst_dir=dst_storage_dir,
        desc="Copy workspaceStorage",
    )
    _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
    return stats


def _print_copy_stats(label: str, stats: CopyStats) -> None:
    mib = stats.bytes_copied / (1024 * 1024)
    mib_s = stats.bytes_per_second / (1024 * 1024)
    info(f"{label}: files={stats.files_copied}, dirs={stats.dirs_created}, bytes={mib:.2f} MiB")
    info(f"{label}: time={stats.duration_s:.2f}s, speed={mib_s:.2f} MiB/s")


def _handle_overwrite_folder_dialog(
    path: Path,
    *,
    overwrite_dst: bool | None,
    assume_yes: bool,
    label: str = "destination",
) -> None:
    if not path.exists():
        return

    if overwrite_dst is False:
        raise FileExistsError(f"{label} exists: {path}. Overwrite disabled.")

    if overwrite_dst is None:
        if assume_yes or not is_interactive():
            raise FileExistsError(
                f"{label} exists: {path}. Use --overwrite-dst/--overwrite-workspace-storage to overwrite."
            )
        if not prompt_yes_no(f"{label} exists: {path}. Overwrite (delete) it?", default=False):
            raise FileExistsError(f"{label} overwrite rejected by user: {path}")

    while True:
        try:
            _robust_rmtree(path)
            return
        except OSError as exc:
            if assume_yes or not is_interactive():
                raise
            print()
            print(f"Failed to delete {label}: {path}")
            print(str(exc))
            print()
            if prompt_choice(
                "What next?",
                {"r": "Retry delete", "a": "Abort"},
                default="r",
            ) == "r":
                time.sleep(0.25)
                continue
            raise PermissionError(f"Aborted by user due to delete failure: {path}") from exc

def _robust_rmtree(path: Path, *, retries: int = 5, delay_s: float = 0.15) -> None:
    """Removes a directory tree, handling Windows readonly files."""
    last_exc: OSError | None = None
    for attempt in range(retries):
        try:
            _rmtree_once(path)
            return
        except OSError as exc:
            last_exc = exc
            if not _is_transient_delete_error(exc):
                raise
            time.sleep(delay_s * (attempt + 1))
    if last_exc is not None:
        raise last_exc


def _rmtree_once(path: Path) -> None:
    def _handle_exc(func, target_path: str, exc: BaseException) -> None:
        if isinstance(exc, FileNotFoundError):
            return
        if isinstance(exc, PermissionError):
            try:
                os.chmod(target_path, stat.S_IWRITE)
            except OSError:
                pass
            try:
                func(target_path)
                return
            except OSError:
                pass
        raise exc

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, ignore_errors=False, onexc=_handle_exc)
        return

    def _onerror(func, target_path: str, exc_info) -> None:  # pragma: no cover
        _handle_exc(func, target_path, exc_info[1])

    shutil.rmtree(path, ignore_errors=False, onerror=_onerror)  # pragma: no cover


def _is_transient_delete_error(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if os.name == "nt":
        winerror = getattr(exc, "winerror", None)
        return winerror in (5, 32, 33)
    return False


def _handle_workspace_db_lock_dialog(
    *,
    src_storage_dir: Path,
    unsafe_db: bool,
    assume_yes: bool,
) -> bool:
    if unsafe_db:
        return True

    db_paths = list(workspace_db_paths(src_storage_dir))
    if is_interactive():
        info("Checking workspace DB lock...")
    try:
        assert_paths_unlocked(db_paths)
        if is_interactive():
            success("LOCK CHECK: OK")
        return False
    except WorkspaceStorageLockedError as exc:
        if assume_yes:
            # * In auto-confirm mode, we do not continue unsafely without explicit flag.
            raise exc
        if not is_interactive():
            raise exc

        while True:
            warn(str(exc))
            choice = prompt_choice(
                "Workspace DB is locked. What next?",
                {
                    "r": "Retry lock check (after closing Cursor)",
                    "u": "Continue with -UnsafeDB (may copy inconsistent state)",
                    "a": "Abort",
                },
                default="r",
            )
            if choice == "r":
                time.sleep(0.25)
                try:
                    assert_paths_unlocked(db_paths)
                    success("LOCK CHECK: OK")
                    return False
                except WorkspaceStorageLockedError as retry_exc:
                    exc = retry_exc
                    continue
            if choice == "u":
                if prompt_yes_no("Proceed with UnsafeDB?", default=False):
                    return True
                continue
            raise WorkspaceStorageLockedError("Aborted by user due to locked workspace DB.")


def _tui_config_to_argv(cfg) -> list[str]:
    argv: list[str] = []
    if cfg.cursor_user_dir is not None:
        argv += ["--cursor-user-dir", str(cfg.cursor_user_dir)]

    argv.append(cfg.cmd)

    if cfg.cmd == "doctor":
        argv += ["--path", str(cfg.src)]
        return argv

    if cfg.cmd == "merge":
        argv += ["--path", str(cfg.src)]
        if cfg.assume_yes:
            argv.append("--yes")
        if cfg.delete_sources:
            argv.append("--delete-sources")
        return argv

    argv += ["--src", str(cfg.src), "--dst", str(cfg.dst)]
    argv.append("--overwrite-dst" if cfg.overwrite_dst else "--no-overwrite-dst")
    if cfg.merge_workspace_storage:
        argv.append("--merge-workspace-storage")
    else:
        argv.append(
            "--overwrite-workspace-storage"
            if cfg.overwrite_workspace_storage
            else "--no-overwrite-workspace-storage"
        )
    if cfg.unsafe_db:
        argv.append("-UnsafeDB")
    return argv


def _normalize_workspace_path(path: Path, *, role: str, must_exist: bool) -> Path:
    raw = str(path).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("\"", "'"):
        raw = raw[1:-1].strip()
    path = Path(raw).expanduser().resolve()
    if must_exist and not path.exists():
        raise FileNotFoundError(f"{role} path does not exist: {path}")

    if path.exists() and path.is_file():
        if not is_interactive():
            raise NotADirectoryError(f"{role} must be a folder, but is a file: {path}")
        if prompt_yes_no(
            f"{role} is a file: {path}. Use its parent folder instead?",
            default=True,
        ):
            return path.parent.resolve()
        raise NotADirectoryError(f"{role} must be a folder: {path}")

    if must_exist and not path.is_dir():
        raise NotADirectoryError(f"{role} must be a folder: {path}")

    return path


def _resolve_destination_folder(*, src: Path, dst_input: Path) -> tuple[Path, Path]:
    """Resolves destination folder semantics.

    Rules:
      - If dst name differs from src name, dst is treated as a *container* and we
        create/use dst/src_name.
      - If dst name equals src name, dst is treated as the final folder.
    """
    src_name = src.name
    if not dst_input.name or dst_input.name != src_name:
        return dst_input, dst_input / src_name
    return dst_input.parent, dst_input

